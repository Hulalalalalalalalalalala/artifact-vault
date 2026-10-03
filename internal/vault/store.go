package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Entry struct {
	Name      string    `json:"name"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

type index struct {
	Entries map[string]Entry `json:"entries"`
}

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

// withLock serializes access to the repository across cooperating processes.
// Mutating operations pass exclusive=true; readers take a shared lock. The
// lock is an flock on <root>/.lock, so it is released automatically if a
// process dies mid-operation and nothing can wait forever on a stale lock.
func (s *Store) withLock(exclusive bool, fn func() error) error {
	return s.withLockOpts(exclusive, true, fn)
}

// withLockOpts is withLock with control over root creation. Read-only-style
// operations that must never materialize a missing repository (such as
// export) pass createRoot=false.
func (s *Store) withLockOpts(exclusive, createRoot bool, fn func() error) error {
	if strings.TrimSpace(s.root) == "" {
		return errors.New("root is required")
	}
	if createRoot {
		if err := os.MkdirAll(s.root, 0o755); err != nil {
			return err
		}
	}
	// Read-only operations that must not materialize anything open the lock
	// without O_CREATE: an initialized repository always has a lock file, so
	// a missing one means the repository was never initialized.
	var lock *os.File
	var err error
	if createRoot {
		lock, err = os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0o644)
	} else {
		lock, err = os.OpenFile(s.lockPath(), os.O_RDWR, 0o644)
	}
	if err != nil {
		if !createRoot && errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("repository %q is not initialized; run init first", s.root)
		}
		return err
	}
	defer lock.Close()
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(lock.Fd()), mode); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return fn()
}

func (s *Store) Init() error {
	return s.withLock(true, s.initLocked)
}

func (s *Store) initLocked() error {
	if err := os.MkdirAll(filepath.Join(s.root, "objects"), 0o755); err != nil {
		return err
	}
	_, err := os.Stat(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return s.save(index{Entries: map[string]Entry{}})
	}
	return err
}

// Put stores the content of source under name. Both a new name and an
// overwrite require the entire current name mapping to be usable first: the
// index is loaded with the same strict rules verify, gc, and snapshot creation
// apply (one complete JSON object with an explicitly present entries mapping;
// a genuine {"entries":{}} is a legitimate empty repository, while a bare
// null, a missing or null entries mapping, a non-object entries value, a
// truncated document, trailing content, or any duplicate key at any level —
// including a name written directly and again through Unicode escapes — is
// corruption), and every existing record is keyed by its recorded name with a
// legal name, a 64-character lowercase-hex digest, and a non-negative size.
// The whole mapping is validated before the input file is opened or anything
// is staged, and a bad record unrelated to name rejects the upload just the
// same: corruption is never rewritten into a seemingly successful put, and the
// mapping is never cleared or saved minus the offending record.
//
// Once the mapping proves usable the content is staged in a temporary file
// inside the repository while its size and SHA-256 are computed, then either
// installed as a new content object or matched against the object already
// stored under the same digest. A successful put means the object behind
// name's digest is verifiably complete: an existing object is reused only when
// it is a regular file whose full contents can be read and whose actual size
// and SHA-256 equal this upload's. Anything else — a truncated or rewritten
// object, a same-size object with different bytes, a symlink (followed or
// dangling), a directory, or an unreadable path — fails the upload and leaves
// the name mapping, the existing object, and every snapshot untouched; a
// damaged object is never repaired by overwriting it. Reuse never copies,
// rewrites, or re-permissions the healthy object, so several names can share
// one object.
//
// Index problems are reported as "cannot store %q: current index is corrupt:
// <reason>", with the duplicated key or offending artifact named, and stay
// distinct from a failure reading the input file. On any failure no object is
// installed for this upload, the index keeps its original bytes, and any
// staged temporary file is removed.
func (s *Store) Put(name, source string) (Entry, error) {
	if err := validateName(name); err != nil {
		return Entry{}, err
	}
	if source == "" {
		return Entry{}, errors.New("file is required")
	}
	var entry Entry
	err := s.withLock(true, func() error {
		if err := s.initLocked(); err != nil {
			return err
		}
		// The entire current mapping must be complete and unambiguous before
		// the upload may add or overwrite a name. Validate before reading the
		// input or staging anything, so a corrupt mapping can never be
		// rewritten into a successful upload and a failure leaves no trace.
		idx, err := s.loadCurrentIndexForPut(name)
		if err != nil {
			return err
		}
		in, err := os.Open(source)
		if err != nil {
			return err
		}
		defer in.Close()
		tmp, err := os.CreateTemp(filepath.Join(s.root, "objects"), ".upload-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)
		hash := sha256.New()
		size, copyErr := io.Copy(io.MultiWriter(tmp, hash), in)
		closeErr := tmp.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		digest := hex.EncodeToString(hash.Sum(nil))
		if err := s.placeObject(name, digest, size, tmpName); err != nil {
			return err
		}
		entry = Entry{Name: name, Digest: digest, Size: size, CreatedAt: time.Now().UTC()}
		idx.Entries[name] = entry
		return s.save(idx)
	})
	if err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// loadCurrentIndexForPut reads the current index for an upload and validates
// every record it holds. The structural rules loadStrict enforces for verify,
// gc, and snapshot creation apply here too, so a missing entries mapping,
// trailing content, or a duplicate key cannot be silently turned into an empty
// repository by saving the upload. A malformed record unrelated to the
// uploaded name rejects the upload as well; the underlying reason names the
// duplicated key or offending artifact and is wrapped to name the upload and
// the current index, which keeps it distinct from a failure to read the input
// file or from damage to an existing content object.
func (s *Store) loadCurrentIndexForPut(name string) (index, error) {
	idx, err := s.loadStrict()
	if err != nil {
		return index{}, fmt.Errorf("cannot store %q: %w", name, err)
	}
	// Sorted order makes the first reported bad record deterministic.
	keys := make([]string, 0, len(idx.Entries))
	for key := range idx.Entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validateEntryRecord(key, idx.Entries[key]); err != nil {
			return index{}, fmt.Errorf("cannot store %q: current index is corrupt: %w", name, err)
		}
	}
	return idx, nil
}

// placeObject makes the content object for digest available in the
// repository. When no object exists at the digest path yet, the staged upload
// at tmpName is renamed into place. When something already exists there it is
// reused only if it proves to be a complete, intact copy of this upload (see
// checkReusableObject); otherwise the upload fails and the staged file is
// removed by the caller's deferred cleanup. An inspection failure is never
// treated as "object missing": only a genuine not-exist installs new content.
func (s *Store) placeObject(name, digest string, size int64, tmpName string) error {
	object := s.objectPath(digest)
	info, err := os.Lstat(object)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.Rename(tmpName, object)
	case err != nil:
		return fmt.Errorf("cannot store %q: cannot inspect existing object %s: %w", name, digest, err)
	}
	if err := checkReusableObject(info, object, digest, size); err != nil {
		return fmt.Errorf("cannot store %q: %w", name, err)
	}
	return nil
}

// checkReusableObject verifies that an existing content object is a complete,
// intact copy of the uploaded content: a regular file — never a symlink,
// whether or not its target exists, and never a directory or other special
// file — whose actual size and SHA-256 match the digest and size computed for
// this upload. The object is read in full; a read failure is reported, not
// treated as absence.
func checkReusableObject(info os.FileInfo, object, digest string, size int64) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("existing object %s is a symbolic link", digest)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("existing object %s is not a regular file", digest)
	}
	file, err := os.Open(object)
	if err != nil {
		return fmt.Errorf("cannot read existing object %s: %w", digest, err)
	}
	hash := sha256.New()
	n, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("cannot read existing object %s: %w", digest, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("cannot read existing object %s: %w", digest, closeErr)
	}
	if n != size {
		return fmt.Errorf("existing object %s is corrupted: content is %d bytes, upload is %d", digest, n, size)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != digest {
		return fmt.Errorf("existing object %s is corrupted: content checksum is %s", digest, actual)
	}
	return nil
}

func (s *Store) List() ([]Entry, error) {
	var entries []Entry
	err := s.withLock(false, func() error {
		idx, err := s.load()
		if err != nil {
			return err
		}
		entries = make([]Entry, 0, len(idx.Entries))
		for _, entry := range idx.Entries {
			entries = append(entries, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Verify checks every entry of the current name mapping against its content
// object: the object must exist and its actual size and SHA-256 must match
// the recorded metadata. The mapping itself must be complete and unambiguous
// first: the index must be one complete JSON object with an explicitly
// present entries mapping (a true {"entries":{}} is a legitimate empty
// repository; null, a missing or null entries field, an array, truncated
// input, trailing content, or any duplicate key — including a name repeated
// through Unicode escapes — is corruption), and every record must pass the
// same validity checks downloads and gc apply (keyed by its recorded name, a
// legal name, a 64-character lowercase-hex digest, a non-negative size). A
// single malformed record fails the whole pass; bad records are never
// skipped to report success over the rest. Mapping problems are reported
// before any object is read, so index corruption is always distinguished
// from object damage.
//
// The whole pass — reading the mapping and checking every object it
// references — runs under one shared repository lock, so the mapping and the
// objects it points at cannot be replaced or collected by another process
// between the first read and the last check: an overwrite, snapshot restore,
// import, or gc either completes before the pass starts (and the pass
// observes the completed state) or waits until the pass ends. The lock is
// shared, so concurrent lists, downloads, and other verifies proceed
// alongside it. Verify never rewrites the mapping, snapshots, or objects,
// and never repairs damaged content; on the first failure it reports the
// cause and returns a zero count.
func (s *Store) Verify() (int, error) {
	count := 0
	err := s.withLock(false, func() error {
		idx, err := s.loadStrict()
		if err != nil {
			return err
		}
		entries := make([]Entry, 0, len(idx.Entries))
		for key, entry := range idx.Entries {
			if err := validateEntryRecord(key, entry); err != nil {
				return fmt.Errorf("current index is corrupt: %w", err)
			}
			entries = append(entries, entry)
		}
		// Sort by name so the first reported failure is deterministic.
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, entry := range entries {
			if err := s.verifyObject(entry); err != nil {
				return fmt.Errorf("verify %q: %w", entry.Name, err)
			}
		}
		count = len(entries)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// verifyObject checks that the content object for entry exists and that its
// actual size and SHA-256 match the recorded metadata.
func (s *Store) verifyObject(entry Entry) error {
	file, err := os.Open(s.objectPath(entry.Digest))
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return errors.New("read failed")
	}
	if size != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.Digest {
		return errors.New("content mismatch")
	}
	return nil
}

func (s *Store) load() (index, error) {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return index{}, err
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return index{}, err
	}
	if idx.Entries == nil {
		idx.Entries = map[string]Entry{}
	}
	return idx, nil
}

func (s *Store) save(idx index) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(s.root, ".index-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.indexPath())
}

func (s *Store) indexPath() string               { return filepath.Join(s.root, "index.json") }
func (s *Store) lockPath() string                { return filepath.Join(s.root, ".lock") }
func (s *Store) objectPath(digest string) string { return filepath.Join(s.root, "objects", digest) }

func validateName(name string) error {
	if strings.TrimSpace(name) == "" || filepath.IsAbs(name) || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
		return errors.New("name must be a nonempty relative slash-separated path")
	}
	clean := filepath.Clean(name)
	if clean != name || strings.HasPrefix(clean, "../") {
		return errors.New("name must be normalized and remain within the vault namespace")
	}
	return nil
}
