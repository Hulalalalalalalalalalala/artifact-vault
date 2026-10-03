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

type Store struct {
	root string
	// verifyHook, when set, runs while Verify holds the shared repository
	// lock with the index already loaded and immediately before the first
	// object is read. It exists for tests that must exercise the pass while
	// it is in flight; Stores produced by New leave it nil.
	verifyHook func()
}

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

// Put stores the content of source under name. The content is staged in a
// temporary file inside the repository while its size and SHA-256 are
// computed, then either installed as a new content object or matched against
// the object already stored under the same digest. A successful put means the
// object behind name's digest is verifiably complete: an existing object is
// reused only when it is a regular file whose full contents can be read and
// whose actual size and SHA-256 equal this upload's. Anything else — a
// truncated or rewritten object, a same-size object with different bytes, a
// symlink (followed or dangling), a directory, or an unreadable path — fails
// the upload and leaves the name mapping, the existing object, and every
// snapshot untouched; a damaged object is never repaired by overwriting it.
// Reuse never copies, rewrites, or re-permissions the healthy object, so
// several names can share one object.
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
		idx, err := s.load()
		if err != nil {
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

// Verify checks every record in the current name mapping against the object
// it references: the object must exist as a regular file whose actual size
// and SHA-256 equal the recorded metadata. Only the current mapping is
// checked; objects referenced solely by snapshots, and unreferenced objects,
// never influence the result.
//
// The whole pass — from reading the mapping through the final object read —
// runs under one shared repository lock (LOCK_SH), held continuously. Other
// read-only operations (List, Get, and another Verify) take the same shared
// lock and proceed concurrently, while every operation that could replace
// the mapping or collect an object (Put, snapshot create/restore/import, and
// GC) takes an exclusive lock and waits. A verify therefore always certifies
// one complete, self-consistent state: it either fully observes a state
// before a concurrent change or fully observes the state after it, and an
// object the mapping it read still references cannot be garbage-collected
// underneath it. This holds across separate processes that opened the same
// repository, because the lock is an flock on <root>/.lock.
//
// Verify never modifies the mapping, any snapshot, or any object, and never
// repairs damage: a missing object, a size or checksum mismatch, a
// non-regular-file path, or a read failure is an error naming the artifact,
// with a zero count. Lock release on return — including an error return —
// lets pending changes proceed immediately.
func (s *Store) Verify() (int, error) {
	var n int
	err := s.withLock(false, func() error {
		idx, err := s.loadCurrentIndex()
		if err != nil {
			return err
		}
		// Validate every record before reading any object, so a corrupt
		// mapping is reported as record corruption rather than as a missing
		// object, and the count is always taken from one complete mapping.
		for key, entry := range idx.Entries {
			if err := validateEntryRecord(key, entry); err != nil {
				return err
			}
		}
		names := make([]string, 0, len(idx.Entries))
		for name := range idx.Entries {
			names = append(names, name)
		}
		sort.Strings(names)
		if hook := s.verifyHook; hook != nil {
			hook()
		}
		// Check each distinct referenced object once; two names sharing one
		// digest still count as two records, but the object is read once.
		checked := make(map[string]struct{}, len(names))
		for _, name := range names {
			entry := idx.Entries[name]
			if _, ok := checked[entry.Digest]; !ok {
				if err := s.verifyObject(entry); err != nil {
					return fmt.Errorf("verify %q: %w", name, err)
				}
				checked[entry.Digest] = struct{}{}
			}
		}
		n = len(names)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// verifyObject checks that the content object for entry exists as a regular
// file — never a symlink (dangling or followed) or another special file —
// and that its actual streamed size and SHA-256 equal the recorded size and
// digest. The caller holds the repository lock, which keeps concurrent
// writers and GC from replacing or collecting the object while it is read.
func (s *Store) verifyObject(entry Entry) error {
	path := s.objectPath(entry.Digest)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("object %s is missing", entry.Digest)
		}
		return fmt.Errorf("cannot inspect object %s: %w", entry.Digest, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("object %s is a symbolic link", entry.Digest)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("object %s is not a regular file", entry.Digest)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read object %s: %w", entry.Digest, err)
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("cannot read object %s: %w", entry.Digest, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("cannot read object %s: %w", entry.Digest, closeErr)
	}
	if size != entry.Size {
		return fmt.Errorf("object %s is corrupted: content is %d bytes, record says %d", entry.Digest, size, entry.Size)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != entry.Digest {
		return fmt.Errorf("object %s is corrupted: content checksum is %s, want %s", entry.Digest, actual, entry.Digest)
	}
	return nil
}

// loadCurrentIndex reads the index for an operation that certifies the
// current mapping: the file must exist, parse, and carry a non-null entries
// mapping. A missing index means the repository was never initialized; a
// null mapping cannot be distinguished from lost references. This is the
// strict reader shared by Verify, Get, and GC.
func (s *Store) loadCurrentIndex() (index, error) {
	data, err := os.ReadFile(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return index{}, fmt.Errorf("repository %q is not initialized: index.json is missing", s.root)
	}
	if err != nil {
		return index{}, err
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return index{}, err
	}
	if idx.Entries == nil {
		return index{}, errors.New("missing entries mapping")
	}
	return idx, nil
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
