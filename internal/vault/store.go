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
	if strings.TrimSpace(s.root) == "" {
		return errors.New("root is required")
	}
	if exclusive {
		if err := os.MkdirAll(s.root, 0o755); err != nil {
			return err
		}
	}
	lock, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
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
		object := s.objectPath(digest)
		if _, err := os.Stat(object); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(tmpName, object); err != nil {
				return err
			}
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

// Sentinel errors classifying download failures. Callers can distinguish a
// missing name from a damaged record, a damaged object, and an unusable output
// target with errors.Is while the wrapped message still names the name or the
// output path.
var (
	ErrNameNotFound      = errors.New("name not found")
	ErrRecordDamaged     = errors.New("record is corrupted")
	ErrObjectDamaged     = errors.New("content object is corrupted")
	ErrOutputUnavailable = errors.New("output is unavailable")
)

// Get downloads the artifact recorded under name to output.
//
// The file is only delivered once the full name record and the full object
// content have been validated: the index must parse and carry a name mapping,
// the selected entry must be filed under its own name with a 64 lowercase-hex
// digest and a non-negative size, and the object must be a regular file whose
// actual size and SHA-256 match the record. The object is streamed to a
// temporary file beside the destination in constant-size buffers, so memory
// use does not grow with the object, and an os.Rename is the single commit
// point: an existing output keeps its exact bytes on any failure, and a
// missing output is never replaced by a half-written file. A crash can leave
// only an unpublished temp file, which never blocks a retry.
//
// Get runs entirely under the shared repository lock and never writes inside
// the repository, so concurrent uploads, snapshot restores, and garbage
// collections serialize against it and it observes one complete record and
// object version at a time.
func (s *Store) Get(name, output string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if output == "" {
		return errors.New("output is required")
	}
	if strings.TrimSpace(s.root) == "" {
		return errors.New("root is required")
	}
	return s.withLock(false, func() error {
		// Resolve and authorize the destination before touching any content.
		prep, err := s.prepareOutput(output)
		if err != nil {
			return err
		}

		idx, err := s.loadStrict()
		if err != nil {
			return fmt.Errorf("cannot download %q: %w: %v", name, ErrRecordDamaged, err)
		}
		entry, ok := idx.Entries[name]
		if !ok {
			return fmt.Errorf("cannot download %q: %w", name, ErrNameNotFound)
		}
		if err := validateEntryRecord(name, entry); err != nil {
			return fmt.Errorf("cannot download %q: %w: %v", name, ErrRecordDamaged, err)
		}

		// Stream the object to a temp file beside the destination while
		// measuring and hashing it in fixed-size buffers. Until the rename
		// below, nothing occupies the requested output path.
		object := s.objectPath(entry.Digest)
		// Lstat (not Stat): a symlink must be rejected even when it points at
		// an intact file elsewhere.
		objInfo, err := os.Lstat(object)
		if err != nil {
			return fmt.Errorf("cannot download %q: %w: object %s: %v", name, ErrObjectDamaged, entry.Digest, err)
		}
		if objInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cannot download %q: %w: object %s is a symbolic link", name, ErrObjectDamaged, entry.Digest)
		}
		if !objInfo.Mode().IsRegular() {
			return fmt.Errorf("cannot download %q: %w: object %s is not a regular file", name, ErrObjectDamaged, entry.Digest)
		}
		if objInfo.Size() != entry.Size {
			return fmt.Errorf("cannot download %q: %w: object %s is %d bytes, record says %d",
				name, ErrObjectDamaged, entry.Digest, objInfo.Size(), entry.Size)
		}
		// O_NOFOLLOW closes the Lstat-to-open race: the descriptor never binds
		// to a symbolic link swapped in after the check.
		in, err := os.OpenFile(object, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				return fmt.Errorf("cannot download %q: %w: object %s is a symbolic link", name, ErrObjectDamaged, entry.Digest)
			}
			return fmt.Errorf("cannot download %q: %w: object %s: %v", name, ErrObjectDamaged, entry.Digest, err)
		}

		tmp, err := os.CreateTemp(prep.TempDir, prep.Pattern)
		if err != nil {
			in.Close()
			return fmt.Errorf("cannot download %q to %s: %w: %v", name, output, ErrOutputUnavailable, err)
		}
		tmpName := tmp.Name()
		// The temp file is an unpublished artifact: remove it on any failure so
		// a retry starts clean without manual cleanup.
		committed := false
		defer func() {
			if !committed {
				os.Remove(tmpName)
			}
		}()

		hasher := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(in, entry.Size+1))
		closeInErr := in.Close()
		if copyErr != nil {
			tmp.Close()
			return fmt.Errorf("cannot download %q: %w: object %s: %v", name, ErrObjectDamaged, entry.Digest, copyErr)
		}
		if closeInErr != nil {
			tmp.Close()
			return fmt.Errorf("cannot download %q: %w: object %s: %v", name, ErrObjectDamaged, entry.Digest, closeInErr)
		}
		if written != entry.Size {
			tmp.Close()
			return fmt.Errorf("cannot download %q: %w: object %s is %d bytes, record says %d",
				name, ErrObjectDamaged, entry.Digest, written, entry.Size)
		}
		if actual := hex.EncodeToString(hasher.Sum(nil)); actual != entry.Digest {
			tmp.Close()
			return fmt.Errorf("cannot download %q: %w: object %s has checksum %s",
				name, ErrObjectDamaged, entry.Digest, actual)
		}
		// Flush the complete payload to disk before publishing it.
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return fmt.Errorf("cannot download %q to %s: %w: %v", name, output, ErrOutputUnavailable, err)
		}
		if err := tmp.Close(); err != nil {
			return fmt.Errorf("cannot download %q to %s: %w: %v", name, output, ErrOutputUnavailable, err)
		}
		// Publish with the destination's previous permission bits (0644 for
		// a new file). Chmod on the unpublished temp file cannot affect an
		// existing hard-linked destination.
		if err := os.Chmod(tmpName, prep.Mode); err != nil {
			return fmt.Errorf("cannot download %q to %s: %w: %v", name, output, ErrOutputUnavailable, err)
		}
		// Single commit point: the destination is atomically either the old
		// file or the complete new file, never a partial one.
		if err := os.Rename(tmpName, output); err != nil {
			return fmt.Errorf("cannot download %q to %s: %w: %v", name, output, ErrOutputUnavailable, err)
		}
		committed = true
		return nil
	})
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

func (s *Store) Verify() (int, error) {
	entries, err := s.List()
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		if err := s.verifyObject(entry); err != nil {
			return 0, fmt.Errorf("verify %q: %w", entry.Name, err)
		}
	}
	return len(entries), nil
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
