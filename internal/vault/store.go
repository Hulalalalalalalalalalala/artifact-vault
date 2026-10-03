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
		info, statErr := os.Lstat(object)
		switch {
		case errors.Is(statErr, os.ErrNotExist):
			// No object for this digest yet: stage the uploaded content.
			if err := os.Rename(tmpName, object); err != nil {
				return err
			}
		case statErr != nil:
			// An inspection failure (permissions, I/O) is not "missing".
			return fmt.Errorf("cannot store %q: cannot inspect existing object %s: %w", name, digest, statErr)
		default:
			// An object already sits at this digest. It may be reused only if
			// it provably holds exactly the bytes just uploaded; anything else
			// (truncated, rewritten, a symlink, a non-regular file) fails the
			// upload rather than pointing the new name at bad content. The
			// existing object is never repaired by overwriting it here.
			if err := checkReusableObject(info, object, digest, size); err != nil {
				return fmt.Errorf("cannot store %q: existing object %s is not reusable: %w", name, digest, err)
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

// checkReusableObject verifies that an object already present at path can
// stand in for a fresh upload whose content hashes to digest and is size
// bytes long. The object must be a regular file (a symlink is refused
// outright, never followed, whatever its target), fully readable, and its
// actual byte count and SHA-256 must match the uploaded content. A healthy
// object is left untouched — same bytes, same permissions — so names that
// already share it keep their object and no copy is made.
func checkReusableObject(info os.FileInfo, path, digest string, size int64) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot read object: %w", err)
	}
	hash := sha256.New()
	n, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("cannot read object: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("cannot read object: %w", closeErr)
	}
	if n != size {
		return fmt.Errorf("size mismatch: object is %d bytes, upload is %d bytes", n, size)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != digest {
		return fmt.Errorf("checksum mismatch: object hashes to %s, upload hashes to %s", actual, digest)
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
