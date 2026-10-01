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

// Snapshot is a point-in-time copy of the name-to-entry mapping. Entries are
// copied, not referenced, so later puts never mutate a saved snapshot.
type Snapshot struct {
	Name      string           `json:"name"`
	CreatedAt time.Time        `json:"createdAt"`
	Entries   map[string]Entry `json:"entries"`
}

// SnapshotInfo is the summary line returned by ListSnapshots.
type SnapshotInfo struct {
	Name    string
	Entries int
}

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

// withLock serializes mutating operations (exclusive) and reads (shared)
// across processes using an advisory flock on a lock file inside the vault.
// The kernel releases the lock automatically if the process is killed, so a
// crash can never leave later operations blocked forever.
func (s *Store) withLock(exclusive bool, fn func() error) error {
	if strings.TrimSpace(s.root) == "" {
		return errors.New("root is required")
	}
	if err := os.MkdirAll(s.root, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.lockPath(), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), mode); err != nil {
		return err
	}
	return fn()
}

func (s *Store) Init() error {
	return s.withLock(true, func() error {
		return s.ensureInitializedLocked()
	})
}

// ensureInitializedLocked creates the vault layout and an empty index if it
// does not exist. Callers must hold the lock.
func (s *Store) ensureInitializedLocked() error {
	if err := os.MkdirAll(s.objectsDir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(s.snapshotsDir(), 0o755); err != nil {
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
		if err := s.ensureInitializedLocked(); err != nil {
			return err
		}
		in, err := os.Open(source)
		if err != nil {
			return err
		}
		defer in.Close()
		tmp, err := os.CreateTemp(s.objectsDir(), ".upload-*")
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
	return entry, err
}

func (s *Store) Get(name, output string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if output == "" {
		return errors.New("output is required")
	}
	return s.withLock(false, func() error {
		idx, err := s.load()
		if err != nil {
			return err
		}
		entry, ok := idx.Entries[name]
		if !ok {
			return fmt.Errorf("artifact %q not found", name)
		}
		in, err := os.Open(s.objectPath(entry.Digest))
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(output)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
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
	var count int
	err := s.withLock(false, func() error {
		idx, err := s.load()
		if err != nil {
			return err
		}
		for _, entry := range idx.Entries {
			if err := s.verifyObject(entry); err != nil {
				return err
			}
		}
		count = len(idx.Entries)
		return nil
	})
	return count, err
}

// verifyObject reads the referenced content object and checks that its actual
// size and SHA-256 digest match the record.
func (s *Store) verifyObject(e Entry) error {
	file, err := os.Open(s.objectPath(e.Digest))
	if err != nil {
		return fmt.Errorf("artifact %q: %w", e.Name, err)
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return fmt.Errorf("artifact %q: read failed: %w", e.Name, err)
	}
	if size != e.Size {
		return fmt.Errorf("artifact %q: size mismatch: record says %d, object has %d", e.Name, e.Size, size)
	}
	if hex.EncodeToString(hash.Sum(nil)) != e.Digest {
		return fmt.Errorf("artifact %q: content digest mismatch", e.Name)
	}
	return nil
}

// CreateSnapshot saves a copy of every current entry under name. The snapshot
// is written to a temporary file and renamed into place only after a full
// write and fsync, so a process killed mid-write leaves either the complete
// snapshot or no snapshot at all.
func (s *Store) CreateSnapshot(name string) (Snapshot, error) {
	if err := validateName(name); err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	err := s.withLock(true, func() error {
		if err := s.ensureInitializedLocked(); err != nil {
			return err
		}
		idx, err := s.load()
		if err != nil {
			return fmt.Errorf("read current index: %w", err)
		}
		for _, e := range idx.Entries {
			if err := validateEntry(e); err != nil {
				return fmt.Errorf("current index: %w", err)
			}
		}
		path := s.snapshotPath(name)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("snapshot %q already exists", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		snap = Snapshot{Name: name, CreatedAt: time.Now().UTC(), Entries: idx.Entries}
		return s.saveSnapshot(snap)
	})
	return snap, err
}

// ListSnapshots returns all saved snapshots sorted by name. A vault with no
// snapshots returns an empty list successfully.
func (s *Store) ListSnapshots() ([]SnapshotInfo, error) {
	var infos []SnapshotInfo
	err := s.withLock(false, func() error {
		root := s.snapshotsDir()
		return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			base := filepath.Base(rel)
			if strings.HasPrefix(base, ".") {
				// Leftover temp file from an interrupted write.
				return nil
			}
			if !strings.HasPrefix(rel, "snap-") || !strings.HasSuffix(rel, ".json") {
				return nil
			}
			snapName := strings.TrimSuffix(strings.TrimPrefix(rel, "snap-"), ".json")
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var snap Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				return fmt.Errorf("snapshot file %s is corrupted: %w", rel, err)
			}
			infos = append(infos, SnapshotInfo{Name: snapName, Entries: len(snap.Entries)})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

// RestoreSnapshot replaces the current name mapping with the snapshot's
// entries in one atomic rename. It never reads the current index, so a vault
// with a corrupted index can still be restored. Every record is validated and
// every referenced object verified before the index is replaced; any failure
// leaves the current mapping, the snapshot, and all objects untouched.
func (s *Store) RestoreSnapshot(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.withLock(true, func() error {
		snap, err := s.loadSnapshot(name)
		if err != nil {
			return err
		}
		for _, e := range snap.Entries {
			if err := validateEntry(e); err != nil {
				return fmt.Errorf("snapshot %q: %w", name, err)
			}
		}
		for _, e := range snap.Entries {
			if err := s.verifyObject(e); err != nil {
				return fmt.Errorf("snapshot %q: %w", name, err)
			}
		}
		return s.save(index{Entries: snap.Entries})
	})
}

func (s *Store) loadSnapshot(name string) (Snapshot, error) {
	data, err := os.ReadFile(s.snapshotPath(name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Snapshot{}, fmt.Errorf("snapshot %q not found", name)
		}
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %q is corrupted: %w", name, err)
	}
	if snap.Entries == nil {
		snap.Entries = map[string]Entry{}
	}
	return snap, nil
}

// validateEntry checks record integrity: legal name, 64-char lowercase hex
// digest, and non-negative size.
func validateEntry(e Entry) error {
	if err := validateName(e.Name); err != nil {
		return fmt.Errorf("artifact name %q is invalid: %w", e.Name, err)
	}
	if !isDigest(e.Digest) {
		return fmt.Errorf("artifact %q has invalid digest %q (want 64 lowercase hex chars)", e.Name, e.Digest)
	}
	if e.Size < 0 {
		return fmt.Errorf("artifact %q has negative size %d", e.Name, e.Size)
	}
	return nil
}

func isDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
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
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.indexPath())
}

// saveSnapshot writes the snapshot under a temp file in the snapshots
// directory and atomically renames it into place. It also removes stale temp
// files from interrupted runs; callers hold the exclusive lock, so no live
// process's temp file can be removed.
func (s *Store) saveSnapshot(snap Snapshot) error {
	if err := s.cleanTempSnapshots(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.snapshotPath(snap.Name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".snapshot-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.snapshotPath(snap.Name))
}

func (s *Store) cleanTempSnapshots() error {
	root := s.snapshotsDir()
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".snapshot-") {
			if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return rmErr
			}
		}
		return nil
	})
}

func (s *Store) indexPath() string     { return filepath.Join(s.root, "index.json") }
func (s *Store) lockPath() string      { return filepath.Join(s.root, ".vault.lock") }
func (s *Store) objectsDir() string    { return filepath.Join(s.root, "objects") }
func (s *Store) snapshotsDir() string  { return filepath.Join(s.root, "snapshots") }
func (s *Store) objectPath(digest string) string {
	return filepath.Join(s.objectsDir(), digest)
}
func (s *Store) snapshotPath(name string) string {
	return filepath.Join(s.snapshotsDir(), "snap-"+name+".json")
}

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
