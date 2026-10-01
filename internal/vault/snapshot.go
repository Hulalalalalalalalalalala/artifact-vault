package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Snapshot is an immutable record of every name mapping in the repository at
// creation time. It only references existing content objects; no artifact
// bytes are copied.
type Snapshot struct {
	Name    string           `json:"name"`
	Entries map[string]Entry `json:"entries"`
}

// SnapshotInfo summarizes a saved snapshot for listing.
type SnapshotInfo struct {
	Name  string
	Count int
}

// CreateSnapshot records the current name mapping under the given snapshot
// name. The snapshot is written to a temporary file and renamed into place,
// so a crash leaves either the complete snapshot or none at all.
func (s *Store) CreateSnapshot(name string) (Snapshot, error) {
	if err := validateName(name); err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	err := s.withLock(true, func() error {
		if err := s.initLocked(); err != nil {
			return err
		}
		idx, err := s.load()
		if err != nil {
			return fmt.Errorf("cannot snapshot: current index is unreadable: %w", err)
		}
		path := s.snapshotPath(name)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("snapshot %q already exists", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		snap = Snapshot{Name: name, Entries: idx.Entries}
		return s.saveSnapshot(path, snap)
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

// ListSnapshots returns every saved snapshot sorted by name. A repository
// with no snapshots yields an empty list.
func (s *Store) ListSnapshots() ([]SnapshotInfo, error) {
	infos := []SnapshotInfo{}
	err := s.withLock(false, func() error {
		dir := s.snapshotsDir()
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
				return nil
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			name := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var snap Snapshot
			if err := json.Unmarshal(data, &snap); err != nil {
				return fmt.Errorf("snapshot %q is corrupted: %w", name, err)
			}
			infos = append(infos, SnapshotInfo{Name: name, Count: len(snap.Entries)})
			return nil
		})
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

// RestoreSnapshot replaces the current name mapping with the snapshot's
// recorded mapping in a single atomic index write. The current index is never
// read, so restore works even when it is corrupted. Every referenced object
// is checked for existence, size, and SHA-256 before the mapping is swapped;
// any failure leaves the current mapping and all snapshots untouched.
func (s *Store) RestoreSnapshot(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.withLock(true, func() error {
		if err := s.initLocked(); err != nil {
			return err
		}
		data, err := os.ReadFile(s.snapshotPath(name))
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("snapshot %q not found", name)
		}
		if err != nil {
			return err
		}
		var snap Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return fmt.Errorf("snapshot %q is corrupted: %w", name, err)
		}
		if snap.Entries == nil {
			snap.Entries = map[string]Entry{}
		}
		for key, entry := range snap.Entries {
			if entry.Name != key {
				return fmt.Errorf("snapshot %q is corrupted: entry %q is filed under %q", name, entry.Name, key)
			}
			if err := validateName(entry.Name); err != nil {
				return fmt.Errorf("snapshot %q is corrupted: invalid entry name %q", name, entry.Name)
			}
			if !isDigest(entry.Digest) {
				return fmt.Errorf("snapshot %q is corrupted: entry %q has digest %q, want 64 lowercase hex characters", name, entry.Name, entry.Digest)
			}
			if entry.Size < 0 {
				return fmt.Errorf("snapshot %q is corrupted: entry %q has negative size %d", name, entry.Name, entry.Size)
			}
		}
		for _, entry := range snap.Entries {
			if err := s.verifyObject(entry); err != nil {
				return fmt.Errorf("cannot restore snapshot %q: object for %q: %w", name, entry.Name, err)
			}
		}
		return s.save(index{Entries: snap.Entries})
	})
}

func (s *Store) saveSnapshot(path string, snap Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*")
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
	return os.Rename(tmpName, path)
}

func (s *Store) snapshotsDir() string { return filepath.Join(s.root, "snapshots") }

func (s *Store) snapshotPath(name string) string {
	return filepath.Join(s.snapshotsDir(), filepath.FromSlash(name)+".json")
}

func isDigest(digest string) bool {
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
