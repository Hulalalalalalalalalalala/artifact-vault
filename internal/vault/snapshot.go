package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// ListSnapshots returns every saved snapshot, sorted by its complete snapshot
// name, with the number of artifact records in its entries mapping.
//
// A snapshot is listed only after its record proves complete and legal: it is
// validated exactly the way RestoreSnapshot validates the record it restores
// (see decodeSnapshotRecord) — a single JSON object whose recorded name
// equals its filing name in full ("releases/stable", never just "stable"),
// with a present, object-valued entries mapping ({} is a legitimate empty
// snapshot; a missing or null entries field is corruption) containing only
// valid artifact records. The content objects the entries reference are not
// read or checked; listing depends on neither the objects nor the health of
// the current name mapping.
//
// One damaged, unreadable, or misplaced record fails the whole operation:
// the error names the complete snapshot and what is wrong with it and no
// SnapshotInfo is returned, so callers never see a partial list or read a
// name or count off a corrupt record. A repository whose snapshots directory
// does not exist yet simply has no snapshots and yields an empty list; a
// record read failing with "not exist" once the directory walk has started
// is reported rather than treated as absence. Non-snapshot files (temporary
// files and anything not ending in .json) are ignored. Listing never
// modifies the current mapping, any snapshot record, or any content object.
func (s *Store) ListSnapshots() ([]SnapshotInfo, error) {
	infos := []SnapshotInfo{}
	err := s.withLock(false, func() error {
		return s.walkSnapshotRecords(func(name string, snap Snapshot) error {
			infos = append(infos, SnapshotInfo{Name: name, Count: len(snap.Entries)})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

// walkSnapshotRecords enumerates the snapshot records filed under snapshots/
// and invokes fn with each record's complete snapshot name and its parsed,
// fully validated contents (see decodeSnapshotRecord). It is the single
// enumeration used by read-only operations that must see exactly the records
// restore would accept — listing and reference collection alike.
//
// A missing snapshots directory means no snapshots exist and is not an error.
// Every other problem aborts the walk: a symlinked or non-directory snapshots
// path, a symlink or other non-regular file beneath it, a .json file whose
// location does not encode a legal snapshot name, a record that cannot be
// read (including one that disappears mid-walk), and any malformed or
// incomplete record. Errors name the complete snapshot when its location is
// known. Files without a .json suffix (temporary files and other stray data)
// are skipped.
func (s *Store) walkSnapshotRecords(fn func(name string, snap Snapshot) error) error {
	dir := s.snapshotsDir()
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("cannot inspect snapshots directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("snapshots path %q is a symbolic link", dir)
	case !info.IsDir():
		return fmt.Errorf("snapshots path %q is not a directory", dir)
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// The directory entry was seen but the path can no longer be
			// accessed: a vanished record is a read failure, not an empty set.
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		isRecord := strings.HasSuffix(d.Name(), ".json")
		// Name the snapshot when the offending path occupies a record slot;
		// other stray entries are identified by path.
		if d.Type()&os.ModeSymlink != 0 {
			if isRecord {
				name := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
				return fmt.Errorf("snapshot %q is a symbolic link", name)
			}
			return fmt.Errorf("snapshots contain symbolic link %q", path)
		}
		if !d.Type().IsRegular() {
			if isRecord {
				name := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
				return fmt.Errorf("snapshot %q is not a regular file", name)
			}
			return fmt.Errorf("snapshots contain non-regular file %q", path)
		}
		if !isRecord {
			return nil
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		if err := validateName(name); err != nil {
			return fmt.Errorf("snapshot record %q does not map to a valid snapshot name: %w", path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("snapshot %q cannot be read: %w", name, err)
		}
		snap, err := decodeSnapshotRecord(data, name)
		if err != nil {
			return fmt.Errorf("snapshot %q is corrupted: %w", name, err)
		}
		return fn(name, snap)
	})
}

// RestoreSnapshot replaces the current name mapping with the snapshot's
// recorded mapping in a single atomic index write. The current index is never
// read, so restore works even when it is corrupted. The selected snapshot
// record must be a complete, well-formed document whose recorded name equals
// the selected snapshot name in full (a record nested under "releases/stable"
// must itself say "releases/stable", never just "stable") and whose entries
// mapping is present and an object ({} is a legitimate empty snapshot; a
// missing, null, or non-object entries field is corruption, never an empty
// mapping). Every referenced object is checked for existence, size, and
// SHA-256 before the mapping is swapped; any failure leaves the current
// mapping's bytes and all snapshots and objects untouched, even when the
// current mapping itself is already corrupted.
func (s *Store) RestoreSnapshot(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return s.withLock(true, func() error {
		if err := s.initLocked(); err != nil {
			return err
		}
		snap, err := s.loadSnapshotRecord(name)
		if err != nil {
			return err
		}
		for _, entry := range snap.Entries {
			if err := s.verifyObject(entry); err != nil {
				return fmt.Errorf("cannot restore snapshot %q: object for %q: %w", name, entry.Name, err)
			}
		}
		return s.save(index{Entries: snap.Entries})
	})
}

// decodeSnapshotRecord parses one snapshot record without touching the
// repository. wantName is the full snapshot name the record is selected or
// filed under and must record verbatim.
//
// A valid record is exactly one JSON object — never the bare null — with no
// duplicate or unknown fields and no trailing data, carrying:
//
//   - "name": present and a string equal to wantName, including every level of
//     a multi-level name; a missing, wrong-type, or merely-suffixed name
//     (record "stable" under "releases/stable") is refused;
//   - "entries": present and a JSON object. {} is a legitimate empty mapping;
//     a missing field, a null, an array, or any non-object value is
//     corruption rather than zero entries.
//
// Every entry is then checked with validateEntryRecord. The errors
// distinguish a missing entries mapping, a mismatching recorded name, and a
// malformed document so callers can tell record corruption apart from a
// snapshot that simply does not exist (that distinction is made by the
// caller, which checks the file before reading it).
func decodeSnapshotRecord(data []byte, wantName string) (Snapshot, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return Snapshot{}, fmt.Errorf("malformed record: %w", err)
	}
	// The document must be a JSON object: a bare null, array, or primitive is
	// a malformed record, never an empty snapshot.
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return Snapshot{}, errors.New("malformed record: expected a JSON object with name and entries")
	}
	var raw struct {
		Name    *string          `json:"name"`
		Entries *json.RawMessage `json:"entries"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Snapshot{}, fmt.Errorf("malformed record: %w", err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return Snapshot{}, fmt.Errorf("malformed record: unexpected trailing content after the snapshot object (%v)", tok)
		}
		return Snapshot{}, fmt.Errorf("malformed record: %w", err)
	}
	if raw.Name == nil {
		return Snapshot{}, errors.New("malformed record: missing snapshot name")
	}
	if *raw.Name != wantName {
		return Snapshot{}, fmt.Errorf("recorded name %q does not match snapshot %q", *raw.Name, wantName)
	}
	if raw.Entries == nil {
		return Snapshot{}, errors.New("record is missing its entries mapping")
	}
	entriesJSON := *raw.Entries
	if string(bytes.TrimSpace(entriesJSON)) == "null" {
		return Snapshot{}, errors.New("record is missing its entries mapping")
	}
	var entries map[string]Entry
	if err := json.Unmarshal(entriesJSON, &entries); err != nil {
		return Snapshot{}, fmt.Errorf("entries mapping is malformed: %w", err)
	}
	if entries == nil {
		return Snapshot{}, errors.New("record is missing its entries mapping")
	}
	for key, entry := range entries {
		if err := validateEntryRecord(key, entry); err != nil {
			return Snapshot{}, err
		}
	}
	return Snapshot{Name: *raw.Name, Entries: entries}, nil
}

func (s *Store) saveSnapshot(path string, snap Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := s.ensureSnapshotParent(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".snapshot-*")
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

// ensureSnapshotParent creates the parent directories of a snapshot record one
// component at a time, refusing to follow symbolic links. Without this a nested
// snapshot name such as "evil/x" could be redirected through a pre-created
// snapshots/evil symlink to write outside the repository.
func (s *Store) ensureSnapshotParent(path string) error {
	base := s.snapshotsDir()
	rel, err := filepath.Rel(base, filepath.Dir(path))
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("snapshot path escapes the snapshots directory")
	}
	// The base directory itself must exist and be a real directory, even for a
	// top-level snapshot (a freshly initialized repository has no snapshots/).
	cur := base
	if err := ensureRealDir(cur); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		next := filepath.Join(cur, component)
		if err := ensureRealDir(next); err != nil {
			return err
		}
		cur = next
	}
	return nil
}

// ensureRealDir makes sure path is a real directory, creating it if absent,
// and refuses an existing symlink or non-directory.
func ensureRealDir(path string) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
		if err != nil {
			return err
		}
	case err != nil:
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("repository path %q is a symbolic link", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("repository path %q is not a directory", path)
	}
	return nil
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
