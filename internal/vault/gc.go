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

// GCObject is an unreferenced content object identified as a candidate for
// garbage collection.
type GCObject struct {
	Digest string
	Size   int64
}

// GCResult reports the outcome of a garbage collection run. For a dry run,
// Candidates holds every object that would be removed and Bytes is their total
// size. For an actual run, Deleted and Bytes count the objects and bytes
// removed; Candidates is still populated for inspection.
type GCResult struct {
	Candidates []GCObject
	Deleted    int
	Bytes      int64
}

// GCError describes a failure during the deletion phase of garbage collection.
// Object is the file whose removal failed; Deleted and Bytes count the objects
// and bytes already removed before the failure.
type GCError struct {
	Object  string
	Deleted int
	Bytes   int64
	Err     error
}

func (e *GCError) Error() string {
	return fmt.Sprintf("gc: failed to delete %s: %v (deleted %d objects, %d bytes before failure)", e.Object, e.Err, e.Deleted, e.Bytes)
}

func (e *GCError) Unwrap() error { return e.Err }

// GC removes content objects that are no longer referenced by the current name
// mapping or any saved snapshot. When dryRun is true nothing is deleted and
// neither the index nor any snapshot is touched.
//
// The entire scan and delete runs under an exclusive flock, so no cooperating
// process can be uploading, restoring, downloading, or verifying while
// candidates are identified or removed. Every reference is validated before any
// deletion: an unreadable or malformed index or snapshot aborts the run with
// no objects removed.
func (s *Store) GC(dryRun bool) (GCResult, error) {
	var result GCResult
	err := s.withLockExisting(true, func() error {
		// Refuse an uninitialized repository; never auto-create it.
		if _, err := os.Stat(s.indexPath()); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return errors.New("repository is not initialized (run init first)")
			}
			return err
		}

		// Load and validate the current index.
		idx, err := s.loadValidatedIndex()
		if err != nil {
			return err
		}

		// Load and validate every snapshot, collecting referenced digests.
		referenced := map[string]struct{}{}
		for _, entry := range idx.Entries {
			referenced[entry.Digest] = struct{}{}
		}
		snapRefs, err := s.loadSnapshotReferences()
		if err != nil {
			return err
		}
		for digest := range snapRefs {
			referenced[digest] = struct{}{}
		}

		// Scan the objects directory for unreferenced regular files.
		candidates, err := s.scanObjects(referenced)
		if err != nil {
			return err
		}
		result.Candidates = candidates

		if dryRun {
			var total int64
			for _, obj := range candidates {
				total += obj.Size
			}
			result.Bytes = total
			return nil
		}

		// Deletion phase: stop at the first failure, reporting progress.
		for _, obj := range candidates {
			path := filepath.Join(s.objectsDir(), obj.Digest)
			if err := os.Remove(path); err != nil {
				return &GCError{Object: path, Deleted: result.Deleted, Bytes: result.Bytes, Err: err}
			}
			result.Deleted++
			result.Bytes += obj.Size
		}
		return nil
	})
	if err != nil {
		return GCResult{}, err
	}
	return result, nil
}

// loadValidatedIndex reads index.json and validates every entry. A missing
// entries map, an invalid entry name, a key/name mismatch, a malformed digest,
// or a negative size all make the index invalid.
func (s *Store) loadValidatedIndex() (index, error) {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		return index{}, fmt.Errorf("cannot read index: %w", err)
	}
	var idx index
	if err := json.Unmarshal(data, &idx); err != nil {
		return index{}, fmt.Errorf("index is corrupted: %w", err)
	}
	if idx.Entries == nil {
		return index{}, errors.New("index is corrupted: missing entries map")
	}
	for key, entry := range idx.Entries {
		if err := validateEntry(key, entry); err != nil {
			return index{}, fmt.Errorf("index is corrupted: %w", err)
		}
	}
	return idx, nil
}

// loadSnapshotReferences walks the snapshots directory, validates every
// snapshot record, and returns the set of referenced digests. A missing
// snapshots directory means no snapshots. Symlinks or un-traversable
// directories inside the snapshots directory are errors, never skipped.
func (s *Store) loadSnapshotReferences() (map[string]struct{}, error) {
	referenced := map[string]struct{}{}
	dir := s.snapshotsDir()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Any symlink in the snapshots tree is an error, including the root.
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("snapshot path %q is a symlink", path)
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".json") {
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
		if snap.Entries == nil {
			return fmt.Errorf("snapshot %q is corrupted: missing entries map", name)
		}
		if snap.Name != name {
			return fmt.Errorf("snapshot %q is corrupted: record name %q does not match its location", name, snap.Name)
		}
		for key, entry := range snap.Entries {
			if err := validateEntry(key, entry); err != nil {
				return fmt.Errorf("snapshot %q is corrupted: %w", name, err)
			}
			referenced[entry.Digest] = struct{}{}
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return referenced, nil
	}
	if err != nil {
		return nil, err
	}
	return referenced, nil
}

// scanObjects returns the regular files directly in the objects directory
// whose names are valid digests and whose digests are not in referenced.
// Temporary files, other names, subdirectories, and symlinks are left
// untouched. The objects directory itself being a symlink or unreadable is an
// error.
func (s *Store) scanObjects(referenced map[string]struct{}) ([]GCObject, error) {
	dir := s.objectsDir()
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("objects directory is a symlink")
	}
	if !info.IsDir() {
		return nil, errors.New("objects is not a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var candidates []GCObject
	for _, e := range entries {
		name := e.Name()
		if !isDigest(name) {
			continue
		}
		// Symlinks, subdirectories, and other non-regular files are kept.
		if e.Type()&os.ModeSymlink != 0 || !e.Type().IsRegular() {
			continue
		}
		if _, ok := referenced[name]; ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, GCObject{Digest: name, Size: info.Size()})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Digest < candidates[j].Digest })
	return candidates, nil
}

// validateEntry checks that an entry is filed under its own name, that the
// name is a valid relative path, that the digest is 64 lowercase hex
// characters, and that the size is non-negative.
func validateEntry(key string, entry Entry) error {
	if entry.Name != key {
		return fmt.Errorf("entry %q is filed under %q", entry.Name, key)
	}
	if err := validateName(entry.Name); err != nil {
		return fmt.Errorf("invalid entry name %q: %w", entry.Name, err)
	}
	if !isDigest(entry.Digest) {
		return fmt.Errorf("entry %q has digest %q, want 64 lowercase hex characters", entry.Name, entry.Digest)
	}
	if entry.Size < 0 {
		return fmt.Errorf("entry %q has negative size %d", entry.Name, entry.Size)
	}
	return nil
}

func (s *Store) objectsDir() string { return filepath.Join(s.root, "objects") }
