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

// GCCandidate is a content object no longer referenced by the current name
// mapping or any snapshot, and therefore eligible for deletion.
type GCCandidate struct {
	Digest string
	Size   int64
}

// GCReport summarizes one garbage collection pass. Candidates is always the
// full set of unreferenced objects found, sorted by digest; Deleted and Bytes
// record what was actually removed (zero for a dry run).
type GCReport struct {
	Candidates []GCCandidate
	Deleted    int
	Bytes      int64
}

// GC removes content objects that neither the current name mapping nor any
// saved snapshot still references. With dryRun set, nothing is deleted and
// the report only lists the candidates. The whole pass runs under the
// exclusive repository lock, so it always observes a complete, quiescent
// state: concurrent uploads, snapshot operations, downloads, and verifies
// either finish before the pass starts or wait until it is done.
//
// GC never creates or initializes a repository, never rewrites the index or
// any snapshot, and only ever deletes regular files directly inside objects/
// whose names are valid digests. Any unreadable or malformed reference
// (index or snapshot) aborts the pass before anything is deleted. If a
// deletion fails, the pass stops immediately; objects already removed stay
// removed and the rest remain as candidates for the next run.
func (s *Store) GC(dryRun bool) (GCReport, error) {
	if strings.TrimSpace(s.root) == "" {
		return GCReport{}, errors.New("root is required")
	}
	// withLock would create a missing root for mutating operations; GC must
	// refuse an absent or uninitialized repository instead.
	info, err := os.Stat(s.root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return GCReport{}, fmt.Errorf("repository %q does not exist; run init first", s.root)
	case err != nil:
		return GCReport{}, err
	case !info.IsDir():
		return GCReport{}, fmt.Errorf("repository root %q is not a directory", s.root)
	}
	var report GCReport
	err = s.withLock(true, func() error {
		var gcErr error
		report, gcErr = s.gcLocked(dryRun)
		return gcErr
	})
	return report, err
}

func (s *Store) gcLocked(dryRun bool) (GCReport, error) {
	referenced, err := s.collectReferences()
	if err != nil {
		return GCReport{}, err
	}
	objectsDir := filepath.Join(s.root, "objects")
	info, err := os.Lstat(objectsDir)
	if err != nil {
		return GCReport{}, fmt.Errorf("cannot inspect objects directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return GCReport{}, fmt.Errorf("objects path %q is a symbolic link", objectsDir)
	}
	if !info.IsDir() {
		return GCReport{}, fmt.Errorf("objects path %q is not a directory", objectsDir)
	}
	dirents, err := os.ReadDir(objectsDir)
	if err != nil {
		return GCReport{}, fmt.Errorf("cannot read objects directory: %w", err)
	}
	candidates := []GCCandidate{}
	for _, dirent := range dirents {
		// Only regular files named by a valid digest are collectable;
		// temp files, other names, subdirectories, and symlinks stay.
		if !dirent.Type().IsRegular() || !isDigest(dirent.Name()) {
			continue
		}
		if _, ok := referenced[dirent.Name()]; ok {
			continue
		}
		fi, err := dirent.Info()
		if err != nil {
			return GCReport{}, fmt.Errorf("cannot stat object %q: %w", dirent.Name(), err)
		}
		candidates = append(candidates, GCCandidate{Digest: dirent.Name(), Size: fi.Size()})
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Digest < candidates[j].Digest })
	report := GCReport{Candidates: candidates}
	if dryRun {
		return report, nil
	}
	for _, candidate := range candidates {
		if err := os.Remove(s.objectPath(candidate.Digest)); err != nil {
			return report, fmt.Errorf("deleted %d objects (%d bytes), then failed to delete object %s: %w",
				report.Deleted, report.Bytes, candidate.Digest, err)
		}
		report.Deleted++
		report.Bytes += candidate.Size
	}
	return report, nil
}

// collectReferences gathers every digest referenced by the current index and
// by all saved snapshots. Any record that cannot be read or fails validation
// is an error: GC must never guess whether a reference exists.
func (s *Store) collectReferences() (map[string]struct{}, error) {
	referenced := map[string]struct{}{}
	idx, err := s.loadStrict()
	if err != nil {
		return nil, fmt.Errorf("cannot collect references: current index is unusable: %w", err)
	}
	for key, entry := range idx.Entries {
		if err := validateEntryRecord(key, entry); err != nil {
			return nil, fmt.Errorf("current index is invalid: %w", err)
		}
		referenced[entry.Digest] = struct{}{}
	}
	dir := s.snapshotsDir()
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return referenced, nil
	case err != nil:
		return nil, fmt.Errorf("cannot inspect snapshots directory: %w", err)
	case info.Mode()&os.ModeSymlink != 0:
		return nil, fmt.Errorf("snapshots path %q is a symbolic link", dir)
	case !info.IsDir():
		return nil, fmt.Errorf("snapshots path %q is not a directory", dir)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("snapshots contain symbolic link %q", path)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("snapshots contain non-regular file %q", path)
		}
		if !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		if err := validateName(name); err != nil {
			return fmt.Errorf("snapshot record %q does not map to a valid snapshot name: %w", path, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snap, err := decodeSnapshotRecord(data, name)
		if err != nil {
			return fmt.Errorf("snapshot %q is corrupted: %w", name, err)
		}
		for _, entry := range snap.Entries {
			referenced[entry.Digest] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return referenced, nil
}

// loadStrict reads the current index for GC. Unlike load it rejects a
// missing or null entries mapping, since GC cannot distinguish "no entries"
// from "references lost" in that case.
func (s *Store) loadStrict() (index, error) {
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

// validateEntryRecord checks one index or snapshot entry the same way
// restore validates snapshot entries: the map key must equal the recorded
// name, the name must be legal, the digest must be 64 lowercase hex
// characters, and the size must not be negative.
func validateEntryRecord(key string, entry Entry) error {
	if entry.Name != key {
		return fmt.Errorf("entry %q is filed under %q", entry.Name, key)
	}
	if err := validateName(entry.Name); err != nil {
		return fmt.Errorf("invalid entry name %q", entry.Name)
	}
	if !isDigest(entry.Digest) {
		return fmt.Errorf("entry %q has digest %q, want 64 lowercase hex characters", entry.Name, entry.Digest)
	}
	if entry.Size < 0 {
		return fmt.Errorf("entry %q has negative size %d", entry.Name, entry.Size)
	}
	return nil
}
