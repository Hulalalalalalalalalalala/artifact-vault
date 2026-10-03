package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	// loadStrict confirms the structure of the mapping and every record it
	// carries before any reference is collected.
	idx, err := s.loadStrict()
	if err != nil {
		return nil, fmt.Errorf("cannot collect references: current index is unusable: %w", err)
	}
	for _, entry := range idx.Entries {
		referenced[entry.Digest] = struct{}{}
	}
	// Every snapshot record is enumerated and validated exactly as list and
	// restore see it: a damaged or unreadable record aborts reference
	// collection before anything is deleted.
	err = s.walkSnapshotRecords(func(_ string, snap Snapshot) error {
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

// loadStrict reads the current index for snapshot creation, GC, and verify.
// Unlike load it requires the document to be one complete, unambiguous name
// mapping; any ambiguity or damage is an error rather than an empty mapping:
//
//   - the document must be exactly one JSON object — never a bare null,
//     array, or primitive — with no trailing content after it;
//   - it may carry only the entries field, which must be present and a JSON
//     object. A true {"entries":{}} is a legitimate empty repository; a
//     missing field, a null, an array, or any other non-object value means
//     references were lost, not that there are zero of them;
//   - truncated input, other malformed JSON, and any unknown field are
//     refused;
//   - any duplicate JSON key anywhere in the document — a repeated entries
//     mapping, a repeated artifact name, or a repeated field inside one
//     record — is refused, because encoding/json would silently keep only
//     the last occurrence and hide whatever references the overwritten
//     records carried. Keys are compared after JSON string decoding, so a
//     name written directly and the same name written with Unicode escapes
//     still collide;
//   - every entry must satisfy validateEntryRecord: the map key equals the
//     recorded name, the name is legal, the digest is 64 lowercase hex
//     characters, and the size is non-negative. A single bad record fails
//     the whole mapping; bad entries are never skipped.
func (s *Store) loadStrict() (index, error) {
	data, err := os.ReadFile(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return index{}, fmt.Errorf("repository %q is not initialized: index.json is missing", s.root)
	}
	if err != nil {
		return index{}, fmt.Errorf("current index cannot be read: %w", err)
	}
	idx, err := decodeIndexRecord(data)
	if err != nil {
		return index{}, fmt.Errorf("current index is corrupt: %w", err)
	}
	return idx, nil
}

// decodeIndexRecord parses one current-index document without touching the
// repository, applying every mapping rule loadStrict documents. The checks
// mirror decodeSnapshotRecord apart from the recorded-name field, which the
// current index does not carry.
func decodeIndexRecord(data []byte) (index, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return index{}, err
	}
	// The document must be a JSON object: a bare null, array, or primitive is
	// a corrupt index, never an empty mapping.
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return index{}, errors.New("expected a JSON object with an entries mapping")
	}
	var raw struct {
		Entries *json.RawMessage `json:"entries"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return index{}, err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return index{}, fmt.Errorf("unexpected trailing content after the index object (%v)", tok)
		}
		return index{}, err
	}
	if raw.Entries == nil {
		return index{}, errors.New("missing entries mapping")
	}
	entriesJSON := *raw.Entries
	if string(bytes.TrimSpace(entriesJSON)) == "null" {
		return index{}, errors.New("missing entries mapping")
	}
	var entries map[string]Entry
	if err := json.Unmarshal(entriesJSON, &entries); err != nil {
		return index{}, fmt.Errorf("entries mapping is malformed: %w", err)
	}
	if entries == nil {
		return index{}, errors.New("missing entries mapping")
	}
	// Report the first invalid record by a deterministic name so the error
	// always names the same offending artifact.
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validateEntryRecord(key, entries[key]); err != nil {
			return index{}, err
		}
	}
	return index{Entries: entries}, nil
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
