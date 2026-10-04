package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

// loadStrict reads the current index for GC and verify. Unlike load it
// requires the document to be one complete JSON object with an explicitly
// present entries mapping: a bare null, an array, a primitive, truncated
// input, or trailing content after the object is corruption, and a missing
// or null entries mapping cannot be distinguished from "references lost".
// (A true {"entries":{}} remains a legitimate empty repository.) It also
// rejects any duplicate JSON key anywhere in the document — a repeated
// entries mapping, a repeated artifact name, or a repeated field inside one
// record — because encoding/json would silently keep only the last record
// and neither GC nor verify can tell which references the overwritten
// records carried. Keys are compared after JSON string decoding, so a name
// written directly and the same name written with Unicode escapes still
// collide.
//
// The entries field must also be spelled exactly "entries": encoding/json
// binds struct fields case-insensitively, so an "Entries" or "ENTRIES" field
// would silently populate the mapping — and, when both spellings appear,
// whichever comes last would silently overwrite the other. Any such variant
// is corruption whether it appears alone or beside the standard field, in
// either order, with identical or different content, empty or not. Field
// names are compared after JSON string decoding, so "entries" written
// through Unicode escapes is the standard field and stays valid while an
// escape that decodes to "Entries" is rejected. Unrelated extra top-level
// fields remain ignored.
func (s *Store) loadStrict() (index, error) {
	data, err := os.ReadFile(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return index{}, fmt.Errorf("repository %q is not initialized: index.json is missing", s.root)
	}
	if err != nil {
		// The index exists but its bytes cannot be read at all: report that
		// distinctly from bytes that are present but malformed, so callers can
		// name an unreadable index without calling it corrupt.
		return index{}, fmt.Errorf("current index cannot be read: %w", err)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return index{}, fmt.Errorf("current index is corrupt: %w", err)
	}
	// The document must be a JSON object: a bare null, array, or primitive is
	// a corrupt index, never an empty mapping.
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return index{}, errors.New("current index is corrupt: expected a JSON object with an entries mapping")
	}
	// A field that spells the entries mapping with different casing
	// ("Entries", "ENTRIES", ...) would be silently bound to it by
	// encoding/json — and would silently overwrite or be overwritten by the
	// standard spelling when both appear — so any such field is corruption,
	// regardless of order, content, or emptiness.
	if err := rejectEntriesCaseVariants(data); err != nil {
		return index{}, fmt.Errorf("current index is corrupt: %w", err)
	}
	var idx index
	// json.Unmarshal rejects truncated input and trailing content after the
	// top-level value.
	if err := json.Unmarshal(data, &idx); err != nil {
		return index{}, fmt.Errorf("current index is corrupt: %w", err)
	}
	if idx.Entries == nil {
		return index{}, errors.New("current index is corrupt: missing entries mapping")
	}
	return idx, nil
}

// rejectEntriesCaseVariants inspects the top-level field names of the index
// document and refuses any field whose decoded name matches "entries" only
// case-insensitively. encoding/json binds struct fields case-insensitively,
// so without this check an "Entries" field would silently populate the
// mapping on its own, and a document carrying both spellings would keep
// only whichever came last — dropping artifact records or replacing them
// with an empty mapping. Names are compared after JSON string decoding:
// "entries" written through Unicode escapes is the standard field and stays
// valid, while an escape decoding to a case variant is rejected. Duplicate
// exact keys were already rejected by rejectDuplicateKeys, so decoding the
// top level into a map cannot collapse two spellings of the same field.
// Fields unrelated to entries are ignored, as before.
func rejectEntriesCaseVariants(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return err
	}
	keys := make([]string, 0, len(top))
	for key := range top {
		keys = append(keys, key)
	}
	// Sorted so the reported field is deterministic when several vary.
	sort.Strings(keys)
	for _, key := range keys {
		if key != "entries" && strings.EqualFold(key, "entries") {
			return fmt.Errorf("field %q: the entries mapping must be spelled exactly \"entries\"", key)
		}
	}
	return nil
}

// loadStrictValidEntries loads the current mapping under loadStrict and then
// validates every record before returning it: the document must be one
// complete JSON object with an explicitly present entries mapping spelled
// exactly "entries" (a true {"entries":{}} is a legitimate empty repository;
// any case-variant spelling such as "Entries" is corruption, alone or beside
// the standard field), hold no duplicate key at any level (including a name
// written directly and again through Unicode escapes), and every record must
// pass validateEntryRecord. Records are
// checked in sorted name order so the first bad record reported is
// deterministic. One bad record fails the whole load; the caller never gets a
// partial mapping. This is the single gate list, put, get, verify, gc, and
// snapshot creation read the current mapping through.
func (s *Store) loadStrictValidEntries() (index, error) {
	idx, err := s.loadStrict()
	if err != nil {
		return index{}, err
	}
	keys := make([]string, 0, len(idx.Entries))
	for key := range idx.Entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := validateEntryRecord(key, idx.Entries[key]); err != nil {
			return index{}, fmt.Errorf("current index is corrupt: %w", err)
		}
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
