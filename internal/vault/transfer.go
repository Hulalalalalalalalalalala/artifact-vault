package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

// ExportResult summarizes a successful snapshot export.
type ExportResult struct {
	Name    string
	Entries int
	Objects int
}

// ImportResult summarizes a successful snapshot import.
type ImportResult struct {
	Name       string
	Entries    int
	NewObjects int
}

// ExportSnapshot writes the named snapshot, together with the content objects
// it needs, to output as a portable package.
//
// Without a base the package is complete: every referenced object is carried,
// and a digest shared by several entries is carried once. With base set to the
// name of another snapshot in the same repository, the package still records
// the target's complete mapping but only carries objects the base does not
// reference; an importer can only apply it on top of an identical base.
//
// Every object the target references is re-read and checked for recorded size
// and SHA-256, including objects omitted from a delta, so a corrupt snapshot
// record or a missing/damaged object never produces a successful package.
//
// The output location is held to the same rules as a download: it must be
// outside the source repository (judged on actual locations, through
// symlinks, and before the file exists), its parent directory must already
// exist, an existing output must be a regular file that is not hard-linked to
// any index, snapshot record, lock file, or content object, and the package
// is committed through a descriptor pinned to the resolved parent directory,
// so a parent swapped for a symlink into the repository while the export runs
// is detected at commit time and can never redirect the package onto a
// repository file. The package is assembled in memory and written to a
// temporary file in that directory before an atomic rename: a failed export
// never creates or alters the output file.
func (s *Store) ExportSnapshot(name, base, output string) (ExportResult, error) {
	if err := validateName(name); err != nil {
		return ExportResult{}, err
	}
	if base != "" {
		if err := validateName(base); err != nil {
			return ExportResult{}, err
		}
	}
	if output == "" {
		return ExportResult{}, errors.New("output is required")
	}
	// Export reads an existing, initialized repository; it never creates one.
	// The root and index are checked before taking the lock (withLockOpts
	// passes createRoot=false so even the root directory is not materialized),
	// and re-checked while holding the lock.
	rootInfo, err := os.Stat(s.root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ExportResult{}, fmt.Errorf("repository %q does not exist; run init first", s.root)
	case err != nil:
		return ExportResult{}, err
	case !rootInfo.IsDir():
		return ExportResult{}, fmt.Errorf("repository root %q is not a directory", s.root)
	}
	if _, err := os.Stat(s.indexPath()); errors.Is(err, os.ErrNotExist) {
		return ExportResult{}, fmt.Errorf("repository %q is not initialized; run init first", s.root)
	} else if err != nil {
		return ExportResult{}, err
	}
	var result ExportResult
	err = s.withLockOpts(true, false, func() error {
		if _, err := os.Stat(s.indexPath()); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("repository %q is not initialized; run init first", s.root)
		} else if err != nil {
			return err
		}
		// Validate the destination before reading any object or staging a
		// temporary file, and hold the pinned parent directory until commit.
		absOut, mode, pin, err := s.checkOutputSafe(output)
		if err != nil {
			return err
		}
		defer pin.Close()

		target, err := s.loadSnapshotRecord(name)
		if err != nil {
			return err
		}
		pkg := &Package{
			Format:   packageFormat,
			Version:  packageVersion,
			Snapshot: target,
			Objects:  []PackageObject{},
		}
		var baseSnap Snapshot
		if base != "" {
			var err error
			baseSnap, err = s.loadSnapshotRecord(base)
			if err != nil {
				return fmt.Errorf("cannot use base snapshot: %w", err)
			}
			pkg.Base = &baseSnap
		}

		// Verify every object the target references, reading each once. This
		// includes objects the delta omits because the base references them:
		// certifying the delta requires those to be intact too. Only objects
		// the base does not reference are carried. Digests are processed in
		// sorted order so the package layout and any failure message are
		// deterministic.
		carry := digestsReferenced(target.Entries)
		if base != "" {
			for digest := range digestsReferenced(baseSnap.Entries) {
				delete(carry, digest)
			}
		}
		for _, digest := range sortedDigests(target.Entries) {
			content, size, err := s.readVerifiedObject(digest, target.Entries)
			if err != nil {
				return fmt.Errorf("snapshot %q references unusable object %s: %w", name, digest, err)
			}
			if _, included := carry[digest]; !included {
				continue
			}
			pkg.Objects = append(pkg.Objects, PackageObject{
				Digest: digest,
				Size:   size,
				Data:   base64.StdEncoding.EncodeToString(content),
			})
		}

		data, err := marshalPackage(pkg)
		if err != nil {
			return err
		}
		if err := s.writeOutputPackage(pin, absOut, data, mode); err != nil {
			return err
		}
		result = ExportResult{Name: name, Entries: len(target.Entries), Objects: len(pkg.Objects)}
		return nil
	})
	if err != nil {
		return ExportResult{}, err
	}
	return result, nil
}

// writeOutputPackage stages the package as a complete temporary file inside
// the pinned parent directory and commits it via Store.commitOutput, which
// revalidates the destination immediately before the atomic rename. On any
// failure the temporary file is removed and an existing output is never
// touched.
func (s *Store) writeOutputPackage(pin *parentPin, absOut string, data []byte, mode os.FileMode) error {
	tmp, tmpBase, err := createTempIn(pin, ".package-")
	if err != nil {
		return fmt.Errorf("cannot create temporary file for output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			removeTempIn(pin, tmpBase)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot prepare output file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	if err := s.commitOutput(pin, tmpBase, absOut); err != nil {
		return err
	}
	committed = true
	_ = syncDirectory(pin.f)
	return nil
}

// ImportSnapshot imports a snapshot package produced by ExportSnapshot into an
// initialized repository.
//
// Import only adds the package's snapshot and any missing content objects; it
// never changes the current name mapping or any existing snapshot or object.
// A delta package is accepted only when the destination already contains a
// snapshot with the base name and byte-identical entry metadata, and every
// object the delta omits is present and intact. Healthy objects already in the
// destination are reused; re-importing a package whose snapshot is already
// present with identical metadata succeeds without creating a second copy. A
// same-named snapshot with different metadata is refused.
//
// Every target record's size must equal the actual byte count of the content
// its digest names, checked separately for each name that references it.
// Carried content is measured while the package is decoded; content a delta
// omits is measured from the destination (after the matching base has proven
// it present and healthy) before anything is written. A record that keeps a
// valid digest but declares another size therefore rejects the entire
// package — other correct records and other correct new objects included —
// and names the target snapshot, artifact, digest, recorded size, and actual
// byte count as record corruption rather than a checksum failure.
//
// All validation and reuse happens before anything is written, so a rejected
// package adds no object, snapshot, or temporary file. New objects then land
// as complete files via temp-file-and-rename, and the snapshot record is
// renamed into place only after every object the mapping references has been
// verified. Consequently only an actual crash or write failure between those
// two commits can leave an unreferenced complete object, which a later gc
// removes and a retry completes; a partially imported snapshot can never be
// observed.
func (s *Store) ImportSnapshot(file string) (ImportResult, error) {
	if file == "" {
		return ImportResult{}, errors.New("file is required")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return ImportResult{}, err
	}
	pkg, err := decodePackage(data)
	if err != nil {
		return ImportResult{}, err
	}
	// Import targets an initialized repository; it never creates one the way
	// mutating artifact commands do.
	rootInfo, err := os.Stat(s.root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return ImportResult{}, fmt.Errorf("repository %q does not exist; run init first", s.root)
	case err != nil:
		return ImportResult{}, err
	case !rootInfo.IsDir():
		return ImportResult{}, fmt.Errorf("repository root %q is not a directory", s.root)
	}
	var result ImportResult
	err = s.withLock(true, func() error {
		if _, err := os.Stat(s.indexPath()); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("repository %q is not initialized; run init first", s.root)
		} else if err != nil {
			return err
		}
		if err := rejectLinkedDirs(s.root); err != nil {
			return err
		}

		// A delta must sit on an exactly matching base: same snapshot name and
		// identical entry metadata. A merely same-named snapshot, or objects
		// that happen to share digests, is not a base.
		if pkg.Base != nil {
			existing, err := s.loadSnapshotRecord(pkg.Base.Name)
			if err != nil {
				return fmt.Errorf("delta base snapshot %q is unavailable: %w", pkg.Base.Name, err)
			}
			if !snapshotsEqual(existing, *pkg.Base) {
				return fmt.Errorf("delta base snapshot %q does not match the package base", pkg.Base.Name)
			}
			if err := s.verifyReferencedObjects(pkg.Base.Name, existing.Entries); err != nil {
				return fmt.Errorf("delta base snapshot %q is not fully present: %w", pkg.Base.Name, err)
			}
		}

		// Record sizes are validated against carried payloads when the package
		// is decoded. Objects a delta omits are not carried, so their sizes are
		// measured from the destination here — while the matching base has just
		// proven them present and healthy — before anything is staged. A target
		// entry that keeps a valid digest but declares another byte count is a
		// corrupt record: it rejects the whole import, including every other
		// correct entry and any new object the package carries, so a failed
		// import can never install even one unreferenced content object.
		if err := s.verifyOmittedEntrySizes(pkg); err != nil {
			return err
		}

		// A same-named destination snapshot is either identical metadata or a
		// collision. A collision is refused before anything is staged.
		targetPath := s.snapshotPath(pkg.Snapshot.Name)
		identicalSnapshot := false
		if existing, statErr := os.Lstat(targetPath); statErr == nil {
			if existing.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("snapshot path %q is a symbolic link", targetPath)
			}
			current, err := s.loadSnapshotRecord(pkg.Snapshot.Name)
			if err != nil {
				return fmt.Errorf("snapshot %q already exists and is unusable: %w", pkg.Snapshot.Name, err)
			}
			if !snapshotsEqual(current, pkg.Snapshot) {
				return fmt.Errorf("snapshot %q already exists with different metadata; refusing to overwrite", pkg.Snapshot.Name)
			}
			identicalSnapshot = true
			// Fast path: everything the published snapshot needs is already
			// present and healthy, so the import is a no-op.
			if s.verifyReferencedObjects(pkg.Snapshot.Name, pkg.Snapshot.Entries) == nil {
				result = ImportResult{Name: pkg.Snapshot.Name, Entries: len(pkg.Snapshot.Entries), NewObjects: 0}
				return nil
			}
			// Otherwise fall through: a carried object that is merely missing
			// can be staged to complete an earlier interrupted import, while a
			// damaged existing object still aborts below.
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}

		objects, err := pkg.materialize()
		if err != nil {
			return err
		}

		// Phase 1, no writes: classify every carried object. Existing files
		// must be healthy and are reused; a damaged one aborts the import and
		// is reported by digest.
		toAdd := make([]objectContent, 0, len(objects))
		for _, obj := range objects {
			path := s.objectPath(obj.digest)
			info, err := os.Lstat(path)
			switch {
			case err == nil:
				if info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("object %s: object path is a symbolic link", obj.digest)
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("object %s: object path is not a regular file", obj.digest)
				}
				// Record sizes were validated against the carried payload when
				// the package was decoded; only the existing object's own type
				// and checksum still need to prove healthy before reuse.
				if _, _, err := s.readHealthyObject(obj.digest); err != nil {
					return fmt.Errorf("object %s already present but damaged: %w", obj.digest, err)
				}
			case errors.Is(err, os.ErrNotExist):
				toAdd = append(toAdd, obj)
			default:
				return err
			}
		}

		// Phase 2: stage missing objects as complete, content-addressed files.
		// A failure here leaves only unreferenced complete objects behind; a
		// retry reuses them and finishes the import.
		for _, obj := range toAdd {
			if err := s.stageObject(obj.digest, obj.content); err != nil {
				return err
			}
		}

		// Phase 3: the published mapping must be fully restorable. This covers
		// reused objects, newly staged ones, and everything omitted by a delta.
		if err := s.verifyReferencedObjects(pkg.Snapshot.Name, pkg.Snapshot.Entries); err != nil {
			return err
		}

		// Phase 4: publish the snapshot record last (unless an identical one is
		// already published). This rename is the commit point; before it a new
		// imported snapshot simply does not exist.
		if !identicalSnapshot {
			if err := s.saveSnapshot(targetPath, pkg.Snapshot); err != nil {
				return err
			}
		}
		result = ImportResult{Name: pkg.Snapshot.Name, Entries: len(pkg.Snapshot.Entries), NewObjects: len(toAdd)}
		return nil
	})
	if err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

// loadSnapshotRecord reads and fully validates one stored snapshot: the path
// must be a regular file (never a symlink), the document must be a single
// well-formed object, carry a present non-null entries mapping, record the
// same name it is filed under (in full), and contain only valid entry records.
func (s *Store) loadSnapshotRecord(name string) (Snapshot, error) {
	path := s.snapshotPath(name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("snapshot %q not found", name)
	}
	if err != nil {
		return Snapshot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Snapshot{}, fmt.Errorf("snapshot %q is a symbolic link", name)
	}
	if !info.Mode().IsRegular() {
		return Snapshot{}, fmt.Errorf("snapshot %q is not a regular file", name)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	snap, err := decodeSnapshotRecord(data, name)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %q is corrupted: %w", name, err)
	}
	return snap, nil
}

// verifyReferencedObjects checks each distinct referenced digest once against
// the stored object's size and SHA-256.
func (s *Store) verifyReferencedObjects(snapshotName string, entries map[string]Entry) error {
	for _, digest := range sortedDigests(entries) {
		if _, _, err := s.readVerifiedObject(digest, entries); err != nil {
			return fmt.Errorf("object %s needed by snapshot %q: %w", digest, snapshotName, err)
		}
	}
	return nil
}

// verifyOmittedEntrySizes enforces the target record-size rule for content the
// package does not carry (the objects a delta omits, which the destination
// must already hold). Sizes for carried content were checked against the
// payloads while the package was decoded, so this looks only at digests absent
// from the carried set: each target entry naming one must record the exact
// byte count of the healthy object already in the destination. Every name is
// checked separately, in sorted order, since one digest may back several
// entries. The check reads and hashes content but writes nothing; it runs
// before any object is staged, so a mismatch rejects the whole package
// without leaving even a correct new object behind.
func (s *Store) verifyOmittedEntrySizes(pkg *Package) error {
	carried := make(map[string]struct{}, len(pkg.Objects))
	for _, obj := range pkg.Objects {
		carried[obj.Digest] = struct{}{}
	}
	actualByDigest := map[string]int64{}
	for _, name := range sortedEntryNames(pkg.Snapshot.Entries) {
		entry := pkg.Snapshot.Entries[name]
		if _, isCarried := carried[entry.Digest]; isCarried {
			continue
		}
		actual, ok := actualByDigest[entry.Digest]
		if !ok {
			_, size, err := s.readHealthyObject(entry.Digest)
			if err != nil {
				// A missing or damaged destination object is content trouble,
				// reported through the same path as the later full verification.
				return fmt.Errorf("object %s needed by snapshot %q: %w", entry.Digest, pkg.Snapshot.Name, err)
			}
			actual = size
			actualByDigest[entry.Digest] = size
		}
		if entry.Size != actual {
			return newEntrySizeMismatchError(pkg.Snapshot.Name, entry.Name, entry.Digest, entry.Size, actual)
		}
	}
	return nil
}

// readHealthyObject loads the content object filed under digest, requiring it
// to be a regular file (never a symlink or other special file) whose full
// bytes hash to digest. It returns the bytes and their true byte count but
// makes no claim about any recorded size, so callers can distinguish a
// checksum failure from a record whose size disagrees with healthy content.
func (s *Store) readHealthyObject(digest string) ([]byte, int64, error) {
	path := s.objectPath(digest)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("object path is a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("object path is not a regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(content)
	if actual := hex.EncodeToString(sum[:]); actual != digest {
		return nil, 0, fmt.Errorf("content checksum is %s", actual)
	}
	return content, int64(len(content)), nil
}

// readVerifiedObject reads a content object and returns its bytes, confirming
// its SHA-256 digest and the size recorded for it in the given entries.
func (s *Store) readVerifiedObject(digest string, entries map[string]Entry) ([]byte, int64, error) {
	content, size, err := s.readHealthyObject(digest)
	if err != nil {
		return nil, 0, err
	}
	// Every entry referencing this digest must agree on the size; a content
	// hash fixes the byte count, so a disagreement is a corrupt record.
	for _, entry := range entries {
		if entry.Digest == digest && size != entry.Size {
			return nil, 0, fmt.Errorf("content is %d bytes, record for %q says %d", size, entry.Name, entry.Size)
		}
	}
	return content, size, nil
}

// stageObject writes one missing object to a temp file and renames it into
// place. The content digest was verified when the package was decoded, so the
// final file is complete before it ever appears under its digest name.
func (s *Store) stageObject(digest string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Join(s.root, "objects"), ".import-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("object %s: %w", digest, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("object %s: %w", digest, err)
	}
	if err := os.Rename(tmpName, s.objectPath(digest)); err != nil {
		return fmt.Errorf("object %s: %w", digest, err)
	}
	return nil
}

// rejectLinkedDirs makes sure an import can never stage files outside the
// repository through a replaced objects or snapshots directory.
func rejectLinkedDirs(root string) error {
	for _, dir := range []string{filepath.Join(root, "objects"), filepath.Join(root, "snapshots")} {
		if err := ensureRealDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// snapshotsEqual reports whether two snapshot records carry the same snapshot
// name and identical metadata for every entry.
func snapshotsEqual(a, b Snapshot) bool {
	return reflect.DeepEqual(a.Entries, b.Entries) && a.Name == b.Name
}

func sortedDigests(entries map[string]Entry) []string {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		seen[entry.Digest] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for digest := range seen {
		out = append(out, digest)
	}
	sort.Strings(out)
	return out
}
