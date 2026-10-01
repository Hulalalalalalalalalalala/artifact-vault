package vault

import (
	"archive/tar"
	"bytes"
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
)

const packageVersion = 1

// packageManifest is the JSON record stored as the first entry of a snapshot
// package. It describes the target snapshot and, for incremental packages,
// the exact base snapshot the package was built against.
type packageManifest struct {
	Version  int       `json:"version"`
	Snapshot Snapshot  `json:"snapshot"`
	Base     *Snapshot `json:"base,omitempty"`
}

// ExportResult summarizes a successful snapshot export.
type ExportResult struct {
	Name    string
	Entries int
	Objects int
}

// ImportResult summarizes a successful snapshot import.
type ImportResult struct {
	Name    string
	Entries int
	Added   int
}

// ExportSnapshot writes a package containing the target snapshot's complete
// mapping and the content objects it references. When baseName is empty every
// referenced object is carried; when set, only objects not referenced by the
// base snapshot are carried. The package always records the target's full
// mapping. Every object referenced by the target — including ones omitted from
// an incremental package — is verified for existence, size, and SHA-256 before
// the package is written. A failure leaves any existing output file untouched.
func (s *Store) ExportSnapshot(name, output, baseName string) (ExportResult, error) {
	if err := validateName(name); err != nil {
		return ExportResult{}, err
	}
	if strings.TrimSpace(output) == "" {
		return ExportResult{}, errors.New("output is required")
	}
	if baseName != "" {
		if err := validateName(baseName); err != nil {
			return ExportResult{}, err
		}
	}

	var result ExportResult
	err := s.withLock(false, func() error {
		if _, err := os.Stat(s.indexPath()); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("repository %q is not initialized; run init first", s.root)
			}
			return err
		}

		target, err := s.loadSnapshot(name)
		if err != nil {
			return err
		}
		if err := validateSnapshot(target); err != nil {
			return fmt.Errorf("snapshot %q is corrupted: %w", name, err)
		}

		var base *Snapshot
		if baseName != "" {
			b, err := s.loadSnapshot(baseName)
			if err != nil {
				return fmt.Errorf("base snapshot: %w", err)
			}
			if err := validateSnapshot(b); err != nil {
				return fmt.Errorf("base snapshot %q is corrupted: %w", baseName, err)
			}
			base = &b
		}

		targetDigests := snapshotDigestSet(target)
		var baseDigests map[string]struct{}
		if base != nil {
			baseDigests = snapshotDigestSet(*base)
		}

		// Verify ALL target-referenced objects, including ones omitted from
		// an incremental package. A missing or corrupted object must not
		// produce a successful package.
		verified := map[string]struct{}{}
		for _, entry := range target.Entries {
			if _, ok := verified[entry.Digest]; ok {
				continue
			}
			verified[entry.Digest] = struct{}{}
			if err := s.verifyObject(entry); err != nil {
				return fmt.Errorf("cannot export snapshot %q: object %s: %w", name, entry.Digest, err)
			}
		}

		carryDigests := map[string]struct{}{}
		for digest := range targetDigests {
			if base == nil {
				carryDigests[digest] = struct{}{}
			} else if _, inBase := baseDigests[digest]; !inBase {
				carryDigests[digest] = struct{}{}
			}
		}

		manifest := packageManifest{
			Version:  packageVersion,
			Snapshot: target,
			Base:     base,
		}

		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(output), ".snapshot-package-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		defer os.Remove(tmpName)

		tw := tar.NewWriter(tmp)

		manifestData, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return err
		}
		manifestData = append(manifestData, '\n')
		if err := tw.WriteHeader(&tar.Header{
			Name: "manifest.json",
			Mode: 0o644,
			Size: int64(len(manifestData)),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(manifestData); err != nil {
			return err
		}

		for _, digest := range sortedKeys(carryDigests) {
			data, err := os.ReadFile(s.objectPath(digest))
			if err != nil {
				return err
			}
			if err := tw.WriteHeader(&tar.Header{
				Name: "objects/" + digest,
				Mode: 0o644,
				Size: int64(len(data)),
			}); err != nil {
				return err
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}

		if err := tw.Close(); err != nil {
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmpName, output); err != nil {
			return err
		}

		result = ExportResult{Name: name, Entries: len(target.Entries), Objects: len(carryDigests)}
		return nil
	})
	if err != nil {
		return ExportResult{}, err
	}
	return result, nil
}

// ImportSnapshot reads a package and adds its snapshot to the repository. The
// current name mapping is never modified. A full package may be imported into
// an empty repository; an incremental package requires the target repository
// to already contain a base snapshot with identical metadata and intact
// referenced objects. Existing healthy objects with the same digest are reused;
// corrupted objects cause rejection. A snapshot with the same name and
// identical metadata is a no-op success; a same-name snapshot with different
// metadata is rejected.
func (s *Store) ImportSnapshot(file string) (ImportResult, error) {
	if strings.TrimSpace(file) == "" {
		return ImportResult{}, errors.New("file is required")
	}

	var result ImportResult
	err := s.withLock(true, func() error {
		if err := s.initLocked(); err != nil {
			return err
		}

		manifest, objectFiles, err := readPackage(file, s)
		if err != nil {
			return fmt.Errorf("cannot import package: %w", err)
		}
		defer func() {
			for _, path := range objectFiles {
				os.Remove(path)
			}
		}()

		if manifest.Version != packageVersion {
			return fmt.Errorf("cannot import package: unknown version %d", manifest.Version)
		}

		target := manifest.Snapshot
		if err := validateName(target.Name); err != nil {
			return fmt.Errorf("cannot import package: invalid snapshot name: %w", err)
		}
		if err := validateSnapshot(target); err != nil {
			return fmt.Errorf("cannot import package: snapshot is corrupted: %w", err)
		}

		var base *Snapshot
		if manifest.Base != nil {
			b := manifest.Base
			if err := validateName(b.Name); err != nil {
				return fmt.Errorf("cannot import package: invalid base snapshot name: %w", err)
			}
			if err := validateSnapshot(*b); err != nil {
				return fmt.Errorf("cannot import package: base snapshot is corrupted: %w", err)
			}
			base = b
		}

		targetDigests := snapshotDigestSet(target)
		var baseDigests map[string]struct{}
		if base != nil {
			baseDigests = snapshotDigestSet(*base)
		}

		// Determine which digests the package is expected to carry.
		expectedPackageDigests := map[string]struct{}{}
		for digest := range targetDigests {
			if base == nil {
				expectedPackageDigests[digest] = struct{}{}
			} else if _, inBase := baseDigests[digest]; !inBase {
				expectedPackageDigests[digest] = struct{}{}
			}
		}

		// Every expected object must be present and intact; no unexpected
		// objects may be carried.
		for digest := range expectedPackageDigests {
			if _, ok := objectFiles[digest]; !ok {
				return fmt.Errorf("cannot import package: missing object %s", digest)
			}
		}
		for digest := range objectFiles {
			if _, ok := expectedPackageDigests[digest]; !ok {
				return fmt.Errorf("cannot import package: unexpected object %s", digest)
			}
		}

		// Verify package objects against their recorded size and digest.
		for digest, path := range objectFiles {
			entry := findEntryByDigest(target, digest)
			if err := verifyObjectFile(path, entry); err != nil {
				return fmt.Errorf("cannot import package: object %s: %w", digest, err)
			}
		}

		// For incremental packages, the target repository must already have
		// the exact base snapshot: same name, same entries. A same-name
		// snapshot with different metadata, or merely sharing some digests,
		// is not a substitute. The base's referenced objects must also be
		// intact.
		if base != nil {
			existingBase, err := s.loadSnapshot(base.Name)
			if err != nil {
				return fmt.Errorf("cannot import package: %w", err)
			}
			if !snapshotsEqual(existingBase, *base) {
				return fmt.Errorf("cannot import package: base snapshot %q metadata mismatch", base.Name)
			}
			for digest := range baseDigests {
				entry := findEntryByDigest(*base, digest)
				if err := s.verifyObject(entry); err != nil {
					return fmt.Errorf("cannot import package: base object %s: %w", digest, err)
				}
			}
		}

		// Add objects that are not already present. Existing objects are
		// verified and reused; corrupted objects cause rejection.
		added := 0
		for digest := range expectedPackageDigests {
			objectPath := s.objectPath(digest)
			if _, err := os.Stat(objectPath); err == nil {
				entry := findEntryByDigest(target, digest)
				if err := s.verifyObject(entry); err != nil {
					return fmt.Errorf("cannot import package: existing object %s is corrupted: %w", digest, err)
				}
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := os.Rename(objectFiles[digest], objectPath); err != nil {
				return fmt.Errorf("cannot import package: failed to write object %s: %w", digest, err)
			}
			delete(objectFiles, digest)
			added++
		}

		// Publish the snapshot. A same-name snapshot with identical metadata
		// is a no-op success; a same-name snapshot with different metadata is
		// rejected.
		existingSnap, err := s.loadSnapshot(target.Name)
		if err == nil {
			if snapshotsEqual(existingSnap, target) {
				result = ImportResult{Name: target.Name, Entries: len(target.Entries), Added: added}
				return nil
			}
			return fmt.Errorf("cannot import package: snapshot %q already exists with different metadata", target.Name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}

		if err := s.saveSnapshot(s.snapshotPath(target.Name), target); err != nil {
			return fmt.Errorf("cannot import package: failed to write snapshot: %w", err)
		}

		result = ImportResult{Name: target.Name, Entries: len(target.Entries), Added: added}
		return nil
	})
	if err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

// readPackage opens a snapshot package and returns its parsed manifest and a
// map of digest to temp file path for each carried object. The manifest is
// checked for duplicate keys before parsing. Only manifest.json and
// objects/<digest> entries are accepted; anything else is an error.
func readPackage(file string, s *Store) (manifest packageManifest, objectFiles map[string]string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return packageManifest{}, nil, err
	}
	defer f.Close()

	if err := os.MkdirAll(s.objectsDir(), 0o755); err != nil {
		return packageManifest{}, nil, err
	}

	objectFiles = map[string]string{}
	defer func() {
		if err != nil {
			for _, path := range objectFiles {
				os.Remove(path)
			}
		}
	}()

	tr := tar.NewReader(f)
	var manifestData []byte
	manifestRead := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return packageManifest{}, nil, err
		}

		if hdr.Typeflag != tar.TypeReg {
			return packageManifest{}, nil, fmt.Errorf("package contains non-regular file %q", hdr.Name)
		}

		if hdr.Name == "manifest.json" {
			if manifestRead {
				return packageManifest{}, nil, errors.New("package contains multiple manifests")
			}
			data, err := io.ReadAll(tr)
			if err != nil {
				return packageManifest{}, nil, err
			}
			manifestData = data
			manifestRead = true
			continue
		}

		if !strings.HasPrefix(hdr.Name, "objects/") {
			return packageManifest{}, nil, fmt.Errorf("package contains unexpected file %q", hdr.Name)
		}
		digest := strings.TrimPrefix(hdr.Name, "objects/")
		if digest == "" || strings.Contains(digest, "/") {
			return packageManifest{}, nil, fmt.Errorf("package contains invalid object path %q", hdr.Name)
		}
		if !isDigest(digest) {
			return packageManifest{}, nil, fmt.Errorf("package contains invalid object digest %q", digest)
		}
		if _, exists := objectFiles[digest]; exists {
			return packageManifest{}, nil, fmt.Errorf("package contains duplicate object %q", digest)
		}

		tmp, err := os.CreateTemp(s.objectsDir(), ".import-object-*")
		if err != nil {
			return packageManifest{}, nil, err
		}
		tmpName := tmp.Name()
		n, copyErr := io.Copy(tmp, tr)
		closeErr := tmp.Close()
		if copyErr != nil {
			os.Remove(tmpName)
			return packageManifest{}, nil, copyErr
		}
		if closeErr != nil {
			os.Remove(tmpName)
			return packageManifest{}, nil, closeErr
		}
		if n != hdr.Size {
			os.Remove(tmpName)
			return packageManifest{}, nil, fmt.Errorf("package object %s size mismatch: header says %d, got %d", digest, hdr.Size, n)
		}
		objectFiles[digest] = tmpName
	}

	if !manifestRead {
		return packageManifest{}, nil, errors.New("package is missing manifest")
	}

	if err := checkDuplicateKeys(manifestData); err != nil {
		return packageManifest{}, nil, fmt.Errorf("package manifest is malformed: %w", err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return packageManifest{}, nil, fmt.Errorf("package manifest is malformed: %w", err)
	}
	// Reject trailing data after the top-level value.
	dec := json.NewDecoder(bytes.NewReader(manifestData))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return packageManifest{}, nil, fmt.Errorf("package manifest is malformed: %w", err)
	}
	if err := dec.Decode(&raw); err != io.EOF {
		return packageManifest{}, nil, errors.New("package manifest has trailing data")
	}

	return manifest, objectFiles, nil
}

// loadSnapshot reads a snapshot record from disk and verifies that its
// recorded name matches its location.
func (s *Store) loadSnapshot(name string) (Snapshot, error) {
	data, err := os.ReadFile(s.snapshotPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, fmt.Errorf("snapshot %q not found: %w", name, err)
	}
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %q is corrupted: %w", name, err)
	}
	if snap.Name != name {
		return Snapshot{}, fmt.Errorf("snapshot %q is corrupted: recorded name %q does not match its location", name, snap.Name)
	}
	return snap, nil
}

// validateSnapshot checks a snapshot's entries the same way restore and GC do:
// the entries mapping must be present, each entry must be filed under its
// recorded name, and names, digests, and sizes must be legal.
func validateSnapshot(snap Snapshot) error {
	if snap.Entries == nil {
		return errors.New("missing entries mapping")
	}
	for key, entry := range snap.Entries {
		if err := validateEntryRecord(key, entry); err != nil {
			return err
		}
	}
	return nil
}

// snapshotDigestSet returns the set of content digests referenced by a
// snapshot's entries.
func snapshotDigestSet(snap Snapshot) map[string]struct{} {
	digests := map[string]struct{}{}
	for _, entry := range snap.Entries {
		digests[entry.Digest] = struct{}{}
	}
	return digests
}

// findEntryByDigest returns one entry with the given digest from a snapshot.
func findEntryByDigest(snap Snapshot, digest string) Entry {
	for _, entry := range snap.Entries {
		if entry.Digest == digest {
			return entry
		}
	}
	return Entry{}
}

// snapshotsEqual reports whether two snapshots have the same name and identical
// entry metadata.
func snapshotsEqual(a, b Snapshot) bool {
	if a.Name != b.Name {
		return false
	}
	if len(a.Entries) != len(b.Entries) {
		return false
	}
	for key, entryA := range a.Entries {
		entryB, ok := b.Entries[key]
		if !ok {
			return false
		}
		if !entriesEqual(entryA, entryB) {
			return false
		}
	}
	return true
}

// entriesEqual reports whether two entries have identical metadata. The
// creation timestamp is not part of the comparison: it records when an
// artifact was uploaded and differs across repositories, while the entry's
// identity is its name, digest, and size.
func entriesEqual(a, b Entry) bool {
	return a.Name == b.Name && a.Digest == b.Digest && a.Size == b.Size
}

// verifyObjectFile checks that the file at path has the size and SHA-256
// recorded in entry.
func verifyObjectFile(path string, entry Entry) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, f)
	if err != nil {
		return err
	}
	if size != entry.Size || hex.EncodeToString(hash.Sum(nil)) != entry.Digest {
		return errors.New("content mismatch")
	}
	return nil
}

// checkDuplicateKeys reports whether a JSON document contains duplicate keys
// in any object.
func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	return checkDupKeys(dec)
}

func checkDupKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch d := tok.(type) {
	case json.Delim:
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return errors.New("expected string key in JSON object")
				}
				if seen[key] {
					return fmt.Errorf("duplicate key %q", key)
				}
				seen[key] = true
				if err := checkDupKeys(dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		case '[':
			for dec.More() {
				if err := checkDupKeys(dec); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		}
	}
	return nil
}

// sortedKeys returns the keys of a string set in sorted order.
func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (s *Store) objectsDir() string { return filepath.Join(s.root, "objects") }
