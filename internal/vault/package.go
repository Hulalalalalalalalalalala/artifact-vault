package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Package format:
//
// A snapshot package is an indented JSON document that moves one complete
// snapshot, together with whatever content objects it needs, between
// repositories. A full package carries every referenced object; an
// incremental package records a Base and only carries objects the base
// snapshot does not reference. Either way Snapshot always holds the complete
// target mapping — additions, overwrites, and deletions relative to the base
// are expressed solely by that mapping.
//
//	{
//	  "format": "artifact-vault-snapshot",
//	  "version": 1,
//	  "snapshot": { "name": "...", "entries": { ... } },
//	  "base": { "name": "...", "entries": { ... } },     // delta only, optional
//	  "objects": [
//	    { "digest": "<sha256 hex>", "size": 123, "data": "<base64>" }
//	  ]
//	}
//
// An object's SHA-256 digest over its decoded bytes is also its filename
// inside objects/, so no package record can name a destination outside that
// directory.
const (
	packageFormat  = "artifact-vault-snapshot"
	packageVersion = 1
)

// PackageObject is one content object carried by a package.
type PackageObject struct {
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	Data   string `json:"data"`
}

// Package is the on-disk snapshot transfer format.
type Package struct {
	Format   string          `json:"format"`
	Version  int             `json:"version"`
	Snapshot Snapshot        `json:"snapshot"`
	Base     *Snapshot       `json:"base,omitempty"`
	Objects  []PackageObject `json:"objects"`
}

// rejectDuplicateKeys walks the raw JSON token stream and fails if any object
// lists the same key twice. encoding/json otherwise keeps only the last
// occurrence, which could hide a duplicate object or entry behind an earlier,
// validated one.
func rejectDuplicateKeys(data []byte) error {
	type frame struct {
		object    bool
		keys      map[string]struct{}
		expectKey bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{object: true, keys: map[string]struct{}{}, expectKey: true})
			case '[':
				stack = append(stack, frame{object: false})
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("unbalanced JSON delimiters")
				}
				stack = stack[:len(stack)-1]
				// The composite value just consumed completes an entry in the
				// enclosing object, so its next string is another key.
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object {
				f := &stack[len(stack)-1]
				if f.expectKey {
					if _, dup := f.keys[t]; dup {
						return fmt.Errorf("duplicate key %q", t)
					}
					f.keys[t] = struct{}{}
					f.expectKey = false
				} else {
					f.expectKey = true
				}
			}
		default:
			// Primitive value in an object frame: the next string token is a key.
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
		}
	}
}

// marshalPackage serializes the package as indented JSON. Export no longer
// assembles packages in memory — it streams the same document — so this is
// the reference serialization tests compare the streamed output against.
func marshalPackage(pkg *Package) ([]byte, error) {
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// decodePackage parses a package without touching any repository. It enforces
// every self-contained invariant the specification places on a package:
//
//   - known format and version;
//   - snapshot (and base, if present) records are complete and valid:
//     snapshot name legal, mapping field spelled exactly "entries" (a JSON
//     object; {} is a legitimate empty mapping — any case-variant spelling
//     such as "Entries" is invalid alone or beside the standard field, a
//     missing/null/non-object mapping is invalid), entries keyed by their
//     recorded name, legal names, 64 lowercase-hex digests, non-negative sizes;
//   - every object digest is valid and unique, the base64 data decodes, and
//     its length and SHA-256 match the record;
//   - the object set carries exactly the objects required by the snapshot
//     mapping minus the base mapping (all of them for a full package),
//     neither omitting a referenced digest nor carrying an unreferenced one;
//   - every target entry records the exact byte count of the content its
//     digest identifies when that content is carried: an entry keeping a valid
//     digest but declaring another size is a corrupt record, even though the
//     object record itself is intact.
//
// Sizes for objects a delta omits cannot be checked until the package meets a
// matching, healthy base in the destination; import performs that check before
// anything is written. Other cross-repository checks (an existing base
// snapshot, objects already present in the destination, name collisions) are
// likewise performed later by import, which has the destination in hand.
func decodePackage(data []byte) (*Package, error) {
	// encoding/json silently keeps the last value when an object lists a key
	// twice; that would let a package hide a duplicate entry or overwrite a
	// structural field. Reject any such document before decoding it.
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("invalid package: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	// The nested snapshot records are kept raw here and decoded separately by
	// decodePackageSnapshotRecord, which applies the same exact-"entries" rule
	// as a stored snapshot record. Decoding them straight into Snapshot would
	// bind case-variant spellings ("Entries") silently through encoding/json's
	// case-insensitive field matching.
	var raw struct {
		Format   string             `json:"format"`
		Version  int                `json:"version"`
		Snapshot json.RawMessage    `json:"snapshot"`
		Base     *json.RawMessage   `json:"base,omitempty"`
		Objects  *[]json.RawMessage `json:"objects"`
	}
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid package: %w", err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("invalid package: unexpected trailing content after top-level value (%v)", tok)
		}
		return nil, fmt.Errorf("invalid package: %w", err)
	}
	if raw.Format != packageFormat {
		return nil, fmt.Errorf("invalid package: unknown format %q", raw.Format)
	}
	if raw.Version != packageVersion {
		return nil, fmt.Errorf("invalid package: unsupported version %d (supported: %d)", raw.Version, packageVersion)
	}
	if raw.Objects == nil {
		return nil, errors.New("invalid package: missing objects array")
	}

	pkg := &Package{Format: raw.Format, Version: raw.Version, Objects: []PackageObject{}}
	targetSnap, err := decodePackageSnapshotRecord("target snapshot", raw.Snapshot)
	if err != nil {
		return nil, err
	}
	pkg.Snapshot = targetSnap
	if raw.Base != nil {
		baseSnap, err := decodePackageSnapshotRecord("incremental base snapshot", *raw.Base)
		if err != nil {
			return nil, err
		}
		pkg.Base = &baseSnap
	}

	seen := map[string]struct{}{}
	for i, item := range *raw.Objects {
		var obj PackageObject
		odec := json.NewDecoder(bytes.NewReader(item))
		odec.DisallowUnknownFields()
		if err := odec.Decode(&obj); err != nil {
			return nil, fmt.Errorf("invalid package: object %d: %w", i, err)
		}
		if _, err := odec.Token(); err != io.EOF {
			if err == nil {
				return nil, fmt.Errorf("invalid package: object %d: trailing content", i)
			}
			return nil, fmt.Errorf("invalid package: object %d: %w", i, err)
		}
		if !isDigest(obj.Digest) {
			return nil, fmt.Errorf("invalid package: object %d: digest %q is not 64 lowercase hex characters", i, obj.Digest)
		}
		if obj.Size < 0 {
			return nil, fmt.Errorf("invalid package: object %s has negative size %d", obj.Digest, obj.Size)
		}
		if _, dup := seen[obj.Digest]; dup {
			return nil, fmt.Errorf("invalid package: duplicate object %s", obj.Digest)
		}
		seen[obj.Digest] = struct{}{}
		content, err := base64.StdEncoding.DecodeString(obj.Data)
		if err != nil {
			return nil, fmt.Errorf("invalid package: object %s: data is not valid base64: %w", obj.Digest, err)
		}
		if int64(len(content)) != obj.Size {
			return nil, fmt.Errorf("invalid package: object %s: data is %d bytes, record says %d", obj.Digest, len(content), obj.Size)
		}
		sum := sha256.Sum256(content)
		if actual := hex.EncodeToString(sum[:]); actual != obj.Digest {
			return nil, fmt.Errorf("invalid package: object %s: content checksum is %s", obj.Digest, actual)
		}
		pkg.Objects = append(pkg.Objects, obj)
	}

	needed := digestsReferenced(pkg.Snapshot.Entries)
	if pkg.Base != nil {
		for digest := range digestsReferenced(pkg.Base.Entries) {
			delete(needed, digest)
		}
	}
	carried := map[string]int64{}
	for _, obj := range pkg.Objects {
		carried[obj.Digest] = obj.Size
	}
	for digest := range needed {
		if _, ok := carried[digest]; !ok {
			return nil, fmt.Errorf("invalid package: required object %s is missing from the package", digest)
		}
	}
	for digest := range carried {
		if _, ok := needed[digest]; !ok {
			return nil, fmt.Errorf("invalid package: object %s is not referenced by the target mapping", digest)
		}
	}
	// Every target entry whose content the package carries must record the
	// carried content's exact byte count. The object's own record was already
	// proven to match its payload above, so an entry size that disagrees is a
	// corrupt snapshot record rather than corrupt content. Each name is
	// checked separately: one digest may be referenced by several entries, and
	// all of them must agree. Objects a delta omits are checked later against
	// the destination by import. Entries are visited in name order so the
	// first reported artifact is deterministic.
	for _, key := range sortedEntryNames(pkg.Snapshot.Entries) {
		entry := pkg.Snapshot.Entries[key]
		actual, isCarried := carried[entry.Digest]
		if isCarried && entry.Size != actual {
			return nil, fmt.Errorf("invalid package: %w", newEntrySizeMismatchError(pkg.Snapshot.Name, entry.Name, entry.Digest, entry.Size, actual))
		}
	}
	return pkg, nil
}

// sortedEntryNames returns a snapshot's entry keys in sorted order, so checks
// that may report one of several entries name a deterministic artifact.
func sortedEntryNames(entries map[string]Entry) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// entrySizeMismatchError reports a target snapshot entry whose recorded size
// disagrees with the actual byte count of the content its digest identifies.
// The digest matches healthy content, so this is record corruption — distinct
// from a checksum failure or missing content — and the fields name everything
// a user needs to tell them apart.
type entrySizeMismatchError struct {
	snapshot string
	artifact string
	digest   string
	recorded int64
	actual   int64
}

func newEntrySizeMismatchError(snapshot, artifact, digest string, recorded, actual int64) error {
	return entrySizeMismatchError{snapshot: snapshot, artifact: artifact, digest: digest, recorded: recorded, actual: actual}
}

func (e entrySizeMismatchError) Error() string {
	return fmt.Sprintf("snapshot %q entry %q references content %s but records size %d; the content is %d bytes",
		e.snapshot, e.artifact, e.digest, e.recorded, e.actual)
}

// decodePackageSnapshotRecord parses one snapshot record embedded in a
// package — the target snapshot, or the base record of an incremental
// package — under the same exact-"entries" rule as an on-disk snapshot record
// (see decodeSnapshotRecord). scope identifies which record it is in package
// terms ("target snapshot" or "incremental base snapshot") so a corrupt field
// is never misreported as a missing base or a content checksum failure.
//
// The record must be a single JSON object with no unknown fields, carrying:
//
//   - "name": present and a legal snapshot name;
//   - "entries": present, spelled exactly "entries" after JSON string
//     decoding, and a JSON object. A genuine {} is a legitimate empty mapping;
//     a missing field, null, array, or other non-object value is invalid. A
//     case-variant spelling ("Entries", "ENTRIES", ...) is invalid whether it
//     appears alone or beside the standard field, in either order, with
//     identical or different content, empty or not: encoding/json binds struct
//     fields case-insensitively, so decoding straight into Snapshot would let
//     the variant silently populate the mapping — and when both spellings
//     appear, whichever came last would silently replace the other, dropping
//     artifact records or installing an empty mapping. "entries" written
//     through Unicode escapes stays valid; an escape decoding to a variant is
//     rejected. The rule binds only this mapping field; artifact names remain
//     case-sensitive.
//
// Every entry is then decoded with unknown fields rejected and checked with
// validateEntryRecord. Duplicate keys anywhere in the package were already
// rejected by rejectDuplicateKeys before this runs.
func decodePackageSnapshotRecord(scope string, data json.RawMessage) (Snapshot, error) {
	// The record must be a JSON object: a null, array, or primitive is an
	// invalid record, never an empty snapshot.
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return Snapshot{}, fmt.Errorf("invalid package: %s: record must be a JSON object with name and entries", scope)
	}
	var raw struct {
		Name    *string          `json:"name"`
		Entries *json.RawMessage `json:"entries"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: malformed record: %w", scope, err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return Snapshot{}, fmt.Errorf("invalid package: %s: malformed record: unexpected trailing content (%v)", scope, tok)
		}
		return Snapshot{}, fmt.Errorf("invalid package: %s: malformed record: %w", scope, err)
	}
	// Name the record by its recorded name in every later error when it carried
	// one, legal or not, so the report names the full snapshot.
	label := scope
	if raw.Name != nil {
		label = fmt.Sprintf(`%s %q`, scope, *raw.Name)
	}
	// A field that spells the entries mapping with different casing would be
	// silently bound to it by the struct decode above — and would silently
	// overwrite or be overwritten by the standard spelling when both appear —
	// so any such field is invalid regardless of order, content, or emptiness.
	// This runs before the present/type checks so a variant alone is reported
	// as a variant, never as a missing entries mapping.
	if err := rejectEntriesCaseVariants(data); err != nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: %w", label, err)
	}
	if raw.Name == nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: record is missing its snapshot name", label)
	}
	if err := validateName(*raw.Name); err != nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: record name %q is not a legal snapshot name", scope, *raw.Name)
	}
	if raw.Entries == nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: record is missing its entries mapping", label)
	}
	entriesJSON := *raw.Entries
	if string(bytes.TrimSpace(entriesJSON)) == "null" {
		return Snapshot{}, fmt.Errorf("invalid package: %s: record is missing its entries mapping", label)
	}
	// Decode the entries object strictly: unknown fields inside an entry record
	// are rejected, exactly as the earlier whole-document decode did when it
	// cascaded into the entry structs.
	var rawEntries map[string]json.RawMessage
	if err := json.Unmarshal(entriesJSON, &rawEntries); err != nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: entries mapping is malformed: %w", label, err)
	}
	if rawEntries == nil {
		return Snapshot{}, fmt.Errorf("invalid package: %s: record is missing its entries mapping", label)
	}
	entries := make(map[string]Entry, len(rawEntries))
	for key := range rawEntries {
		var entry Entry
		edec := json.NewDecoder(bytes.NewReader(rawEntries[key]))
		edec.DisallowUnknownFields()
		if err := edec.Decode(&entry); err != nil {
			return Snapshot{}, fmt.Errorf("invalid package: %s: entries mapping is malformed: %w", label, err)
		}
		if _, err := edec.Token(); err != io.EOF {
			if err == nil {
				return Snapshot{}, fmt.Errorf("invalid package: %s: entries mapping is malformed: unexpected trailing content in entry %q", label, key)
			}
			return Snapshot{}, fmt.Errorf("invalid package: %s: entries mapping is malformed: entry %q: %w", label, key, err)
		}
		entries[key] = entry
	}
	for key, entry := range entries {
		if err := validateEntryRecord(key, entry); err != nil {
			return Snapshot{}, fmt.Errorf("invalid package: %s: %w", label, err)
		}
	}
	return Snapshot{Name: *raw.Name, Entries: entries}, nil
}

// digestsReferenced returns the set of object digests referenced by a set of
// snapshot entries. Multiple entries may share one digest.
func digestsReferenced(entries map[string]Entry) map[string]struct{} {
	digests := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		digests[entry.Digest] = struct{}{}
	}
	return digests
}

// objectContent is a decoded package object kept in memory during import.
type objectContent struct {
	digest  string
	size    int64
	content []byte
}

// materialize decodes the base64 payloads of every carried object into
// memory. Import holds the objects while it stages them; packages are
// bounded artifacts meant to be copied between machines.
func (p *Package) materialize() ([]objectContent, error) {
	objects := make([]objectContent, 0, len(p.Objects))
	// Sort so staging order (and any error message) is deterministic.
	ordered := append([]PackageObject(nil), p.Objects...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Digest < ordered[j].Digest })
	for _, obj := range ordered {
		content, err := base64.StdEncoding.DecodeString(obj.Data)
		if err != nil {
			return nil, fmt.Errorf("object %s: %w", obj.Digest, err)
		}
		objects = append(objects, objectContent{digest: obj.Digest, size: obj.Size, content: content})
	}
	return objects, nil
}
