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

// marshalPackage serializes the package as indented JSON.
func marshalPackage(pkg *Package) ([]byte, error) {
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// streamReader exposes only Read, hiding any WriteTo/ReaderFrom the underlying
// reader may carry. io.CopyBuffer otherwise dispatches to *os.File.WriteTo,
// which is harmless but would route the copy through code outside this
// package; stripping the methods guarantees the supplied fixed-size buffer is
// the only read buffer, so streaming an object never allocates with its size.
type streamReader struct{ r io.Reader }

func (sr streamReader) Read(p []byte) (int, error) { return sr.r.Read(p) }

// packageObjectSource supplies one carried object's content on demand. The
// reader is opened only while the object is being serialized and is closed
// immediately afterwards, so an export of many objects holds one object file
// open at a time and never its bytes.
type packageObjectSource struct {
	digest string
	size   int64
	open   func() (io.ReadCloser, error)
}

// writeStreamingPackage serializes a package with exactly the bytes
// marshalPackage produces — same version, field order, two-space indentation,
// JSON escaping, trailing newline, and standard base64 encoding — while
// streaming each carried object's payload (and its base64 expansion) through
// fixed-size buffers. Neither the raw object bytes nor their encoded form is
// held in memory, so extra memory does not grow with an object's size or the
// total byte count. The snapshot and base metadata are rendered the same way
// marshalPackage renders them; objects must already be supplied in digest
// order. An empty objects slice serializes as [].
func writeStreamingPackage(w io.Writer, snap Snapshot, base *Snapshot, objects []packageObjectSource) error {
	head, err := packageMetaHead(snap, base)
	if err != nil {
		return err
	}
	if _, err := w.Write(head); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ",\n  \"objects\": "); err != nil {
		return err
	}
	if len(objects) == 0 {
		_, err := io.WriteString(w, "[]\n}\n")
		return err
	}
	if _, err := io.WriteString(w, "[\n"); err != nil {
		return err
	}
	// One fixed buffer is reused for every object.
	buf := make([]byte, exportBufferSize)
	for i := range objects {
		if err := writeStreamingObject(w, buf, objects[i]); err != nil {
			return err
		}
		if i+1 < len(objects) {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
		}
	}
	_, err = io.WriteString(w, "\n  ]\n}\n")
	return err
}

// packageMetaHead renders every package field before the objects array
// (format, version, snapshot, and base when present) with the exact
// indentation marshalPackage uses. MarshalIndent terminates the top-level
// object with a "\n}" after its last field; those two bytes are dropped so the
// caller can continue with ",\n  \"objects\": ..." and the document footer.
func packageMetaHead(snap Snapshot, base *Snapshot) ([]byte, error) {
	var meta struct {
		Format   string    `json:"format"`
		Version  int       `json:"version"`
		Snapshot Snapshot  `json:"snapshot"`
		Base     *Snapshot `json:"base,omitempty"`
	}
	meta.Format = packageFormat
	meta.Version = packageVersion
	meta.Snapshot = snap
	meta.Base = base
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return data[:len(data)-2], nil
}

// writeStreamingObject writes one object record — opening the content,
// base64-encoding it straight into the record's "data" string, and closing the
// reader — without buffering the payload. Standard base64 uses only JSON-safe
// characters, so the encoded bytes need no escaping and sit verbatim inside
// the JSON string. The frame's indentation matches MarshalIndent for an
// element of the top-level "objects" array.
func writeStreamingObject(w io.Writer, buf []byte, obj packageObjectSource) (err error) {
	rc, err := obj.open()
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	// The digest is 64 lowercase hex characters, but marshal it to stay
	// consistent with the JSON encoder regardless of content.
	digestJSON, err := json.Marshal(obj.digest)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "    {\n      \"digest\": %s,\n      \"size\": %d,\n      \"data\": \"", digestJSON, obj.size); err != nil {
		return err
	}
	enc := base64.NewEncoder(base64.StdEncoding, w)
	if _, copyErr := io.CopyBuffer(enc, streamReader{rc}, buf); copyErr != nil {
		_ = enc.Close()
		return copyErr
	}
	// Close flushes the final, possibly padded base64 quantum.
	if err := enc.Close(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\"\n    }")
	return err
}

// decodePackage parses a package without touching any repository. It enforces
// every self-contained invariant the specification places on a package:
//
//   - known format and version;
//   - snapshot (and base, if present) records are complete and valid:
//     snapshot name legal, entries keyed by their recorded name, legal names,
//     64 lowercase-hex digests, non-negative sizes;
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
	var raw struct {
		Format   string             `json:"format"`
		Version  int                `json:"version"`
		Snapshot Snapshot           `json:"snapshot"`
		Base     *Snapshot          `json:"base,omitempty"`
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
	if err := validateSnapshotRecord("snapshot", raw.Snapshot); err != nil {
		return nil, err
	}
	pkg.Snapshot = raw.Snapshot
	if raw.Base != nil {
		if err := validateSnapshotRecord("base", *raw.Base); err != nil {
			return nil, err
		}
		pkg.Base = raw.Base
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

// validateSnapshotRecord validates one embedded snapshot the same way restore
// and gc validate on-disk snapshots.
func validateSnapshotRecord(scope string, snap Snapshot) error {
	if err := validateName(snap.Name); err != nil {
		return fmt.Errorf("invalid package: %s snapshot name %q is not a legal snapshot name", scope, snap.Name)
	}
	if snap.Entries == nil {
		return fmt.Errorf("invalid package: %s snapshot %q is missing its entries mapping", scope, snap.Name)
	}
	for key, entry := range snap.Entries {
		if err := validateEntryRecord(key, entry); err != nil {
			return fmt.Errorf("invalid package: %s snapshot %q: %w", scope, snap.Name, err)
		}
	}
	return nil
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
