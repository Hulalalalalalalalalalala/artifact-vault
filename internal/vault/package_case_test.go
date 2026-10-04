package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// jsonBackslash is a single backslash assembled from its byte value, so test
// source can spell JSON unicode escapes without writing a literal escape
// sequence. JSON — not Go — then decodes them: U+0045 is "E", U+0049 is "I",
// U+0065 is lower-case "e".
const jsonBackslash = string(rune(92))

var (
	// decodes to the field name "Entries" (a case variant)
	escKeyEntries = "\"" + jsonBackslash + "u0045ntries\""
	// decodes to the field name "entrIes" (a case variant in the middle)
	escKeyEntrIes = "\"entr" + jsonBackslash + "u0049es\""
	// decodes to the standard field name "entries"
	escKeyEntriesStd = "\"" + jsonBackslash + "u0065ntries\""
)

// rawObjectRecord renders one truthful carried object record for content.
func rawObjectRecord(content string) string {
	return fmt.Sprintf(`{"digest":%q,"size":%d,"data":%q}`,
		digestOf(content), len(content), base64.StdEncoding.EncodeToString([]byte(content)))
}

// writeRawPackage writes literal package bytes to a temp file and returns its
// path, for packages that cannot be built through the typed Package struct.
func writeRawPackage(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "package.vaultpkg")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertPackageRejected runs decodePackage and requires an error whose message
// contains every want substring and none of the notWant substrings.
func assertPackageRejected(t *testing.T, doc string, want, notWant []string) {
	t.Helper()
	pkg, err := decodePackage([]byte(doc))
	if err == nil {
		t.Fatalf("decode accepted a package it must reject: %+v", pkg)
	}
	msg := err.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Fatalf("error %q does not report %q", msg, w)
		}
	}
	for _, nw := range notWant {
		if strings.Contains(msg, nw) {
			t.Fatalf("error %q misreports the failure as %q", msg, nw)
		}
	}
}

// TestPackageSnapshotEntriesCaseVariantsRejected proves that the snapshot
// record embedded in an import package is held to the same exact-"entries"
// rule as a stored snapshot record: a mapping field whose decoded name equals
// "entries" only case-insensitively is an invalid package whether the variant
// appears alone or beside the standard field, in either order, with identical
// or different content, empty or not. The error identifies the record as the
// package's target snapshot (never as a missing base or a content failure),
// names the full snapshot and the offending field, and no Package is returned.
func TestPackageSnapshotEntriesCaseVariantsRejected(t *testing.T) {
	d := digestOf("payload")
	rec := validRecordJSON("keep.txt", d, 7)
	object := rawObjectRecord("payload")
	cases := map[string]struct {
		fields    string // snapshot record fields following the name field
		wantField string
	}{
		"variant alone with records": {
			fields:    `"Entries":{"keep.txt":` + rec + `}`,
			wantField: `"Entries"`,
		},
		"variant alone empty": {
			fields:    `"ENTRIES":{}`,
			wantField: `"ENTRIES"`,
		},
		"empty variant after standard field": {
			fields:    `"entries":{"keep.txt":` + rec + `},"Entries":{}`,
			wantField: `"Entries"`,
		},
		"empty variant before standard field": {
			fields:    `"Entries":{},"entries":{"keep.txt":` + rec + `}`,
			wantField: `"Entries"`,
		},
		"identical content in both spellings": {
			fields:    `"entries":{"keep.txt":` + rec + `},"Entries":{"keep.txt":` + rec + `}`,
			wantField: `"Entries"`,
		},
		"third casing beside standard field": {
			fields:    `"entries":{"keep.txt":` + rec + `},"ENTRIES":{}`,
			wantField: `"ENTRIES"`,
		},
		"unicode escape decoding to a variant": {
			fields:    escKeyEntries + `:{},"entries":{"keep.txt":` + rec + `}`,
			wantField: `"Entries"`,
		},
		"unicode escape inside the field name": {
			fields:    escKeyEntrIes + `:{}`,
			wantField: `"entrIes"`,
		},
	}
	want := []string{"invalid package", "target snapshot", `"releases/target"`}
	notWant := []string{"incremental base", "missing its entries", "missing base", "checksum"}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			doc := `{"format":"artifact-vault-snapshot","version":1,` +
				`"snapshot":{"name":"releases/target",` + tc.fields + `},` +
				`"objects":[` + object + `]}`
			assertPackageRejected(t, doc, append(want, tc.wantField), notWant)
		})
	}
}

// TestPackageBaseEntriesCaseVariantsRejected proves the rule reaches the base
// record of an incremental package too, and that a corrupt base record is
// identified as the incremental base rather than as a target problem or a
// missing/unavailable base snapshot.
func TestPackageBaseEntriesCaseVariantsRejected(t *testing.T) {
	d := digestOf("payload")
	rec := validRecordJSON("keep.txt", d, 7)
	object := rawObjectRecord("payload")
	cases := map[string]struct {
		fields    string
		wantField string
	}{
		"variant alone": {
			fields:    `"Entries":{"keep.txt":` + rec + `}`,
			wantField: `"Entries"`,
		},
		"variant beside standard field": {
			fields:    `"entries":{},"ENTRIES":{"keep.txt":` + rec + `}`,
			wantField: `"ENTRIES"`,
		},
		"unicode escape decoding to a variant": {
			fields:    escKeyEntries + `:{}`,
			wantField: `"Entries"`,
		},
	}
	want := []string{"invalid package", "incremental base snapshot", `"releases/base"`}
	notWant := []string{"unavailable", "does not match", "not fully present", "checksum"}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			// The target snapshot is perfectly healthy; only the base record
			// carries the ambiguous field.
			doc := `{"format":"artifact-vault-snapshot","version":1,` +
				`"snapshot":{"name":"target","entries":{"keep.txt":` + rec + `}},` +
				`"base":{"name":"releases/base",` + tc.fields + `},` +
				`"objects":[` + object + `]}`
			assertPackageRejected(t, doc, append(want, tc.wantField), notWant)
		})
	}
}

// TestPackageSnapshotExactEntriesSpellingAccepted covers the embedded records
// that must keep importing: the standard field written through Unicode
// escapes, an explicitly empty target mapping, an explicitly empty base
// mapping, and an artifact literally named "Entries" — the rule binds only the
// mapping field, never artifact names.
func TestPackageSnapshotExactEntriesSpellingAccepted(t *testing.T) {
	d := digestOf("payload")
	object := rawObjectRecord("payload")
	rec := validRecordJSON("keep.txt", d, 7)
	cases := map[string]string{
		"standard field through unicode escape": `{"format":"artifact-vault-snapshot","version":1,` +
			`"snapshot":{"name":"s",` + escKeyEntriesStd + `:{"keep.txt":` + rec + `}},` +
			`"objects":[` + object + `]}`,
		"explicit empty target mapping": `{"format":"artifact-vault-snapshot","version":1,` +
			`"snapshot":{"name":"s","entries":{}},"objects":[]}`,
		"explicit empty base mapping": `{"format":"artifact-vault-snapshot","version":1,` +
			`"snapshot":{"name":"t","entries":{}},` +
			`"base":{"name":"b","entries":{}},"objects":[]}`,
	}
	for label, doc := range cases {
		t.Run(label, func(t *testing.T) {
			pkg, err := decodePackage([]byte(doc))
			if err != nil {
				t.Fatalf("a healthy package was rejected: %v\n%s", err, doc)
			}
			if pkg.Base != nil && pkg.Base.Entries == nil {
				t.Fatal("base entries decoded to a nil map")
			}
		})
	}

	// An artifact named "Entries" is unrelated to the mapping-field rule and
	// imports normally with its case-sensitive name intact.
	artifactRec := validRecordJSON("Entries", d, 7)
	doc := `{"format":"artifact-vault-snapshot","version":1,` +
		`"snapshot":{"name":"s","entries":{"Entries":` + artifactRec + `}},` +
		`"objects":[` + object + `]}`
	pkg, err := decodePackage([]byte(doc))
	if err != nil {
		t.Fatalf("package naming an artifact Entries was rejected: %v", err)
	}
	if _, ok := pkg.Snapshot.Entries["Entries"]; !ok {
		t.Fatalf("the Entries artifact did not survive decoding: %+v", pkg.Snapshot.Entries)
	}
}

// TestPackageMissingNullOrNonObjectEntriesStillRejected pins the pre-existing
// rejection of absent/null/non-object mappings on both embedded records, now
// reported through the new decoder, and that strictness over unknown fields is
// retained.
func TestPackageMissingNullOrNonObjectEntriesStillRejected(t *testing.T) {
	cases := map[string]string{
		"target missing entries":  `"snapshot":{"name":"s"}`,
		"target null entries":     `"snapshot":{"name":"s","entries":null}`,
		"target array entries":    `"snapshot":{"name":"s","entries":[1,2]}`,
		"target string entries":   `"snapshot":{"name":"s","entries":"x"}`,
		"snapshot record is null": `"snapshot":null`,
		"base missing entries":    `"snapshot":{"name":"t","entries":{}},"base":{"name":"b"}`,
		"base null entries":       `"snapshot":{"name":"t","entries":{}},"base":{"name":"b","entries":null}`,
		"unknown record field":    `"snapshot":{"name":"s","entries":{},"sneaky":true}`,
		"unknown entry field":     `"snapshot":{"name":"s","entries":{"a":{"name":"a","digest":"` + strings.Repeat("a", 64) + `","size":0,"createdAt":"2026-01-01T00:00:00Z","x":1}}}`,
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			doc := `{"format":"artifact-vault-snapshot","version":1,` + body + `,"objects":[]}`
			if _, err := decodePackage([]byte(doc)); err == nil {
				t.Fatalf("decode accepted %s", label)
			}
		})
	}
}

// TestImportCaseVariantTargetRejectsEverythingWithoutSideEffects is the
// end-to-end atomicity guarantee for an ambiguous target record. The
// destination already holds a same-named snapshot with identical intended
// metadata; the package also carries a genuinely new correct object. Import
// must still refuse, return no usable result, and leave the current mapping,
// every snapshot and object (including the new one, which must not be
// installed), and the repository temp files exactly as they were.
func TestImportCaseVariantTargetRejectsEverythingWithoutSideEffects(t *testing.T) {
	const oldData = "payload"       // already in the destination
	const newData = "brand new one" // carried by the package, genuinely new
	dOld := digestOf(oldData)
	dNew := digestOf(newData)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	// Current mapping references an unrelated artifact; it must survive intact.
	if _, err := New(dst).Put("current.txt", writeFile(t, "current mapping")); err != nil {
		t.Fatal(err)
	}
	// A same-named target snapshot with the same intended metadata: identical
	// metadata must not make the ambiguous package acceptable.
	intended := Snapshot{Name: "s", Entries: map[string]Entry{
		"keep.txt": entryRec("keep.txt", dOld, 7),
		"new.txt":  entryRec("new.txt", dNew, int64(len(newData))),
	}}
	if err := New(dst).saveSnapshot(New(dst).snapshotPath("s"), intended); err != nil {
		t.Fatal(err)
	}
	beforeObjects := objectDirNames(t, dst)

	doc := `{"format":"artifact-vault-snapshot","version":1,` +
		`"snapshot":{"name":"s","Entries":{` +
		`"keep.txt":` + validRecordJSON("keep.txt", dOld, 7) + `,` +
		`"new.txt":` + validRecordJSON("new.txt", dNew, len(newData)) +
		`}},"objects":[` +
		rawObjectRecord(oldData) + `,` + rawObjectRecord(newData) + `]}`

	res, err := New(dst).ImportSnapshot(writeRawPackage(t, doc))
	if err == nil {
		t.Fatal("import accepted an ambiguous target snapshot record")
	}
	msg := err.Error()
	for _, want := range []string{"target snapshot", `"s"`, `"Entries"`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not report %q", msg, want)
		}
	}
	if strings.Contains(msg, "already exists") {
		t.Fatalf("ambiguous record was handled as a snapshot collision: %q", msg)
	}
	if res != (ImportResult{}) {
		t.Fatalf("failed import returned a usable result: %+v", res)
	}
	if objectExists(dst, dNew) {
		t.Fatal("failed import installed the package's other, correct new object")
	}
	if after := objectDirNames(t, dst); strings.Join(after, ",") != strings.Join(beforeObjects, ",") {
		t.Fatalf("objects directory changed\nbefore: %v\nafter:  %v", beforeObjects, after)
	}
	assertNoTemporaryFiles(t, dst)
	// The pre-existing same-named snapshot is unchanged.
	current, err := New(dst).loadSnapshotRecord("s")
	if err != nil {
		t.Fatal(err)
	}
	if !snapshotsEqual(current, intended) {
		t.Fatalf("existing snapshot changed\nwant: %+v\ngot:  %+v", intended.Entries, current.Entries)
	}
	// Current mapping is untouched and import never restores it.
	entries, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "current.txt" {
		t.Fatalf("current mapping changed after failed import: %+v", entries)
	}
}

// TestImportCaseVariantBaseRejectsWithoutTouchingRepo covers a delta whose
// base record is ambiguous: it must fail naming the incremental base snapshot
// (not "base unavailable"), return no result, install neither the carried new
// object nor the target snapshot, and leave a genuinely matching pre-existing
// base snapshot and its object intact.
func TestImportCaseVariantBaseRejectsWithoutTouchingRepo(t *testing.T) {
	const oldData = "olddata"
	const newData = "brand new"
	dOld := digestOf(oldData)
	dNew := digestOf(newData)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	// Install a healthy, genuinely matching base snapshot and its object.
	basePkg := Package{
		Format:   packageFormat,
		Version:  packageVersion,
		Snapshot: Snapshot{Name: "base", Entries: map[string]Entry{"keep.txt": entryRec("keep.txt", dOld, 7)}},
		Objects:  []PackageObject{packageObject(oldData)},
	}
	if _, err := New(dst).ImportSnapshot(writePackage(t, basePkg)); err != nil {
		t.Fatal(err)
	}
	beforeObjects := objectDirNames(t, dst)

	// Delta whose base record spells the field "Entries".
	doc := `{"format":"artifact-vault-snapshot","version":1,` +
		`"snapshot":{"name":"target","entries":{` +
		`"keep.txt":` + validRecordJSON("keep.txt", dOld, 7) + `,` +
		`"new.txt":` + validRecordJSON("new.txt", dNew, len(newData)) + `}},` +
		`"base":{"name":"base","Entries":{"keep.txt":` + validRecordJSON("keep.txt", dOld, 7) + `}},` +
		`"objects":[` + rawObjectRecord(newData) + `]}`

	res, err := New(dst).ImportSnapshot(writeRawPackage(t, doc))
	if err == nil {
		t.Fatal("import accepted a delta with an ambiguous base record")
	}
	msg := err.Error()
	for _, want := range []string{"incremental base snapshot", `"base"`, `"Entries"`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not report %q", msg, want)
		}
	}
	for _, notWant := range []string{"unavailable", "does not match", "not fully present"} {
		if strings.Contains(msg, notWant) {
			t.Fatalf("a malformed base record was misreported as %q: %q", notWant, msg)
		}
	}
	if res != (ImportResult{}) {
		t.Fatalf("failed delta returned a usable result: %+v", res)
	}
	if objectExists(dst, dNew) {
		t.Fatal("failed delta installed its carried new object")
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 || infos[0].Name != "base" {
		t.Fatalf("only the base snapshot should exist: %+v", infos)
	}
	if after := objectDirNames(t, dst); strings.Join(after, ",") != strings.Join(beforeObjects, ",") {
		t.Fatalf("objects directory changed\nbefore: %v\nafter:  %v", beforeObjects, after)
	}
	assertNoTemporaryFiles(t, dst)
}

// TestImportCaseSensitiveArtifactNamesRoundTrip proves healthy packages keep
// working once the mapping-field rule is enforced: an export/import round trip
// preserves artifacts whose names differ only by case or literally read
// "Entries", reusing objects and keeping every name, digest, size, and
// creation time.
func TestImportCaseSensitiveArtifactNamesRoundTrip(t *testing.T) {
	contents := map[string]string{
		"Entries": "capitalized payload\n",
		"App.bin": "upper app payload\n",
		"app.bin": "lower app payload\n",
	}
	src := filepath.Join(t.TempDir(), "vault")
	if err := New(src).Init(); err != nil {
		t.Fatal(err)
	}
	for name, content := range contents {
		if _, err := New(src).Put(name, writeFile(t, content)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(src).CreateSnapshot("casey"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "casey.pkg")
	if res := mustExport(t, src, "casey", "", out); res.Entries != len(contents) {
		t.Fatalf("export entries=%d, want %d", res.Entries, len(contents))
	}

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	res, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatalf("import of a healthy package with case-sensitive names failed: %v", err)
	}
	if res.Entries != len(contents) || res.NewObjects != len(contents) {
		t.Fatalf("import result=%+v, want %d entries and %d new objects", res, len(contents), len(contents))
	}
	// Re-import reuses every object and adds nothing.
	res2, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatal(err)
	}
	if res2.NewObjects != 0 {
		t.Fatalf("re-import staged %d new objects", res2.NewObjects)
	}
	// The imported snapshot keeps every name, digest, size, and creation time of
	// the source record.
	srcSnap, err := New(src).loadSnapshotRecord("casey")
	if err != nil {
		t.Fatal(err)
	}
	dstSnap, err := New(dst).loadSnapshotRecord("casey")
	if err != nil {
		t.Fatal(err)
	}
	if !snapshotsEqual(srcSnap, dstSnap) {
		t.Fatalf("imported snapshot metadata differs\nsrc:  %+v\ndest: %+v", srcSnap.Entries, dstSnap.Entries)
	}
	if err := New(dst).RestoreSnapshot("casey"); err != nil {
		t.Fatal(err)
	}
	listed, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != len(contents) {
		t.Fatalf("listed %d rows, want %d: %+v", len(listed), len(contents), listed)
	}
}

// TestPackageCaseVariantFailsBeforeRepositoryChecks proves the ambiguity is
// detected while the package is decoded, without a repository, so it can never
// be misreported as a missing base or a content/object failure.
func TestPackageCaseVariantFailsBeforeRepositoryChecks(t *testing.T) {
	doc := `{"format":"artifact-vault-snapshot","version":1,` +
		`"snapshot":{"name":"s","Entries":{}},"objects":[]}`
	assertPackageRejected(t, doc,
		[]string{"target snapshot", `"s"`, `"Entries"`},
		[]string{"object", "checksum", "base"})
	// Sanity: the document is well-formed JSON; it is the semantic rule that
	// rejects it.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &probe); err != nil {
		t.Fatal(err)
	}
}
