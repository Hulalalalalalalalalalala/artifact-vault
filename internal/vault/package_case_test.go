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

// packageObjectJSON renders one objects-array element carrying content.
func packageObjectJSON(content string) string {
	return fmt.Sprintf(`{"digest":%q,"size":%d,"data":%q}`,
		digestOf(content), len(content), base64.StdEncoding.EncodeToString([]byte(content)))
}

// fullPackageJSON renders a complete package whose target snapshot record
// carries the given raw fields after its name, plus the given object elements.
func fullPackageJSON(name, snapshotFields string, objects ...string) string {
	return `{"format":"artifact-vault-snapshot","version":1,` +
		`"snapshot":{"name":` + fmt.Sprintf("%q", name) + `,` + snapshotFields + `},` +
		`"objects":[` + strings.Join(objects, ",") + `]}`
}

// writeTempPackage writes content to a fresh package file and returns its path.
func writeTempPackage(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pkg")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// assertRepoUntouchedByImport proves a rejected import changed nothing: the
// current mapping keeps its exact bytes and rows, no snapshot was published,
// and the objects directory holds exactly the pre-existing objects with no
// temporary files left behind.
func assertRepoUntouchedByImport(t *testing.T, root string, indexBefore []byte, wantObjects ...string) {
	t.Helper()
	indexAfter, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatalf("failed import rewrote the current mapping\nwas: %s\nnow: %s", indexBefore, indexAfter)
	}
	infos, err := New(root).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("failed import published snapshots: %+v", infos)
	}
	got := objectNames(t, root)
	if len(got) != len(wantObjects) {
		t.Fatalf("objects=%v, want exactly %v (no new object, no temporary file)", got, wantObjects)
	}
	for i, want := range wantObjects {
		if got[i] != want {
			t.Fatalf("objects=%v, want %v", got, wantObjects)
		}
	}
}

// TestPackageTargetEntriesCaseVariantsAreCorrupt proves the import-time rule
// for the package's target snapshot record matches the on-disk rule: the
// entries mapping must be spelled exactly "entries". A case variant —
// "Entries", "ENTRIES", or a Unicode escape decoding to one — is corruption
// whether it appears alone or beside the standard field, in either order,
// with identical or different content, empty or not. The error identifies the
// package's target snapshot by its full name and the offending field (never a
// missing-base or checksum error), and the failed import leaves the
// destination's mapping, snapshots, objects, and temporary-file set exactly
// as they were.
func TestPackageTargetEntriesCaseVariantsAreCorrupt(t *testing.T) {
	goodDigest := digestOf("keep me")
	rec := validRecordJSON("keep.txt", goodDigest, 7)
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
			fields:    `"\u0045ntries":{},"entries":{"keep.txt":` + rec + `}`,
			wantField: `"Entries"`,
		},
		"unicode escape inside the name": {
			fields:    `"entr\u0049es":{}`,
			wantField: `"entrIes"`,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			dst, _ := seedVault(t, map[string]string{"other.txt": "other"})
			indexBefore, err := os.ReadFile(filepath.Join(dst, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			pkg := writeTempPackage(t, fullPackageJSON("releases/target", tc.fields, packageObjectJSON("keep me")))
			_, err = New(dst).ImportSnapshot(pkg)
			if err == nil {
				t.Fatal("import accepted a target snapshot with a case-variant entries field")
			}
			msg := err.Error()
			for _, want := range []string{
				"invalid package",
				`snapshot "releases/target"`,
				tc.wantField,
				`must be spelled exactly "entries"`,
			} {
				if !strings.Contains(msg, want) {
					t.Fatalf("error %q does not report %q", msg, want)
				}
			}
			for _, wrong := range []string{"delta base", "checksum", "not found"} {
				if strings.Contains(msg, wrong) {
					t.Fatalf("error %q misreports the corruption as %q", msg, wrong)
				}
			}
			assertRepoUntouchedByImport(t, dst, indexBefore, digestOf("other"))
		})
	}
}

// TestPackageBaseEntriesCaseVariantsAreCorrupt proves the same spelling rule
// for the delta base record inside a package: a case-variant entries field
// rejects the whole package even when the destination holds a matching,
// healthy base snapshot. The error names the delta base by its full name and
// the offending field — never a missing or mismatching base — and nothing in
// the destination changes: the installed base snapshot keeps its exact bytes,
// no target snapshot is published, and no carried object is installed.
func TestPackageBaseEntriesCaseVariantsAreCorrupt(t *testing.T) {
	goodDigest := digestOf("keep me")
	cases := map[string]struct {
		fields    string // base record fields following the name field
		wantField string
	}{
		"variant alone": {
			fields:    `"Entries":{}`,
			wantField: `"Entries"`,
		},
		"variant beside standard field": {
			fields:    `"entries":%s,"ENTRIES":{}`,
			wantField: `"ENTRIES"`,
		},
		"variant before standard field": {
			fields:    `"Entries":{},"entries":%s`,
			wantField: `"Entries"`,
		},
		"unicode escape decoding to a variant": {
			fields:    `"\u0045ntries":{},"entries":%s`,
			wantField: `"Entries"`,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			// The destination holds the exact base the delta names.
			dst, _ := seedVault(t, map[string]string{"keep.txt": "keep me"})
			if _, err := New(dst).CreateSnapshot("releases/base"); err != nil {
				t.Fatal(err)
			}
			baseRecordPath := filepath.Join(dst, "snapshots", "releases", "base.json")
			baseRecord, err := os.ReadFile(baseRecordPath)
			if err != nil {
				t.Fatal(err)
			}
			var filed struct {
				Entries json.RawMessage `json:"entries"`
			}
			if err := json.Unmarshal(baseRecord, &filed); err != nil {
				t.Fatal(err)
			}
			// The target adds new.txt on top of the base mapping; the delta
			// carries only its object.
			var targetEntries map[string]Entry
			if err := json.Unmarshal(filed.Entries, &targetEntries); err != nil {
				t.Fatal(err)
			}
			targetEntries["new.txt"] = Entry{
				Name: "new.txt", Digest: digestOf("new"), Size: 3,
				CreatedAt: targetEntries["keep.txt"].CreatedAt,
			}
			targetJSON, err := json.Marshal(targetEntries)
			if err != nil {
				t.Fatal(err)
			}
			baseFields := tc.fields
			if strings.Contains(baseFields, "%s") {
				baseFields = fmt.Sprintf(baseFields, filed.Entries)
			}
			pkg := writeTempPackage(t,
				`{"format":"artifact-vault-snapshot","version":1,`+
					`"snapshot":{"name":"releases/target","entries":`+string(targetJSON)+`},`+
					`"base":{"name":"releases/base",`+baseFields+`},`+
					`"objects":[`+packageObjectJSON("new")+`]}`)
			indexBefore, err := os.ReadFile(filepath.Join(dst, "index.json"))
			if err != nil {
				t.Fatal(err)
			}

			_, err = New(dst).ImportSnapshot(pkg)
			if err == nil {
				t.Fatal("import accepted a delta base with a case-variant entries field")
			}
			msg := err.Error()
			for _, want := range []string{
				"invalid package",
				`base snapshot "releases/base"`,
				tc.wantField,
				`must be spelled exactly "entries"`,
			} {
				if !strings.Contains(msg, want) {
					t.Fatalf("error %q does not report %q", msg, want)
				}
			}
			for _, wrong := range []string{"unavailable", "does not match", "not fully present", "checksum"} {
				if strings.Contains(msg, wrong) {
					t.Fatalf("error %q misreports the corrupt base record as %q", msg, wrong)
				}
			}

			// Nothing changed: the mapping, the installed base record's bytes,
			// and the object set are exactly as before; the target snapshot was
			// never published and the carried object never landed.
			indexAfter, err := os.ReadFile(filepath.Join(dst, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(indexAfter) != string(indexBefore) {
				t.Fatal("failed import rewrote the current mapping")
			}
			gotRecord, err := os.ReadFile(baseRecordPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotRecord) != string(baseRecord) {
				t.Fatal("failed import rewrote the installed base snapshot record")
			}
			infos, err := New(dst).ListSnapshots()
			if err != nil {
				t.Fatal(err)
			}
			if len(infos) != 1 || infos[0].Name != "releases/base" {
				t.Fatalf("snapshots=%+v, want only the pre-existing releases/base", infos)
			}
			got := objectNames(t, dst)
			if len(got) != 1 || got[0] != goodDigest {
				t.Fatalf("objects=%v, want only the pre-existing %s (no carried object, no temporary file)", got, goodDigest)
			}
		})
	}
}

// TestPackageExactSpellingAndArtifactCasingAccepted covers the packages that
// must keep importing under the tightened rule: the standard field written
// through a Unicode escape, an explicitly empty mapping, and an artifact
// literally named "Entries" — the rule constrains only the snapshot record's
// mapping field, never artifact names.
func TestPackageExactSpellingAndArtifactCasingAccepted(t *testing.T) {
	t.Run("standard field through unicode escape", func(t *testing.T) {
		dst, _ := seedVault(t, map[string]string{"other.txt": "other"})
		rec := validRecordJSON("keep.txt", digestOf("keep me"), 7)
		pkg := writeTempPackage(t, fullPackageJSON("escaped",
			`"\u0065ntries":{"keep.txt":`+rec+`}`, packageObjectJSON("keep me")))
		res, err := New(dst).ImportSnapshot(pkg)
		if err != nil {
			t.Fatalf("import rejected the standard field written through escapes: %v", err)
		}
		if res.Name != "escaped" || res.Entries != 1 || res.NewObjects != 1 {
			t.Fatalf("import result=%+v, want escaped with 1 entry and 1 new object", res)
		}
		assertEntriesAfterRestore(t, dst, "escaped", map[string]string{"keep.txt": "keep me"})
	})

	t.Run("explicit empty mapping", func(t *testing.T) {
		dst, _ := seedVault(t, map[string]string{"other.txt": "other"})
		pkg := writeTempPackage(t, fullPackageJSON("empty", `"entries":{}`))
		res, err := New(dst).ImportSnapshot(pkg)
		if err != nil {
			t.Fatalf("import rejected an explicit empty mapping: %v", err)
		}
		if res.Entries != 0 || res.NewObjects != 0 {
			t.Fatalf("import result=%+v, want 0 entries 0 new objects", res)
		}
		infos, err := New(dst).ListSnapshots()
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || infos[0].Name != "empty" || infos[0].Count != 0 {
			t.Fatalf("infos=%+v, want one empty snapshot with 0 entries", infos)
		}
	})

	t.Run("artifact named Entries", func(t *testing.T) {
		dst, _ := seedVault(t, map[string]string{"other.txt": "other"})
		rec := validRecordJSON("Entries", digestOf("capital payload"), 15)
		pkg := writeTempPackage(t, fullPackageJSON("cased",
			`"entries":{"Entries":`+rec+`}`, packageObjectJSON("capital payload")))
		res, err := New(dst).ImportSnapshot(pkg)
		if err != nil {
			t.Fatalf("import rejected an artifact named Entries: %v", err)
		}
		if res.Entries != 1 || res.NewObjects != 1 {
			t.Fatalf("import result=%+v, want 1 entry 1 new object", res)
		}
		assertEntriesAfterRestore(t, dst, "cased", map[string]string{"Entries": "capital payload"})
	})
}

// TestPackageEntriesMappingPresenceRules confirms the pre-existing mapping
// rules are unchanged beside the new spelling rule: a missing, null, or
// non-object entries mapping stays rejected, and a package whose snapshot
// name and metadata are already installed identically is still refused when
// its record also carries a case-variant spelling.
func TestPackageEntriesMappingPresenceRules(t *testing.T) {
	rec := validRecordJSON("keep.txt", digestOf("keep me"), 7)
	for label, fields := range map[string]string{
		"missing entries mapping": `"note":"nothing else"`,
		"null entries mapping":    `"entries":null`,
		"array entries mapping":   `"entries":[]`,
	} {
		t.Run(label, func(t *testing.T) {
			dst, _ := seedVault(t, map[string]string{"other.txt": "other"})
			indexBefore, err := os.ReadFile(filepath.Join(dst, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			pkg := writeTempPackage(t, fullPackageJSON("bad", fields, packageObjectJSON("keep me")))
			if _, err := New(dst).ImportSnapshot(pkg); err == nil {
				t.Fatalf("import accepted %s", label)
			}
			assertRepoUntouchedByImport(t, dst, indexBefore, digestOf("other"))
		})
	}

	t.Run("identical installed snapshot does not rescue a variant", func(t *testing.T) {
		dst, _ := seedVault(t, map[string]string{"other.txt": "other"})
		healthy := fullPackageJSON("dup", `"entries":{"keep.txt":`+rec+`}`, packageObjectJSON("keep me"))
		if _, err := New(dst).ImportSnapshot(writeTempPackage(t, healthy)); err != nil {
			t.Fatal(err)
		}
		recordPath := filepath.Join(dst, "snapshots", "dup.json")
		recordBefore, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		indexBefore, err := os.ReadFile(filepath.Join(dst, "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		// Same name, same entry metadata — but the record carries the mapping
		// under both spellings, which is ambiguous and must still be refused.
		corrupt := fullPackageJSON("dup",
			`"entries":{"keep.txt":`+rec+`},"Entries":{"keep.txt":`+rec+`}`,
			packageObjectJSON("keep me"))
		_, err = New(dst).ImportSnapshot(writeTempPackage(t, corrupt))
		if err == nil {
			t.Fatal("import accepted a both-spellings record over an identical installed snapshot")
		}
		msg := err.Error()
		if !strings.Contains(msg, `snapshot "dup"`) || !strings.Contains(msg, `"Entries"`) {
			t.Fatalf("error %q does not name the snapshot and the offending field", msg)
		}
		indexAfter, err := os.ReadFile(filepath.Join(dst, "index.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(indexAfter) != string(indexBefore) {
			t.Fatal("failed import rewrote the current mapping")
		}
		recordAfter, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(recordAfter) != string(recordBefore) {
			t.Fatal("failed import rewrote the installed snapshot record")
		}
		infos, err := New(dst).ListSnapshots()
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 1 || infos[0].Name != "dup" || infos[0].Count != 1 {
			t.Fatalf("infos=%+v, want only the pre-existing dup snapshot", infos)
		}
	})
}
