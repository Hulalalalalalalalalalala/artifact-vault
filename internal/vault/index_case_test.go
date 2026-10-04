package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEntriesFieldCaseVariantsAreCorrupt proves that a top-level field whose
// decoded name matches "entries" only case-insensitively makes the whole
// current index unreadable for every operation that depends on it. The
// variant may appear alone or beside the standard field, in either order,
// with identical or different content, empty or not — the outcome is always
// a "current index is corrupt" error naming the offending field, never a
// successful or partial result, and nothing in the repository changes:
// the index bytes, existing snapshots, all objects (including genuinely
// unreferenced ones), and existing outputs stay exactly as they were.
func TestEntriesFieldCaseVariantsAreCorrupt(t *testing.T) {
	goodDigest := digestOf("keep me")
	rec := validRecordJSON("keep.txt", goodDigest, 7)
	cases := map[string]struct {
		index     string
		wantField string
	}{
		"variant alone with records": {
			index:     `{"Entries":{"keep.txt":` + rec + `}}`,
			wantField: `"Entries"`,
		},
		"variant alone empty": {
			index:     `{"ENTRIES":{}}`,
			wantField: `"ENTRIES"`,
		},
		"empty variant after standard field": {
			index:     `{"entries":{"keep.txt":` + rec + `},"Entries":{}}`,
			wantField: `"Entries"`,
		},
		"empty variant before standard field": {
			index:     `{"Entries":{},"entries":{"keep.txt":` + rec + `}}`,
			wantField: `"Entries"`,
		},
		"identical content in both spellings": {
			index:     `{"entries":{"keep.txt":` + rec + `},"Entries":{"keep.txt":` + rec + `}}`,
			wantField: `"Entries"`,
		},
		"third casing beside standard field": {
			index:     `{"entries":{"keep.txt":` + rec + `},"ENTRIES":{}}`,
			wantField: `"ENTRIES"`,
		},
		"unicode escape decoding to a variant": {
			index:     `{"\u0045ntries":{}}`,
			wantField: `"Entries"`,
		},
		"unicode escape inside the name": {
			index:     `{"entr\u0049es":{}}`,
			wantField: `"entrIes"`,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			// A genuinely unreferenced object: even this must survive GC
			// while the index is corrupt.
			extra := []byte("extra unreferenced content")
			if _, err := store.Put("extra.txt", writeInput(t, extra)); err != nil {
				t.Fatal(err)
			}
			extraObject := objectPathOf(root, extra)

			indexPath := filepath.Join(root, "index.json")
			if err := os.WriteFile(indexPath, []byte(tc.index), 0o644); err != nil {
				t.Fatal(err)
			}
			assertCorrupt := func(op string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s succeeded over a corrupt index", op)
				}
				msg := err.Error()
				if !strings.Contains(msg, "current index is corrupt") {
					t.Fatalf("%s error %q does not identify the current index as corrupt", op, msg)
				}
				if !strings.Contains(msg, tc.wantField) {
					t.Fatalf("%s error %q does not name the offending field %s", op, msg, tc.wantField)
				}
			}

			// List: no partial artifact rows.
			entries, err := store.List()
			assertCorrupt("list", err)
			if entries != nil {
				t.Fatalf("list returned partial entries: %+v", entries)
			}

			// Verify: no usable count.
			count, err := store.Verify()
			assertCorrupt("verify", err)
			if count != 0 {
				t.Fatalf("verify returned count %d", count)
			}

			// Get: no output is created.
			output := filepath.Join(t.TempDir(), "out.bin")
			assertCorrupt("get", store.Get("keep.txt", output))
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("failed get left an output behind: %v", err)
			}

			// Put: no new object, no name record, no staged temp file.
			newContent := []byte("brand new upload")
			_, err = store.Put("new.txt", writeInput(t, newContent))
			assertCorrupt("put", err)
			if !strings.Contains(err.Error(), `cannot store "new.txt"`) {
				t.Fatalf("put error %q lost the upload context", err)
			}
			if _, err := os.Stat(objectPathOf(root, newContent)); !os.IsNotExist(err) {
				t.Fatalf("failed put installed a new object: %v", err)
			}
			assertNoPutTemps(t, root)

			// Snapshot creation: no record is left behind.
			_, err = store.CreateSnapshot("snap")
			assertCorrupt("create snapshot", err)
			if !strings.Contains(err.Error(), `cannot create snapshot "snap"`) {
				t.Fatalf("snapshot error %q lost the snapshot context", err)
			}
			if _, err := os.Stat(filepath.Join(root, "snapshots", "snap.json")); !os.IsNotExist(err) {
				t.Fatalf("failed snapshot creation left a record: %v", err)
			}

			// GC, dry run and real: both fail and delete nothing, not even
			// the genuinely unreferenced object.
			if _, err := store.GC(true); err == nil {
				t.Fatal("dry-run gc succeeded over a corrupt index")
			}
			_, gcErr := store.GC(false)
			assertCorrupt("gc", gcErr)
			if got, err := os.ReadFile(extraObject); err != nil || string(got) != string(extra) {
				t.Fatalf("gc touched the unreferenced object: content=%q err=%v", got, err)
			}

			// The corrupt index bytes are preserved exactly.
			got, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.index {
				t.Fatalf("index was rewritten\nwas: %s\nnow: %s", tc.index, got)
			}
		})
	}
}

// TestEntriesFieldExactSpellingAccepted covers the shapes that must keep
// working: the standard field written through Unicode escapes, unrelated
// extra top-level fields, and a legitimate empty mapping.
func TestEntriesFieldExactSpellingAccepted(t *testing.T) {
	goodDigest := digestOf("keep me")
	rec := validRecordJSON("keep.txt", goodDigest, 7)
	cases := map[string]struct {
		index string
		want  int
	}{
		"standard field through unicode escape": {
			index: `{"\u0065ntries":{"keep.txt":` + rec + `}}`,
			want:  1,
		},
		"unrelated extra fields ignored": {
			index: `{"meta":{"version":7},"entries":{"keep.txt":` + rec + `},"Notes":"x","ENTRIE":{}}`,
			want:  1,
		},
		"legitimate empty mapping": {
			index: `{"entries":{}}`,
			want:  0,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(tc.index), 0o644); err != nil {
				t.Fatal(err)
			}
			entries, err := store.List()
			if err != nil {
				t.Fatalf("list failed over a healthy index: %v", err)
			}
			if len(entries) != tc.want {
				t.Fatalf("entries=%+v, want %d rows", entries, tc.want)
			}
			if tc.want == 1 && entries[0].Name != "keep.txt" {
				t.Fatalf("entries=%+v", entries)
			}
		})
	}
}

// TestArtifactNamesRemainCaseSensitive proves the tightened rule applies only
// to the top-level entries field: artifact names keep their casing, including
// an artifact literally named "Entries" and names differing only by case.
func TestArtifactNamesRemainCaseSensitive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	contents := map[string][]byte{
		"Entries": []byte("capitalized payload\n"),
		"entries": []byte("lowercase payload\n"),
		"ENTRIES": []byte("shouting payload\n"),
	}
	for name, content := range contents {
		if _, err := store.Put(name, writeInput(t, content)); err != nil {
			t.Fatalf("put %q: %v", name, err)
		}
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(contents) {
		t.Fatalf("entries=%+v", entries)
	}
	for name, content := range contents {
		output := filepath.Join(t.TempDir(), "out.bin")
		if err := store.Get(name, output); err != nil {
			t.Fatalf("get %q: %v", name, err)
		}
		got, err := os.ReadFile(output)
		if err != nil || string(got) != string(content) {
			t.Fatalf("get %q: content=%q err=%v", name, got, err)
		}
	}
}

// TestRestoreSnapshotRepairsCaseVariantIndex proves snapshot recovery still
// works: a healthy snapshot replaces the corrupt current index even though
// the tightened rules make that index unreadable everywhere else.
func TestRestoreSnapshotRepairsCaseVariantIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("keep.txt", writeInput(t, []byte("keep me")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("good"); err != nil {
		t.Fatal(err)
	}
	corrupt := `{"Entries":{}}`
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(corrupt), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.List(); err == nil {
		t.Fatal("list succeeded over a corrupt index")
	}
	if err := store.RestoreSnapshot("good"); err != nil {
		t.Fatalf("restore over a corrupt current index: %v", err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" || entries[0].Digest != entry.Digest {
		t.Fatalf("entries=%+v", entries)
	}
	output := filepath.Join(t.TempDir(), "out.bin")
	if err := store.Get("keep.txt", output); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(output); err != nil || string(got) != "keep me" {
		t.Fatalf("content=%q err=%v", got, err)
	}
}
