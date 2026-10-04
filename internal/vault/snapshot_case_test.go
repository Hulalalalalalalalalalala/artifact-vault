package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSnapshotRecordEntriesCaseVariantsAreCorrupt proves that a saved snapshot
// record whose top-level entries field is spelled with any casing other than
// exactly "entries" is corruption for every operation that reads saved
// snapshots. The variant may appear alone or beside the standard field, in
// either order, with identical or different content, empty or not — the
// outcome is always a "snapshot <full name> is corrupted" error naming the
// offending field, never a successful or partial result, and nothing in the
// repository changes: the current mapping, the corrupt record's bytes, all
// objects (including genuinely unreferenced ones), and existing outputs stay
// exactly as they were.
func TestSnapshotRecordEntriesCaseVariantsAreCorrupt(t *testing.T) {
	goodDigest := digestOf("keep me")
	rec := validRecordJSON("keep.txt", goodDigest, 7)
	cases := map[string]struct {
		fields    string // top-level fields following the name field
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
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateSnapshot("good"); err != nil {
				t.Fatal(err)
			}
			// A genuinely unreferenced object: even this must survive GC
			// while a corrupt snapshot record exists.
			extra := []byte("extra unreferenced content")
			if _, err := store.Put("extra.txt", writeInput(t, extra)); err != nil {
				t.Fatal(err)
			}
			extraObject := objectPathOf(root, extra)
			if err := store.RestoreSnapshot("good"); err != nil {
				t.Fatal(err)
			}

			record := `{"name":"releases/corrupt",` + tc.fields + `}`
			recordPath := filepath.Join(root, "snapshots", "releases", "corrupt.json")
			if err := os.MkdirAll(filepath.Dir(recordPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, []byte(record), 0o644); err != nil {
				t.Fatal(err)
			}
			assertCorrupt := func(op string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s succeeded over a corrupt snapshot record", op)
				}
				msg := err.Error()
				if !strings.Contains(msg, `snapshot "releases/corrupt" is corrupted`) {
					t.Fatalf("%s error %q does not identify the corrupt snapshot by its full name", op, msg)
				}
				if !strings.Contains(msg, tc.wantField) {
					t.Fatalf("%s error %q does not name the offending field %s", op, msg, tc.wantField)
				}
			}

			// Restore: fails and the current mapping is unchanged.
			assertCorrupt("restore", store.RestoreSnapshot("releases/corrupt"))
			entries, err := store.List()
			if err != nil || len(entries) != 1 || entries[0].Name != "keep.txt" {
				t.Fatalf("failed restore changed the current mapping: entries=%+v err=%v", entries, err)
			}

			// List: fails with no partial snapshot list.
			infos, err := store.ListSnapshots()
			assertCorrupt("list snapshots", err)
			if infos != nil {
				t.Fatalf("list returned partial snapshots: %+v", infos)
			}

			// Export: fails and creates no package.
			output := filepath.Join(t.TempDir(), "pkg.json")
			_, err = store.ExportSnapshot("releases/corrupt", "", output)
			assertCorrupt("export", err)
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("failed export created a package: %v", err)
			}

			// Export over an existing output: content and permissions stay
			// exactly as they were.
			existing := filepath.Join(t.TempDir(), "existing.json")
			if err := os.WriteFile(existing, []byte("previous output"), 0o640); err != nil {
				t.Fatal(err)
			}
			_, err = store.ExportSnapshot("releases/corrupt", "", existing)
			assertCorrupt("export over existing output", err)
			got, err := os.ReadFile(existing)
			if err != nil || string(got) != "previous output" {
				t.Fatalf("failed export altered the existing output: content=%q err=%v", got, err)
			}
			if info, err := os.Stat(existing); err != nil || info.Mode().Perm() != 0o640 {
				t.Fatalf("failed export changed the existing output's permissions: mode=%v err=%v", info.Mode(), err)
			}

			// Incremental export using the corrupt snapshot as its base fails
			// and creates no package either.
			deltaOut := filepath.Join(t.TempDir(), "delta.json")
			_, err = store.ExportSnapshot("good", "releases/corrupt", deltaOut)
			assertCorrupt("incremental export", err)
			if _, err := os.Stat(deltaOut); !os.IsNotExist(err) {
				t.Fatalf("failed incremental export created a package: %v", err)
			}

			// GC, dry run and real: both fail before deleting anything, not
			// even the genuinely unreferenced object.
			_, err = store.GC(true)
			assertCorrupt("dry-run gc", err)
			_, err = store.GC(false)
			assertCorrupt("gc", err)
			if got, err := os.ReadFile(extraObject); err != nil || string(got) != string(extra) {
				t.Fatalf("gc touched the unreferenced object: content=%q err=%v", got, err)
			}

			// The corrupt record bytes are preserved exactly.
			got, err = os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != record {
				t.Fatalf("snapshot record was rewritten\nwas: %s\nnow: %s", record, got)
			}
		})
	}
}

// TestSnapshotRecordExactSpellingAccepted covers the snapshot records that
// must keep working: the standard field written through Unicode escapes, an
// explicitly empty entries mapping, and artifact names that merely resemble
// the field name — the rule applies only to the top-level mapping field.
func TestSnapshotRecordExactSpellingAccepted(t *testing.T) {
	goodDigest := digestOf("keep me")
	rec := validRecordJSON("keep.txt", goodDigest, 7)
	cases := map[string]struct {
		record string
		want   int
	}{
		"standard field through unicode escape": {
			record: `{"name":"releases/ok","\u0065ntries":{"keep.txt":` + rec + `}}`,
			want:   1,
		},
		"legitimate empty mapping": {
			record: `{"name":"releases/ok","entries":{}}`,
			want:   0,
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			recordPath := filepath.Join(root, "snapshots", "releases", "ok.json")
			if err := os.MkdirAll(filepath.Dir(recordPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, []byte(tc.record), 0o644); err != nil {
				t.Fatal(err)
			}
			infos, err := store.ListSnapshots()
			if err != nil {
				t.Fatalf("list failed over a healthy snapshot record: %v", err)
			}
			if len(infos) != 1 || infos[0].Name != "releases/ok" || infos[0].Count != tc.want {
				t.Fatalf("infos=%+v, want one releases/ok snapshot with %d entries", infos, tc.want)
			}
			if err := store.RestoreSnapshot("releases/ok"); err != nil {
				t.Fatalf("restore failed over a healthy snapshot record: %v", err)
			}
			entries, err := store.List()
			if err != nil {
				t.Fatal(err)
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

// TestSnapshotArtifactNamesRemainCaseSensitive proves the tightened rule
// applies only to the top-level entries field of a snapshot record: artifact
// names keep their casing, including an artifact literally named "Entries"
// and names differing only by case, and snapshots recording them list,
// restore, and export normally.
func TestSnapshotArtifactNamesRemainCaseSensitive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	contents := map[string][]byte{
		"Entries": []byte("capitalized payload\n"),
		"App.bin": []byte("upper app payload\n"),
		"app.bin": []byte("lower app payload\n"),
	}
	for name, content := range contents {
		if _, err := store.Put(name, writeInput(t, content)); err != nil {
			t.Fatalf("put %q: %v", name, err)
		}
	}
	if _, err := store.CreateSnapshot("casey"); err != nil {
		t.Fatal(err)
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "casey" || infos[0].Count != len(contents) {
		t.Fatalf("infos=%+v, want one casey snapshot with %d entries", infos, len(contents))
	}
	output := filepath.Join(t.TempDir(), "pkg.json")
	result, err := store.ExportSnapshot("casey", "", output)
	if err != nil {
		t.Fatalf("export failed over case-sensitive artifact names: %v", err)
	}
	if result.Entries != len(contents) {
		t.Fatalf("export result=%+v, want %d entries", result, len(contents))
	}
	if err := store.RestoreSnapshot("casey"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(contents) {
		t.Fatalf("entries=%+v", entries)
	}
	for name, content := range contents {
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := store.Get(name, out); err != nil {
			t.Fatalf("get %q: %v", name, err)
		}
		got, err := os.ReadFile(out)
		if err != nil || string(got) != string(content) {
			t.Fatalf("get %q: content=%q err=%v", name, got, err)
		}
	}
}
