package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCaseVariantEntriesFieldIsCorruption pins the exact-spelling rule for
// the current index's top-level entries field: a field that differs from
// "entries" only by letter case makes the whole index corrupt — alone or
// beside the standard field, in either order, empty or not, identical
// content or not, written directly or through Unicode escapes. Every
// operation that depends on the current mapping must fail naming the corrupt
// index and the offending field, return no partial result, and leave the
// index bytes, snapshots, and all objects (referenced, stray, and staged)
// untouched; a healthy snapshot must still restore over the corrupt index.
func TestCaseVariantEntriesFieldIsCorruption(t *testing.T) {
	goodDigest := digestOf("good")
	rec := `"keep.txt":{"name":"keep.txt","digest":"` + goodDigest + `","size":4,"createdAt":"2026-01-01T00:00:00Z"}`
	cases := map[string]struct {
		index string
		field string // the decoded offending field the error must name
	}{
		"variant alone empty":         {`{"Entries":{}}`, "Entries"},
		"variant alone with records":  {`{"ENTRIES":{` + rec + `}}`, "ENTRIES"},
		"standard then empty variant": {`{"entries":{` + rec + `},"Entries":{}}`, "Entries"},
		"empty variant then standard": {`{"Entries":{},"entries":{` + rec + `}}`, "Entries"},
		"identical mappings both":     {`{"entries":{` + rec + `},"Entries":{` + rec + `}}`, "Entries"},
		"mixed case variant":          {`{"eNtRiEs":{}}`, "eNtRiEs"},
		"unicode escaped variant":     {`{"\u0045ntries":{}}`, "Entries"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			keep, err := store.Put("keep.txt", writeInput(t, []byte("keep me")))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateSnapshot("snap"); err != nil {
				t.Fatal(err)
			}
			// A truly unreferenced object: even this must survive a failed GC.
			stray := digestOf("stray")
			if err := os.WriteFile(filepath.Join(root, "objects", stray), []byte("stray"), 0o644); err != nil {
				t.Fatal(err)
			}
			indexPath := filepath.Join(root, "index.json")
			if err := os.WriteFile(indexPath, []byte(tc.index), 0o644); err != nil {
				t.Fatal(err)
			}
			snapBefore, err := os.ReadFile(filepath.Join(root, "snapshots", "snap.json"))
			if err != nil {
				t.Fatal(err)
			}

			// Every dependent operation fails, naming the corrupt current
			// index and the offending field.
			assertCorrupt := func(op string, err error) {
				t.Helper()
				if err == nil {
					t.Fatalf("%s: expected an error", op)
				}
				if !strings.Contains(err.Error(), "current index is corrupt") {
					t.Fatalf("%s: error does not report the current index as corrupt: %v", op, err)
				}
				if !strings.Contains(err.Error(), `"`+tc.field+`"`) {
					t.Fatalf("%s: error does not name the offending field %q: %v", op, tc.field, err)
				}
			}

			entries, listErr := store.List()
			assertCorrupt("list", listErr)
			if entries != nil {
				t.Fatalf("list returned a partial result: %v", entries)
			}

			newContent := []byte("brand new upload")
			newDigest := digestOf(string(newContent))
			_, putErr := store.Put("new.txt", writeInput(t, newContent))
			assertCorrupt("put", putErr)
			if !strings.Contains(putErr.Error(), `cannot store "new.txt"`) {
				t.Fatalf("put error does not name the upload: %v", putErr)
			}
			if objectExists(root, newDigest) {
				t.Fatal("failed put installed a new object")
			}
			if temps := uploadTemps(t, root); len(temps) != 0 {
				t.Fatalf("failed put left a staged upload behind: %v", temps)
			}

			// A missing output stays missing; an existing output is untouched.
			freshOut := filepath.Join(t.TempDir(), "out.bin")
			assertCorrupt("get", store.Get("keep.txt", freshOut))
			if _, err := os.Lstat(freshOut); !os.IsNotExist(err) {
				t.Fatalf("failed get created an output: %v", err)
			}
			existingOut := writeInput(t, []byte("original output"))
			assertCorrupt("get over existing", store.Get("keep.txt", existingOut))
			if got, _ := os.ReadFile(existingOut); string(got) != "original output" {
				t.Fatalf("failed get rewrote the existing output: %q", got)
			}

			count, verifyErr := store.Verify()
			assertCorrupt("verify", verifyErr)
			if count != 0 {
				t.Fatalf("verify returned a partial count: %d", count)
			}

			for _, dryRun := range []bool{true, false} {
				report, gcErr := store.GC(dryRun)
				assertCorrupt("gc", gcErr)
				if report.Deleted != 0 || report.Bytes != 0 {
					t.Fatalf("gc deleted during a failed pass: %+v", report)
				}
			}
			if !objectExists(root, stray) {
				t.Fatal("failed gc deleted an unreferenced object")
			}
			if !objectExists(root, keep.Digest) {
				t.Fatal("failed gc deleted a referenced object")
			}

			_, snapErr := store.CreateSnapshot("new")
			assertCorrupt("create snapshot", snapErr)
			if _, err := os.Lstat(filepath.Join(root, "snapshots", "new.json")); !os.IsNotExist(err) {
				t.Fatalf("failed snapshot create left a record behind: %v", err)
			}

			// The original index bytes, the existing snapshot, and the object
			// content are all preserved.
			indexAfter, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(indexAfter) != tc.index {
				t.Fatalf("corrupt index was rewritten\nwas: %s\nnow: %s", tc.index, indexAfter)
			}
			snapAfter, err := os.ReadFile(filepath.Join(root, "snapshots", "snap.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(snapAfter) != string(snapBefore) {
				t.Fatal("existing snapshot record changed")
			}
			if got, _ := os.ReadFile(filepath.Join(root, "objects", keep.Digest)); string(got) != "keep me" {
				t.Fatalf("object content changed: %q", got)
			}

			// A healthy snapshot still replaces the corrupt current index.
			if err := store.RestoreSnapshot("snap"); err != nil {
				t.Fatalf("restore over a corrupt index failed: %v", err)
			}
			restored, err := store.List()
			if err != nil {
				t.Fatal(err)
			}
			if len(restored) != 1 || restored[0].Name != "keep.txt" {
				t.Fatalf("restored mapping=%v", restored)
			}
		})
	}
}

// TestEscapedStandardEntriesFieldIsValid confirms the field name is judged by
// the letters it decodes to: a standard lowercase "entries" written through
// Unicode escapes is the real entries mapping, not a case variant.
func TestEscapedStandardEntriesFieldIsValid(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	escaped := strings.Replace(string(data), `"entries"`, `"\u0065ntries"`, 1)
	if escaped == string(data) {
		t.Fatal("test setup did not rewrite the entries field")
	}
	if err := os.WriteFile(indexPath, []byte(escaped), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("escaped standard entries field rejected: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("entries=%v", entries)
	}
}

// TestUnrelatedTopLevelFieldsStillIgnored confirms the exact-spelling rule
// does not turn unrelated extra top-level fields into the current mapping:
// they are ignored exactly as before.
func TestUnrelatedTopLevelFieldsStillIgnored(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	extra := `{"meta":{"note":"unrelated"},"version":2,` + string(data[1:])
	if err := os.WriteFile(indexPath, []byte(extra), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatalf("unrelated top-level fields rejected: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("entries=%v", entries)
	}
}

// TestArtifactNamesStayCaseSensitive confirms the exact-spelling rule only
// restricts the top-level mapping field: artifact names remain
// case-sensitive, so an artifact named "Entries" and a pair of names
// differing only by case all store, list, and download normally.
func TestArtifactNamesStayCaseSensitive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	for name, content := range map[string]string{
		"Entries":  "uppercase artifact\n",
		"entries":  "lowercase artifact\n",
		"ENTRIES":  "all-caps artifact\n",
		"dir/Entr": "nested artifact\n",
	} {
		if _, err := store.Put(name, writeInput(t, []byte(content))); err != nil {
			t.Fatalf("put %q: %v", name, err)
		}
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("entries=%v", entries)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := store.Get("Entries", out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "uppercase artifact\n" {
		t.Fatalf("Entries content=%q", got)
	}
	if err := store.Get("entries", out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); string(got) != "lowercase artifact\n" {
		t.Fatalf("entries content=%q", got)
	}
	if count, err := store.Verify(); err != nil || count != 4 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}
