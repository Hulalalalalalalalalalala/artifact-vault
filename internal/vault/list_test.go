package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestListHealthyMapping establishes the healthy output contract: rows sorted
// by the complete artifact name, multi-level names shown verbatim, two names
// sharing one digest each getting a row, zero-byte artifacts listed normally,
// and a genuine {"entries":{}} listing zero rows without an error.
func TestListHealthyMapping(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)

	// An initialized but empty repository: the explicit empty mapping lists
	// successfully with no rows.
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if entries, err := store.List(); err != nil || len(entries) != 0 {
		t.Fatalf("empty mapping: entries=%+v err=%v", entries, err)
	}

	zero := writeInput(t, nil)
	payload := writeInput(t, []byte("shared bytes\n"))
	other := writeInput(t, []byte("other bytes\n"))
	first, err := store.Put("z/last.bin", payload)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Put("a/first.bin", payload) // shares first's object
	if err != nil {
		t.Fatal(err)
	}
	empty, err := store.Put("m/empty.bin", zero)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("mid.bin", other); err != nil {
		t.Fatal(err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	gotNames := make([]string, 0, len(entries))
	for _, e := range entries {
		gotNames = append(gotNames, e.Name)
	}
	wantNames := []string{"a/first.bin", "m/empty.bin", "mid.bin", "z/last.bin"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("names=%v, want %v", gotNames, wantNames)
	}
	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	// The shared digest yields two independent rows.
	if second.Digest != first.Digest {
		t.Fatalf("shared uploads disagree on digest: %+v vs %+v", first, second)
	}
	if byName["a/first.bin"].Digest != first.Digest ||
		byName["z/last.bin"].Digest != first.Digest {
		t.Fatalf("shared digest not preserved: %+v", entries)
	}
	if byName["m/empty.bin"].Size != 0 || byName["m/empty.bin"].Digest != empty.Digest {
		t.Fatalf("zero-byte entry=%+v", byName["m/empty.bin"])
	}
	// Rows must be fully sorted by name even though puts were out of order.
	if !sort.StringsAreSorted(gotNames) {
		t.Fatalf("entries not sorted: %v", gotNames)
	}
}

// TestListRejectsUnusableCurrentIndex is the listing counterpart of the strict
// rules put/verify/snapshot enforce: artifact rows appear only when the whole
// mapping is complete, unambiguous, and every record is legal. Every damaged
// shape fails the whole list, returns no partial entries, names the concrete
// reason (duplicated key or offending mapping name), and leaves the index
// bytes untouched.
func TestListRejectsUnusableCurrentIndex(t *testing.T) {
	goodDigest := digestOf("keep me")
	validRecord := validRecordJSON("keep.txt", goodDigest, 7)
	// A healthy record sitting beside the damage proves no partial list is
	// returned: the good name must not show up either.
	goodRow := `"keep.txt":` + validRecord
	cases := map[string]struct {
		index       string
		wantInError string
	}{
		"bare null": {
			index:       `null`,
			wantInError: "expected a JSON object with an entries mapping",
		},
		"empty object": {
			index:       `{}`,
			wantInError: "missing entries mapping",
		},
		"null entries": {
			index:       `{"entries":null}`,
			wantInError: "missing entries mapping",
		},
		"array entries": {
			index:       `{"entries":[]}`,
			wantInError: "cannot unmarshal",
		},
		"string entries": {
			index:       `{"entries":"none"}`,
			wantInError: "cannot unmarshal",
		},
		"number entries": {
			index:       `{"entries":3}`,
			wantInError: "cannot unmarshal",
		},
		"truncated document": {
			index:       `{"entries":{`,
			wantInError: "unexpected end of JSON input",
		},
		"trailing content": {
			index:       `{"entries":{}} {}`,
			wantInError: "invalid character",
		},
		"top level array": {
			index:       `[]`,
			wantInError: "expected a JSON object with an entries mapping",
		},
		"duplicate entries field": {
			index:       `{"entries":null,"entries":{}}`,
			wantInError: `duplicate key "entries"`,
		},
		"duplicate artifact name": {
			index:       `{"entries":{` + goodRow + `,"keep.txt":` + validRecord + `}}`,
			wantInError: `duplicate key "keep.txt"`,
		},
		"same name through unicode escape": {
			index: `{"entries":{` +
				`"a/b":{"name":"a/b","digest":"` + goodDigest + `","size":7,"createdAt":"2026-01-01T00:00:00Z"},` +
				`"a` + `\` + `u002fb":{"name":"a/b","digest":"` + goodDigest + `","size":7,"createdAt":"2026-01-01T00:00:00Z"}` +
				`}}`,
			wantInError: `duplicate key "a/b"`,
		},
		"duplicate field inside record": {
			index: `{"entries":{"keep.txt":{"name":"keep.txt","digest":"` + goodDigest +
				`","size":7,"size":8,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `duplicate key "size"`,
		},
		"good row beside a key mismatch": {
			index: `{"entries":{` + goodRow + `,` +
				`"other.txt":{"name":"wrong.txt","digest":"` + goodDigest +
				`","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `entry "wrong.txt" is filed under "other.txt"`,
		},
		"good row beside an illegal name": {
			index: `{"entries":{` + goodRow + `,` +
				`"../evil":{"name":"../evil","digest":"` + goodDigest +
				`","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `invalid entry name "../evil"`,
		},
		"good row beside a bad digest": {
			index: `{"entries":{` + goodRow + `,` +
				`"other.txt":{"name":"other.txt","digest":"XYZ","size":7,` +
				`"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "want 64 lowercase hex characters",
		},
		"good row beside a negative size": {
			index: `{"entries":{` + goodRow + `,` +
				`"other.txt":{"name":"other.txt","digest":"` + goodDigest +
				`","size":-9,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "negative size",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			indexPath := filepath.Join(root, "index.json")
			if err := os.WriteFile(indexPath, []byte(tc.index), 0o644); err != nil {
				t.Fatal(err)
			}

			entries, err := store.List()
			if err == nil {
				t.Fatal("expected list over a corrupt index to fail")
			}
			if entries != nil {
				t.Fatalf("failed list returned usable partial entries: %+v", entries)
			}
			msg := err.Error()
			if !strings.Contains(msg, "current index is corrupt") {
				t.Fatalf("error %q does not identify the current index as corrupt", msg)
			}
			if !strings.Contains(msg, tc.wantInError) {
				t.Fatalf("error %q does not indicate %q", msg, tc.wantInError)
			}

			// Listing never repairs or rewrites the damaged bytes.
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

// TestListReportsFirstBadRecordDeterministically names the alphabetically
// first offending mapping name when several records are bad.
func TestListReportsFirstBadRecordDeterministically(t *testing.T) {
	goodDigest := digestOf("good")
	index := `{"entries":{` +
		`"zeta":{"name":"zeta","digest":"nope","size":0,"createdAt":"2026-01-01T00:00:00Z"},` +
		`"alpha":{"name":"alpha","digest":"` + goodDigest + `","size":-3,"createdAt":"2026-01-01T00:00:00Z"}` +
		`}}`
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err == nil {
		t.Fatal("expected list to fail")
	}
	if entries != nil {
		t.Fatalf("partial list returned: %+v", entries)
	}
	if !strings.Contains(err.Error(), `entry "alpha"`) {
		t.Fatalf("error %q does not name the alphabetically first bad record alpha", err)
	}
}

// TestListMissingRepositoryReportsUninitialized distinguishes a repository
// that was never initialized from an empty list: both a missing root and a
// directory with no index.json fail rather than listing zero artifacts.
func TestListMissingRepositoryReportsUninitialized(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-vault")
	if entries, err := New(missing).List(); err == nil {
		t.Fatalf("missing root listed %+v instead of failing", entries)
	} else if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("error %q does not report the repository as uninitialized", err)
	}

	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Directory present with a lock file but no index.json: still not
	// initialized, never an empty list.
	if entries, err := store.List(); err == nil {
		t.Fatalf("missing index.json listed %+v instead of failing", entries)
	} else if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("error %q does not report the repository as uninitialized", err)
	}
}

// TestListUnreadableIndexNotCorrupt distinguishes bytes that cannot be read
// from bytes that are present but malformed.
func TestListUnreadableIndexNotCorrupt(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission-based unreadability cannot be tested as root")
	}
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.json")
	if err := os.Chmod(indexPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(indexPath, 0o644) })

	entries, err := store.List()
	if err == nil {
		t.Fatal("expected list over an unreadable index to fail")
	}
	if entries != nil {
		t.Fatalf("unreadable index returned entries: %+v", entries)
	}
	msg := err.Error()
	if !strings.Contains(msg, "current index cannot be read") {
		t.Fatalf("error %q does not say the index cannot be read", msg)
	}
	if strings.Contains(msg, "corrupt") {
		t.Fatalf("an unreadable index must not be called corrupt: %q", msg)
	}
}

// TestListIgnoresObjectsAndSnapshots proves list reads only the current
// mapping: a missing or content-damaged object and a damaged snapshot record
// never block the legal current records, and listing changes nothing.
func TestListIgnoresObjectsAndSnapshots(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("keep.txt", writeInput(t, []byte("real bytes\n")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	indexBefore, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Remove the referenced object: the row must still list.
	object := filepath.Join(root, "objects", entry.Digest)
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if entries, err := store.List(); err != nil || len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("missing object blocked listing: entries=%+v err=%v", entries, err)
	}

	// Restore a same-size, wrong-content object: listing still does not read it.
	if err := os.WriteFile(object, []byte("different bytes!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if entries, err := store.List(); err != nil || len(entries) != 1 {
		t.Fatalf("damaged object blocked listing: entries=%+v err=%v", entries, err)
	}

	// Damage a snapshot record: current mapping lists unaffected.
	if err := os.WriteFile(filepath.Join(root, "snapshots", "snap.json"),
		[]byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if entries, err := store.List(); err != nil || len(entries) != 1 || entries[0].Digest != entry.Digest {
		t.Fatalf("damaged snapshot blocked listing: entries=%+v err=%v", entries, err)
	}

	// The current index bytes are untouched by the repeated lists.
	indexAfter, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(indexAfter, indexBefore) {
		t.Fatalf("list rewrote the index:\nwas: %s\nnow: %s", indexBefore, indexAfter)
	}
}
