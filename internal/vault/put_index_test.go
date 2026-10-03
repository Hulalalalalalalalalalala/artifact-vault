package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// corruptIndexCases are the same structural and record-level rules verify, gc,
// and snapshot creation apply to the current index. A put must enforce every
// one of them for both a brand-new name and an overwrite, even when the bad
// record has nothing to do with the name being uploaded.
func corruptIndexCases(goodDigest, validEntry string) map[string]struct {
	index       string
	wantInError string
} {
	return map[string]struct {
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
			index:       `{"entries":{"other.txt":` + validEntry + `,"other.txt":` + validEntry + `}}`,
			wantInError: `duplicate key "other.txt"`,
		},
		"same name through unicode escape": {
			index: `{"entries":{` +
				`"a/b.txt":{"name":"a/b.txt","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"},` +
				`"a` + `\` + `u002fb.txt":{"name":"a/b.txt","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}` +
				`}}`,
			wantInError: `duplicate key "a/b.txt"`,
		},
		"duplicate field inside entry": {
			index:       `{"entries":{"other.txt":{"name":"other.txt","digest":"` + goodDigest + `","size":0,"size":1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `duplicate key "size"`,
		},
		"entry key mismatch": {
			index:       `{"entries":{"other.txt":{"name":"elsewhere.txt","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `is filed under`,
		},
		"entry illegal name": {
			index:       `{"entries":{"../evil":{"name":"../evil","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `invalid entry name`,
		},
		"entry bad digest": {
			index:       `{"entries":{"other.txt":{"name":"other.txt","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "want 64 lowercase hex characters",
		},
		"entry negative size": {
			index:       `{"entries":{"other.txt":{"name":"other.txt","digest":"` + goodDigest + `","size":-7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "negative size",
		},
		// A bad record sitting next to a valid record for a name unrelated to
		// this upload still rejects the whole upload.
		"unrelated bad record next to valid one": {
			index: `{"entries":{` +
				`"keep.txt":{"name":"keep.txt","digest":"` + goodDigest + `","size":7,"createdAt":"2026-01-01T00:00:00Z"},` +
				`"other.txt":{"name":"other.txt","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}` +
				`}}`,
			wantInError: "want 64 lowercase hex characters",
		},
	}
}

// TestPutRejectsCorruptCurrentIndex is the upload-time counterpart of the
// strict index rules verify, gc, and snapshot creation enforce. Neither a new
// name nor an overwrite may be saved against a mapping that is not itself
// complete and valid: corruption must never be rewritten into a seemingly
// successful put. The error names the upload and the current index (with the
// duplicated key or offending artifact in the underlying reason), the API
// returns no usable entry, the corrupt index bytes, every snapshot, and every
// existing object are left untouched, and no object for the upload or staging
// temporary file appears.
func TestPutRejectsCorruptCurrentIndex(t *testing.T) {
	goodDigest := hex.EncodeToString(sha256.New().Sum(nil))
	validEntry := `{"name":"other.txt","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}`
	cases := corruptIndexCases(goodDigest, validEntry)
	for _, uploadName := range []string{"new.txt", "keep.txt"} {
		for label, tc := range cases {
			t.Run(uploadName+"/"+label, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "vault")
				store := New(root)
				keep, err := store.Put("keep.txt", writeInput(t, []byte("keep me")))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.CreateSnapshot("keep"); err != nil {
					t.Fatal(err)
				}
				stray := hex.EncodeToString(sha256.New().Sum([]byte("stray")))
				if err := os.WriteFile(filepath.Join(root, "objects", stray), []byte("stray"), 0o644); err != nil {
					t.Fatal(err)
				}

				indexPath := filepath.Join(root, "index.json")
				if err := os.WriteFile(indexPath, []byte(tc.index), 0o644); err != nil {
					t.Fatal(err)
				}
				snapshotBytes, err := os.ReadFile(filepath.Join(root, "snapshots", "keep.json"))
				if err != nil {
					t.Fatal(err)
				}

				content := []byte("fresh upload payload\n")
				entry, err := store.Put(uploadName, writeInput(t, content))
				if err == nil {
					t.Fatal("expected put to be rejected")
				}
				if !reflect.DeepEqual(entry, Entry{}) {
					t.Fatalf("failed put returned a usable entry: %+v", entry)
				}
				msg := err.Error()
				if !strings.Contains(msg, `cannot store "`+uploadName+`"`) {
					t.Fatalf("error %q does not name the upload", msg)
				}
				if !strings.Contains(msg, "current index") {
					t.Fatalf("error %q does not identify the current index as the cause", msg)
				}
				if !strings.Contains(msg, tc.wantInError) {
					t.Fatalf("error %q does not indicate %q", msg, tc.wantInError)
				}

				// The corrupt index keeps its exact bytes.
				gotIndex, err := os.ReadFile(indexPath)
				if err != nil {
					t.Fatal(err)
				}
				if string(gotIndex) != tc.index {
					t.Fatalf("index was rewritten\nwas: %s\nnow: %s", tc.index, gotIndex)
				}
				// The existing snapshot record is byte-for-byte unchanged.
				gotSnapshot, err := os.ReadFile(filepath.Join(root, "snapshots", "keep.json"))
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(gotSnapshot, snapshotBytes) {
					t.Fatal("existing snapshot record was rewritten")
				}
				infos, err := New(root).ListSnapshots()
				if err != nil {
					t.Fatal(err)
				}
				if len(infos) != 1 || infos[0].Name != "keep" {
					t.Fatalf("failed put changed the snapshot set: %+v", infos)
				}
				// No content object was installed for this upload, and every
				// pre-existing object survives.
				if _, err := os.Stat(objectPathOf(root, content)); !os.IsNotExist(err) {
					t.Fatalf("upload object appeared despite failure: %v", err)
				}
				for _, path := range []string{
					filepath.Join(root, "objects", keep.Digest),
					filepath.Join(root, "objects", stray),
				} {
					if _, err := os.Stat(path); err != nil {
						t.Fatalf("object %s disappeared: %v", path, err)
					}
				}
				// No staging or index temporary files remain.
				if temps := uploadTemps(t, root); len(temps) != 0 {
					t.Fatalf("staged upload left behind: %v", temps)
				}
				matches, err := filepath.Glob(filepath.Join(root, ".index-*"))
				if err != nil {
					t.Fatal(err)
				}
				if len(matches) != 0 {
					t.Fatalf("index temporary file left behind: %v", matches)
				}
			})
		}
	}
}

// TestPutRejectsUnreadableCurrentIndex distinguishes an index that cannot be
// read at all from a missing or unreadable input file: the error still names
// the upload and the current index, and nothing is staged.
func TestPutRejectsUnreadableCurrentIndex(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not block root")
	}
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	keep, err := store.Put("keep.txt", writeInput(t, []byte("keep me")))
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.json")
	if err := os.Chmod(indexPath, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(indexPath, 0o644)

	entry, err := store.Put("new.txt", writeInput(t, []byte("readable input\n")))
	if err == nil {
		t.Fatal("expected put against an unreadable index to fail")
	}
	if !reflect.DeepEqual(entry, Entry{}) {
		t.Fatalf("failed put returned a usable entry: %+v", entry)
	}
	msg := err.Error()
	if !strings.Contains(msg, `cannot store "new.txt"`) || !strings.Contains(msg, "current index") {
		t.Fatalf("error %q must name the upload and the index", msg)
	}
	if temps := uploadTemps(t, root); len(temps) != 0 {
		t.Fatalf("staged upload left behind: %v", temps)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", keep.Digest)); err != nil {
		t.Fatalf("existing object disappeared: %v", err)
	}
}

// TestPutMissingInputStaysDistinctFromIndexFailure makes sure a readable,
// valid index plus an unreadable input reports the input failure rather than
// index corruption, and leaves the mapping in place.
func TestPutMissingInputStaysDistinctFromIndexFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	_, err := store.Put("new.txt", missing)
	if err == nil {
		t.Fatal("expected put of a missing input to fail")
	}
	if strings.Contains(err.Error(), "current index") {
		t.Fatalf("input failure was reported as index corruption: %v", err)
	}
	if len(entriesOf(t, store)) != 1 {
		t.Fatalf("mapping changed after an input failure: %v", entriesOf(t, store))
	}
}

// TestPutEmptyMappingAcceptsUploads keeps first-upload behavior: a genuine
// {"entries":{}} mapping is a legitimate empty repository that receives both
// an empty file and an ordinary file.
func TestPutEmptyMappingAcceptsUploads(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	empty, err := store.Put("empty/one", writeInput(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	normal, err := store.Put("normal/one", writeInput(t, []byte("ordinary bytes\n")))
	if err != nil {
		t.Fatal(err)
	}
	entries := entriesOf(t, store)
	if len(entries) != 2 || entries["empty/one"].Digest != empty.Digest || entries["normal/one"].Digest != normal.Digest {
		t.Fatalf("entries=%v", entries)
	}
	if _, err := os.Stat(objectPathOf(root, nil)); err != nil {
		t.Fatalf("empty object missing: %v", err)
	}
	if _, err := os.Stat(objectPathOf(root, []byte("ordinary bytes\n"))); err != nil {
		t.Fatalf("normal object missing: %v", err)
	}
}

// TestPutOverwriteOnlyChangesOverwrittenRecord confirms that overwriting one
// name leaves every other record's digest, size, and creation time exactly in
// place (and never deletes the displaced object).
func TestPutOverwriteOnlyChangesOverwrittenRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	firstA, err := store.Put("a.txt", writeInput(t, []byte("a first version")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.Put("b.txt", writeInput(t, []byte("b stays put")))
	if err != nil {
		t.Fatal(err)
	}
	newA, err := store.Put("a.txt", writeInput(t, []byte("a second version")))
	if err != nil {
		t.Fatal(err)
	}
	if newA.Digest == firstA.Digest {
		t.Fatal("overwrite did not change the digest")
	}
	entries := entriesOf(t, store)
	if len(entries) != 2 {
		t.Fatalf("entries=%v", entries)
	}
	if entries["b.txt"] != b {
		t.Fatalf("other record changed: %+v -> %+v", b, entries["b.txt"])
	}
	if entries["a.txt"] != newA {
		t.Fatalf("overwritten record mismatch: %+v -> %+v", newA, entries["a.txt"])
	}
	// The displaced object is left on disk; put never collects it.
	if _, err := os.Stat(filepath.Join(root, "objects", firstA.Digest)); err != nil {
		t.Fatalf("displaced object removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", b.Digest)); err != nil {
		t.Fatalf("shared/unrelated object removed: %v", err)
	}
}
