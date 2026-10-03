package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// validRecordJSON renders one well-formed index entry record for the given
// key/digest/size. Tests splice these into index documents and then damage one
// field at a time.
func validRecordJSON(name, digest string, size int) string {
	return fmt.Sprintf(`{"name":%q,"digest":%q,"size":%d,"createdAt":"2026-01-01T00:00:00Z"}`,
		name, digest, size)
}

// objectNames returns every entry name directly inside the objects directory,
// sorted. It is the complete on-disk content-object set.
func objectNames(t *testing.T, root string) []string {
	t.Helper()
	dirents, err := os.ReadDir(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(dirents))
	for _, d := range dirents {
		names = append(names, d.Name())
	}
	sort.Strings(names)
	return names
}

// assertNoPutTemps fails if a put left a staged or index temporary file
// anywhere in the repository.
func assertNoPutTemps(t *testing.T, root string) {
	t.Helper()
	for _, pattern := range []string{
		filepath.Join(root, "objects", ".upload-*"),
		filepath.Join(root, ".index-*"),
	} {
		if matches, err := filepath.Glob(pattern); err != nil {
			t.Fatal(err)
		} else if len(matches) != 0 {
			t.Fatalf("temporary files left behind: %v", matches)
		}
	}
}

// TestPutRejectsUnusableCurrentIndex is the upload counterpart of the strict
// index rules verify and snapshot creation enforce: a put must never turn a
// damaged current mapping into a seemingly successful upload. Every malformed
// shape fails the whole upload, names the upload and the index problem,
// returns no usable entry, and leaves the index bytes, every object, and every
// snapshot byte-for-byte untouched with no staged temporary file.
func TestPutRejectsUnusableCurrentIndex(t *testing.T) {
	goodDigest := digestOf("keep me")
	validRecord := validRecordJSON("keep.txt", goodDigest, 7)
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
			index:       `{"entries":{"keep.txt":` + validRecord + `,"keep.txt":` + validRecord + `}}`,
			wantInError: `duplicate key "keep.txt"`,
		},
		"same name through unicode escape": {
			// The second key spells the same name with a JSON Unicode escape
			// for the slash; the standalone raw string contributes the
			// literal escape byte, and the JSON decoder turns it into "/".
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
		"unrelated entry key mismatch": {
			index: `{"entries":{"other.txt":{"name":"wrong.txt","digest":"` + goodDigest +
				`","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `entry "wrong.txt" is filed under "other.txt"`,
		},
		"unrelated entry illegal name": {
			index: `{"entries":{"../evil":{"name":"../evil","digest":"` + goodDigest +
				`","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `invalid entry name "../evil"`,
		},
		"unrelated entry bad digest": {
			index: `{"entries":{"other.txt":{"name":"other.txt","digest":"XYZ","size":7,` +
				`"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "want 64 lowercase hex characters",
		},
		"unrelated entry negative size": {
			index: `{"entries":{"other.txt":{"name":"other.txt","digest":"` + goodDigest +
				`","size":-9,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "negative size",
		},
		"overwritten name record itself corrupt": {
			index: `{"entries":{"new/name.bin":{"name":"new/name.bin","digest":"XYZ","size":7,` +
				`"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "want 64 lowercase hex characters",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			keep, err := store.Put("keep.txt", writeFile(t, "keep me"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateSnapshot("keep"); err != nil {
				t.Fatal(err)
			}
			// An object the damaged mapping does not reference; it must survive
			// the rejected upload too.
			stray := digestOf("stray")
			if err := os.WriteFile(filepath.Join(root, "objects", stray), []byte("stray"), 0o644); err != nil {
				t.Fatal(err)
			}

			indexPath := filepath.Join(root, "index.json")
			if err := os.WriteFile(indexPath, []byte(tc.index), 0o644); err != nil {
				t.Fatal(err)
			}
			snapshotBefore, err := os.ReadFile(filepath.Join(root, "snapshots", "keep.json"))
			if err != nil {
				t.Fatal(err)
			}
			objectsBefore := objectNames(t, root)
			// The uploaded digest must not appear even though the content is new.
			uploadDigest := digestOf("brand new upload bytes")

			entry, err := store.Put("new/name.bin", writeInput(t, []byte("brand new upload bytes")))
			if err == nil {
				t.Fatal("expected put over a corrupt index to fail")
			}
			if !reflect.DeepEqual(entry, Entry{}) {
				t.Fatalf("failed put returned a usable entry: %+v", entry)
			}
			msg := err.Error()
			if !strings.Contains(msg, `cannot store "new/name.bin"`) {
				t.Fatalf("error %q does not name the upload", msg)
			}
			if !strings.Contains(msg, "current index is corrupt") {
				t.Fatalf("error %q does not identify the current index as corrupt", msg)
			}
			if !strings.Contains(msg, tc.wantInError) {
				t.Fatalf("error %q does not indicate %q", msg, tc.wantInError)
			}
			// An index failure must not be reported as an input or object
			// problem.
			if strings.Contains(msg, "input file") {
				t.Fatalf("index corruption was reported as an input failure: %q", msg)
			}

			// The corrupt index bytes survive verbatim.
			gotIndex, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotIndex) != tc.index {
				t.Fatalf("index was rewritten\nwas: %s\nnow: %s", tc.index, gotIndex)
			}
			// No object for this upload's digest was installed and no existing
			// object disappeared.
			if objects := objectNames(t, root); !reflect.DeepEqual(objects, objectsBefore) {
				t.Fatalf("object set changed: %v -> %v", objectsBefore, objects)
			}
			if _, err := os.Stat(filepath.Join(root, "objects", uploadDigest)); !os.IsNotExist(err) {
				t.Fatalf("upload installed its digest object despite the failure: %v", err)
			}
			for _, d := range []string{keep.Digest, stray} {
				if _, err := os.Stat(filepath.Join(root, "objects", d)); err != nil {
					t.Fatalf("existing object %s disappeared: %v", d, err)
				}
			}
			// Snapshots are untouched.
			snapshotAfter, err := os.ReadFile(filepath.Join(root, "snapshots", "keep.json"))
			if err != nil || !reflect.DeepEqual(snapshotAfter, snapshotBefore) {
				t.Fatalf("snapshot record changed: %v", err)
			}
			assertNoPutTemps(t, root)
		})
	}
}

// TestPutValidatesIndexBeforeOpeningInput proves the mapping precondition
// comes first: with a corrupt index the error is the index problem even when
// the named input file does not exist at all, while a healthy index reports
// the missing input directly.
func TestPutValidatesIndexBeforeOpeningInput(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeFile(t, "keep me")); err != nil {
		t.Fatal(err)
	}
	missingInput := filepath.Join(t.TempDir(), "does-not-exist")

	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(`{"entries":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := store.Put("new/name.bin", missingInput)
	if err == nil {
		t.Fatal("expected put to fail")
	}
	if !strings.Contains(err.Error(), "current index is corrupt") {
		t.Fatalf("corrupt index must take precedence over a missing input: %v", err)
	}
	if strings.Contains(err.Error(), "input file") {
		t.Fatalf("error should be the index problem, got %v", err)
	}

	// Healthy index: the same missing input is reported as an input failure,
	// distinct from index corruption.
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(`{"entries":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = store.Put("new/name.bin", missingInput)
	if err == nil {
		t.Fatal("expected put to fail")
	}
	if !strings.Contains(err.Error(), `cannot store "new/name.bin"`) ||
		!strings.Contains(err.Error(), "cannot read input file") {
		t.Fatalf("healthy index should surface the input failure, got %v", err)
	}
	if strings.Contains(err.Error(), "current index") {
		t.Fatalf("input failure must not blame the index: %v", err)
	}
}

// TestPutRejectsUnreadableIndex distinguishes an index whose bytes cannot be
// read from one whose bytes are corrupt: the error names the upload and says
// the index cannot be read, not that it is corrupt, and nothing is staged.
func TestPutRejectsUnreadableIndex(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission-based unreadability cannot be tested as root")
	}
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	keep, err := store.Put("keep.txt", writeFile(t, "keep me"))
	if err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.json")
	if err := os.Chmod(indexPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(indexPath, 0o644) })
	objectsBefore := objectNames(t, root)

	entry, err := store.Put("new/name.bin", writeInput(t, []byte("fresh bytes")))
	if err == nil {
		t.Fatal("expected put over an unreadable index to fail")
	}
	if !reflect.DeepEqual(entry, Entry{}) {
		t.Fatalf("failed put returned a usable entry: %+v", entry)
	}
	msg := err.Error()
	if !strings.Contains(msg, `cannot store "new/name.bin"`) {
		t.Fatalf("error %q does not name the upload", msg)
	}
	if !strings.Contains(msg, "current index cannot be read") {
		t.Fatalf("error %q does not say the index cannot be read", msg)
	}
	if strings.Contains(msg, "corrupt") {
		t.Fatalf("an unreadable index must not be called corrupt: %q", msg)
	}
	if objects := objectNames(t, root); !reflect.DeepEqual(objects, objectsBefore) {
		t.Fatalf("object set changed: %v -> %v", objectsBefore, objects)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", keep.Digest)); err != nil {
		t.Fatalf("existing object disappeared: %v", err)
	}
	assertNoPutTemps(t, root)
}

// TestPutReportsFirstBadRecordDeterministically verifies the whole upload is
// rejected when several existing records are bad, naming the first offending
// artifact in name order rather than the one being uploaded.
func TestPutReportsFirstBadRecordDeterministically(t *testing.T) {
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
	_, err := store.Put("new/name.bin", writeInput(t, []byte("x")))
	if err == nil {
		t.Fatal("expected put to fail")
	}
	if !strings.Contains(err.Error(), `entry "alpha"`) {
		t.Fatalf("error %q does not name the alphabetically first bad record alpha", err)
	}
}

// TestPutIntoEmptyMappingWorks confirms a genuine {"entries":{}} mapping is a
// healthy empty repository that accepts both an empty and a normal upload,
// and that a first upload still auto-initializes a repository without one.
func TestPutIntoEmptyMappingWorks(t *testing.T) {
	t.Run("explicit empty mapping", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		store := New(root)
		if err := store.Init(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "index.json"),
			[]byte("{\n  \"entries\": {}\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		empty, err := store.Put("empty/one", writeInput(t, nil))
		if err != nil {
			t.Fatalf("empty file upload into an empty mapping failed: %v", err)
		}
		if empty.Size != 0 || empty.Digest != digestOf("") {
			t.Fatalf("empty entry=%+v", empty)
		}
		normal, err := store.Put("normal/one", writeInput(t, []byte("payload")))
		if err != nil {
			t.Fatalf("normal upload into an empty mapping failed: %v", err)
		}
		entries := entriesOf(t, store)
		if len(entries) != 2 {
			t.Fatalf("entries=%v", entries)
		}
		if entries["normal/one"].Digest != normal.Digest {
			t.Fatalf("entries=%v", entries)
		}
	})
	t.Run("auto initialize", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		store := New(root)
		entry, err := store.Put("first.txt", writeInput(t, []byte("first ever")))
		if err != nil {
			t.Fatalf("first upload must still auto-initialize: %v", err)
		}
		if count, err := store.Verify(); err != nil || count != 1 {
			t.Fatalf("verify after auto-init: count=%d err=%v", count, err)
		}
		if entry.Name != "first.txt" {
			t.Fatalf("entry=%+v", entry)
		}
	})
}

// TestPutOverwriteKeepsEveryOtherRecord verifies an overwrite replaces only
// the named record: another name's digest, size, and creation time remain
// exactly as they were, and the displaced object is left for gc rather than
// being removed by the upload.
func TestPutOverwriteKeepsEveryOtherRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	firstContent := []byte("version one of a\n")
	otherContent := []byte("unrelated artifact b\n")
	newContent := []byte("version two of a is longer\n")
	if _, err := store.Put("dir/a.bin", writeInput(t, firstContent)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("dir/b.bin", writeInput(t, otherContent)); err != nil {
		t.Fatal(err)
	}
	before := entriesOf(t, store)
	beforeB := before["dir/b.bin"]
	oldDigest := before["dir/a.bin"].Digest

	// Give the replacement entry a strictly later wall-clock creation time so
	// preserving b's timestamp is observable.
	time.Sleep(10 * time.Millisecond)
	newEntry, err := store.Put("dir/a.bin", writeInput(t, newContent))
	if err != nil {
		t.Fatal(err)
	}
	if newEntry.Digest != digestOf(string(newContent)) || newEntry.Size != int64(len(newContent)) {
		t.Fatalf("new entry=%+v", newEntry)
	}
	after := entriesOf(t, store)
	if len(after) != 2 {
		t.Fatalf("entry count changed: %v", after)
	}
	if after["dir/b.bin"] != beforeB {
		t.Fatalf("overwrite changed the other record: %+v -> %+v", beforeB, after["dir/b.bin"])
	}
	if after["dir/a.bin"].Digest != newEntry.Digest {
		t.Fatalf("overwritten record not replaced: %+v", after["dir/a.bin"])
	}
	if after["dir/a.bin"].CreatedAt == before["dir/a.bin"].CreatedAt {
		t.Fatal("overwritten record kept the old creation time")
	}
	// The displaced object stays on disk; put never collects it.
	if _, err := os.Stat(filepath.Join(root, "objects", oldDigest)); err != nil {
		t.Fatalf("displaced object removed by put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", newEntry.Digest)); err != nil {
		t.Fatalf("new object missing: %v", err)
	}
	assertNoPutTemps(t, root)
}
