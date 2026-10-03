package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeIndex replaces the current index with raw bytes, simulating damage
// done outside the vault (a crash mid-write, a hand edit, a bad restore).
func writeIndex(t *testing.T, root string, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRejectsCorruptIndex confirms verify never reports success over a
// damaged name mapping: every malformed shape fails the whole pass with an
// error that identifies the current index, returns a zero count, and leaves
// the damaged index byte-for-byte untouched.
func TestVerifyRejectsCorruptIndex(t *testing.T) {
	goodDigest := digestOf("good")
	cases := map[string]string{
		"empty file":                ``,
		"whitespace only":           "  \n",
		"bare null":                 `null`,
		"empty object":              `{}`,
		"missing entries":           `{"other":1}`,
		"null entries":              `{"entries":null}`,
		"array entries":             `{"entries":[]}`,
		"string entries":            `{"entries":"none"}`,
		"top-level array":           `[{"entries":{}}]`,
		"top-level string":          `"index"`,
		"top-level number":          `42`,
		"truncated":                 `{"entries":{"a":{"name":"a","dig`,
		"trailing content":          `{"entries":{}} {"entries":{}}`,
		"trailing garbage":          `{"entries":{}}garbage`,
		"duplicate entries key":     `{"entries":{},"entries":{}}`,
		"duplicate artifact":        `{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"},"a":{"name":"a","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"duplicate identical field": `{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"unicode escaped duplicate": `{"entries":{"a/b":{"name":"a/b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"},"a` + `/` + `b":{"name":"a/b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
	}
	for label, index := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			writeIndex(t, root, index)

			count, err := store.Verify()
			if err == nil {
				t.Fatal("expected verify to fail on a corrupt index")
			}
			if count != 0 {
				t.Fatalf("count=%d, want 0", count)
			}
			if !strings.Contains(err.Error(), "current index") {
				t.Fatalf("error does not identify the current index: %v", err)
			}
			// The damaged index is never rewritten by the check.
			got, readErr := os.ReadFile(filepath.Join(root, "index.json"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != index {
				t.Fatal("verify rewrote the damaged index")
			}
		})
	}
}

// TestVerifyDuplicateKeyErrorNamesKey confirms a duplicate-key failure names
// the duplicated key so the damage can be located by hand.
func TestVerifyDuplicateKeyErrorNamesKey(t *testing.T) {
	goodDigest := digestOf("good")
	cases := map[string]struct {
		index string
		key   string
	}{
		"entries":  {`{"entries":{},"entries":{}}`, "entries"},
		"artifact": {`{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"},"a":{"name":"a","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a"},
		"field":    {`{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "digest"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			writeIndex(t, root, tc.index)
			_, err := store.Verify()
			if err == nil {
				t.Fatal("expected verify to fail")
			}
			if !strings.Contains(err.Error(), "duplicate key") || !strings.Contains(err.Error(), `"`+tc.key+`"`) {
				t.Fatalf("error does not name the duplicated key %q: %v", tc.key, err)
			}
		})
	}
}

// TestVerifyRejectsIllegalRecords confirms every record is held to the same
// standard download and gc apply: the filing key must equal the recorded
// name, the name must be legal, the digest 64 lowercase hex characters, and
// the size non-negative. One illegal record fails the whole pass even when
// every object is healthy, and the error names the record's mapping name.
func TestVerifyRejectsIllegalRecords(t *testing.T) {
	goodDigest := digestOf("good")
	cases := map[string]struct {
		index string
		name  string
	}{
		"key mismatch":   {`{"entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a"},
		"escaping name":  {`{"entries":{"../x":{"name":"../x","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "../x"},
		"unnormalized":   {`{"entries":{"a//b":{"name":"a//b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a//b"},
		"short digest":   {`{"entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a"},
		"uppercase hex":  {`{"entries":{"a":{"name":"a","digest":"` + strings.ToUpper(goodDigest) + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a"},
		"negative size":  {`{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a"},
		"missing digest": {`{"entries":{"a":{"name":"a","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`, "a"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeInput(t, []byte("keep me"))); err != nil {
				t.Fatal(err)
			}
			writeIndex(t, root, tc.index)

			count, err := store.Verify()
			if err == nil {
				t.Fatal("expected verify to fail on an illegal record")
			}
			if count != 0 {
				t.Fatalf("count=%d, want 0", count)
			}
			if !strings.Contains(err.Error(), "current index") {
				t.Fatalf("error does not identify the current index: %v", err)
			}
			if !strings.Contains(err.Error(), `"`+tc.name+`"`) {
				t.Fatalf("error does not name the mapping name %q: %v", tc.name, err)
			}
		})
	}
}

// TestVerifyReportsMappingBeforeObjects confirms a corrupt name mapping is
// reported as index corruption — never as an object problem — even when the
// referenced objects are damaged at the same time.
func TestVerifyReportsMappingBeforeObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("a.txt", writeInput(t, []byte("payload")))
	if err != nil {
		t.Fatal(err)
	}
	// Damage the object and break the mapping's key/name consistency.
	if err := os.Truncate(objectPathOf(root, []byte("payload")), 1); err != nil {
		t.Fatal(err)
	}
	writeIndex(t, root, `{"entries":{"a.txt":{"name":"renamed.txt","digest":"`+entry.Digest+`","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`)

	_, err = store.Verify()
	if err == nil {
		t.Fatal("expected verify to fail")
	}
	if !strings.Contains(err.Error(), "current index") {
		t.Fatalf("mapping problem must be reported as index corruption, got: %v", err)
	}
	if strings.Contains(err.Error(), "content") || strings.Contains(err.Error(), "object") {
		t.Fatalf("mapping problem must be reported before object problems, got: %v", err)
	}
}

// TestVerifyObjectFailures confirms the object-level failure semantics are
// unchanged: a missing object, a read problem, or a size/digest mismatch
// fails the pass with the artifact name and a zero count, and the error is
// distinguishable from index corruption.
func TestVerifyObjectFailures(t *testing.T) {
	cases := map[string]struct {
		damage func(t *testing.T, root string, entry Entry)
		want   string
	}{
		"missing object": {
			damage: func(t *testing.T, root string, entry Entry) {
				if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
					t.Fatal(err)
				}
			},
		},
		"size mismatch": {
			damage: func(t *testing.T, root string, entry Entry) {
				if err := os.Truncate(filepath.Join(root, "objects", entry.Digest), 2); err != nil {
					t.Fatal(err)
				}
			},
			want: "content mismatch",
		},
		"digest mismatch": {
			damage: func(t *testing.T, root string, entry Entry) {
				if err := os.WriteFile(filepath.Join(root, "objects", entry.Digest), []byte("tampered!!"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			want: "content mismatch",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			entry, err := store.Put("app.bin", writeInput(t, []byte("ten bytes!")))
			if err != nil {
				t.Fatal(err)
			}
			tc.damage(t, root, entry)

			count, err := store.Verify()
			if err == nil {
				t.Fatal("expected verify to fail")
			}
			if count != 0 {
				t.Fatalf("count=%d, want 0", count)
			}
			if !strings.Contains(err.Error(), `"app.bin"`) {
				t.Fatalf("error does not name the artifact: %v", err)
			}
			if strings.Contains(err.Error(), "current index") {
				t.Fatalf("object problem misreported as index corruption: %v", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v should mention %q", err, tc.want)
			}
		})
	}
}

// TestVerifyCountsNames confirms a healthy repository is counted by artifact
// name: two names sharing one digest count as two, an empty file takes part
// normally, and an explicit empty mapping verifies as zero artifacts.
func TestVerifyCountsNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	shared := writeInput(t, []byte("shared payload"))
	for _, name := range []string{"a/one.bin", "b/two.bin"} {
		if _, err := store.Put(name, shared); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Put("empty.bin", writeInput(t, nil)); err != nil {
		t.Fatal(err)
	}
	count, err := store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count=%d, want 3 (two names sharing one digest plus an empty file)", count)
	}

	empty := New(filepath.Join(t.TempDir(), "vault"))
	if err := empty.Init(); err != nil {
		t.Fatal(err)
	}
	count, err = empty.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("empty repository count=%d, want 0", count)
	}
}

// TestVerifyDoesNotTouchRepository confirms a failed verify is fully
// read-only: the damaged index, every snapshot, and every object keep their
// exact bytes.
func TestVerifyDoesNotTouchRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("keep.txt", writeInput(t, []byte("keep me")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	damaged := `{"entries":{"keep.txt":{"name":"keep.txt","digest":"` + entry.Digest + `","size":6,"createdAt":"2026-01-01T00:00:00Z"},"keep.txt":{"name":"keep.txt","digest":"` + entry.Digest + `","size":6,"createdAt":"2026-01-01T00:00:00Z"}}}`
	writeIndex(t, root, damaged)

	paths := []string{
		filepath.Join(root, "index.json"),
		filepath.Join(root, "snapshots", "snap.json"),
		filepath.Join(root, "objects", entry.Digest),
	}
	before := map[string][]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = data
	}

	if _, err := store.Verify(); err == nil {
		t.Fatal("expected verify to fail")
	}
	for path, want := range before {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s changed across a failed verify", path)
		}
	}
}
