package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSnapshotCreateListRestore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")

	if _, err := store.Put("releases/app.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("docs/readme.txt", v1); err != nil {
		t.Fatal(err)
	}
	snap, err := store.CreateSnapshot("before-release")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) != 2 {
		t.Fatalf("snapshot entries=%d", len(snap.Entries))
	}

	// Overwrite one artifact and add another after the snapshot.
	if _, err := store.Put("releases/app.txt", v2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("extra.txt", v2); err != nil {
		t.Fatal(err)
	}

	// A fresh Store (simulating a restart) still lists the snapshot.
	infos, err := New(root).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "before-release" || infos[0].Count != 2 {
		t.Fatalf("infos=%+v", infos)
	}

	if err := New(root).RestoreSnapshot("before-release"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries after restore=%d", len(entries))
	}
	for _, entry := range entries {
		if entry.Name == "extra.txt" {
			t.Fatal("extra.txt should be gone after restore")
		}
	}
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := store.Get("releases/app.txt", output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "version one\n" {
		t.Fatalf("restored content=%q", got)
	}
	// The snapshot itself is untouched by the restore.
	if err := store.RestoreSnapshot("before-release"); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotEmptyRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	snap, err := store.CreateSnapshot("empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) != 0 {
		t.Fatalf("entries=%d", len(snap.Entries))
	}
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries=%d", len(entries))
	}
}

func TestSnapshotListEmptyAndSorted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("infos=%+v", infos)
	}
	input := writeFile(t, "payload")
	if _, err := store.Put("a.txt", input); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zeta", "alpha", "mid/way"} {
		if _, err := store.CreateSnapshot(name); err != nil {
			t.Fatal(err)
		}
	}
	infos, err = store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alpha", "mid/way", "zeta"}
	if len(infos) != len(want) {
		t.Fatalf("infos=%+v", infos)
	}
	for i, info := range infos {
		if info.Name != want[i] || info.Count != 1 {
			t.Fatalf("infos[%d]=%+v", i, info)
		}
	}
}

func TestSnapshotNameValidation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../escape", "/abs", "a//b", `back\slash`} {
		if _, err := store.CreateSnapshot(name); err == nil {
			t.Fatalf("create %q: expected error", name)
		}
		if err := store.RestoreSnapshot(name); err == nil {
			t.Fatalf("restore %q: expected error", name)
		}
	}
}

func TestSnapshotDuplicateCreateFails(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("dup"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("dup"); err == nil {
		t.Fatal("expected duplicate snapshot error")
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("infos=%+v", infos)
	}
}

func TestRestoreMissingSnapshotFails(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	if err := store.RestoreSnapshot("nope"); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestRestoreWithCorruptIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "good data")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("stable"); err != nil {
		t.Fatal(err)
	}
	// Corrupt the current index; restore must still succeed.
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("stable"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestCreateWithCorruptIndexFails(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("should-not-appear"); err == nil {
		t.Fatal("expected create to fail on corrupt index")
	}
	infos, err := New(root).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("failed create left snapshot behind: %+v", infos)
	}
}

func TestRestoreValidatesRecords(t *testing.T) {
	goodDigest := hex.EncodeToString(sha256.New().Sum(nil))
	cases := map[string]string{
		"bad json":       `{broken`,
		"bad entry name": `{"name":"s","entries":{"../evil":{"name":"../evil","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"bad digest":     `{"name":"s","entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"negative size":  `{"name":"s","entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"key mismatch":   `{"name":"s","entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
	}
	for label, record := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("keep.txt", writeFile(t, "keep me")); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "snapshots", "s.json"), []byte(record), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := store.RestoreSnapshot("s"); err == nil {
				t.Fatal("expected restore to reject corrupted record")
			}
			// The current mapping is unchanged.
			entries, err := store.List()
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name != "keep.txt" {
				t.Fatalf("entries=%+v", entries)
			}
		})
	}
}

func TestRestoreDetectsMissingOrCorruptObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	input := writeFile(t, "precious\n")
	entry, err := store.Put("a.txt", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", input); err != nil {
		t.Fatal(err)
	}

	// Missing object: restore fails and the current mapping survives.
	object := filepath.Join(root, "objects", entry.Digest)
	data, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("snap"); err == nil {
		t.Fatal("expected restore to fail on missing object")
	}
	if entries, err := store.List(); err != nil || len(entries) != 2 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}

	// Corrupted content (right length, wrong bytes): also fails.
	if err := os.WriteFile(object, []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("snap"); err == nil {
		t.Fatal("expected restore to fail on content mismatch")
	}
	if entries, err := store.List(); err != nil || len(entries) != 2 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}

	// Repair the object; restore succeeds.
	if err := os.WriteFile(object, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentPutsBothSurvive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			input := writeFile(t, fmt.Sprintf("payload-%d", i))
			if _, err := New(root).Put(fmt.Sprintf("artifact-%d.txt", i), input); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != workers {
		t.Fatalf("entries=%d, want %d", len(entries), workers)
	}
	if _, err := store.Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSnapshotAndPutSerialize(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("base.txt", writeFile(t, "base")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := New(root).CreateSnapshot("concurrent"); err != nil {
			errs <- err
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := New(root).Put("later.txt", writeFile(t, "later")); err != nil {
			errs <- err
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// The snapshot must equal either the pre-put or post-put mapping.
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("infos=%+v", infos)
	}
	if infos[0].Count != 1 && infos[0].Count != 2 {
		t.Fatalf("snapshot count=%d is neither pre- nor post-put mapping", infos[0].Count)
	}
	// Restore must yield a consistent mapping containing base.txt.
	if err := store.RestoreSnapshot("concurrent"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if infos[0].Count != len(entries) {
		t.Fatalf("restored %d entries, snapshot had %d", len(entries), infos[0].Count)
	}
	found := false
	for _, entry := range entries {
		if entry.Name == "base.txt" {
			found = true
		}
		if !strings.HasPrefix(entry.Name, "base") && entry.Name != "later.txt" {
			t.Fatalf("unexpected entry %q", entry.Name)
		}
	}
	if !found {
		t.Fatal("base.txt missing after restore")
	}
}

// TestCreateSnapshotRejectsUnusableCurrentIndex is the creation-time
// counterpart of the strict index rules verify and gc enforce: a snapshot is
// never taken from a mapping that is not itself complete and unambiguous. A
// bare null, an empty {}, a missing or null entries mapping, a non-object
// entries value, a truncated document, trailing content, any duplicate key
// (including a name written again through a Unicode escape), or an entry that
// fails the key-matches-name / legal-name / digest / non-negative-size rules
// must reject the whole operation. The error names the snapshot being created
// and says the current index is corrupt (with the duplicated key or offending
// artifact in the underlying reason), no snapshot is left behind, and the
// index bytes, existing snapshots, and objects are untouched.
func TestCreateSnapshotRejectsUnusableCurrentIndex(t *testing.T) {
	goodDigest := hex.EncodeToString(sha256.New().Sum(nil))
	validEntry := `{"name":"a","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}`
	// A JSON key naming a/b directly and the same key written with a Unicode
	// escape (/) must collide once the strings are decoded.
	unicodeDupIndex := `{"entries":{` +
		`"a/b":{"name":"a/b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"},` +
		`"a` + `\` + `u002fb":{"name":"a/b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}` +
		`}}`
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
			index:       `{"entries":{"a":` + validEntry + `,"a":` + validEntry + `}}`,
			wantInError: `duplicate key "a"`,
		},
		"same name through unicode escape": {
			index:       unicodeDupIndex,
			wantInError: `duplicate key "a/b"`,
		},
		"duplicate field inside entry": {
			index:       `{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":0,"size":1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `duplicate key "size"`,
		},
		"entry key mismatch": {
			index:       `{"entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `is filed under`,
		},
		"entry illegal name": {
			index:       `{"entries":{"../evil":{"name":"../evil","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: `invalid entry name`,
		},
		"entry bad digest": {
			index:       `{"entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "want 64 lowercase hex characters",
		},
		"entry negative size": {
			index:       `{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError: "negative size",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			keepEntry, err := store.Put("keep.txt", writeFile(t, "keep me"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateSnapshot("keep"); err != nil {
				t.Fatal(err)
			}
			// An object referenced by nothing once the mapping is replaced.
			stray := hex.EncodeToString(sha256.New().Sum([]byte("stray")))
			if err := os.WriteFile(filepath.Join(root, "objects", stray), []byte("stray"), 0o644); err != nil {
				t.Fatal(err)
			}
			indexPath := filepath.Join(root, "index.json")
			if err := os.WriteFile(indexPath, []byte(tc.index), 0o644); err != nil {
				t.Fatal(err)
			}
			keepRecord, err := os.ReadFile(filepath.Join(root, "snapshots", "keep.json"))
			if err != nil {
				t.Fatal(err)
			}

			snap, err := store.CreateSnapshot("snap")
			if err == nil {
				t.Fatal("expected create to be rejected")
			}
			if !reflect.DeepEqual(snap, Snapshot{}) {
				t.Fatalf("failed create returned a usable snapshot: %+v", snap)
			}
			msg := err.Error()
			if !strings.Contains(msg, `cannot create snapshot "snap"`) {
				t.Fatalf("error %q does not name the snapshot being created", msg)
			}
			if !strings.Contains(msg, "current index") {
				t.Fatalf("error %q does not identify the current index as the cause", msg)
			}
			if !strings.Contains(msg, tc.wantInError) {
				t.Fatalf("error %q does not indicate %q", msg, tc.wantInError)
			}

			// No new snapshot; the existing one is byte-for-byte unchanged.
			infos, err := New(root).ListSnapshots()
			if err != nil {
				t.Fatal(err)
			}
			if len(infos) != 1 || infos[0].Name != "keep" {
				t.Fatalf("failed create changed the snapshot set: %+v", infos)
			}
			gotRecord, err := os.ReadFile(filepath.Join(root, "snapshots", "keep.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotRecord, keepRecord) {
				t.Fatal("existing snapshot record was rewritten")
			}
			// The corrupt index bytes and every object are untouched.
			gotIndex, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotIndex) != tc.index {
				t.Fatalf("index was rewritten\nwas: %s\nnow: %s", tc.index, gotIndex)
			}
			for _, path := range []string{
				filepath.Join(root, "objects", keepEntry.Digest),
				filepath.Join(root, "objects", stray),
			} {
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("object %s disappeared: %v", path, err)
				}
			}
			// No temporary files left behind in the repository.
			for _, dir := range []string{root, filepath.Join(root, "snapshots")} {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), ".snapshot-") || strings.HasPrefix(e.Name(), ".index-") {
						t.Fatalf("temporary file left behind: %s", filepath.Join(dir, e.Name()))
					}
				}
			}
		})
	}
}

// TestCreateSnapshotErrorKindsStayDistinct makes sure an unusable current
// index is never confused with the snapshot name being illegal or with a
// snapshot of that name already existing.
func TestCreateSnapshotErrorKindsStayDistinct(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("dup"); err != nil {
		t.Fatal(err)
	}

	// Healthy index: illegal name first, no index mention.
	_, err := store.CreateSnapshot("../escape")
	if err == nil || !strings.Contains(err.Error(), "name must be") || strings.Contains(err.Error(), "current index") {
		t.Fatalf("illegal-name error wrong: %v", err)
	}
	// Healthy index: same-named snapshot, distinct from index corruption.
	_, err = store.CreateSnapshot("dup")
	if err == nil || !strings.Contains(err.Error(), `snapshot "dup" already exists`) || strings.Contains(err.Error(), "current index") {
		t.Fatalf("duplicate-snapshot error wrong: %v", err)
	}

	// Corrupt index: the failure names the index, never "already exists"
	// even when the snapshot name is free, and nothing is written.
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(`{"entries":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateSnapshot("new-name")
	if err == nil || !strings.Contains(err.Error(), `cannot create snapshot "new-name"`) ||
		!strings.Contains(err.Error(), "missing entries mapping") {
		t.Fatalf("corrupt-index error wrong: %v", err)
	}
}

// TestCreateSnapshotReportsFirstBadEntryDeterministically verifies the whole
// create is rejected (not filtered) when several entries are bad, and that the
// artifact named in the error is the first in name order.
func TestCreateSnapshotReportsFirstBadEntryDeterministically(t *testing.T) {
	goodDigest := hex.EncodeToString(sha256.New().Sum(nil))
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
	_, err := store.CreateSnapshot("snap")
	if err == nil {
		t.Fatal("expected create to fail")
	}
	if !strings.Contains(err.Error(), `entry "alpha"`) {
		t.Fatalf("error %q does not name the alphabetically first bad entry alpha", err)
	}
}

// TestCreateSnapshotEmptyEntriesIsValid confirms a genuine {"entries":{}}
// mapping — unlike null or a missing entries field — is a healthy repository
// whose snapshot creates, lists, and restores with zero entries.
func TestCreateSnapshotEmptyEntriesIsValid(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"),
		[]byte("{\n  \"entries\": {}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := store.CreateSnapshot("empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) != 0 {
		t.Fatalf("entries=%d", len(snap.Entries))
	}
	infos, err := New(root).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "empty" || infos[0].Count != 0 {
		t.Fatalf("infos=%+v", infos)
	}
	if err := New(root).RestoreSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
}

// TestCreateSnapshotPreservesAllMetadata verifies a created snapshot keeps
// every name, digest, size, and creation time exactly — including when several
// names share one digest, each keeps its own record.
func TestCreateSnapshotPreservesAllMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	same := writeFile(t, "identical bytes")
	first, err := store.Put("releases/app.bin", same)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Put("mirror/app.bin", same)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.Put("docs/note.txt", writeFile(t, "different bytes"))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := store.CreateSnapshot("releases/stable")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Entries) != 3 {
		t.Fatalf("entries=%d", len(snap.Entries))
	}
	a := snap.Entries["releases/app.bin"]
	b := snap.Entries["mirror/app.bin"]
	if a.Digest != first.Digest || b.Digest != second.Digest || a.Digest != b.Digest {
		t.Fatal("the two names sharing one object must both keep its digest")
	}
	if !a.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("first entry creation time not preserved: %v != %v", a.CreatedAt, first.CreatedAt)
	}
	if !b.CreatedAt.Equal(second.CreatedAt) {
		t.Fatalf("second entry creation time not preserved: %v != %v", b.CreatedAt, second.CreatedAt)
	}
	if snap.Entries["docs/note.txt"].Digest != other.Digest {
		t.Fatal("third entry digest not preserved")
	}

	// Mutate the live mapping, then restore: names, digests, sizes, and
	// creation times must all come back from the snapshot record.
	v2 := writeFile(t, "version two\n")
	if _, err := store.Put("releases/app.bin", v2); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Entry{}
	for _, e := range entries {
		got[e.Name] = e
	}
	if !reflect.DeepEqual(got, snap.Entries) {
		t.Fatalf("restored mapping %+v != snapshot entries %+v", got, snap.Entries)
	}
}

func writeSnapshotRecord(t *testing.T, root, name, record string) {
	t.Helper()
	path := filepath.Join(root, "snapshots", filepath.FromSlash(name)+".json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRestoreRejectsIncompleteOrMisnamedRecords exercises the rule that a
// restore only swaps in a complete record whose name matches the selected
// snapshot in full. A missing, null, or non-object entries field is never an
// empty mapping, a wrong name is never applied, and malformed JSON is a
// corrupt record rather than an empty snapshot. Every failure names the
// selected snapshot, states what is wrong, and leaves the current mapping,
// the snapshot record, and the objects untouched.
func TestRestoreRejectsIncompleteOrMisnamedRecords(t *testing.T) {
	goodDigest := hex.EncodeToString(sha256.New().Sum(nil))
	entry := func() string {
		return `{"name":"a.txt","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}`
	}
	cases := map[string]struct {
		snapshotName string
		record       string
		wantInError  string
	}{
		"missing entries": {
			snapshotName: "s",
			record:       `{"name":"s"}`,
			wantInError:  "missing its entries mapping",
		},
		"null entries": {
			snapshotName: "s",
			record:       `{"name":"s","entries":null}`,
			wantInError:  "missing its entries mapping",
		},
		"body is null": {
			snapshotName: "s",
			record:       `null`,
			wantInError:  "malformed record",
		},
		"body is empty object": {
			snapshotName: "s",
			record:       `{}`,
			wantInError:  "missing snapshot name",
		},
		"entries is an array": {
			snapshotName: "s",
			record:       `{"name":"s","entries":[]}`,
			wantInError:  "entries mapping is malformed",
		},
		"entries is a string": {
			snapshotName: "s",
			record:       `{"name":"s","entries":"none"}`,
			wantInError:  "entries mapping is malformed",
		},
		"entries is a number": {
			snapshotName: "s",
			record:       `{"name":"s","entries":3}`,
			wantInError:  "entries mapping is malformed",
		},
		"missing name": {
			snapshotName: "s",
			record:       `{"entries":{}}`,
			wantInError:  "missing snapshot name",
		},
		"null name": {
			snapshotName: "s",
			record:       `{"name":null,"entries":{}}`,
			wantInError:  "malformed record",
		},
		"other name": {
			snapshotName: "s",
			record:       `{"name":"other","entries":{}}`,
			wantInError:  "does not match snapshot",
		},
		// Multi-level names must match in full: the leaf name alone is wrong.
		"nested name recorded as leaf": {
			snapshotName: "releases/stable",
			record:       `{"name":"stable","entries":{}}`,
			wantInError:  `recorded name "stable" does not match snapshot "releases/stable"`,
		},
		"nested name recorded elsewhere": {
			snapshotName: "releases/stable",
			record:       `{"name":"releases/canary","entries":{}}`,
			wantInError:  "does not match snapshot",
		},
		"unknown field": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{},"extra":1}`,
			wantInError:  "malformed record",
		},
		"duplicate name field": {
			snapshotName: "s",
			record:       `{"name":"other","name":"s","entries":{}}`,
			wantInError:  "malformed record",
		},
		"duplicate entries field": {
			snapshotName: "s",
			record:       `{"name":"s","entries":null,"entries":{}}`,
			wantInError:  "malformed record",
		},
		"trailing content": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{}} {}`,
			wantInError:  "malformed record",
		},
		"top level array": {
			snapshotName: "s",
			record:       `[]`,
			wantInError:  "malformed record",
		},
		"entry missing digest": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{"a.txt":{"name":"a.txt","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError:  "want 64 lowercase hex characters",
		},
		"duplicate entry key": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{"a":` + entry() + `,"a":` + entry() + `}}`,
			wantInError:  "malformed record",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			input := writeFile(t, "keep me")
			keepEntry, err := store.Put("keep.txt", input)
			if err != nil {
				t.Fatal(err)
			}
			writeSnapshotRecord(t, root, tc.snapshotName, tc.record)
			recordPath := filepath.Join(root, "snapshots", filepath.FromSlash(tc.snapshotName)+".json")
			recordBefore, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			indexBefore, err := os.ReadFile(filepath.Join(root, "index.json"))
			if err != nil {
				t.Fatal(err)
			}

			err = store.RestoreSnapshot(tc.snapshotName)
			if err == nil {
				t.Fatal("expected restore to be rejected")
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", tc.snapshotName)) {
				t.Fatalf("error %q does not name the selected snapshot %q", err, tc.snapshotName)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Fatalf("error %q does not indicate %q", err, tc.wantInError)
			}

			// The current mapping survives intact and is still usable.
			entries, err := store.List()
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name != "keep.txt" || entries[0].Digest != keepEntry.Digest {
				t.Fatalf("entries after failed restore=%+v", entries)
			}
			indexAfter, err := os.ReadFile(filepath.Join(root, "index.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(indexBefore, indexAfter) {
				t.Fatalf("index changed on failed restore\nwas: %s\nnow: %s", indexBefore, indexAfter)
			}
			// The snapshot record is not rewritten or repaired.
			recordAfter, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(recordBefore, recordAfter) {
				t.Fatalf("snapshot record changed on failed restore\nwas: %s\nnow: %s", recordBefore, recordAfter)
			}
		})
	}
}

// TestRestoreFailurePreservesCorruptIndex makes sure a rejected restore never
// replaces an already-unreadable current mapping with an empty one: the
// corrupt bytes must remain exactly as they were.
func TestRestoreFailurePreservesCorruptIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeFile(t, "keep me")); err != nil {
		t.Fatal(err)
	}
	writeSnapshotRecord(t, root, "s", `{"name":"s","entries":null}`)
	corruptIndex := []byte("{not json")
	if err := os.WriteFile(filepath.Join(root, "index.json"), corruptIndex, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("s"); err == nil {
		t.Fatal("expected restore to be rejected")
	}
	got, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(corruptIndex) {
		t.Fatalf("corrupt index changed on failed restore: %q", got)
	}
}

// TestRestoreMissingVsCorrupt distinguishes a nonexistent snapshot from a
// damaged record in the error text.
func TestRestoreMissingVsCorrupt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	err := store.RestoreSnapshot("absent")
	if err == nil || !strings.Contains(err.Error(), `snapshot "absent" not found`) {
		t.Fatalf("err=%v", err)
	}
	writeSnapshotRecord(t, root, "broken", `{broken`)
	err = store.RestoreSnapshot("broken")
	if err == nil || !strings.Contains(err.Error(), `snapshot "broken" is corrupted`) {
		t.Fatalf("err=%v", err)
	}
}

// TestRestoreEmptySnapshotIsValid confirms that an entries object present but
// empty is a legitimate snapshot which restores to an empty list, unlike a
// missing or null entries field.
func TestRestoreEmptySnapshotIsValid(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	// The snapshot is taken while the repository is empty, so its record is
	// {"name":"empty","entries":{}}.
	if _, err := store.CreateSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", writeFile(t, "more")); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after restoring empty snapshot=%+v", entries)
	}
}

// TestRestoreMatchesRecordedMetadata verifies that a successful restore makes
// the current mapping byte-for-byte the snapshot's mapping: names, digests,
// sizes, and creation times all come from the record, and subsequent
// downloads fetch the snapshot's content.
func TestRestoreMatchesRecordedMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")
	old, err := store.Put("releases/app.txt", v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("releases/app.txt", v2); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}

	recordData, err := os.ReadFile(filepath.Join(root, "snapshots", "snap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recorded Snapshot
	if err := json.Unmarshal(recordData, &recorded); err != nil {
		t.Fatal(err)
	}
	indexData, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var current struct {
		Entries map[string]Entry `json:"entries"`
	}
	if err := json.Unmarshal(indexData, &current); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recorded.Entries, current.Entries) {
		t.Fatalf("restored mapping %+v != snapshot entries %+v", current.Entries, recorded.Entries)
	}
	if current.Entries["releases/app.txt"].Digest != old.Digest {
		t.Fatal("restored entry does not point at the snapshot's object")
	}

	out := filepath.Join(t.TempDir(), "app.txt")
	if err := store.Get("releases/app.txt", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "version one\n" {
		t.Fatalf("download after restore=%q", got)
	}
}

// TestSnapshotListRejectsDamagedRecords is the listing counterpart to the
// restore validation tests: every record is checked with the same rules
// restore applies, so a record restore would reject can never appear in a
// listing with a fabricated name or entry count. A single bad record fails
// the whole list — even with a healthy snapshot filed beside it — the error
// names the complete snapshot and the reason, and no infos are returned.
func TestSnapshotListRejectsDamagedRecords(t *testing.T) {
	goodDigest := hex.EncodeToString(sha256.New().Sum(nil))
	entry := func() string {
		return `{"name":"a","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}`
	}
	cases := map[string]struct {
		snapshotName string
		record       string
		wantInError  string
	}{
		"empty object": {
			snapshotName: "s",
			record:       `{}`,
			wantInError:  "missing snapshot name",
		},
		"bare null": {
			snapshotName: "s",
			record:       `null`,
			wantInError:  "malformed record",
		},
		"missing entries": {
			snapshotName: "s",
			record:       `{"name":"s"}`,
			wantInError:  "missing its entries mapping",
		},
		"null entries": {
			snapshotName: "s",
			record:       `{"name":"s","entries":null}`,
			wantInError:  "missing its entries mapping",
		},
		"array entries": {
			snapshotName: "s",
			record:       `{"name":"s","entries":[]}`,
			wantInError:  "entries mapping is malformed",
		},
		"missing name": {
			snapshotName: "s",
			record:       `{"entries":{}}`,
			wantInError:  "missing snapshot name",
		},
		"wrong name": {
			snapshotName: "s",
			record:       `{"name":"other","entries":{}}`,
			wantInError:  `recorded name "other" does not match snapshot "s"`,
		},
		"nested record names only the leaf": {
			snapshotName: "releases/stable",
			record:       `{"name":"stable","entries":{}}`,
			wantInError:  `recorded name "stable" does not match snapshot "releases/stable"`,
		},
		"malformed json": {
			snapshotName: "s",
			record:       `{broken`,
			wantInError:  "malformed record",
		},
		"duplicate field": {
			snapshotName: "s",
			record:       `{"name":"other","name":"s","entries":{}}`,
			wantInError:  "malformed record",
		},
		"unknown field": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{},"extra":1}`,
			wantInError:  "malformed record",
		},
		"trailing content": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{}} garbage`,
			wantInError:  "malformed record",
		},
		"entry key mismatch": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError:  `is filed under`,
		},
		"entry bad digest": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{"a":{"name":"a","digest":"zzz","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError:  "want 64 lowercase hex characters",
		},
		"entry negative size": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-4,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			wantInError:  "negative size",
		},
		"duplicate artifact name": {
			snapshotName: "s",
			record:       `{"name":"s","entries":{"a":` + entry() + `,"a":` + entry() + `}}`,
			wantInError:  "malformed record",
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if _, err := store.Put("healthy.txt", writeFile(t, "healthy")); err != nil {
				t.Fatal(err)
			}
			if _, err := store.CreateSnapshot("healthy"); err != nil {
				t.Fatal(err)
			}
			writeSnapshotRecord(t, root, tc.snapshotName, tc.record)

			infos, err := store.ListSnapshots()
			if err == nil {
				t.Fatalf("expected list to fail, got %+v", infos)
			}
			if infos != nil {
				t.Fatalf("failed list returned partial infos: %+v", infos)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("%q", tc.snapshotName)) {
				t.Fatalf("error %q does not name snapshot %q", err, tc.snapshotName)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Fatalf("error %q does not indicate %q", err, tc.wantInError)
			}
		})
	}
}

// TestSnapshotListEmptyEntriesCountsZero confirms a record that explicitly
// carries an empty entries object is a healthy snapshot listed with zero
// entries, rather than being treated as corrupt or missing.
func TestSnapshotListEmptyEntriesCountsZero(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "empty" || infos[0].Count != 0 {
		t.Fatalf("infos=%+v", infos)
	}
}

// TestSnapshotListCountsMapRecordsNotObjects verifies the count is the number
// of records in the entries mapping: two artifact names sharing one content
// object count as two, and a multi-level snapshot name is shown in full.
func TestSnapshotListCountsMapRecordsNotObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	same := writeFile(t, "identical payload")
	if _, err := store.Put("releases/app.bin", same); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("mirror/app.bin", same); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	infos, err := New(root).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("infos=%+v", infos)
	}
	if infos[0].Name != "releases/stable" {
		t.Fatalf("name=%q, want the full multi-level name", infos[0].Name)
	}
	if infos[0].Count != 2 {
		t.Fatalf("count=%d, want 2 map records even with one shared object", infos[0].Count)
	}
}

// TestSnapshotListEmptyRepository covers both an initialized repository that
// has never held a snapshot and a root whose snapshots directory is absent.
func TestSnapshotListEmptyRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	infos, err := New(root).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 || infos == nil {
		t.Fatalf("want non-nil empty slice, got %+v", infos)
	}
}

// TestSnapshotListIgnoresNonSnapshotFiles makes sure temporary and stray
// files without a .json suffix are skipped while real records still list.
func TestSnapshotListIgnoresNonSnapshotFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("real"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "snapshots")
	for _, stray := range []string{".snapshot-tmp123", "notes.bak", "real.json.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, stray), []byte("not a snapshot"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "real" {
		t.Fatalf("infos=%+v", infos)
	}
}

// TestSnapshotListRejectsSymlink makes a symlinked snapshot record fatal,
// matching the restore/gc treatment of symlinks.
func TestSnapshotListRejectsSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.CreateSnapshot("real"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"name":"link","entries":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "snapshots", "link.json")); err != nil {
		t.Fatal(err)
	}
	if infos, err := store.ListSnapshots(); err == nil {
		t.Fatalf("expected symlink to fail the list, got %+v", infos)
	}
}

// TestSnapshotListNeedsNeitherObjectsNorHealthyMapping shows listing only
// inspects snapshot metadata: it succeeds with entries whose objects are
// gone and even while the current index itself is unreadable.
func TestSnapshotListNeedsNeitherObjectsNorHealthyMapping(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("a.txt", writeFile(t, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatalf("listing must not depend on objects or the current mapping: %v", err)
	}
	if len(infos) != 1 || infos[0].Name != "snap" || infos[0].Count != 1 {
		t.Fatalf("infos=%+v", infos)
	}
}

// TestSnapshotListIsReadOnly verifies a listing leaves every byte of the
// current mapping, snapshot records, and objects untouched, on both a
// successful listing and one aborted by a damaged record.
func TestSnapshotListIsReadOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("a.txt", writeFile(t, "payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string][]byte {
		out := map[string][]byte{}
		for _, p := range []string{
			filepath.Join(root, "index.json"),
			filepath.Join(root, "snapshots", "snap.json"),
			filepath.Join(root, "objects", entry.Digest),
		} {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out[p] = data
		}
		return out
	}
	check := func(before map[string][]byte) {
		t.Helper()
		for p, want := range before {
			got, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s changed during snapshot list", p)
			}
		}
	}

	before := snapshot()
	if _, err := store.ListSnapshots(); err != nil {
		t.Fatal(err)
	}
	check(before)

	writeSnapshotRecord(t, root, "broken", `{"name":"broken"}`)
	if _, err := store.ListSnapshots(); err == nil {
		t.Fatal("expected the damaged record to fail the list")
	}
	check(before)
}

// TestRestoreNestedSnapshotNameMustMatchInFull covers a real multi-level
// snapshot: a record whose name disagrees with the selected path is rejected
// even when its entries are otherwise valid, and restoring the untouched
// record after it is repaired (name corrected) succeeds.
func TestRestoreNestedSnapshotNameMustMatchInFull(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(root, "snapshots", "releases", "stable.json")
	if err := os.WriteFile(recordPath, []byte(`{"name":"stable","entries":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := store.RestoreSnapshot("releases/stable")
	if err == nil || !strings.Contains(err.Error(), `recorded name "stable" does not match snapshot "releases/stable"`) {
		t.Fatalf("err=%v", err)
	}
	// The healthy list must survive the rejected restore.
	if entries, err := store.List(); err != nil || len(entries) != 1 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	// Repair the record through the API: a healthy record named in full is
	// published again. Restoring it succeeds even when the current index is
	// unreadable, proving a healthy snapshot can replace a corrupt current
	// mapping without requiring it to load.
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("entries after healthy restore=%+v", entries)
	}
}
