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

// writeSnapshotRecord writes raw record content for snapshot name, creating
// parent directories for multi-level names.
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
