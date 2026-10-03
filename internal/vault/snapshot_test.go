package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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
		"bad json":        `{broken`,
		"null body":       `null`,
		"empty object":    `{}`,
		"missing entries": `{"name":"s"}`,
		"null entries":    `{"name":"s","entries":null}`,
		"wrong name":      `{"name":"other","entries":{}}`,
		"bad entry name":  `{"name":"s","entries":{"../evil":{"name":"../evil","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"bad digest":      `{"name":"s","entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"negative size":   `{"name":"s","entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"key mismatch":    `{"name":"s","entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
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
			err := store.RestoreSnapshot("s")
			if err == nil {
				t.Fatal("expected restore to reject corrupted record")
			}
			// The failure names the snapshot the user selected and never reads
			// as a success.
			if !strings.Contains(err.Error(), `"s"`) {
				t.Fatalf("error does not name snapshot %q: %v", "s", err)
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

func TestRestoreRequiresFullMultilevelName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("keep.txt", writeFile(t, "keep me")); err != nil {
		t.Fatal(err)
	}
	snapDir := filepath.Join(root, "snapshots", "releases")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(snapDir, "stable.json")

	// A record remembering only the final component, or recording another name
	// entirely, is not releases/stable.
	for _, record := range []string{
		`{"name":"stable","entries":{}}` + "\n",
		`{"name":"releases/other","entries":{}}` + "\n",
	} {
		if err := os.WriteFile(snapPath, []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
		err := store.RestoreSnapshot("releases/stable")
		if err == nil {
			t.Fatalf("record %q should be rejected", record)
		}
		if !strings.Contains(err.Error(), "releases/stable") {
			t.Fatalf("error must name the selected snapshot: %v", err)
		}
		if entries, err := store.List(); err != nil || len(entries) != 1 {
			t.Fatalf("mapping changed after rejected restore: %+v err=%v", entries, err)
		}
	}

	// The correctly named record with an explicit empty entries mapping is a
	// legitimate empty snapshot and restores to an empty list.
	if err := os.WriteFile(snapPath, []byte(`{"name":"releases/stable","entries":{}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	if entries, err := store.List(); err != nil || len(entries) != 0 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

func TestRestoreFailureKeepsCorruptIndexCorrupt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "good")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("stable"); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.json")
	if err := os.WriteFile(indexPath, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(root, "snapshots", "stable.json")
	healthy, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	// Damage the record: the entries mapping is missing, so the corrupt index
	// must not be replaced by an empty mapping.
	if err := os.WriteFile(snapPath, []byte(`{"name":"stable"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("stable"); err == nil {
		t.Fatal("expected restore to fail")
	}
	got, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "{not json" {
		t.Fatalf("corrupt index was rewritten: %q", got)
	}
	// A complete, healthy snapshot still repairs the corrupt index.
	if err := os.WriteFile(snapPath, healthy, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("stable"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

func TestRestorePreservesRecordedMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("releases/app.bin", writeFile(t, "payload bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("releases/app.bin", writeFile(t, "changed payload")); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("releases/stable"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	got := entries[0]
	if got.Name != entry.Name || got.Digest != entry.Digest || got.Size != entry.Size || !got.CreatedAt.Equal(entry.CreatedAt) {
		t.Fatalf("restored metadata mismatch:\n got %+v\nwant %+v", got, entry)
	}
	output := filepath.Join(t.TempDir(), "app.bin")
	if err := store.Get("releases/app.bin", output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "payload bytes" {
		t.Fatalf("restored content=%q", data)
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
