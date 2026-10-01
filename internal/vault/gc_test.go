package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func objectExists(root, digest string) bool {
	_, err := os.Lstat(filepath.Join(root, "objects", digest))
	return err == nil
}

func TestGCCollectsOverwrittenAndOrphanedObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	d1 := digestOf("one")
	d2 := digestOf("two")
	d3 := digestOf("three")

	if _, err := store.Put("a.txt", writeFile(t, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap/one"); err != nil {
		t.Fatal(err)
	}
	// Overwrite a.txt; d1 survives only through the snapshot.
	if _, err := store.Put("a.txt", writeFile(t, "two")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", writeFile(t, "three")); err != nil {
		t.Fatal(err)
	}
	// Restore drops b.txt and the overwritten version from the mapping.
	if err := store.RestoreSnapshot("snap/one"); err != nil {
		t.Fatal(err)
	}

	dry, err := store.GC(true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{d2, d3}
	if d3 < d2 {
		want = []string{d3, d2}
	}
	if len(dry.Candidates) != 2 {
		t.Fatalf("dry-run candidates=%+v", dry.Candidates)
	}
	for i, candidate := range dry.Candidates {
		if candidate.Digest != want[i] {
			t.Fatalf("candidates[%d]=%q, want %q", i, candidate.Digest, want[i])
		}
	}
	if dry.Deleted != 0 || dry.Bytes != 0 {
		t.Fatalf("dry run deleted %d objects, %d bytes", dry.Deleted, dry.Bytes)
	}
	// Dry run deletes nothing.
	for _, digest := range []string{d1, d2, d3} {
		if !objectExists(root, digest) {
			t.Fatalf("dry run removed object %s", digest)
		}
	}

	report, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 2 || report.Bytes != int64(len("two")+len("three")) {
		t.Fatalf("deleted=%d bytes=%d", report.Deleted, report.Bytes)
	}
	if objectExists(root, d2) || objectExists(root, d3) {
		t.Fatal("unreferenced objects survived GC")
	}
	// The snapshot-only object is kept and the snapshot still restores.
	if !objectExists(root, d1) {
		t.Fatal("snapshot-referenced object was collected")
	}
	if err := New(root).RestoreSnapshot("snap/one"); err != nil {
		t.Fatal(err)
	}
	// A second pass finds nothing.
	again, err := New(root).GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if again.Deleted != 0 || again.Bytes != 0 || len(again.Candidates) != 0 {
		t.Fatalf("second GC: %+v", again)
	}
}

func TestGCKeepsObjectsReferencedOnlyByNestedSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	d1 := digestOf("one")
	d2 := digestOf("two")
	d3 := digestOf("three")
	if _, err := store.Put("a.txt", writeFile(t, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("deep/nested/snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", writeFile(t, "two")); err != nil {
		t.Fatal(err)
	}
	// d1 is now referenced only by the nested snapshot, d2 by the index:
	// nothing may be collected.
	report, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 0 || !objectExists(root, d1) || !objectExists(root, d2) {
		t.Fatalf("deleted=%d d1=%v d2=%v", report.Deleted, objectExists(root, d1), objectExists(root, d2))
	}
	// Overwrite again: d2 loses its last reference and is collected, while
	// d1 is still protected by the snapshot.
	if _, err := store.Put("a.txt", writeFile(t, "three")); err != nil {
		t.Fatal(err)
	}
	report, err = store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 || !objectExists(root, d1) || objectExists(root, d2) || !objectExists(root, d3) {
		t.Fatalf("deleted=%d d1=%v d2=%v d3=%v", report.Deleted,
			objectExists(root, d1), objectExists(root, d2), objectExists(root, d3))
	}
	if err := store.RestoreSnapshot("deep/nested/snap"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := store.Get("a.txt", output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one" {
		t.Fatalf("content=%q", got)
	}
}

func TestGCSharedDigestIsOneObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	shared := digestOf("same payload")
	input := writeFile(t, "same payload")
	for _, name := range []string{"a.txt", "b.txt"} {
		if _, err := store.Put(name, input); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateSnapshot("both"); err != nil {
		t.Fatal(err)
	}
	// Referenced: nothing to collect.
	report, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 0 {
		t.Fatalf("deleted=%d", report.Deleted)
	}
	// Drop both names (restore an empty mapping) so the shared object is
	// unreferenced: it is collected exactly once.
	empty := `{"name":"empty","entries":{}}` + "\n"
	if err := os.WriteFile(filepath.Join(root, "snapshots", "empty.json"), []byte(empty), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "snapshots", "both.json")); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	report, err = store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 || report.Bytes != int64(len("same payload")) {
		t.Fatalf("deleted=%d bytes=%d", report.Deleted, report.Bytes)
	}
	if objectExists(root, shared) {
		t.Fatal("shared object survived")
	}
}

func TestGCEmptyRepositoryAndIdempotence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for _, dryRun := range []bool{true, false} {
		report, err := store.GC(dryRun)
		if err != nil {
			t.Fatal(err)
		}
		if report.Deleted != 0 || report.Bytes != 0 || len(report.Candidates) != 0 {
			t.Fatalf("dryRun=%v report=%+v", dryRun, report)
		}
	}
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Reopening the repository must not turn retained objects into candidates.
	report, err := New(root).GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 0 || len(report.Candidates) != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestGCCollectsEmptyObjectAsZeroBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("empty.txt", writeFile(t, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("empty.txt", writeFile(t, "nonempty")); err != nil {
		t.Fatal(err)
	}
	report, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 || report.Bytes != 0 {
		t.Fatalf("deleted=%d bytes=%d", report.Deleted, report.Bytes)
	}
}

func TestGCRequiresExistingInitializedRepository(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "vault")
	if _, err := New(missing).GC(false); err == nil {
		t.Fatal("expected error for missing root")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("GC created the missing root")
	}
	// Root exists but was never initialized.
	empty := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(empty).GC(false); err == nil {
		t.Fatal("expected error for uninitialized root")
	}
	if _, err := os.Stat(filepath.Join(empty, "index.json")); !os.IsNotExist(err) {
		t.Fatal("GC initialized the repository")
	}
}

func TestGCLeavesForeignFilesAlone(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("a.txt", writeFile(t, "keep"))
	if err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(root, "objects")
	stray := digestOf("stray garbage")
	for name, content := range map[string]string{
		".upload-123": "partial upload",
		"notadigest":  "mystery file",
		stray:         "unreferenced but valid digest name",
	} {
		if err := os.WriteFile(filepath.Join(objects, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(objects, "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(entry.Digest, filepath.Join(objects, digestOf("symlink"))); err != nil {
		t.Fatal(err)
	}
	report, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 || report.Bytes != int64(len("unreferenced but valid digest name")) {
		t.Fatalf("deleted=%d bytes=%d", report.Deleted, report.Bytes)
	}
	for _, name := range []string{".upload-123", "notadigest", "subdir", digestOf("symlink"), entry.Digest} {
		if _, err := os.Lstat(filepath.Join(objects, name)); err != nil {
			t.Fatalf("%s was touched: %v", name, err)
		}
	}
	if objectExists(root, stray) {
		t.Fatal("stray digest-named object survived")
	}
}

func TestGCDoesNotRewriteIndexSnapshotsOrKeptObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("a.txt", writeFile(t, "precious"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", writeFile(t, "garbage")); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	indexBefore, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapBefore, err := os.ReadFile(filepath.Join(root, "snapshots", "snap.json"))
	if err != nil {
		t.Fatal(err)
	}
	objectBefore, err := os.ReadFile(filepath.Join(root, "objects", entry.Digest))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string][]byte{
		filepath.Join(root, "index.json"):             indexBefore,
		filepath.Join(root, "snapshots", "snap.json"): snapBefore,
		filepath.Join(root, "objects", entry.Digest):  objectBefore,
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s changed across GC", path)
		}
	}
}

func TestGCRejectsCorruptReferences(t *testing.T) {
	goodDigest := digestOf("good")
	cases := map[string]struct {
		index    string
		snapName string
		snap     string
	}{
		"index bad json":      {index: `{broken`},
		"index no entries":    {index: `{}`},
		"index null entries":  {index: `{"entries":null}`},
		"index key mismatch":  {index: `{"entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`},
		"index bad name":      {index: `{"entries":{"../x":{"name":"../x","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`},
		"index bad digest":    {index: `{"entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`},
		"index negative size": {index: `{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`},
		"snap bad json":       {snapName: "s", snap: `{broken`},
		"snap no entries":     {snapName: "s", snap: `{"name":"s"}`},
		"snap name mismatch":  {snapName: "s", snap: `{"name":"other","entries":{}}`},
		"snap nested mismatch": {snapName: "deep/s",
			snap: `{"name":"s","entries":{}}`},
		"snap bad entry": {snapName: "s",
			snap: `{"name":"s","entries":{"a":{"name":"a","digest":"zzz","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			entry, err := store.Put("keep.txt", writeFile(t, "keep me"))
			if err != nil {
				t.Fatal(err)
			}
			// An unreferenced object that must survive the failed pass.
			stray := digestOf("stray")
			if err := os.WriteFile(filepath.Join(root, "objects", stray), []byte("stray"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.index != "" {
				if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(tc.index), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.snapName != "" {
				path := filepath.Join(root, "snapshots", filepath.FromSlash(tc.snapName)+".json")
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.snap), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, dryRun := range []bool{true, false} {
				if _, err := store.GC(dryRun); err == nil {
					t.Fatalf("dryRun=%v: expected error", dryRun)
				}
			}
			if !objectExists(root, stray) {
				t.Fatal("failed GC deleted an object")
			}
			if !objectExists(root, entry.Digest) {
				t.Fatal("failed GC deleted a referenced object")
			}
		})
	}
}

func TestGCRejectsSymlinks(t *testing.T) {
	t.Run("objects is a symlink", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		store := New(root)
		if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		if err := os.RemoveAll(filepath.Join(root, "objects")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(root, "objects")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GC(false); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("snapshots is a symlink", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		store := New(root)
		if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(root, "snapshots")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GC(true); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("symlink inside snapshots", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "vault")
		store := New(root)
		entry, err := store.Put("a.txt", writeFile(t, "data"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateSnapshot("real"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "snapshots", "real.json"), filepath.Join(root, "snapshots", "link.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GC(false); err == nil {
			t.Fatal("expected error")
		}
		if !objectExists(root, entry.Digest) {
			t.Fatal("referenced object deleted")
		}
	})
}

func TestConcurrentGCAndPutStayConsistent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("base.txt", writeFile(t, "base")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	const workers = 6
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			input := writeFile(t, fmt.Sprintf("payload-%d", i))
			if _, err := New(root).Put(fmt.Sprintf("artifact-%d.txt", i), input); err != nil {
				errs <- err
			}
		}(i)
		go func() {
			defer wg.Done()
			if _, err := New(root).GC(false); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Whatever the interleaving, every referenced object must be intact and
	// a final GC must find nothing or only genuinely orphaned objects.
	if _, err := store.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	report, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := New(root).GC(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Candidates) != 0 {
		t.Fatalf("candidates after GC: %+v (deleted %d)", again.Candidates, report.Deleted)
	}
}
