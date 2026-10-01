package vault

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPutGetAndVerify(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	input := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(input, []byte("release payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := New(root)
	entry, err := store.Put("releases/app.txt", input)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Size != 16 {
		t.Fatalf("size=%d", entry.Size)
	}
	output := filepath.Join(t.TempDir(), "output.txt")
	if err := store.Get(entry.Name, output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "release payload\n" {
		t.Fatalf("content=%q", got)
	}
	if count, err := store.Verify(); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestRejectsEscapingName(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	if _, err := store.Put("../escape", "missing"); err == nil {
		t.Fatal("expected invalid name error")
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func putString(t *testing.T, store *Store, name, content string) Entry {
	t.Helper()
	dir := t.TempDir()
	path := writeFile(t, dir, "input.txt", content)
	entry, err := store.Put(name, path)
	if err != nil {
		t.Fatalf("put %q: %v", name, err)
	}
	return entry
}

func TestSnapshotCreateListRestore(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	e1 := putString(t, store, "a.txt", "aaa")
	e2 := putString(t, store, "dir/b.txt", "bbb")

	snap, err := store.CreateSnapshot("v1")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Name != "v1" || len(snap.Entries) != 2 {
		t.Fatalf("snapshot=%+v", snap)
	}

	// Overwrite a.txt and add c.txt after the snapshot.
	putString(t, store, "a.txt", "aaa-overwritten")
	putString(t, store, "c.txt", "ccc")

	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "v1" || infos[0].Entries != 2 {
		t.Fatalf("infos=%+v", infos)
	}

	if err := store.RestoreSnapshot("v1"); err != nil {
		t.Fatal(err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%+v", entries)
	}
	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	// c.txt must be gone; a.txt must have its original metadata.
	if _, ok := byName["c.txt"]; ok {
		t.Fatal("c.txt should not survive restore")
	}
	gotA, ok := byName["a.txt"]
	if !ok {
		t.Fatal("a.txt missing after restore")
	}
	if gotA.Digest != e1.Digest || gotA.Size != e1.Size || !gotA.CreatedAt.Equal(e1.CreatedAt) {
		t.Fatalf("a.txt metadata changed: %+v vs %+v", gotA, e1)
	}
	gotB := byName["dir/b.txt"]
	if gotB.Digest != e2.Digest || gotB.Size != e2.Size {
		t.Fatalf("b.txt metadata changed: %+v vs %+v", gotB, e2)
	}

	// Restored content is the original content.
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := store.Get("a.txt", output); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(output)
	if string(got) != "aaa" {
		t.Fatalf("content=%q", got)
	}

	// Objects are retained and the snapshot is still there.
	if count, err := store.Verify(); err != nil || count != 2 {
		t.Fatalf("verify count=%d err=%v", count, err)
	}
	infos, err = store.ListSnapshots()
	if err != nil || len(infos) != 1 {
		t.Fatalf("snapshots after restore: %+v err=%v", infos, err)
	}
}

func TestSnapshotSurvivesLaterOverwrite(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	original := putString(t, store, "app.bin", "v1-content")
	if _, err := store.CreateSnapshot("v1"); err != nil {
		t.Fatal(err)
	}
	putString(t, store, "app.bin", "v2-content-much-longer")

	// Snapshot still records the original digest and size.
	snap, err := store.loadSnapshot("v1")
	if err != nil {
		t.Fatal(err)
	}
	record := snap.Entries["app.bin"]
	if record.Digest != original.Digest || record.Size != original.Size {
		t.Fatalf("snapshot mutated: %+v vs %+v", record, original)
	}

	// Restore brings back the original content.
	if err := store.RestoreSnapshot("v1"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "app.bin")
	if err := store.Get("app.bin", output); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(output)
	if string(got) != "v1-content" {
		t.Fatalf("content=%q", got)
	}
}

func TestSnapshotEmptyRepo(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
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
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "empty" || infos[0].Entries != 0 {
		t.Fatalf("infos=%+v", infos)
	}
	if err := store.RestoreSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestSnapshotListEmptyAndSorted(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 0 {
		t.Fatalf("expected empty list, got %+v", infos)
	}
	putString(t, store, "a", "1")
	for _, name := range []string{"z", "a", "m"} {
		if _, err := store.CreateSnapshot(name); err != nil {
			t.Fatal(err)
		}
	}
	infos, err = store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "m", "z"}
	if len(infos) != 3 {
		t.Fatalf("infos=%+v", infos)
	}
	for i, w := range want {
		if infos[i].Name != w {
			t.Fatalf("infos=%+v, want order %v", infos, want)
		}
	}
}

func TestSnapshotCreateErrors(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "1")

	if _, err := store.CreateSnapshot(""); err == nil {
		t.Fatal("expected error for missing name")
	}
	if _, err := store.CreateSnapshot("../escape"); err == nil {
		t.Fatal("expected error for illegal name")
	}
	if _, err := store.CreateSnapshot("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("a"); err == nil {
		t.Fatal("expected error for duplicate snapshot")
	}
	// Failed create must not leave a snapshot behind.
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "a" {
		t.Fatalf("infos=%+v", infos)
	}
}

func TestSnapshotRestoreMissing(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "1")
	if err := store.RestoreSnapshot("nope"); err == nil {
		t.Fatal("expected error for missing snapshot")
	}
	if err := store.RestoreSnapshot("../escape"); err == nil {
		t.Fatal("expected error for illegal name")
	}
}

func TestSnapshotRestoreRejectsCorruptedRecords(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "1")
	if _, err := store.CreateSnapshot("v1"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"bad digest", func(s *Snapshot) {
			e := s.Entries["a"]
			e.Digest = "zz" + e.Digest[2:]
			s.Entries["a"] = e
		}},
		{"short digest", func(s *Snapshot) {
			e := s.Entries["a"]
			e.Digest = "abcdef"
			s.Entries["a"] = e
		}},
		{"uppercase digest", func(s *Snapshot) {
			e := s.Entries["a"]
			e.Digest = "A" + e.Digest[1:]
			s.Entries["a"] = e
		}},
		{"negative size", func(s *Snapshot) {
			e := s.Entries["a"]
			e.Size = -1
			s.Entries["a"] = e
		}},
		{"illegal name", func(s *Snapshot) {
			e := s.Entries["a"]
			delete(s.Entries, "a")
			e.Name = "../escape"
			s.Entries["../escape"] = e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap, err := store.loadSnapshot("v1")
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&snap)
			if err := store.saveSnapshot(snap); err != nil {
				t.Fatal(err)
			}
			if err := store.RestoreSnapshot("v1"); err == nil {
				t.Fatalf("expected restore error for %s", tc.name)
			}
			// Current mapping must be untouched.
			entries, err := store.List()
			if err != nil || len(entries) != 1 {
				t.Fatalf("mapping changed after failed restore: %+v err=%v", entries, err)
			}
		})
	}
}

func TestSnapshotRestoreDetectsObjectTampering(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "original")
	if _, err := store.CreateSnapshot("v1"); err != nil {
		t.Fatal(err)
	}
	putString(t, store, "b", "keep-me")

	snap, err := store.loadSnapshot("v1")
	if err != nil {
		t.Fatal(err)
	}
	obj := store.objectPath(snap.Entries["a"].Digest)

	// Replace the object with different content (same size).
	if err := os.WriteFile(obj, []byte("X"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("v1"); err == nil {
		t.Fatal("expected digest mismatch error")
	}

	// Restore the object, then delete it entirely.
	if err := os.WriteFile(obj, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(obj); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("v1"); err == nil {
		t.Fatal("expected missing object error")
	}

	// Current mapping and snapshot survive the failed restores.
	entries, err := store.List()
	if err != nil || len(entries) != 2 {
		t.Fatalf("mapping changed: %+v err=%v", entries, err)
	}
	infos, err := store.ListSnapshots()
	if err != nil || len(infos) != 1 {
		t.Fatalf("snapshots changed: %+v err=%v", infos, err)
	}
}

func TestSnapshotRestoreWithCorruptedIndex(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "alpha")
	putString(t, store, "b", "beta")
	if _, err := store.CreateSnapshot("v1"); err != nil {
		t.Fatal(err)
	}
	putString(t, store, "c", "gamma")

	// Corrupt the current index file.
	if err := os.WriteFile(store.indexPath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Restore must not need the current index.
	if err := store.RestoreSnapshot("v1"); err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%+v", entries)
	}
	output := filepath.Join(t.TempDir(), "a")
	if err := store.Get("a", output); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(output)
	if string(got) != "alpha" {
		t.Fatalf("content=%q", got)
	}
}

func TestSnapshotCreateFailsOnCorruptedIndex(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "1")
	if err := os.WriteFile(store.indexPath(), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("v1"); err == nil {
		t.Fatal("expected error for corrupted index")
	}
	infos, err := store.ListSnapshots()
	if err != nil || len(infos) != 0 {
		t.Fatalf("no snapshot should exist, got %+v err=%v", infos, err)
	}
}

func TestConcurrentPutsAllPreserved(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dir := t.TempDir()
			path := writeFile(t, dir, "input.txt", "payload")
			name := filepath.ToSlash(filepath.Join("dir", string(rune('a'+i%26)), string(rune('a'+(i/26)%26))))
			if _, err := store.Put(name, path); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != n {
		t.Fatalf("expected %d entries, got %d", n, len(entries))
	}
}

func TestSnapshotConcurrentWithPuts(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "1")
	if _, err := store.CreateSnapshot("v1"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			dir := t.TempDir()
			path := writeFile(t, dir, "input.txt", "new")
			_, _ = store.Put("a", path)
		}(i)
		go func() {
			defer wg.Done()
			_ = store.RestoreSnapshot("v1")
		}()
	}
	wg.Wait()

	// Final state must be consistent: either the snapshot (a=1) or a put
	// result (a=new), never a torn mapping, and the snapshot must be intact.
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%+v", entries)
	}
	output := filepath.Join(t.TempDir(), "a")
	if err := store.Get("a", output); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(output)
	if string(got) != "1" && string(got) != "new" {
		t.Fatalf("torn content=%q", got)
	}
	infos, err := store.ListSnapshots()
	if err != nil || len(infos) != 1 {
		t.Fatalf("snapshots=%+v err=%v", infos, err)
	}
}

func TestSnapshotNameWithSlash(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "vault"))
	putString(t, store, "a", "1")
	if _, err := store.CreateSnapshot("releases/v1"); err != nil {
		t.Fatal(err)
	}
	infos, err := store.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "releases/v1" {
		t.Fatalf("infos=%+v", infos)
	}
	if err := store.RestoreSnapshot("releases/v1"); err != nil {
		t.Fatal(err)
	}
}
