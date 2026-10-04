package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// helper: put several named files into a fresh store and return its root.
func seedVault(t *testing.T, files map[string]string) (string, *Store) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	for name, content := range files {
		if _, err := store.Put(name, writeFile(t, content)); err != nil {
			t.Fatal(err)
		}
	}
	return root, store
}

func mustExport(t *testing.T, root, name, base, out string) ExportResult {
	t.Helper()
	res, err := New(root).ExportSnapshot(name, base, out)
	if err != nil {
		t.Fatalf("export %s: %v", name, err)
	}
	return res
}

func assertEntriesAfterRestore(t *testing.T, root, snap string, want map[string]string) {
	t.Helper()
	store := New(root)
	if err := store.RestoreSnapshot(snap); err != nil {
		t.Fatalf("restore %s: %v", snap, err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		t.Fatalf("restore %s: %d entries, want %d (%+v)", snap, len(entries), len(want), entries)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Digest
	}
	for name, content := range want {
		d, ok := got[name]
		if !ok {
			t.Fatalf("restore %s: missing entry %q", snap, name)
		}
		if d != digestOf(content) {
			t.Fatalf("restore %s: entry %q digest %s, want %s", snap, name, d, digestOf(content))
		}
	}
}

func TestExportImportFullRoundTrip(t *testing.T) {
	src, _ := seedVault(t, map[string]string{
		"releases/app.txt": "version one\n",
		"docs/readme.txt":  "version one\n", // same digest, must be carried once
		"empty.txt":        "",
	})
	if _, err := New(src).CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snap.pkg")
	res := mustExport(t, src, "snap", "", out)
	if res.Entries != 3 || res.Objects != 2 {
		t.Fatalf("export result=%+v, want 3 entries 2 objects", res)
	}

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	ires, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatal(err)
	}
	if ires.Entries != 3 || ires.NewObjects != 2 {
		t.Fatalf("import result=%+v, want 3 entries 2 new objects", ires)
	}
	// A fresh store (simulating restart) lists and restores the snapshot.
	infos, err := New(dst).ListSnapshots()
	if err != nil || len(infos) != 1 || infos[0].Name != "snap" || infos[0].Count != 3 {
		t.Fatalf("infos=%+v err=%v", infos, err)
	}
	assertEntriesAfterRestore(t, dst, "snap", map[string]string{
		"releases/app.txt": "version one\n",
		"docs/readme.txt":  "version one\n",
		"empty.txt":        "",
	})
	// The zero-byte object really transferred.
	if !objectExists(dst, digestOf("")) {
		t.Fatal("empty content object missing after import")
	}
}

func TestExportImportDoesNotTouchCurrentMapping(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "alpha"})
	if _, err := New(src).CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "snap.pkg")
	mustExport(t, src, "snap", "", out)

	dst, dstStore := seedVault(t, map[string]string{"current.txt": "stays here"})
	if _, err := New(dst).ImportSnapshot(out); err != nil {
		t.Fatal(err)
	}
	entries, err := dstStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "current.txt" {
		t.Fatalf("current mapping changed by import: %+v", entries)
	}
}

func TestFullPackageImportsIntoEmptyInitializedVault(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload", "b.txt": "payload"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	if res := mustExport(t, src, "s", "", out); res.Objects != 1 {
		t.Fatalf("objects=%d, want 1 (dedup)", res.Objects)
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	ires, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatal(err)
	}
	if ires.NewObjects != 1 {
		t.Fatalf("new objects=%d, want 1", ires.NewObjects)
	}
	assertEntriesAfterRestore(t, dst, "s", map[string]string{"a.txt": "payload", "b.txt": "payload"})
}

func TestImportRequiresInitializedRepository(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "x"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)

	missing := filepath.Join(t.TempDir(), "vault")
	if _, err := New(missing).ImportSnapshot(out); err == nil {
		t.Fatal("import into missing root should fail")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("import created the missing root")
	}
	exists := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(exists, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(exists).ImportSnapshot(out); err == nil {
		t.Fatal("import into uninitialized root should fail")
	}
	if _, err := os.Stat(filepath.Join(exists, "index.json")); !os.IsNotExist(err) {
		t.Fatal("import initialized the repository")
	}
}

func TestIncrementalExportImport(t *testing.T) {
	src, srcStore := seedVault(t, map[string]string{
		"keep.txt":   "same",
		"change.txt": "old",
		"gone.txt":   "leaving",
	})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	// Evolve the mapping: overwrite change.txt, add new.txt, drop gone.txt.
	if _, err := New(src).Put("change.txt", writeFile(t, "new")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("new.txt", writeFile(t, "brand new")); err != nil {
		t.Fatal(err)
	}
	idx, err := srcStore.load()
	if err != nil {
		t.Fatal(err)
	}
	delete(idx.Entries, "gone.txt")
	target := Snapshot{Name: "target", Entries: idx.Entries}
	if err := srcStore.saveSnapshot(srcStore.snapshotPath("target"), target); err != nil {
		t.Fatal(err)
	}

	full := filepath.Join(t.TempDir(), "base.pkg")
	delta := filepath.Join(t.TempDir(), "target.pkg")
	if res := mustExport(t, src, "base", "", full); res.Objects != 3 {
		t.Fatalf("base objects=%d, want 3", res.Objects)
	}
	res := mustExport(t, src, "target", "base", delta)
	// Base digests: same, old, leaving. Target digests: same, new, brand new.
	// The delta carries the two non-base digests despite three entries.
	if res.Entries != 3 || res.Objects != 2 {
		t.Fatalf("delta result=%+v, want 3 entries 2 objects", res)
	}

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	// Delta without the base is refused.
	if _, err := New(dst).ImportSnapshot(delta); err == nil {
		t.Fatal("delta imported without a base snapshot")
	}
	if _, err := New(dst).ImportSnapshot(full); err != nil {
		t.Fatal(err)
	}
	ires, err := New(dst).ImportSnapshot(delta)
	if err != nil {
		t.Fatal(err)
	}
	if ires.NewObjects != 2 {
		t.Fatalf("delta new objects=%d, want 2", ires.NewObjects)
	}
	// Add, overwrite, and disappearance are all governed by the target mapping.
	assertEntriesAfterRestore(t, dst, "target", map[string]string{
		"keep.txt":   "same",
		"change.txt": "new",
		"new.txt":    "brand new",
	})
	// gone.txt must not be resurrected by restoring the target.
	entries, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "gone.txt" {
			t.Fatal("deleted name reappeared after restore")
		}
	}
}

func TestIncrementalRequiresExactBase(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "alpha", "b.txt": "beta"})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("a.txt", writeFile(t, "alpha2")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	delta := filepath.Join(t.TempDir(), "t.pkg")
	mustExport(t, src, "target", "base", delta)

	t.Run("same named snapshot with different metadata", func(t *testing.T) {
		dst := filepath.Join(t.TempDir(), "vault")
		if err := New(dst).Init(); err != nil {
			t.Fatal(err)
		}
		// Hand-write a "base" snapshot with different entries but referencing
		// an object that genuinely exists, so digest coincidence cannot help.
		if _, err := New(dst).Put("different.txt", writeFile(t, "other content")); err != nil {
			t.Fatal(err)
		}
		entries, err := New(dst).List()
		if err != nil {
			t.Fatal(err)
		}
		snap := Snapshot{Name: "base", Entries: map[string]Entry{}}
		for _, e := range entries {
			snap.Entries[e.Name] = e
		}
		if err := New(dst).saveSnapshot(New(dst).snapshotPath("base"), snap); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dst).ImportSnapshot(delta); err == nil {
			t.Fatal("delta accepted on a mismatched base")
		}
		// Nothing published, no target snapshot.
		if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 || infos[0].Name != "base" {
			t.Fatalf("snapshots after failed import: %+v", infos)
		}
	})

	t.Run("objects present but base snapshot absent", func(t *testing.T) {
		// A vault that happens to hold every needed digest via its own history
		// still lacks the named base snapshot and must be refused.
		dst, _ := seedVault(t, map[string]string{
			"x/a.txt": "alpha2",
			"y/b.txt": "beta",
		})
		if _, err := New(dst).ImportSnapshot(delta); err == nil {
			t.Fatal("delta accepted without named base snapshot")
		}
		if infos, _ := New(dst).ListSnapshots(); len(infos) != 0 {
			t.Fatalf("snapshots=%+v", infos)
		}
	})
}

// other2 writes distinct helper content to a temp file.
func other2(t *testing.T, content string) string {
	t.Helper()
	return writeFile(t, content)
}

func TestIncrementalBaseMissingObjectRejected(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "alpha", "b.txt": "beta"})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("a.txt", writeFile(t, "alpha2")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(t.TempDir(), "base.pkg")
	delta := filepath.Join(t.TempDir(), "target.pkg")
	mustExport(t, src, "base", "", full)
	mustExport(t, src, "target", "base", delta)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(full); err != nil {
		t.Fatal(err)
	}
	// Remove an object the delta omits: b.txt is unchanged between base and
	// target, so its object is not carried, and it must still be intact.
	if err := os.Remove(filepath.Join(dst, "objects", digestOf("beta"))); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(delta); err == nil {
		t.Fatal("delta accepted while an omitted object is missing")
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 {
		t.Fatalf("target snapshot published despite failed import: %+v", infos)
	}
}

func TestIdenticalSnapshotsExportAndImport(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "same"})
	if _, err := New(src).CreateSnapshot("one"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("two"); err != nil {
		t.Fatal(err)
	}
	o1 := filepath.Join(t.TempDir(), "one.pkg")
	o2 := filepath.Join(t.TempDir(), "two.pkg")
	r1 := mustExport(t, src, "one", "", o1)
	r2 := mustExport(t, src, "two", "one", o2)
	if r1.Objects != 1 || r2.Objects != 0 {
		t.Fatalf("full objects=%d, delta objects=%d, want 1 and 0", r1.Objects, r2.Objects)
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(o1); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(o2); err != nil {
		t.Fatal(err)
	}
	assertEntriesAfterRestore(t, dst, "two", map[string]string{"a.txt": "same"})
}

func TestExportEmptySnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).CreateSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "empty.pkg")
	res := mustExport(t, root, "empty", "", out)
	if res.Entries != 0 || res.Objects != 0 {
		t.Fatalf("result=%+v", res)
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	ires, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatal(err)
	}
	if ires.Entries != 0 || ires.NewObjects != 0 {
		t.Fatalf("import result=%+v", ires)
	}
	if err := New(dst).RestoreSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	if entries, err := New(dst).List(); err != nil || len(entries) != 0 {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
}

func TestReimportIdenticalSnapshotAddsNoCopies(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(out); err != nil {
		t.Fatal(err)
	}
	again, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatalf("repeat import failed: %v", err)
	}
	if again.NewObjects != 0 {
		t.Fatalf("repeat import added %d objects", again.NewObjects)
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 {
		t.Fatalf("snapshots=%+v", infos)
	}
}

func TestReimportRepairsMissingObject(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload", "b.txt": "other"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(out); err != nil {
		t.Fatal(err)
	}
	// Lose an object the published snapshot references, then re-import: the
	// package carries it, so it is staged again and the snapshot restores.
	lost := digestOf("other")
	if err := os.Remove(filepath.Join(dst, "objects", lost)); err != nil {
		t.Fatal(err)
	}
	res, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatalf("repair import failed: %v", err)
	}
	if res.NewObjects != 1 {
		t.Fatalf("new objects=%d, want 1", res.NewObjects)
	}
	assertEntriesAfterRestore(t, dst, "s", map[string]string{"a.txt": "payload", "b.txt": "other"})
}

func TestIncrementalImportNamesCorruptBaseObject(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "alpha", "b.txt": "beta"})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("a.txt", writeFile(t, "alpha2")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(t.TempDir(), "base.pkg")
	delta := filepath.Join(t.TempDir(), "target.pkg")
	mustExport(t, src, "base", "", full)
	mustExport(t, src, "target", "base", delta)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(full); err != nil {
		t.Fatal(err)
	}
	// Damage a base object the delta omits; import must fail and name it.
	if err := os.WriteFile(filepath.Join(dst, "objects", digestOf("beta")), []byte("X"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New(dst).ImportSnapshot(delta)
	if err == nil || !strings.Contains(err.Error(), digestOf("beta")) {
		t.Fatalf("expected error naming object %s, got %v", digestOf("beta"), err)
	}
}

func TestImportRejectsSameNameDifferentSnapshot(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s1.pkg")
	mustExport(t, src, "s", "", out)

	dst, _ := seedVault(t, map[string]string{"a.txt": "different payload"})
	if _, err := New(dst).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(out); err == nil {
		t.Fatal("import overwrote a same-named snapshot")
	}
	// Existing snapshot and mapping survive and still restore their own data.
	assertEntriesAfterRestore(t, dst, "s", map[string]string{"a.txt": "different payload"})
}

func TestImportReusesExistingHealthyObjects(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload", "b.txt": "other"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)

	// Destination already holds one of the two objects through its own history.
	dst, _ := seedVault(t, map[string]string{"mine.txt": "payload"})
	ires, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatal(err)
	}
	if ires.NewObjects != 1 {
		t.Fatalf("new objects=%d, want 1 (reuse)", ires.NewObjects)
	}
	assertEntriesAfterRestore(t, dst, "s", map[string]string{"a.txt": "payload", "b.txt": "other"})
}

func TestImportRejectsCorruptExistingObject(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dst, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-create a damaged object at the digest the package wants to reuse.
	damaged := filepath.Join(dst, "objects", digestOf("payload"))
	if err := os.WriteFile(damaged, []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := New(dst).ImportSnapshot(out)
	if err == nil || !strings.Contains(err.Error(), digestOf("payload")) {
		t.Fatalf("expected error naming the damaged object %s, got %v", digestOf("payload"), err)
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 0 {
		t.Fatalf("snapshot published despite damaged object: %+v", infos)
	}
}

func TestExportVerifiesAllObjectsIncludingDeltaOmitted(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "alpha", "b.txt": "beta"})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("a.txt", writeFile(t, "alpha2")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "target.pkg")
	// Corrupt an object the target still references (b.txt, omitted from delta).
	damaged := filepath.Join(src, "objects", digestOf("beta"))
	good, err := os.ReadFile(damaged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(damaged, []byte("TAMPERED"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).ExportSnapshot("target", "base", out); err == nil {
		t.Fatal("export succeeded with a corrupt referenced object")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed export left an output file behind")
	}
	if err := os.WriteFile(damaged, good, 0o644); err != nil {
		t.Fatal(err)
	}
	mustExport(t, src, "target", "base", out)
}

func TestExportFailureLeavesExistingOutputUntouched(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "alpha"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)
	sentinel, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the only object; re-export must fail and keep the old package.
	if err := os.WriteFile(filepath.Join(src, "objects", digestOf("alpha")), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).ExportSnapshot("s", "", out); err == nil {
		t.Fatal("export should have failed")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(sentinel) {
		t.Fatal("failed export overwrote the existing package")
	}
}

func TestExportRejectsCorruptSnapshotRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	record := `{"name":"bad","entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}` + "\n"
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshots", "bad.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bad.pkg")
	if _, err := New(root).ExportSnapshot("bad", "", out); err == nil {
		t.Fatal("export of corrupt snapshot succeeded")
	}
}

func TestImportedObjectsAreGCProtected(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "only-in-snapshot"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(out); err != nil {
		t.Fatal(err)
	}
	// Current mapping is empty; the object survives only via the snapshot.
	report, err := New(dst).GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 0 || !objectExists(dst, digestOf("only-in-snapshot")) {
		t.Fatalf("gc removed an imported snapshot's object: %+v", report)
	}
}

func TestDecodePackageRejectsMalformedDocuments(t *testing.T) {
	d := digestOf("payload")
	goodObj := PackageObject{
		Digest: d,
		Size:   int64(len("payload")),
		Data:   base64.StdEncoding.EncodeToString([]byte("payload")),
	}
	goodSnap := Snapshot{Name: "s", Entries: map[string]Entry{
		"a.txt": {Name: "a.txt", Digest: d, Size: int64(len("payload")), CreatedAt: stamp},
	}}
	encode := func(pkg Package) []byte {
		data, err := json.Marshal(&pkg)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	base := func() Package {
		return Package{
			Format:   packageFormat,
			Version:  packageVersion,
			Snapshot: goodSnap,
			Objects:  []PackageObject{goodObj},
		}
	}

	cases := map[string]func() Package{
		"unknown version": func() Package {
			p := base()
			p.Version = 99
			return p
		},
		"unknown format": func() Package {
			p := base()
			p.Format = "something-else"
			return p
		},
		"bad snapshot name": func() Package {
			p := base()
			p.Snapshot = Snapshot{Name: "../escape", Entries: map[string]Entry{
				"../escape": {Name: "../escape", Digest: d, Size: 7, CreatedAt: stamp},
			}}
			return p
		},
		"bad entry name": func() Package {
			p := base()
			p.Snapshot.Entries["a.txt"] = Entry{Name: "b.txt", Digest: d, Size: 7, CreatedAt: stamp}
			return p
		},
		"bad digest": func() Package {
			p := base()
			p.Objects[0].Digest = strings.Repeat("z", 64)
			return p
		},
		"negative size": func() Package {
			p := base()
			p.Objects[0].Size = -1
			return p
		},
		"checksum mismatch": func() Package {
			p := base()
			p.Objects[0].Digest = digestOf("other")
			return p
		},
		"declared size mismatch": func() Package {
			p := base()
			p.Objects[0].Size = 999
			return p
		},
		"bad base64": func() Package {
			p := base()
			p.Objects[0].Data = "!!!not base64!!!"
			return p
		},
		"missing content": func() Package {
			p := base()
			p.Objects = []PackageObject{}
			return p
		},
		"extra object": func() Package {
			p := base()
			p.Objects = append(p.Objects, PackageObject{
				Digest: digestOf("extra"), Size: 5,
				Data: base64.StdEncoding.EncodeToString([]byte("extra")),
			})
			return p
		},
		"duplicate object": func() Package {
			p := base()
			p.Objects = append(p.Objects, goodObj)
			return p
		},
	}
	for label, build := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := decodePackage(encode(build())); err == nil {
				t.Fatalf("decode accepted %s", label)
			}
		})
	}

	t.Run("duplicate json key", func(t *testing.T) {
		bad := strings.Replace(string(encode(base())), `"version":1`, `"version":1,"version":1`, 1)
		if _, err := decodePackage([]byte(bad)); err == nil {
			t.Fatal("duplicate JSON key accepted")
		}
	})
	t.Run("unknown top-level field", func(t *testing.T) {
		bad := strings.Replace(string(encode(base())), `"version":1`, `"version":1,"sneaky":true`, 1)
		if _, err := decodePackage([]byte(bad)); err == nil {
			t.Fatal("unknown field accepted")
		}
	})
}

// stamp is a fixed creation time used to build test package records.
var stamp = func() time.Time {
	t, err := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	if err != nil {
		panic(err)
	}
	return t
}()

func TestImportRejectsMalformedPackageWithoutSideEffects(t *testing.T) {
	dst, _ := seedVault(t, map[string]string{"keep.txt": "keep"})
	before, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{
		`{not json`,
		`{"format":"artifact-vault-snapshot","version":999}`,
		`{"format":"artifact-vault-snapshot","version":1,"snapshot":{"name":"s","entries":{}}}`,
	} {
		path := filepath.Join(t.TempDir(), "bad.pkg")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := New(dst).ImportSnapshot(path); err == nil {
			t.Fatalf("import accepted %q", content)
		}
	}
	after, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0].Name != "keep.txt" {
		t.Fatalf("mapping changed after failed imports: %+v", after)
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 0 {
		t.Fatalf("snapshots=%+v", infos)
	}
}

func TestImportLeavesOnlyUnreferencedObjectsOnRetry(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	// Pre-create a valid digest-named object that the import would stage,
	// simulating a previous interrupted attempt: retry must reuse and finish.
	obj := digestOf("payload")
	if err := os.MkdirAll(filepath.Join(dst, "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "objects", obj), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	ires, err := New(dst).ImportSnapshot(out)
	if err != nil {
		t.Fatal(err)
	}
	if ires.NewObjects != 0 {
		t.Fatalf("new objects=%d, want 0 (staged object reused)", ires.NewObjects)
	}
	assertEntriesAfterRestore(t, dst, "s", map[string]string{"a.txt": "payload"})
}

func TestConcurrentImportExportGCObserveCompleteSnapshots(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"base.txt": "base"})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	const n = 6
	pkgs := make([]string, n)
	for i := 0; i < n; i++ {
		content := fmt.Sprintf("payload-%d", i)
		name := fmt.Sprintf("art-%d.txt", i)
		if _, err := New(src).Put(name, writeFile(t, content)); err != nil {
			t.Fatal(err)
		}
		snap := fmt.Sprintf("snap-%d", i)
		if _, err := New(src).CreateSnapshot(snap); err != nil {
			t.Fatal(err)
		}
		pkgs[i] = filepath.Join(t.TempDir(), snap+".pkg")
		mustExport(t, src, snap, "", pkgs[i])
	}

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		wg.Add(2)
		pkg := pkgs[i]
		go func() {
			defer wg.Done()
			if _, err := New(dst).ImportSnapshot(pkg); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := New(dst).GC(false); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Every imported snapshot must list and restore with all objects intact.
	infos, err := New(dst).ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != n {
		t.Fatalf("snapshots=%d, want %d: %+v", len(infos), n, infos)
	}
	for i := 0; i < n; i++ {
		snap := fmt.Sprintf("snap-%d", i)
		if err := New(dst).RestoreSnapshot(snap); err != nil {
			t.Fatalf("restore %s: %v", snap, err)
		}
	}
	if _, err := New(dst).Verify(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentExportsObserveCompleteSnapshots(t *testing.T) {
	root, _ := seedVault(t, map[string]string{"a.txt": "alpha", "b.txt": "beta"})
	if _, err := New(root).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	const n = 6
	var wg sync.WaitGroup
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		wg.Add(2)
		i := i
		go func() {
			defer wg.Done()
			// Concurrent upload never exposes a half-written object to export.
			if _, err := New(root).Put(fmt.Sprintf("art-%d.txt", i), writeFile(t, fmt.Sprintf("p%d", i))); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			out := filepath.Join(t.TempDir(), fmt.Sprintf("base-%d.pkg", i))
			if _, err := New(root).ExportSnapshot("base", "", out); err != nil {
				errs <- err
			}
			// Every produced package must import and restore cleanly.
			dst := filepath.Join(t.TempDir(), "vault")
			if err := New(dst).Init(); err != nil {
				errs <- err
				return
			}
			if _, err := New(dst).ImportSnapshot(out); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestImportRefusesSymlinkedSnapshotSubdir(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(src).CreateSnapshot("evil/snap"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "evil/snap", "", out)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dst, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dst, "snapshots", "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(out); err == nil {
		t.Fatal("import followed a symlinked snapshot subdirectory")
	}
	if _, err := os.Stat(filepath.Join(outside, "snap.json")); !os.IsNotExist(err) {
		t.Fatal("import wrote outside the repository through a symlink")
	}
}

// carriedObject builds a package object record carrying content verbatim.
func carriedObject(content string) PackageObject {
	return PackageObject{
		Digest: digestOf(content),
		Size:   int64(len(content)),
		Data:   base64.StdEncoding.EncodeToString([]byte(content)),
	}
}

// entryRecord builds one snapshot entry; size is taken explicitly so tests can
// record a size that disagrees with the content.
func entryRecord(name, content string, size int64) Entry {
	return Entry{Name: name, Digest: digestOf(content), Size: size, CreatedAt: stamp}
}

// writePackage serializes a package to a temporary file and returns its path.
func writePackage(t *testing.T, pkg Package) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "package.vaultpkg")
	data, err := json.Marshal(&pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// countRegularFiles returns how many regular files (of any name) live beneath
// dir, and the number of import/snapshot-style temporary leftovers in root.
func inspectRepositoryFiles(t *testing.T, root string) (objects int, tempFiles int) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, ".import-") || strings.HasPrefix(base, ".snapshot-") ||
			strings.HasPrefix(base, ".upload-") || strings.HasPrefix(base, ".index-") {
			tempFiles++
		}
		if filepath.Dir(path) == filepath.Join(root, "objects") && info.Mode().IsRegular() {
			objects++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return objects, tempFiles
}

// TestImportRejectsRecordSizeMismatchWithoutAnyNewObject is the headline
// failure: carried content really is 7 bytes and the object record says 7, but
// the target snapshot writes 8 for the artifact. Even though a second object
// in the same package is perfectly correct, the whole package is refused and
// neither object is installed, so the failed import adds nothing to the
// repository.
func TestImportRejectsRecordSizeMismatchWithoutAnyNewObject(t *testing.T) {
	bad := "payload" // 7 actual bytes
	good := "other"  // 5 bytes, carried correctly
	pkg := Package{
		Format:  packageFormat,
		Version: packageVersion,
		Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{
			"bad.txt":  entryRecord("bad.txt", bad, 8),
			"good.txt": entryRecord("good.txt", good, int64(len(good))),
		}},
		Objects: []PackageObject{carriedObject(bad), carriedObject(good)},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	before, beforeTemp := inspectRepositoryFiles(t, dst)

	res, err := New(dst).ImportSnapshot(writePackage(t, pkg))
	if err == nil {
		t.Fatal("import accepted a snapshot record whose size disagrees with the content")
	}
	// The failure identifies target snapshot, artifact, content digest, the
	// recorded size, and the actual byte count ...
	msg := err.Error()
	for _, want := range []string{`snapshot "s"`, "bad.txt", digestOf(bad), "is 7 bytes", "record says 8"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
	// ... and reads as a corrupt *record*, distinct from a checksum failure.
	if !strings.Contains(msg, "record for \"bad.txt\" is corrupt") || strings.Contains(msg, "checksum") {
		t.Fatalf("size mismatch must be reported as record corruption, got %q", msg)
	}
	// The Go result is unusable.
	if res != (ImportResult{}) {
		t.Fatalf("failed import returned a usable result: %+v", res)
	}
	// No snapshot published, no new content object (correct or incorrect), no
	// temporary file left behind.
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 0 {
		t.Fatalf("snapshots after failed import: %+v", infos)
	}
	after, afterTemp := inspectRepositoryFiles(t, dst)
	if after != before || afterTemp != beforeTemp {
		t.Fatalf("failed import changed repository files: objects %d->%d, temp %d->%d", before, after, beforeTemp, afterTemp)
	}
	if objectExists(dst, digestOf(bad)) || objectExists(dst, digestOf(good)) {
		t.Fatal("failed import installed a content object without a snapshot reference")
	}
}

// TestImportSizeMismatchChecksEveryNameSharingContent makes sure one digest
// referenced by two artifact names is checked under both names: a record that
// agrees on the size passes for its name and the disagreeing one is named.
func TestImportSizeMismatchChecksEveryNameSharingContent(t *testing.T) {
	content := "payload"
	pkg := Package{
		Format:  packageFormat,
		Version: packageVersion,
		Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{
			"a.txt": entryRecord("a.txt", content, int64(len(content))), // correct
			"b.txt": entryRecord("b.txt", content, 8),                   // wrong
		}},
		Objects: []PackageObject{carriedObject(content)},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	_, err := New(dst).ImportSnapshot(writePackage(t, pkg))
	if err == nil {
		t.Fatal("import accepted a shared digest whose second record misstates its size")
	}
	msg := err.Error()
	if !strings.Contains(msg, `record for "b.txt" is corrupt`) || strings.Contains(msg, "a.txt") {
		t.Fatalf("error must name the disagreeing record b.txt, got %q", msg)
	}
	if objectExists(dst, digestOf(content)) {
		t.Fatal("shared object was installed despite one bad record")
	}
}

// TestImportZeroByteContentSizeRules covers the empty-content boundary: a
// zero-byte object with a size-0 record imports normally, while a record
// claiming even one byte for the same empty content is rejected.
func TestImportZeroByteContentSizeRules(t *testing.T) {
	empty := ""

	t.Run("recorded zero imports", func(t *testing.T) {
		pkg := Package{
			Format:   packageFormat,
			Version:  packageVersion,
			Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{"empty.txt": entryRecord("empty.txt", empty, 0)}},
			Objects:  []PackageObject{carriedObject(empty)},
		}
		dst := filepath.Join(t.TempDir(), "vault")
		if err := New(dst).Init(); err != nil {
			t.Fatal(err)
		}
		res, err := New(dst).ImportSnapshot(writePackage(t, pkg))
		if err != nil {
			t.Fatal(err)
		}
		if res.Entries != 1 || res.NewObjects != 1 {
			t.Fatalf("result=%+v, want 1 entry and 1 new object", res)
		}
		if !objectExists(dst, digestOf(empty)) {
			t.Fatal("zero-byte object not installed")
		}
	})

	t.Run("recorded one byte rejected", func(t *testing.T) {
		pkg := Package{
			Format:   packageFormat,
			Version:  packageVersion,
			Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{"empty.txt": entryRecord("empty.txt", empty, 1)}},
			Objects:  []PackageObject{carriedObject(empty)},
		}
		dst := filepath.Join(t.TempDir(), "vault")
		if err := New(dst).Init(); err != nil {
			t.Fatal(err)
		}
		_, err := New(dst).ImportSnapshot(writePackage(t, pkg))
		if err == nil {
			t.Fatal("import accepted a size-1 record for zero-byte content")
		}
		if msg := err.Error(); !strings.Contains(msg, "is 0 bytes, but the record says 1") {
			t.Fatalf("error %q does not state actual 0 and recorded 1", msg)
		}
		if objectExists(dst, digestOf(empty)) {
			t.Fatal("empty object installed after rejected import")
		}
	})
}

// TestImportDeltaRejectsSizeMismatchForOmittedObject applies the size rule to
// objects an incremental package does not carry: the destination already has
// the matching base and healthy content, but the target snapshot keeps the
// same digest while claiming a different size. The package is refused and the
// existing object's bytes and permissions are untouched.
func TestImportDeltaRejectsSizeMismatchForOmittedObject(t *testing.T) {
	keep := "same"
	baseSnap := Snapshot{Name: "base", Entries: map[string]Entry{
		"keep.txt": entryRecord("keep.txt", keep, int64(len(keep))),
	}}
	basePkg := Package{
		Format: packageFormat, Version: packageVersion, Snapshot: baseSnap,
		Objects: []PackageObject{carriedObject(keep)},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(writePackage(t, basePkg)); err != nil {
		t.Fatal(err)
	}
	objPath := filepath.Join(dst, "objects", digestOf(keep))
	beforeInfo, err := os.Stat(objPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatal(err)
	}

	// Target reuses the base digest (so the object is omitted from the delta)
	// but lies about its size.
	target := Snapshot{Name: "target", Entries: map[string]Entry{
		"keep.txt": entryRecord("keep.txt", keep, int64(len(keep))+1),
	}}
	delta := Package{
		Format: packageFormat, Version: packageVersion, Snapshot: target, Base: &baseSnap,
		Objects: []PackageObject{},
	}
	_, err = New(dst).ImportSnapshot(writePackage(t, delta))
	if err == nil {
		t.Fatal("delta accepted a target record whose size disagrees with omitted content")
	}
	msg := err.Error()
	for _, want := range []string{`snapshot "target"`, "keep.txt", digestOf(keep), "is 4 bytes", "record says 5"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
	// Only the base snapshot exists; the target was never published.
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 || infos[0].Name != "base" {
		t.Fatalf("snapshots after failed delta: %+v", infos)
	}
	afterInfo, err := os.Stat(objPath)
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, err := os.ReadFile(objPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterInfo.Mode() != beforeInfo.Mode() {
		t.Fatalf("object permissions changed: %v -> %v", beforeInfo.Mode(), afterInfo.Mode())
	}
	if string(afterBytes) != string(beforeBytes) {
		t.Fatal("object bytes changed after failed delta import")
	}
}

// TestImportDeltaSizeMismatchDiscardsOtherCorrectObjects makes sure a correct
// new object carried alongside a bad omitted-object record does not survive
// the failed import.
func TestImportDeltaSizeMismatchDiscardsOtherCorrectObjects(t *testing.T) {
	keep := "same"
	brandNew := "brand new"
	baseSnap := Snapshot{Name: "base", Entries: map[string]Entry{
		"keep.txt": entryRecord("keep.txt", keep, int64(len(keep))),
	}}
	basePkg := Package{
		Format: packageFormat, Version: packageVersion, Snapshot: baseSnap,
		Objects: []PackageObject{carriedObject(keep)},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(writePackage(t, basePkg)); err != nil {
		t.Fatal(err)
	}
	target := Snapshot{Name: "target", Entries: map[string]Entry{
		"keep.txt": entryRecord("keep.txt", keep, int64(len(keep))+1), // bad, omitted object
		"new.txt":  entryRecord("new.txt", brandNew, int64(len(brandNew))),
	}}
	delta := Package{
		Format:   packageFormat,
		Version:  packageVersion,
		Snapshot: target,
		Base:     &baseSnap,
		Objects:  []PackageObject{carriedObject(brandNew)},
	}
	if _, err := New(dst).ImportSnapshot(writePackage(t, delta)); err == nil {
		t.Fatal("delta accepted with a bad omitted-object size record")
	}
	if objectExists(dst, digestOf(brandNew)) {
		t.Fatal("the package's correct new object was left behind by the failed import")
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 {
		t.Fatalf("target snapshot published despite failed import: %+v", infos)
	}
}

// TestCheckEntrySizes unit-tests the per-name rule directly, including empty
// content and deterministic reporting order.
func TestCheckEntrySizes(t *testing.T) {
	d := digestOf("payload")
	if err := checkEntrySizes("s", map[string]Entry{}, map[string]int64{}); err != nil {
		t.Fatalf("empty snapshot must pass: %v", err)
	}
	shared := map[string]Entry{
		"a.txt": {Name: "a.txt", Digest: d, Size: 7},
		"b.txt": {Name: "b.txt", Digest: d, Size: 7},
	}
	if err := checkEntrySizes("s", shared, map[string]int64{d: 7}); err != nil {
		t.Fatalf("two names sharing healthy content must both pass: %v", err)
	}
	zero := digestOf("")
	if err := checkEntrySizes("s",
		map[string]Entry{"empty.txt": {Name: "empty.txt", Digest: zero, Size: 0}},
		map[string]int64{zero: 0}); err != nil {
		t.Fatalf("zero-byte content with a size-0 record must pass: %v", err)
	}
	bad := map[string]Entry{
		"a.txt": {Name: "a.txt", Digest: d, Size: 9}, // sorts first, reported first
		"b.txt": {Name: "b.txt", Digest: d, Size: 8},
	}
	err := checkEntrySizes("s", bad, map[string]int64{d: 7})
	if err == nil {
		t.Fatal("size disagreement must be rejected")
	}
	msg := err.Error()
	for _, want := range []string{`snapshot "s"`, `record for "a.txt" is corrupt`, d, "is 7 bytes", "record says 9"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

func TestImportPackageCannotWriteOutsideSnapshots(t *testing.T) {
	src, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "s.pkg")
	mustExport(t, src, "s", "", out)
	good, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	// Even an attempted path-like digest/name can never pass validation: this
	// documents that only 64-hex names (objects/<digest>) are ever written.
	var pkg Package
	if err := json.Unmarshal(good, &pkg); err != nil {
		t.Fatal(err)
	}
	pkg.Snapshot.Name = "../evil"
	pkg.Snapshot.Entries["../evil"] = pkg.Snapshot.Entries["a.txt"]
	delete(pkg.Snapshot.Entries, "a.txt")
	data, err := json.Marshal(&pkg)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.pkg")
	if err := os.WriteFile(bad, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(bad); err == nil {
		t.Fatal("import accepted a snapshot name escaping the namespace")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil.json")); !os.IsNotExist(err) {
		t.Fatal("import wrote outside the snapshots directory")
	}
}
