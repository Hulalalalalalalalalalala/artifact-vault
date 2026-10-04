package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// referencePackage builds the in-memory representation the pre-streaming
// exporter assembled and returns its reference serialization.
func referencePackage(t *testing.T, root, name, base string) []byte {
	t.Helper()
	store := New(root)
	target, err := store.loadSnapshotRecord(name)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &Package{Format: packageFormat, Version: packageVersion, Snapshot: target, Objects: []PackageObject{}}
	carry := digestsReferenced(target.Entries)
	if base != "" {
		baseSnap, err := store.loadSnapshotRecord(base)
		if err != nil {
			t.Fatal(err)
		}
		pkg.Base = &baseSnap
		for digest := range digestsReferenced(baseSnap.Entries) {
			delete(carry, digest)
		}
	}
	for _, digest := range sortedDigests(target.Entries) {
		content, size, err := store.readVerifiedObject(digest, target.Entries)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := carry[digest]; !ok {
			continue
		}
		pkg.Objects = append(pkg.Objects, PackageObject{
			Digest: digest,
			Size:   size,
			Data:   base64.StdEncoding.EncodeToString(content),
		})
	}
	data, err := marshalPackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestExportStreamedPackageMatchesReferenceFormat pins the streaming exporter
// to the exact bytes the in-memory format produced: same version, fields,
// indentation, and content encoding.
func TestExportStreamedPackageMatchesReferenceFormat(t *testing.T) {
	src, _ := seedVault(t, map[string]string{
		"releases/app.txt": "version one\n",
		"docs/readme.txt":  "version one\n", // same digest, carried once
		"empty.txt":        "",
		"big.bin":          strings.Repeat("xy", 1<<20),
	})
	if _, err := New(src).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).Put("new.txt", writeFile(t, "added later")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(src).CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, base string }{
		{"base", ""},       // full export
		{"target", ""},     // full export, several objects
		{"target", "base"}, // delta carrying one object
		{"base", "base"},   // delta carrying no objects
	} {
		out := filepath.Join(t.TempDir(), "pkg")
		if _, err := New(src).ExportSnapshot(tc.name, tc.base, out); err != nil {
			t.Fatalf("export %s base %q: %v", tc.name, tc.base, err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if want := referencePackage(t, src, tc.name, tc.base); !bytes.Equal(got, want) {
			t.Fatalf("export %s base %q: streamed package differs from the reference format\ngot:\n%s\nwant:\n%s", tc.name, tc.base, got, want)
		}
	}
}

// TestExportFailsWholeRunWhenLaterObjectCorrupt corrupts the object whose
// digest sorts last, so healthy objects are fully processed first; the export
// must still fail as a whole, name the corrupt object, and leave neither an
// output nor a temporary file in the output directory.
func TestExportFailsWholeRunWhenLaterObjectCorrupt(t *testing.T) {
	src, _ := seedVault(t, map[string]string{
		"a.txt": "alpha",
		"z.txt": "zulu",
	})
	if _, err := New(src).CreateSnapshot("s"); err != nil {
		t.Fatal(err)
	}
	corrupt := digestOf("alpha")
	if other := digestOf("zulu"); other > corrupt {
		corrupt = other
	}
	obj := filepath.Join(src, "objects", corrupt)
	good, err := os.ReadFile(obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(obj, []byte("X"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(obj, good, 0o644) })

	dir := t.TempDir()
	out := filepath.Join(dir, "s.pkg")
	if _, err := New(src).ExportSnapshot("s", "", out); err == nil ||
		!strings.Contains(err.Error(), corrupt) {
		t.Fatalf("expected failure naming object %s, got %v", corrupt, err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("failed export created an output")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".package-") {
			t.Fatalf("failed export left temporary file %s", e.Name())
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
	idx, err := srcStore.loadStrictValidEntries()
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
		"snapshot entry size disagrees with healthy content": func() Package {
			p := base()
			// The object record stays truthful (7 bytes of payload); only the
			// snapshot record lies. A second name shares the same digest with
			// the correct size to prove every name is checked independently.
			p.Snapshot.Entries["b.txt"] = Entry{Name: "b.txt", Digest: d, Size: 8, CreatedAt: stamp}
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

// entryRec builds a package entry record for tests.
func entryRec(name, digest string, size int64) Entry {
	return Entry{Name: name, Digest: digest, Size: size, CreatedAt: stamp}
}

// packageObject builds a truthful carried object for content.
func packageObject(content string) PackageObject {
	return PackageObject{
		Digest: digestOf(content),
		Size:   int64(len(content)),
		Data:   base64.StdEncoding.EncodeToString([]byte(content)),
	}
}

// writePackage marshals a hand-built package to a file and returns its path.
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

// objectDirNames lists every entry name directly in a repository's objects
// directory, including leftover temporary files.
func objectDirNames(t *testing.T, root string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(ents))
	for _, ent := range ents {
		names = append(names, ent.Name())
	}
	sort.Strings(names)
	return names
}

func assertNoTemporaryFiles(t *testing.T, root string) {
	t.Helper()
	for _, dir := range []string{"objects", "snapshots", "."} {
		ents, err := os.ReadDir(filepath.Join(root, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, ent := range ents {
			if strings.HasPrefix(ent.Name(), ".") && ent.Name() != ".lock" {
				t.Fatalf("leftover temporary file %s in %s", ent.Name(), dir)
			}
		}
	}
}

// TestImportRejectsRecordSizeMismatchWithoutLeavingObject reproduces the
// defect: a package carries healthy 7-byte content (its object record honestly
// says 7), but the target snapshot records 8 for one of the two names that
// share the digest. Import must refuse the whole package and leave neither the
// new content object, a snapshot, nor a temporary file behind, and the error
// must identify the snapshot, artifact, digest, recorded size, and actual byte
// count as a record problem rather than a checksum failure.
func TestImportRejectsRecordSizeMismatchWithoutLeavingObject(t *testing.T) {
	const content = "abcdefg" // exactly 7 bytes
	d := digestOf(content)
	pkg := Package{
		Format:  packageFormat,
		Version: packageVersion,
		Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{
			// a.txt sorts first and is correct; b.txt shares the digest but
			// lies about the size. Every name must be checked, not just one.
			"a.txt": entryRec("a.txt", d, 7),
			"b.txt": entryRec("b.txt", d, 8),
		}},
		Objects: []PackageObject{packageObject(content)},
	}
	path := writePackage(t, pkg)

	dst, _ := seedVault(t, map[string]string{"keep.txt": "keep"})
	before := objectDirNames(t, dst)

	res, err := New(dst).ImportSnapshot(path)
	if err == nil {
		t.Fatal("import accepted a snapshot record whose size disagrees with its content")
	}
	msg := err.Error()
	for _, want := range []string{`snapshot "s"`, "b.txt", d, "8", "7"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not report %q", msg, want)
		}
	}
	if strings.Contains(msg, "checksum") {
		t.Fatalf("a record-size mismatch was reported as a checksum failure: %q", msg)
	}
	if res != (ImportResult{}) {
		t.Fatalf("failed import returned a usable result: %+v", res)
	}
	if objectExists(dst, d) {
		t.Fatal("failed import installed the content object anyway")
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 0 {
		t.Fatalf("failed import published a snapshot: %+v", infos)
	}
	if after := objectDirNames(t, dst); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("objects directory changed\nbefore: %v\nafter:  %v", before, after)
	}
	assertNoTemporaryFiles(t, dst)

	// The current mapping is untouched.
	entries, err := New(dst).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "keep.txt" {
		t.Fatalf("current mapping changed after failed import: %+v", entries)
	}
}

// TestImportRejectsWrongSizeEvenWhenItSortsFirst flips the shared-digest case:
// the lying record must be caught regardless of name order.
func TestImportRejectsWrongSizeEvenWhenItSortsFirst(t *testing.T) {
	const content = "abcdefg" // 7 bytes
	d := digestOf(content)
	pkg := Package{
		Format:  packageFormat,
		Version: packageVersion,
		Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{
			"a.txt": entryRec("a.txt", d, 8), // wrong, sorts first
			"z.txt": entryRec("z.txt", d, 7), // correct
		}},
		Objects: []PackageObject{packageObject(content)},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	res, err := New(dst).ImportSnapshot(writePackage(t, pkg))
	if err == nil {
		t.Fatal("import accepted the wrong-size record")
	}
	if !strings.Contains(err.Error(), "a.txt") || res != (ImportResult{}) {
		t.Fatalf("unexpected err=%v res=%+v", err, res)
	}
	if objectExists(dst, d) {
		t.Fatal("failed import left the object behind")
	}
}

// TestImportDeltaRejectsOmittedRecordSizeMismatch covers incremental packages:
// the object the delta omits is healthy in the destination via a matching
// base, but the target record keeps its digest while declaring another size.
// The package also carries a correct new object; neither it nor the target
// snapshot may remain after the refusal.
func TestImportDeltaRejectsOmittedRecordSizeMismatchWithoutLeavingNewObject(t *testing.T) {
	const oldData = "olddata" // 7 bytes, present through the base
	const newData = "brand new"
	dOld := digestOf(oldData)
	dNew := digestOf(newData)

	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	// Establish the matching base snapshot and its object in the destination.
	basePkg := Package{
		Format:   packageFormat,
		Version:  packageVersion,
		Snapshot: Snapshot{Name: "base", Entries: map[string]Entry{"keep.txt": entryRec("keep.txt", dOld, 7)}},
		Objects:  []PackageObject{packageObject(oldData)},
	}
	if _, err := New(dst).ImportSnapshot(writePackage(t, basePkg)); err != nil {
		t.Fatal(err)
	}

	// Delta: keep.txt keeps the base digest but lies about the size (omitted
	// object); new.txt is a correct, carried, genuinely new object.
	delta := Package{
		Format: packageFormat, Version: packageVersion,
		Snapshot: Snapshot{Name: "target", Entries: map[string]Entry{
			"keep.txt": entryRec("keep.txt", dOld, 8),
			"new.txt":  entryRec("new.txt", dNew, int64(len(newData))),
		}},
		Base:    &Snapshot{Name: "base", Entries: map[string]Entry{"keep.txt": entryRec("keep.txt", dOld, 7)}},
		Objects: []PackageObject{packageObject(newData)},
	}
	res, err := New(dst).ImportSnapshot(writePackage(t, delta))
	if err == nil {
		t.Fatal("delta imported a target record that mis-sizes an omitted base object")
	}
	msg := err.Error()
	for _, want := range []string{`snapshot "target"`, "keep.txt", dOld, "8", "7"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not report %q", msg, want)
		}
	}
	if strings.Contains(msg, "checksum") {
		t.Fatalf("record-size mismatch reported as checksum failure: %q", msg)
	}
	if res != (ImportResult{}) {
		t.Fatalf("failed delta returned a usable result: %+v", res)
	}
	if objectExists(dst, dNew) {
		t.Fatal("failed delta left the correct new object behind anyway")
	}
	// Only the base snapshot survives; target is never published.
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 1 || infos[0].Name != "base" {
		t.Fatalf("snapshots after failed delta: %+v", infos)
	}
	// The pre-existing base object is byte-for-byte unchanged.
	got, err := os.ReadFile(filepath.Join(dst, "objects", dOld))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != oldData {
		t.Fatalf("base object altered: %q", got)
	}
	if names := objectDirNames(t, dst); len(names) != 1 || names[0] != dOld {
		t.Fatalf("objects directory after failed delta: %v", names)
	}
	assertNoTemporaryFiles(t, dst)
}

// TestImportRecordSizeMismatchRejectsOtherCorrectObjects makes the "no partial
// save" rule explicit: a fully correct new object carried beside the bad
// record is installed only if the whole package is valid.
func TestImportRecordSizeMismatchRejectsOtherCorrectObjects(t *testing.T) {
	const bad = "abcdefg" // 7-byte content recorded as 8
	const good = "totally fine separate content"
	dBad := digestOf(bad)
	dGood := digestOf(good)
	pkg := Package{
		Format:  packageFormat,
		Version: packageVersion,
		Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{
			"bad.txt":  entryRec("bad.txt", dBad, 8),
			"good.txt": entryRec("good.txt", dGood, int64(len(good))),
		}},
		Objects: []PackageObject{packageObject(bad), packageObject(good)},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dst).ImportSnapshot(writePackage(t, pkg)); err == nil {
		t.Fatal("import accepted a package containing one mis-sized record")
	}
	if objectExists(dst, dBad) {
		t.Fatal("the mis-sized object was installed")
	}
	if objectExists(dst, dGood) {
		t.Fatal("the other, correct object was partially installed")
	}
	if infos, _ := New(dst).ListSnapshots(); len(infos) != 0 {
		t.Fatalf("snapshot published: %+v", infos)
	}
	assertNoTemporaryFiles(t, dst)
}

// TestImportZeroByteContentWithZeroSizeImports pins the legitimate edge:
// empty content and a zero-size record are valid and transfer normally.
func TestImportZeroByteContentWithZeroSizeImports(t *testing.T) {
	d0 := digestOf("")
	pkg := Package{
		Format:   packageFormat,
		Version:  packageVersion,
		Snapshot: Snapshot{Name: "s", Entries: map[string]Entry{"empty.txt": entryRec("empty.txt", d0, 0)}},
		Objects:  []PackageObject{{Digest: d0, Size: 0, Data: ""}},
	}
	dst := filepath.Join(t.TempDir(), "vault")
	if err := New(dst).Init(); err != nil {
		t.Fatal(err)
	}
	res, err := New(dst).ImportSnapshot(writePackage(t, pkg))
	if err != nil {
		t.Fatalf("zero-byte import failed: %v", err)
	}
	if res.Entries != 1 || res.NewObjects != 1 {
		t.Fatalf("result=%+v, want 1 entry 1 new object", res)
	}
	if !objectExists(dst, d0) {
		t.Fatal("zero-byte object missing after import")
	}
	assertEntriesAfterRestore(t, dst, "s", map[string]string{"empty.txt": ""})
}

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
