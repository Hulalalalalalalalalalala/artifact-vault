package vault

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// makePackage creates a tar package from a manifest and a map of digest to
// content. It is used to build both valid and malformed packages for testing.
func makePackage(t *testing.T, manifest packageManifest, objects map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "package.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := tw.WriteHeader(&tar.Header{
		Name: "manifest.json",
		Mode: 0o644,
		Size: int64(len(data)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}

	for digest, content := range objects {
		if err := tw.WriteHeader(&tar.Header{
			Name: "objects/" + digest,
			Mode: 0o644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func testManifest(name string, entries map[string]Entry, base *Snapshot) packageManifest {
	return packageManifest{
		Version:  packageVersion,
		Snapshot: Snapshot{Name: name, Entries: entries},
		Base:     base,
	}
}

func entryFor(name string, content string) Entry {
	sum := sha256.Sum256([]byte(content))
	return Entry{
		Name:      name,
		Digest:    hex.EncodeToString(sum[:]),
		Size:      int64(len(content)),
		CreatedAt: testTime,
	}
}

func TestExportImportFullPackage(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("releases/app.txt", writeFile(t, "version one\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("docs/readme.txt", writeFile(t, "readme\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("before-release"); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	result, err := src.ExportSnapshot("before-release", pkgPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "before-release" || result.Entries != 2 || result.Objects != 2 {
		t.Fatalf("export result=%+v", result)
	}

	// Import into an empty target repository.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Name != "before-release" || imp.Entries != 2 || imp.Added != 2 {
		t.Fatalf("import result=%+v", imp)
	}

	// Delete the package and reopen; the snapshot must still be listable and
	// restorable.
	if err := os.Remove(pkgPath); err != nil {
		t.Fatal(err)
	}
	reopened := New(dstRoot)
	infos, err := reopened.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "before-release" || infos[0].Count != 2 {
		t.Fatalf("infos=%+v", infos)
	}
	if err := reopened.RestoreSnapshot("before-release"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.txt")
	if err := reopened.Get("releases/app.txt", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "version one\n" {
		t.Fatalf("restored content=%q", got)
	}
}

func TestExportImportIncrementalPackage(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")
	if _, err := src.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("b.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	// Overwrite a.txt and add c.txt after the base snapshot.
	if _, err := src.Put("a.txt", v2); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("c.txt", v2); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	result, err := src.ExportSnapshot("target", pkgPath, "base")
	if err != nil {
		t.Fatal(err)
	}
	// Target references v1 (b.txt) and v2 (a.txt, c.txt). Base references v1
	// (a.txt, b.txt). Incremental carries only v2.
	if result.Objects != 1 {
		t.Fatalf("export objects=%d, want 1", result.Objects)
	}

	// Target repository has the base snapshot and its objects.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Put("b.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}

	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Added != 1 {
		t.Fatalf("import added=%d, want 1", imp.Added)
	}

	// Restore and verify the target mapping.
	if err := dst.RestoreSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	entries, err := dst.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries=%d", len(entries))
	}
	for _, e := range entries {
		if e.Name == "a.txt" || e.Name == "c.txt" {
			if e.Digest != digestOf("version two\n") {
				t.Fatalf("entry %s digest=%s", e.Name, e.Digest)
			}
		}
	}
}

func TestExportImportEmptySnapshot(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if err := src.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("empty"); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	result, err := src.ExportSnapshot("empty", pkgPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Entries != 0 || result.Objects != 0 {
		t.Fatalf("export result=%+v", result)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Entries != 0 || imp.Added != 0 {
		t.Fatalf("import result=%+v", imp)
	}
	infos, err := dst.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Count != 0 {
		t.Fatalf("infos=%+v", infos)
	}
}

func TestExportImportEmptyFile(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("empty.txt", writeFile(t, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err != nil {
		t.Fatal(err)
	}
	if err := dst.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.txt")
	if err := dst.Get("empty.txt", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("restored content=%q, want empty", got)
	}
}

func TestExportImportIdenticalSnapshots(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "same")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	result, err := src.ExportSnapshot("target", pkgPath, "base")
	if err != nil {
		t.Fatal(err)
	}
	if result.Objects != 0 {
		t.Fatalf("export objects=%d, want 0", result.Objects)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", writeFile(t, "same")); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Added != 0 {
		t.Fatalf("import added=%d, want 0", imp.Added)
	}
}

func TestImportReusesExistingHealthyObjects(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	// Target repository already has the same object.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Added != 0 {
		t.Fatalf("import added=%d, want 0 (object should be reused)", imp.Added)
	}
}

func TestImportSameNameIdenticalSnapshotIsIdempotent(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	// Target repository already has the same snapshot with identical metadata.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Added != 0 {
		t.Fatalf("import added=%d, want 0", imp.Added)
	}
	infos, err := dst.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("snapshots=%d, want 1 (no duplicate)", len(infos))
	}
}

func TestImportSameNameDifferentSnapshotRejects(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	// Target repository has a same-name snapshot with different content.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("b.txt", writeFile(t, "other")); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject same-name different snapshot")
	}
	// The existing snapshot is unchanged.
	infos, err := dst.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Count != 1 {
		t.Fatalf("snapshots=%+v, want unchanged", infos)
	}
}

func TestImportRejectsCorruptedExistingObject(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	// Target repository has the same object but it is corrupted.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Corrupt the object.
	entries, err := dst.List()
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(dstRoot, "objects", entries[0].Digest)
	if err := os.WriteFile(objectPath, []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject corrupted object")
	} else if !strings.Contains(err.Error(), entries[0].Digest) {
		t.Fatalf("error=%v, want it to mention the corrupted digest %s", err, entries[0].Digest)
	}
}

func TestImportRejectsMalformedPackages(t *testing.T) {
	goodContent := "data"
	goodDigest := digestOf(goodContent)
	goodEntry := entryFor("a.txt", goodContent)

	cases := map[string]struct {
		manifest packageManifest
		objects  map[string][]byte
	}{
		"unknown version": {
			manifest: packageManifest{Version: 2, Snapshot: Snapshot{Name: "snap", Entries: map[string]Entry{"a.txt": goodEntry}}},
			objects:  map[string][]byte{goodDigest: []byte(goodContent)},
		},
		"invalid snapshot name": {
			manifest: testManifest("../evil", map[string]Entry{"a.txt": goodEntry}, nil),
			objects:  map[string][]byte{goodDigest: []byte(goodContent)},
		},
		"invalid entry name": {
			manifest: testManifest("snap", map[string]Entry{"../evil": goodEntry}, nil),
			objects:  map[string][]byte{goodDigest: []byte(goodContent)},
		},
		"invalid digest": {
			manifest: testManifest("snap", map[string]Entry{"a.txt": entryFor("a.txt", "data")}, nil),
			objects:  map[string][]byte{digestOf("different"): []byte("different")},
		},
		"negative size": {
			manifest: testManifest("snap", map[string]Entry{"a.txt": {Name: "a.txt", Digest: goodDigest, Size: -1, CreatedAt: testTime}}, nil),
			objects:  map[string][]byte{goodDigest: []byte(goodContent)},
		},
		"missing content": {
			manifest: testManifest("snap", map[string]Entry{"a.txt": goodEntry}, nil),
			objects:  map[string][]byte{},
		},
		"checksum mismatch": {
			manifest: testManifest("snap", map[string]Entry{"a.txt": goodEntry}, nil),
			objects:  map[string][]byte{goodDigest: []byte("different content")},
		},
		"unexpected object": {
			manifest: testManifest("snap", map[string]Entry{"a.txt": goodEntry}, nil),
			objects:  map[string][]byte{goodDigest: []byte(goodContent), digestOf("extra"): []byte("extra")},
		},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			pkgPath := makePackage(t, tc.manifest, tc.objects)
			dstRoot := filepath.Join(t.TempDir(), "dst")
			dst := New(dstRoot)
			if err := dst.Init(); err != nil {
				t.Fatal(err)
			}
			if _, err := dst.ImportSnapshot(pkgPath); err == nil {
				t.Fatal("expected import to reject malformed package")
			}
			// The target repository is unchanged.
			infos, err := dst.ListSnapshots()
			if err != nil {
				t.Fatal(err)
			}
			if len(infos) != 0 {
				t.Fatalf("snapshots=%+v, want empty", infos)
			}
		})
	}
}

func TestImportRejectsDuplicateEntries(t *testing.T) {
	// Build a package with duplicate entry keys in the manifest JSON.
	goodContent := "data"
	goodDigest := digestOf(goodContent)
	manifestJSON := fmt.Sprintf(`{
		"version": 1,
		"snapshot": {
			"name": "snap",
			"entries": {
				"a.txt": {"name": "a.txt", "digest": "%s", "size": %d, "createdAt": "2026-01-01T00:00:00Z"},
				"a.txt": {"name": "a.txt", "digest": "%s", "size": %d, "createdAt": "2026-01-01T00:00:00Z"}
			}
		}
	}`, goodDigest, len(goodContent), goodDigest, len(goodContent))

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	f, err := os.Create(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifestJSON))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(manifestJSON)); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "objects/" + goodDigest, Mode: 0o644, Size: int64(len(goodContent))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(goodContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject duplicate entries")
	}
}

func TestImportRejectsPathTraversal(t *testing.T) {
	goodContent := "data"
	manifest := testManifest("snap", map[string]Entry{"a.txt": entryFor("a.txt", goodContent)}, nil)
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	f, err := os.Create(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifestData))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifestData); err != nil {
		t.Fatal(err)
	}
	// Attempt to write outside the objects directory.
	if err := tw.WriteHeader(&tar.Header{Name: "objects/../evil", Mode: 0o644, Size: int64(len(goodContent))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(goodContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject path traversal")
	}
	// No file was written outside the repository.
	if _, err := os.Stat(filepath.Join(dstRoot, "evil")); !os.IsNotExist(err) {
		t.Fatal("path traversal wrote outside objects/")
	}
}

func TestExportRejectsCorruptedSnapshot(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// Corrupt the snapshot record.
	snapPath := filepath.Join(srcRoot, "snapshots", "snap.json")
	if err := os.WriteFile(snapPath, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err == nil {
		t.Fatal("expected export to reject corrupted snapshot")
	}
	// The output file was not created.
	if _, err := os.Stat(pkgPath); !os.IsNotExist(err) {
		t.Fatal("export created output file despite failure")
	}
}

func TestExportRejectsMissingObject(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	entry, err := src.Put("a.txt", writeFile(t, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// Remove the object.
	if err := os.Remove(filepath.Join(srcRoot, "objects", entry.Digest)); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err == nil {
		t.Fatal("expected export to reject missing object")
	}
	if _, err := os.Stat(pkgPath); !os.IsNotExist(err) {
		t.Fatal("export created output file despite failure")
	}
}

func TestExportRejectsCorruptedObject(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	entry, err := src.Put("a.txt", writeFile(t, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// Corrupt the object.
	if err := os.WriteFile(filepath.Join(srcRoot, "objects", entry.Digest), []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err == nil {
		t.Fatal("expected export to reject corrupted object")
	}
	if _, err := os.Stat(pkgPath); !os.IsNotExist(err) {
		t.Fatal("export created output file despite failure")
	}
}

func TestExportFailureLeavesExistingOutputUntouched(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	entry, err := src.Put("a.txt", writeFile(t, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// Remove the object so export fails.
	if err := os.Remove(filepath.Join(srcRoot, "objects", entry.Digest)); err != nil {
		t.Fatal(err)
	}

	// Create an existing output file.
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	originalContent := []byte("original package content")
	if err := os.WriteFile(pkgPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err == nil {
		t.Fatal("expected export to fail")
	}
	// The existing output file is untouched.
	got, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, originalContent) {
		t.Fatal("export modified existing output file despite failure")
	}
}

func TestExportBaseNotFound(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, "nonexistent"); err == nil {
		t.Fatal("expected export to reject missing base snapshot")
	}
}

func TestExportBaseCorrupted(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	// Corrupt the base snapshot.
	basePath := filepath.Join(srcRoot, "snapshots", "base.json")
	if err := os.WriteFile(basePath, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, "base"); err == nil {
		t.Fatal("expected export to reject corrupted base snapshot")
	}
}

func TestIncrementalImportRequiresExactBase(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("a.txt", writeFile(t, "v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("target", pkgPath, "base"); err != nil {
		t.Fatal(err)
	}

	// Target repository has a same-name snapshot with different metadata.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("b.txt", writeFile(t, "other")); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected incremental import to reject base metadata mismatch")
	}
}

func TestIncrementalImportRejectsIncompleteBase(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	v1 := writeFile(t, "v1")
	v2 := writeFile(t, "v2")
	if _, err := src.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("a.txt", v2); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("target"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("target", pkgPath, "base"); err != nil {
		t.Fatal(err)
	}

	// Target repository has the base snapshot but its object is missing.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	// Remove the base object.
	entries, err := dst.List()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dstRoot, "objects", entries[0].Digest)); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected incremental import to reject incomplete base content")
	}
}

func TestImportedContentProtectedFromGC(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err != nil {
		t.Fatal(err)
	}

	// GC must not collect the imported snapshot's objects.
	report, err := dst.GC(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 0 {
		t.Fatalf("GC candidates=%+v, want none (imported content protected)", report.Candidates)
	}
}

func TestConcurrentExportImportGC(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}

	const workers = 4
	var wg sync.WaitGroup
	errs := make(chan error, workers*3)
	for i := 0; i < workers; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			if _, err := New(dstRoot).ImportSnapshot(pkgPath); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := New(dstRoot).GC(false); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := New(srcRoot).ExportSnapshot("snap", filepath.Join(t.TempDir(), fmt.Sprintf("pkg-%d.tar", i)), ""); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// The imported snapshot is consistent.
	infos, err := dst.ListSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("snapshots=%d, want 1", len(infos))
	}
	if err := dst.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
}

func TestRetryAfterFixingCorruptedObject(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	// Target repository has a corrupted object.
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if _, err := dst.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	entries, err := dst.List()
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(dstRoot, "objects", entries[0].Digest)
	if err := os.WriteFile(objectPath, []byte("corrupted"), 0o644); err != nil {
		t.Fatal(err)
	}

	// First import fails.
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected first import to fail")
	}

	// Fix the corrupted object by removing it.
	if err := os.Remove(objectPath); err != nil {
		t.Fatal(err)
	}

	// Retry succeeds.
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Added != 1 {
		t.Fatalf("import added=%d, want 1", imp.Added)
	}
	if err := dst.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
}

func TestImportDeduplicatesSharedDigests(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	shared := writeFile(t, "shared content")
	if _, err := src.Put("a.txt", shared); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("b.txt", shared); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	result, err := src.ExportSnapshot("snap", pkgPath, "")
	if err != nil {
		t.Fatal(err)
	}
	// Two entries share one digest; the package carries it once.
	if result.Objects != 1 {
		t.Fatalf("export objects=%d, want 1 (deduplicated)", result.Objects)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	imp, err := dst.ImportSnapshot(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if imp.Added != 1 {
		t.Fatalf("import added=%d, want 1", imp.Added)
	}
	if err := dst.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	entries, err := dst.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d, want 2", len(entries))
	}
}

func TestGCCollectsUnreferencedImportObjects(t *testing.T) {
	srcRoot := filepath.Join(t.TempDir(), "src")
	src := New(srcRoot)
	if _, err := src.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := src.ExportSnapshot("snap", pkgPath, ""); err != nil {
		t.Fatal(err)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash: write an object to objects/<digest> without publishing
	// the snapshot. The object is complete but unreferenced.
	content := []byte("orphaned content")
	digest := digestOf(string(content))
	if err := os.WriteFile(filepath.Join(dstRoot, "objects", digest), content, 0o644); err != nil {
		t.Fatal(err)
	}

	// GC must collect the unreferenced object.
	report, err := dst.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Deleted != 1 {
		t.Fatalf("GC deleted=%d, want 1", report.Deleted)
	}
	if objectExists(dstRoot, digest) {
		t.Fatal("unreferenced object survived GC")
	}

	// A real import still works after GC.
	if _, err := dst.ImportSnapshot(pkgPath); err != nil {
		t.Fatal(err)
	}
	if err := dst.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
}

func TestImportRejectsInvalidManifestJSON(t *testing.T) {
	// Build a package with invalid JSON in the manifest.
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	f, err := os.Create(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	manifestJSON := `{broken`
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifestJSON))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(manifestJSON)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject invalid manifest JSON")
	}
}

func TestImportRejectsMissingManifest(t *testing.T) {
	// Build a package with no manifest.
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	f, err := os.Create(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	content := []byte("data")
	digest := digestOf(string(content))
	if err := tw.WriteHeader(&tar.Header{Name: "objects/" + digest, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject missing manifest")
	}
}

func TestExportRejectsNonExistentRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if _, err := store.ExportSnapshot("snap", pkgPath, ""); err == nil {
		t.Fatal("expected export to reject non-existent repository")
	}
}

func TestImportRejectsNonExistentFile(t *testing.T) {
	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(filepath.Join(t.TempDir(), "nonexistent.tar")); err == nil {
		t.Fatal("expected import to reject non-existent file")
	}
}

func TestImportRejectsInvalidTar(t *testing.T) {
	// A file that is not a valid tar archive.
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if err := os.WriteFile(pkgPath, []byte("this is not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject invalid tar")
	}
}

func TestImportRejectsEmptyPackage(t *testing.T) {
	// An empty package file.
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	if err := os.WriteFile(pkgPath, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject empty package")
	}
}

func TestImportRejectsDirectoryEntry(t *testing.T) {
	// A package containing a directory entry.
	pkgPath := filepath.Join(t.TempDir(), "package.tar")
	f, err := os.Create(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	manifestJSON := `{"version":1,"snapshot":{"name":"snap","entries":{}}}`
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifestJSON))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(manifestJSON)); err != nil {
		t.Fatal(err)
	}
	// Add a directory entry.
	if err := tw.WriteHeader(&tar.Header{Name: "objects/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	dstRoot := filepath.Join(t.TempDir(), "dst")
	dst := New(dstRoot)
	if err := dst.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.ImportSnapshot(pkgPath); err == nil {
		t.Fatal("expected import to reject directory entry")
	}
}
