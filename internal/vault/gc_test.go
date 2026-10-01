package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// objectNames returns the names of every entry directly in the objects dir.
func objectNames(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// digestOf returns the sha256 hex digest of content.
func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestGCDryRunListsUnreferencedObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")

	if _, err := store.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", v2); err != nil {
		t.Fatal(err)
	}
	// v1's object is now unreferenced; v2's object is referenced.

	result, err := store.GC(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates=%+v, want exactly one unreferenced object", result.Candidates)
	}
	want := digestOf("version one\n")
	if result.Candidates[0].Digest != want {
		t.Fatalf("candidate digest=%s, want %s", result.Candidates[0].Digest, want)
	}
	if result.Candidates[0].Size != int64(len("version one\n")) {
		t.Fatalf("candidate size=%d", result.Candidates[0].Size)
	}
	if result.Bytes != int64(len("version one\n")) {
		t.Fatalf("bytes=%d", result.Bytes)
	}
	if result.Deleted != 0 {
		t.Fatalf("dry run deleted=%d", result.Deleted)
	}

	// Dry run must not delete anything.
	names := objectNames(t, root)
	if len(names) != 2 {
		t.Fatalf("objects after dry run=%v, want both objects still present", names)
	}
}

func TestGCActualDeletesUnreferencedObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")

	if _, err := store.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", v2); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted=%d, want 1", result.Deleted)
	}
	if result.Bytes != int64(len("version one\n")) {
		t.Fatalf("bytes=%d", result.Bytes)
	}

	// The unreferenced object is gone; the referenced one remains and is intact.
	names := objectNames(t, root)
	if len(names) != 1 || names[0] != digestOf("version two\n") {
		t.Fatalf("objects=%v", names)
	}
	if count, err := store.Verify(); err != nil || count != 1 {
		t.Fatalf("verify count=%d err=%v", count, err)
	}
}

func TestGCNoCandidatesReportsZero(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}

	for _, dryRun := range []bool{true, false} {
		result, err := store.GC(dryRun)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Candidates) != 0 || result.Deleted != 0 || result.Bytes != 0 {
			t.Fatalf("dryRun=%v result=%+v, want zero", dryRun, result)
		}
	}
}

func TestGCEmptyFileCountsAsOneObjectZeroBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	empty := writeFile(t, "")
	if _, err := store.Put("a.txt", empty); err != nil {
		t.Fatal(err)
	}
	// Overwrite with non-empty so the empty object becomes unreferenced.
	if _, err := store.Put("a.txt", writeFile(t, "nonempty")); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 || result.Bytes != 0 {
		t.Fatalf("deleted=%d bytes=%d, want 1 object, 0 bytes", result.Deleted, result.Bytes)
	}
}

func TestGCSnapshotKeepsReferencedObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")

	if _, err := store.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", v2); err != nil {
		t.Fatal(err)
	}

	// v1 is referenced only by the snapshot; it must be kept. v2 is referenced
	// by the index. No candidates.
	result, err := store.GC(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != 0 {
		t.Fatalf("candidates=%+v, snapshot-referenced object must be kept", result.Candidates)
	}

	result, err = store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 0 {
		t.Fatalf("deleted=%d, want 0", result.Deleted)
	}
	if count, err := store.Verify(); err != nil || count != 1 {
		t.Fatalf("verify count=%d err=%v", count, err)
	}
}

func TestGCMultiLevelSnapshotNameKeepsObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")

	if _, err := store.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("mid/way"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", v2); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 0 {
		t.Fatalf("deleted=%d, snapshot with multi-level name must keep its object", result.Deleted)
	}
}

func TestGCDeduplicatesSharedDigestsActuallyDeletesOne(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	content := writeFile(t, "shared content\n")

	if _, err := store.Put("a.txt", content); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", content); err != nil {
		t.Fatal(err)
	}
	// No snapshot; overwrite both so the shared digest is unreferenced.
	if _, err := store.Put("a.txt", writeFile(t, "new a\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", writeFile(t, "new b\n")); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	// The shared digest counts as one object, not two.
	if result.Deleted != 1 {
		t.Fatalf("deleted=%d, want 1 (shared digest counts as one object)", result.Deleted)
	}
	if result.Bytes != int64(len("shared content\n")) {
		t.Fatalf("bytes=%d", result.Bytes)
	}
}

func TestGCRepeatedRunAndReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "v1")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("a.txt", writeFile(t, "v2")); err != nil {
		t.Fatal(err)
	}

	// First run deletes the unreferenced object.
	if _, err := store.GC(false); err != nil {
		t.Fatal(err)
	}
	// Second run in the same process finds nothing.
	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 0 {
		t.Fatalf("second run deleted=%d", result.Deleted)
	}
	// Reopen the repository and run again; still nothing.
	result, err = New(root).GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 0 {
		t.Fatalf("reopened run deleted=%d", result.Deleted)
	}
}

func TestGCOrphanObjectOnDiskIsDeleted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Plant an orphan object file with a valid digest name.
	orphanDigest := digestOf("orphan")
	if err := os.WriteFile(filepath.Join(root, "objects", orphanDigest), []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted=%d, want 1 orphan", result.Deleted)
	}
	if _, err := os.Stat(filepath.Join(root, "objects", orphanDigest)); !os.IsNotExist(err) {
		t.Fatalf("orphan still present, err=%v", err)
	}
}

func TestGCIgnoresTempFilesAndOtherNames(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Plant files that must be left alone.
	orphanDigest := digestOf("orphan")
	targets := map[string]string{
		orphanDigest:                "orphan", // valid digest, unreferenced -> deleted
		".upload-1234":              "temp",   // temp file -> kept
		"not-a-digest":              "other",  // other name -> kept
		"abc":                       "short",  // too short -> kept
		strings.Repeat("z", 64):     "nonhex", // 64 chars but not hex -> kept
		strings.Repeat("a", 63):     "short",  // 63 chars -> kept
		strings.Repeat("a", 65):     "long",   // 65 chars -> kept
	}
	for name, content := range targets {
		if err := os.WriteFile(filepath.Join(root, "objects", name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted=%d, want only the valid-digest orphan", result.Deleted)
	}
	// The temp and other-named files remain.
	for name := range targets {
		if name == orphanDigest {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, "objects", name)); err != nil {
			t.Fatalf("file %q should be kept, got err=%v", name, err)
		}
	}
}

func TestGCIgnoresSubdirectoriesAndSymlinks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Plant a subdirectory and a symlink with digest-like names.
	sub := filepath.Join(root, "objects", strings.Repeat("a", 64))
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "objects", strings.Repeat("b", 64))
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 0 {
		t.Fatalf("deleted=%d, subdirs and symlinks must be kept", result.Deleted)
	}
	if _, err := os.Stat(sub); err != nil {
		t.Fatalf("subdir should be kept, err=%v", err)
	}
	// Lstat so we don't follow the symlink.
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink should be kept, err=%v", err)
	}
}

func TestGCDryRunSortedByDigest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	// Plant several orphan objects with distinct digests.
	contents := []string{"alpha", "beta", "gamma", "delta"}
	for _, c := range contents {
		if err := os.WriteFile(filepath.Join(root, "objects", digestOf(c)), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.GC(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Candidates) != len(contents) {
		t.Fatalf("candidates=%d, want %d", len(result.Candidates), len(contents))
	}
	sorted := make([]string, len(result.Candidates))
	for i, c := range result.Candidates {
		sorted[i] = c.Digest
	}
	if !sort.StringsAreSorted(sorted) {
		t.Fatalf("candidates not sorted: %v", sorted)
	}
}

func TestGCRejectsMissingRoot(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "does-not-exist"))
	if _, err := store.GC(true); err == nil {
		t.Fatal("expected error for missing root")
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestGCRejectsUninitializedRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// Root exists but index.json is absent.
	store := New(root)
	if _, err := store.GC(true); err == nil {
		t.Fatal("expected error for uninitialized repository")
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error for uninitialized repository")
	}
	// No objects were created.
	if _, err := os.Stat(filepath.Join(root, "objects")); !os.IsNotExist(err) {
		t.Fatalf("objects dir should not be auto-created, err=%v", err)
	}
}

func TestGCRejectsObjectsSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	// Replace objects dir with a symlink.
	if err := os.Remove(filepath.Join(root, "objects")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(t.TempDir(), "real-objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "real-objects"), filepath.Join(root, "objects")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(true); err == nil {
		t.Fatal("expected error when objects is a symlink")
	}
}

func TestGCRejectsCorruptIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Plant an orphan so there would be something to delete.
	if err := os.WriteFile(filepath.Join(root, "objects", digestOf("orphan")), []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error for corrupt index")
	}
	// The orphan must not have been deleted.
	if _, err := os.Stat(filepath.Join(root, "objects", digestOf("orphan"))); err != nil {
		t.Fatalf("orphan should not be deleted when index is corrupt, err=%v", err)
	}
}

func TestGCRejectsIndexMissingEntries(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error when index has no entries map")
	}
}

func TestGCRejectsIndexInvalidEntries(t *testing.T) {
	goodDigest := digestOf("x")
	cases := map[string]string{
		"bad entry name":  `{"entries":{"../evil":{"name":"../evil","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"bad digest":      `{"entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"negative size":   `{"entries":{"a":{"name":"a","digest":"` + goodDigest + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"key mismatch":    `{"entries":{"a":{"name":"b","digest":"` + goodDigest + `","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}`,
	}
	for label, record := range cases {
		t.Run(label, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "vault")
			store := New(root)
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(record), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GC(false); err == nil {
				t.Fatal("expected error for invalid index entry")
			}
		})
	}
}

func TestGCRejectsCorruptSnapshot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshots", "s.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error for corrupt snapshot")
	}
}

func TestGCRejectsSnapshotRecordNameMismatch(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Record name "wrong" but filed as "right.json".
	record := `{"name":"wrong","entries":{"a":{"name":"a","digest":"` + digestOf("data") + `","size":4,"createdAt":"2026-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(filepath.Join(root, "snapshots", "right.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error when snapshot record name does not match location")
	}
}

func TestGCRejectsSnapshotSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the snapshots tree must be an error.
	if err := os.Symlink(filepath.Join(root, "index.json"), filepath.Join(root, "snapshots", "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error for symlink in snapshots directory")
	}
}

func TestGCRejectsSnapshotsDirSymlink(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// snapshots dir itself is a symlink.
	if err := os.MkdirAll(filepath.Join(t.TempDir(), "real-snapshots"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "real-snapshots"), filepath.Join(root, "snapshots")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GC(false); err == nil {
		t.Fatal("expected error when snapshots is a symlink")
	}
}

func TestGCMissingSnapshotsDirIsOK(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// No snapshots dir exists; GC should succeed and find no candidates.
	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 0 {
		t.Fatalf("deleted=%d, want 0", result.Deleted)
	}
}

func TestGCRestoreOrphansAreDeleted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	v1 := writeFile(t, "version one\n")
	v2 := writeFile(t, "version two\n")

	if _, err := store.Put("a.txt", v1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", v2); err != nil {
		t.Fatal(err)
	}
	// Restore the snapshot; b.txt's object becomes unreferenced.
	if err := store.RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}

	result, err := store.GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted=%d, want 1 (b.txt's object orphaned by restore)", result.Deleted)
	}
	// The restored mapping is intact.
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "a.txt" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestGCDeleteFailureReportsProgress(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory write permissions; cannot simulate deletion failure")
	}
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("a.txt", writeFile(t, "data")); err != nil {
		t.Fatal(err)
	}
	// Plant two orphan objects.
	for _, c := range []string{"orphan1", "orphan2"} {
		if err := os.WriteFile(filepath.Join(root, "objects", digestOf(c)), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Make the first candidate undeletable by removing write permission on the
	// objects directory. Running as a non-root user, os.Remove will fail.
	objectsDir := filepath.Join(root, "objects")
	if err := os.Chmod(objectsDir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(objectsDir, 0o755)

	_, err := store.GC(false)
	if err == nil {
		t.Fatal("expected deletion error")
	}
	var gcErr *GCError
	if !asGCError(err, &gcErr) {
		t.Fatalf("expected GCError, got %T: %v", err, err)
	}
	if gcErr.Object == "" {
		t.Fatal("GCError.Object is empty")
	}
	// At least one object failed; deleted count reflects partial progress.
	if gcErr.Deleted < 0 {
		t.Fatalf("deleted=%d", gcErr.Deleted)
	}
}

func asGCError(err error, target **GCError) bool {
	for err != nil {
		if e, ok := err.(*GCError); ok {
			*target = e
			return true
		}
		err = unwrap(err)
	}
	return false
}

func unwrap(err error) error {
	if u, ok := err.(interface{ Unwrap() error }); ok {
		return u.Unwrap()
	}
	return nil
}

func TestGCConcurrentWithPuts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("base.txt", writeFile(t, "base")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	// Run GC and puts concurrently; all must succeed without error.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := New(root).GC(false); err != nil {
				errs <- err
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := New(root).Put(fmt.Sprintf("conc-%d.txt", i), writeFile(t, fmt.Sprintf("payload-%d", i))); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// The repository is still consistent.
	if _, err := store.Verify(); err != nil {
		t.Fatal(err)
	}
}
