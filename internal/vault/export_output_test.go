package vault

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// exportVault seeds a fresh vault with one artifact and one snapshot,
// returning its root.
func exportVault(t *testing.T) string {
	t.Helper()
	root, _ := seedVault(t, map[string]string{"a.txt": "payload"})
	if _, err := New(root).CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	return root
}

// assertExportRefused runs the export and requires an error whose message
// contains every wanted substring.
func assertExportRefused(t *testing.T, root, name, base, output string, want ...string) {
	t.Helper()
	_, err := New(root).ExportSnapshot(name, base, output)
	if err == nil {
		t.Fatalf("export to %q succeeded, want error containing %v", output, want)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("export error %q does not contain %q", err.Error(), w)
		}
	}
}

func TestExportRejectsOutputInsideRepository(t *testing.T) {
	root := exportVault(t)
	cases := map[string]string{
		"index.json":         filepath.Join(root, "index.json"),
		"lock":               filepath.Join(root, ".lock"),
		"object file":        filepath.Join(root, "objects", digestOf("payload")),
		"snapshot record":    filepath.Join(root, "snapshots", "snap.json"),
		"not yet created":    filepath.Join(root, "new-output.pkg"),
		"nested not created": filepath.Join(root, "sub", "new.pkg"),
	}
	for label, output := range cases {
		t.Run(label, func(t *testing.T) {
			assertExportRefused(t, root, "snap", "", output, "inside the repository", output)
		})
	}
}

func TestExportRejectsOutputThroughSymlinkedParent(t *testing.T) {
	root := exportVault(t)
	link := filepath.Join(t.TempDir(), "vault-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(link, "evil.pkg")
	assertExportRefused(t, root, "snap", "", output, "inside the repository", output)
}

func TestExportRejectsOutputWithSymlinkedRoot(t *testing.T) {
	realRoot := exportVault(t)
	link := filepath.Join(t.TempDir(), "vault-link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Fatal(err)
	}
	// The store is opened through the symlink; the output names a repo file.
	output := filepath.Join(link, "index.json")
	assertExportRefused(t, link, "snap", "", output, "inside the repository", output)
}

func TestExportRejectsOutputWithParentSymlinkedIntoRepo(t *testing.T) {
	root := exportVault(t)
	// A symlink outside the repository whose target is the repository itself.
	link := filepath.Join(t.TempDir(), "portal")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(link, "sneaky.pkg")
	assertExportRefused(t, root, "snap", "", output, "inside the repository")
}

func TestExportAllowsAdjacentDirectoryWithSamePrefix(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).Put("a.txt", writeFile(t, "payload")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// A sibling whose name starts with the same prefix as the repository name
	// must be usable: containment is component-wise, not a string prefix.
	adjacent := filepath.Join(parent, "vault2")
	if err := os.Mkdir(adjacent, 0o755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(adjacent, "out.pkg")
	if _, err := New(root).ExportSnapshot("snap", "", output); err != nil {
		t.Fatalf("export to same-prefix adjacent dir failed: %v", err)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("output not written: %v", err)
	}
}

func TestExportRejectsPathEscapingWithParentRef(t *testing.T) {
	root := exportVault(t)
	// Resolves to root/index.json through a ".." component: still inside.
	output := filepath.Join(root, "..", filepath.Base(root), "index.json")
	assertExportRefused(t, root, "snap", "", output, "inside the repository")
}

func TestExportRejectsNonRegularOutput(t *testing.T) {
	root := exportVault(t)
	t.Run("directory", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "outdir")
		if err := os.Mkdir(output, 0o755); err != nil {
			t.Fatal(err)
		}
		assertExportRefused(t, root, "snap", "", output, "not a regular file")
	})
	t.Run("symlink to file", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target.txt")
		if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, output); err != nil {
			t.Fatal(err)
		}
		assertExportRefused(t, root, "snap", "", output, "symbolic link")
		// The link target must be untouched.
		if got, _ := os.ReadFile(target); string(got) != "target" {
			t.Fatal("symlink target changed")
		}
	})
	t.Run("dangling symlink", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "dangling")
		if err := os.Symlink(filepath.Join(t.TempDir(), "does-not-exist"), output); err != nil {
			t.Fatal(err)
		}
		assertExportRefused(t, root, "snap", "", output, "symbolic link")
	})
	t.Run("fifo", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(output, 0o644); err != nil {
			t.Fatal(err)
		}
		assertExportRefused(t, root, "snap", "", output, "not a regular file")
	})
}

func TestExportRejectsHardlinkToRepositoryFile(t *testing.T) {
	root := exportVault(t)
	cases := map[string]string{
		"index":    filepath.Join(root, "index.json"),
		"lock":     filepath.Join(root, ".lock"),
		"object":   filepath.Join(root, "objects", digestOf("payload")),
		"snapshot": filepath.Join(root, "snapshots", "snap.json"),
	}
	for label, repoFile := range cases {
		t.Run(label, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "hardlink")
			if err := os.Link(repoFile, output); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(repoFile)
			if err != nil {
				t.Fatal(err)
			}
			assertExportRefused(t, root, "snap", "", output, "hard link to repository file", repoFile)
			// The repository file behind the link must be byte-identical.
			after, err := os.ReadFile(repoFile)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("repository file changed through the hard link")
			}
		})
	}
}

func TestExportRejectsHardlinkToUnreferencedObject(t *testing.T) {
	// An object present in objects/ but not referenced by the exported
	// snapshot is still a repository file and must be protected.
	root, _ := seedVault(t, map[string]string{"a.txt": "v1"})
	if _, err := New(root).Put("a.txt", writeFile(t, "v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// "snap" references v2; v1 is unreferenced but still under objects/.
	output := filepath.Join(t.TempDir(), "hardlink")
	if err := os.Link(filepath.Join(root, "objects", digestOf("v1")), output); err != nil {
		t.Fatal(err)
	}
	assertExportRefused(t, root, "snap", "", output, "hard link to repository file")
}

func TestExportRejectsMissingRepositoryWithoutCreating(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	output := filepath.Join(t.TempDir(), "out.pkg")
	_, err := New(root).ExportSnapshot("snap", "", output)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing-repo error, got %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("export created the missing repository root")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("export created an output file")
	}
}

func TestExportRejectsUninitializedRepositoryWithoutCreating(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.pkg")
	_, err := New(root).ExportSnapshot("snap", "", output)
	if err == nil || !strings.Contains(err.Error(), "is not initialized") {
		t.Fatalf("expected uninitialized-repo error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "index.json")); !os.IsNotExist(err) {
		t.Fatal("export initialized the repository")
	}
}

func TestExportRejectsMissingParentWithoutCreating(t *testing.T) {
	root := exportVault(t)
	output := filepath.Join(t.TempDir(), "no", "such", "out.pkg")
	_, err := New(root).ExportSnapshot("snap", "", output)
	if err == nil || !strings.Contains(err.Error(), "parent directory is not accessible") {
		t.Fatalf("expected missing-parent error, got %v", err)
	}
	if _, err := os.Stat(filepath.Dir(output)); !os.IsNotExist(err) {
		t.Fatal("export created the missing parent directory")
	}
}

func TestExportAllowsSymlinkedParentLeadingOutside(t *testing.T) {
	root := exportVault(t)
	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "portal")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(link, "out.pkg")
	if _, err := New(root).ExportSnapshot("snap", "", output); err != nil {
		t.Fatalf("export through outside-leading symlink failed: %v", err)
	}
	// The package landed in the real outside directory.
	if _, err := os.Stat(filepath.Join(outside, "out.pkg")); err != nil {
		t.Fatalf("package not written to outside dir: %v", err)
	}
}

func TestExportCommitTimeParentSwapRefused(t *testing.T) {
	root := exportVault(t)
	outside := t.TempDir()
	output := filepath.Join(outside, "out.pkg")
	// Phase-1 validation passes: output is outside the repository.
	absOut, mode, err := New(root).checkExportOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	// Another process swaps the parent for a symlink into the repository.
	if err := os.RemoveAll(outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, outside); err != nil {
		t.Fatal(err)
	}
	// The commit must refuse rather than rename into the repository.
	err = New(root).writePackageAtomic(absOut, mode, output, []byte("data"))
	if err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Fatalf("expected commit-time refusal, got %v", err)
	}
	// No package was written into the repository.
	if _, err := os.Stat(filepath.Join(root, "out.pkg")); !os.IsNotExist(err) {
		t.Fatal("commit wrote a package into the repository")
	}
}

func TestExportSnapshotErrorsNameSnapshotNotOutput(t *testing.T) {
	root := exportVault(t)
	output := filepath.Join(t.TempDir(), "out.pkg")
	t.Run("missing snapshot", func(t *testing.T) {
		_, err := New(root).ExportSnapshot("nope", "", output)
		if err == nil || !strings.Contains(err.Error(), `snapshot "nope" not found`) {
			t.Fatalf("expected snapshot-not-found error, got %v", err)
		}
	})
	t.Run("corrupt snapshot", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(root, "snapshots"), 0o755); err != nil {
			t.Fatal(err)
		}
		record := `{"name":"bad","entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}` + "\n"
		if err := os.WriteFile(filepath.Join(root, "snapshots", "bad.json"), []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := New(root).ExportSnapshot("bad", "", output)
		if err == nil || !strings.Contains(err.Error(), "corrupted") {
			t.Fatalf("expected corrupt-snapshot error, got %v", err)
		}
	})
}

func TestExportObjectErrorNamesObject(t *testing.T) {
	root := exportVault(t)
	// Remove the object the snapshot references.
	if err := os.Remove(filepath.Join(root, "objects", digestOf("payload"))); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.pkg")
	_, err := New(root).ExportSnapshot("snap", "", output)
	if err == nil || !strings.Contains(err.Error(), digestOf("payload")) {
		t.Fatalf("expected object error naming the digest, got %v", err)
	}
}

func TestExportReplacesExistingRegularFile(t *testing.T) {
	root := exportVault(t)
	output := filepath.Join(t.TempDir(), "out.pkg")
	if err := os.WriteFile(output, []byte("old package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).ExportSnapshot("snap", "", output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "artifact-vault-snapshot") {
		t.Fatalf("existing output was not replaced with a package: %q", got)
	}
	// Permissions of the existing file are preserved.
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 0600", info.Mode().Perm())
	}
}

func TestExportWritesNewFileWhenAbsent(t *testing.T) {
	root := exportVault(t)
	output := filepath.Join(t.TempDir(), "out.pkg")
	if _, err := New(root).ExportSnapshot("snap", "", output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "artifact-vault-snapshot") {
		t.Fatalf("new output is not a package: %q", got)
	}
}

func TestExportEmptySnapshotStillWorks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).CreateSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "empty.pkg")
	res, err := New(root).ExportSnapshot("empty", "", output)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 0 || res.Objects != 0 {
		t.Fatalf("result=%+v", res)
	}
}

func TestExportDeltaWithNoNewObjectsStillWorks(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).Put("a.txt", writeFile(t, "same")); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "delta.pkg")
	res, err := New(root).ExportSnapshot("base", "base", output)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1 || res.Objects != 0 {
		t.Fatalf("result=%+v", res)
	}
}

func TestExportFailureWithUnsafeOutputLeavesNoTrace(t *testing.T) {
	root := exportVault(t)
	// Corrupt the object so the export fails, and point the output at a
	// directory: neither should be touched.
	if err := os.WriteFile(filepath.Join(root, "objects", digestOf("payload")), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "outdir")
	if err := os.Mkdir(output, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := New(root).ExportSnapshot("snap", "", output)
	if err == nil {
		t.Fatal("expected failure")
	}
	// The directory is intact and no package was created beside it.
	info, err := os.Stat(output)
	if err != nil || !info.IsDir() {
		t.Fatal("unsafe output was replaced or removed")
	}
	entries, err := os.ReadDir(filepath.Dir(output))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".package-") {
			t.Fatal("failed export left a temp file behind")
		}
	}
}

func TestExportDoesNotModifyRepository(t *testing.T) {
	root := exportVault(t)
	paths := []string{
		filepath.Join(root, "index.json"),
		filepath.Join(root, ".lock"),
		filepath.Join(root, "snapshots", "snap.json"),
		filepath.Join(root, "objects", digestOf("payload")),
	}
	before := map[string][]byte{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		before[p] = data
	}
	output := filepath.Join(t.TempDir(), "out.pkg")
	if _, err := New(root).ExportSnapshot("snap", "", output); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		after, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before[p]) {
			t.Fatalf("repository file %s changed across export", p)
		}
	}
}
