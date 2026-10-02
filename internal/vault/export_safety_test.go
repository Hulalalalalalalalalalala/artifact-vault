package vault

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// exportVault seeds a vault with one artifact and one snapshot and returns the
// root, store, entry, and digest.
func exportVault(t *testing.T, content string) (string, *Store, Entry) {
	t.Helper()
	root, store := seedVault(t, map[string]string{"a.txt": content})
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	return root, store, Entry{Digest: digestOf(content)}
}

func TestExportRejectsOutputOnRepositoryFiles(t *testing.T) {
	root, store, entry := exportVault(t, "payload")
	if _, err := store.CreateSnapshot("other"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"index":              filepath.Join(root, "index.json"),
		"lock":               filepath.Join(root, ".lock"),
		"object":             filepath.Join(root, "objects", entry.Digest),
		"snapshot record":    filepath.Join(root, "snapshots", "snap.json"),
		"other snapshot":     filepath.Join(root, "snapshots", "other.json"),
		"not yet created":    filepath.Join(root, "new-package.json"),
		"nested new path":    filepath.Join(root, "sub", "dir", "pkg.json"),
		"inside objects dir": filepath.Join(root, "objects", "pkg.json"),
	}
	for label, out := range cases {
		t.Run(label, func(t *testing.T) {
			_, err := store.ExportSnapshot("snap", "", out)
			if err == nil || !strings.Contains(err.Error(), "inside the repository") {
				t.Fatalf("expected inside-repository error, got %v", err)
			}
			if !strings.Contains(err.Error(), out) {
				t.Fatalf("error must name the output path %q: %v", out, err)
			}
		})
	}
}

func TestIncrementalExportRejectsOutputOnRepositoryFiles(t *testing.T) {
	root, store, entry := exportVault(t, "payload")
	if _, err := store.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	// A delta that carries no new objects must still protect the output.
	deltaTargets := map[string]string{
		"index":           filepath.Join(root, "index.json"),
		"lock":            filepath.Join(root, ".lock"),
		"object":          filepath.Join(root, "objects", entry.Digest),
		"snapshot record": filepath.Join(root, "snapshots", "snap.json"),
		"missing in repo": filepath.Join(root, "nope.pkg"),
	}
	for label, out := range deltaTargets {
		t.Run(label, func(t *testing.T) {
			if _, err := store.ExportSnapshot("snap", "base", out); err == nil ||
				!strings.Contains(err.Error(), "inside the repository") {
				t.Fatalf("delta export: expected inside-repository error, got %v", err)
			}
		})
	}
}

func TestExportResolvesSymlinkedRepositoryRoot(t *testing.T) {
	realRoot, _, _ := exportVault(t, "payload")
	// Refer to the same repository exclusively through a symlinked root.
	link := filepath.Join(t.TempDir(), "vault-link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Fatal(err)
	}
	store := New(link)
	if err := os.MkdirAll(filepath.Join(realRoot, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"via link path":    filepath.Join(link, "index.json"),
		"via real path":    filepath.Join(realRoot, "objects", digestOf("payload")),
		"missing via link": filepath.Join(link, "sub", "pkg.json"),
	}
	for label, out := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
				!strings.Contains(err.Error(), "inside the repository") {
				t.Fatalf("expected inside-repository error, got %v", err)
			}
		})
	}
}

func TestExportRejectsOutputThroughSymlinkedParent(t *testing.T) {
	root, store, _ := exportVault(t, "payload")
	outside := t.TempDir()
	// A symlink outside the repository that points back into it, at any
	// parent layer.
	link := filepath.Join(outside, "into-vault")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"direct symlinked parent": filepath.Join(link, "pkg.json"),
		"nested symlink": func() string {
			nested := filepath.Join(outside, "nested")
			if err := os.Mkdir(nested, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(root, "objects"), filepath.Join(nested, "objs")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(nested, "objs", "pkg.json")
		}(),
	}
	for label, out := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
				!strings.Contains(err.Error(), "inside the repository") {
				t.Fatalf("expected inside-repository error through symlink, got %v", err)
			}
		})
	}
}

func TestExportRelativePaths(t *testing.T) {
	root, store, _ := exportVault(t, "payload")
	// A sibling whose name shares the repository's prefix must stay usable.
	parent := filepath.Dir(root)
	sibling := filepath.Join(parent, filepath.Base(root)+"-backup")
	if err := os.Mkdir(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(parent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	// "../<repo>/index.json" must not bypass the check.
	if _, err := store.ExportSnapshot("snap", "", filepath.Join("..", filepath.Base(parent), filepath.Base(root), "index.json")); err == nil ||
		!strings.Contains(err.Error(), "inside the repository") {
		t.Fatalf("relative parent traversal into repo was accepted: %v", err)
	}
	// The prefixed sibling directory is a legitimate destination.
	good := filepath.Join(sibling, "snap.pkg")
	if _, err := store.ExportSnapshot("snap", "", good); err != nil {
		t.Fatalf("export into prefixed sibling failed: %v", err)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatalf("package missing in sibling directory: %v", err)
	}
}

func TestExportAllowsSymlinkedParentOutsideRepository(t *testing.T) {
	_, store, _ := exportVault(t, "payload")
	outside := t.TempDir()
	realDir := filepath.Join(outside, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(outside, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(alias, "snap.pkg")
	if _, err := store.ExportSnapshot("snap", "", out); err != nil {
		t.Fatalf("symlinked parent resolving outside the repo should work: %v", err)
	}
	if _, err := os.Stat(filepath.Join(realDir, "snap.pkg")); err != nil {
		t.Fatalf("package did not land in the resolved directory: %v", err)
	}
}

func TestExportRejectsNonRegularOutput(t *testing.T) {
	_, store, _ := exportVault(t, "payload")
	t.Run("directory", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "outdir")
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
			!strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected non-regular-file error, got %v", err)
		}
	})
	t.Run("valid symlink", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, out); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
			!strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("expected symlink error, got %v", err)
		}
		if got, _ := os.ReadFile(target); string(got) != "old" {
			t.Fatalf("symlink target was modified: %q", got)
		}
	})
	t.Run("dangling symlink", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "dangling")
		if err := os.Symlink(filepath.Join(t.TempDir(), "gone"), out); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
			!strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("expected dangling-symlink error, got %v", err)
		}
	})
	t.Run("fifo", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(out, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
			!strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected special-file error, got %v", err)
		}
	})
}

func TestExportRejectsHardlinkToAnyRepositoryFile(t *testing.T) {
	root, store, entry := exportVault(t, "payload")
	// An unreferenced object: overwrite a.txt, snapshot only the new content;
	// the old object stays in objects/ but no snapshot or the index uses it.
	if _, err := store.Put("a.txt", writeFile(t, "replacement")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("fresh"); err != nil {
		t.Fatal(err)
	}
	unreferenced := filepath.Join(root, "objects", entry.Digest)
	if _, err := os.Stat(unreferenced); err != nil {
		t.Fatalf("unreferenced object missing: %v", err)
	}
	cases := map[string]string{
		"index":               filepath.Join(root, "index.json"),
		"lock":                filepath.Join(root, ".lock"),
		"referenced object":   filepath.Join(root, "objects", digestOf("replacement")),
		"unreferenced object": unreferenced,
		"snapshot record":     filepath.Join(root, "snapshots", "snap.json"),
	}
	for label, repoFile := range cases {
		t.Run(label, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "hardlink.pkg")
			if err := os.Link(repoFile, out); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(repoFile)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.ExportSnapshot("fresh", "", out)
			if err == nil || !strings.Contains(err.Error(), "hard link to repository file") {
				t.Fatalf("expected hardlink error, got %v", err)
			}
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

func TestExportRequiresExistingInitializedRepository(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "vault")
	out := filepath.Join(t.TempDir(), "snap.pkg")
	if _, err := New(missing).ExportSnapshot("snap", "", out); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected missing-repository error, got %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("export created the missing repository root")
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("export created an output despite the missing repository")
	}

	// A directory that exists but has no index.json is uninitialized.
	uninit := filepath.Join(t.TempDir(), "vault")
	if err := os.MkdirAll(uninit, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(uninit).ExportSnapshot("snap", "", out); err == nil ||
		!strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("expected uninitialized-repository error, got %v", err)
	}
	if entries, err := os.ReadDir(uninit); err != nil || len(entries) != 0 {
		t.Fatalf("export modified the uninitialized repository: %v %v", entries, err)
	}
}

func TestExportParentDirectoryRules(t *testing.T) {
	_, store, _ := exportVault(t, "payload")
	t.Run("missing parent is not created", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "no", "such", "snap.pkg")
		if _, err := store.ExportSnapshot("snap", "", out); err == nil ||
			!strings.Contains(err.Error(), "parent directory is not accessible") {
			t.Fatalf("expected inaccessible-parent error, got %v", err)
		}
		if _, err := os.Stat(filepath.Dir(out)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("export created the missing parent directory")
		}
	})
	t.Run("unsearchable parent is an error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions")
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		out := filepath.Join(dir, "snap.pkg")
		if _, err := store.ExportSnapshot("snap", "", out); err == nil {
			t.Fatal("export succeeded with an inaccessible parent")
		}
	})
}

func TestExportReplacesExistingRegularFileAndPreservesMode(t *testing.T) {
	_, store, _ := exportVault(t, "payload")
	out := filepath.Join(t.TempDir(), "snap.pkg")
	if err := os.WriteFile(out, []byte("old package contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := store.ExportSnapshot("snap", "", out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 1 || res.Objects != 1 {
		t.Fatalf("result=%+v", res)
	}
	pkg, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pkg), "artifact-vault-snapshot") {
		t.Fatalf("output was not replaced with the package: %q", pkg[:min(60, len(pkg))])
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 0600", info.Mode().Perm())
	}
}

func TestExportFailureLeavesOutputStateUntouched(t *testing.T) {
	root, store, entry := exportVault(t, "alpha")
	t.Run("missing snapshot names the snapshot", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "snap.pkg")
		_, err := store.ExportSnapshot("nope", "", out)
		if err == nil || !strings.Contains(err.Error(), `snapshot "nope" not found`) {
			t.Fatalf("expected snapshot-not-found error, got %v", err)
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed export created an output")
		}
	})
	t.Run("corrupt record names the snapshot", func(t *testing.T) {
		record := `{"name":"bad","entries":{"a":{"name":"a","digest":"XYZ","size":0,"createdAt":"2026-01-01T00:00:00Z"}}}` + "\n"
		if err := os.WriteFile(filepath.Join(root, "snapshots", "bad.json"), []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "bad.pkg")
		_, err := store.ExportSnapshot("bad", "", out)
		if err == nil || !strings.Contains(err.Error(), `snapshot "bad" is corrupted`) {
			t.Fatalf("expected corrupt-snapshot error, got %v", err)
		}
	})
	t.Run("missing object names the object", func(t *testing.T) {
		obj := filepath.Join(root, "objects", entry.Digest)
		good, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(obj); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "missing.pkg")
		_, err = store.ExportSnapshot("snap", "", out)
		if err == nil || !strings.Contains(err.Error(), entry.Digest) {
			t.Fatalf("expected error naming object %s, got %v", entry.Digest, err)
		}
		if strings.Contains(err.Error(), "output") {
			t.Fatalf("object failure misreported as an output error: %v", err)
		}
		if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed export created an output")
		}
		if err := os.WriteFile(obj, good, 0o644); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("checksum mismatch preserves the existing package", func(t *testing.T) {
		obj := filepath.Join(root, "objects", entry.Digest)
		good, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "snap.pkg")
		if _, err := store.ExportSnapshot("snap", "", out); err != nil {
			t.Fatal(err)
		}
		sentinel, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(obj, []byte("X"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ExportSnapshot("snap", "", out); err == nil {
			t.Fatal("export of a corrupt object succeeded")
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(sentinel) {
			t.Fatal("failed export replaced the existing package")
		}
		if err := os.WriteFile(obj, good, 0o644); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExportDoesNotModifyRepository(t *testing.T) {
	root, store, entry := exportVault(t, "payload")
	paths := []string{
		filepath.Join(root, "index.json"),
		filepath.Join(root, ".lock"),
		filepath.Join(root, "snapshots", "snap.json"),
		filepath.Join(root, "objects", entry.Digest),
	}
	before := map[string][]byte{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		before[p] = data
	}
	out := filepath.Join(t.TempDir(), "snap.pkg")
	if _, err := store.ExportSnapshot("snap", "", out); err != nil {
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

func TestExportRetryAfterLeftoverTemp(t *testing.T) {
	_, store, _ := exportVault(t, "payload")
	dir := t.TempDir()
	// Simulate a temporary file left by an export process that died.
	leftover := filepath.Join(dir, ".package-deadbeef")
	if err := os.WriteFile(leftover, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "snap.pkg")
	if _, err := store.ExportSnapshot("snap", "", out); err != nil {
		t.Fatalf("retry export failed: %v", err)
	}
	pkg, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pkg), packageFormat) {
		t.Fatal("output is not a complete package")
	}
}

func TestExportEmptySnapshotAndObjectlessDelta(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).CreateSnapshot("empty"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "empty.pkg")
	res, err := New(root).ExportSnapshot("empty", "", out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Entries != 0 || res.Objects != 0 {
		t.Fatalf("empty export result=%+v", res)
	}
	// A delta carrying no new objects must still produce a package.
	out2 := filepath.Join(t.TempDir(), "delta.pkg")
	res2, err := New(root).ExportSnapshot("empty", "empty", out2)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Objects != 0 {
		t.Fatalf("objectless delta carried %d objects", res2.Objects)
	}
}

// TestExportCommitDetectsParentSwap performs the parent-replacement race the
// pin-and-revalidate commit is designed to stop: while the package is being
// staged, the output's parent directory is replaced by a symlink to the
// repository and the output name is made to collide with the index. The
// export must refuse and leave every repository file untouched.
func TestExportCommitDetectsParentSwap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}
	root, store := seedVault(t, map[string]string{"big.txt": strings.Repeat("ab", 5<<20)})
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	indexBefore, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}

	outside := t.TempDir()
	outdir := filepath.Join(outside, "deliver")
	if err := os.Mkdir(outdir, 0o755); err != nil {
		t.Fatal(err)
	}
	// "index.json" inside a directory symlinked to the repository would
	// overwrite the real index if the commit followed the swapped path.
	out := filepath.Join(outdir, "index.json")

	var wg sync.WaitGroup
	wg.Add(1)
	var exportErr error
	go func() {
		defer wg.Done()
		_, exportErr = store.ExportSnapshot("snap", "", out)
	}()

	// Swap as soon as the package temp file appears in the pinned directory.
	deadline := time.Now().Add(10 * time.Second)
	swapped := false
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(outdir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".package-") {
				if err := os.Rename(outdir, outdir+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(root, outdir); err != nil {
					t.Fatal(err)
				}
				swapped = true
				break
			}
		}
		if swapped {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !swapped {
		t.Fatal("never observed the staged package temp file")
	}
	wg.Wait()

	if exportErr == nil || !strings.Contains(exportErr.Error(), "unsafe") {
		t.Fatalf("expected unsafe-output error after parent swap, got %v", exportErr)
	}
	indexAfter, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(indexBefore) {
		t.Fatal("the repository index was overwritten through the swapped parent")
	}
	if _, err := os.Stat(filepath.Join(root, "index.json.tmp")); err == nil {
		t.Fatal("stray temp file landed in the repository")
	}
	// The package must not have appeared inside the repository under any name.
	if entries, err := os.ReadDir(root); err != nil {
		t.Fatal(err)
	} else {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".package-") {
				t.Fatal("package temp file committed into the repository")
			}
		}
	}
}

// --- command-line parity -----------------------------------------------------

var (
	exportBinaryOnce sync.Once
	exportBinaryPath string
	exportBinaryErr  error
)

func exportBinary(t *testing.T) string {
	t.Helper()
	exportBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "artifact-vault-build-")
		if err != nil {
			exportBinaryErr = err
			return
		}
		bin := filepath.Join(dir, "artifact-vault")
		exportBinaryErr = exec.Command("go", "build", "-o", bin, "../../cmd/artifact-vault").Run()
		exportBinaryPath = bin
	})
	if exportBinaryErr != nil {
		t.Fatalf("build CLI: %v", exportBinaryErr)
	}
	return exportBinaryPath
}

func TestExportCLIParity(t *testing.T) {
	root, _, _ := exportVault(t, "payload")
	if _, err := New(root).CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	bin := exportBinary(t)

	t.Run("unsafe output is refused on the command line", func(t *testing.T) {
		cmd := exec.Command(bin, "snapshot", "export", "--root", root,
			"--name", "snap", "--output", filepath.Join(root, "index.json"))
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			t.Fatal("CLI export over the index succeeded")
		}
		if !strings.Contains(stderr.String(), "inside the repository") {
			t.Fatalf("stderr=%q", stderr.String())
		}
	})
	t.Run("unsafe delta output is refused on the command line", func(t *testing.T) {
		cmd := exec.Command(bin, "snapshot", "export", "--root", root,
			"--name", "snap", "--base", "base", "--output", filepath.Join(root, "objects", digestOf("payload")))
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			t.Fatal("CLI delta export over an object succeeded")
		}
		if !strings.Contains(stderr.String(), "inside the repository") {
			t.Fatalf("stderr=%q", stderr.String())
		}
	})
	t.Run("successful CLI export keeps the summary", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "snap.pkg")
		cmd := exec.Command(bin, "snapshot", "export", "--root", root,
			"--name", "snap", "--output", out)
		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("CLI export failed: %v %q", err, stderr.String())
		}
		if want := fmt.Sprintf("exported snapshot snap with %d entries, %d objects\n", 1, 1); stdout.String() != want {
			t.Fatalf("stdout=%q, want %q", stdout.String(), want)
		}
	})
}
