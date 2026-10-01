package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// getVault seeds a fresh vault with one artifact and returns its root and
// store.
func getVault(t *testing.T, content string) (string, *Store, Entry) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	entry, err := store.Put("a.txt", writeFile(t, content))
	if err != nil {
		t.Fatal(err)
	}
	return root, store, entry
}

func readOutput(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestGetRoundTrip(t *testing.T) {
	_, store, _ := getVault(t, "release payload\n")
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := store.Get("a.txt", output); err != nil {
		t.Fatal(err)
	}
	if got := readOutput(t, output); string(got) != "release payload\n" {
		t.Fatalf("content=%q", got)
	}
}

func TestGetOverwritesExistingFile(t *testing.T) {
	_, store, _ := getVault(t, "new contents")
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(output, []byte("old, much longer contents"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Get("a.txt", output); err != nil {
		t.Fatal(err)
	}
	if got := readOutput(t, output); string(got) != "new contents" {
		t.Fatalf("content=%q", got)
	}
}

func TestGetPreservesFilePermissions(t *testing.T) {
	_, store, _ := getVault(t, "payload")
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(output, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Get("a.txt", output); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 0600", info.Mode().Perm())
	}
}

func TestGetEmptyObject(t *testing.T) {
	_, store, _ := getVault(t, "placeholder")
	if _, err := store.Put("empty.txt", writeFile(t, "")); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "empty.out")
	if err := store.Get("empty.txt", output); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("size=%d, want 0", info.Size())
	}
	if got := readOutput(t, output); len(got) != 0 {
		t.Fatalf("content=%q, want empty", got)
	}
}

func TestGetMissingName(t *testing.T) {
	_, store, _ := getVault(t, "payload")
	output := filepath.Join(t.TempDir(), "out.txt")
	err := store.Get("nope.txt", output)
	if err == nil || !strings.Contains(err.Error(), `artifact "nope.txt" not found`) {
		t.Fatalf("expected not-found error, got %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed get created an output file")
	}
}

func TestGetRejectsCorruptIndex(t *testing.T) {
	cases := map[string]string{
		"bad json":       `{broken`,
		"no entries":     `{}`,
		"null entries":   `{"entries":null}`,
		"index is array": `[]`,
	}
	for label, data := range cases {
		t.Run(label, func(t *testing.T) {
			root, store, _ := getVault(t, "payload")
			if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "out.txt")
			err := store.Get("a.txt", output)
			if err == nil || !strings.Contains(err.Error(), "record is corrupted") {
				t.Fatalf("expected record-corruption error, got %v", err)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed get created an output file")
			}
		})
	}
}

func TestGetRejectsCorruptRecord(t *testing.T) {
	d := digestOf("payload")
	cases := map[string]string{
		"key mismatch": `{"entries":{"a.txt":{"name":"b.txt","digest":"` + d + `","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"bad digest":   `{"entries":{"a.txt":{"name":"a.txt","digest":"XYZ","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"negative size": `{"entries":{"a.txt":{"name":"a.txt","digest":"` + d + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		"bad name":     `{"entries":{"../x":{"name":"../x","digest":"` + d + `","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
	}
	for label, data := range cases {
		t.Run(label, func(t *testing.T) {
			root, store, _ := getVault(t, "payload")
			if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "out.txt")
			err := store.Get("a.txt", output)
			if err == nil || !strings.Contains(err.Error(), "record is corrupted") {
				t.Fatalf("expected record-corruption error, got %v", err)
			}
		})
	}
}

func TestGetRejectsMissingObject(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.txt")
	err := store.Get("a.txt", output)
	if err == nil || !strings.Contains(err.Error(), "object "+entry.Digest+" is missing") {
		t.Fatalf("expected missing-object error naming the digest, got %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed get created an output file")
	}
}

func TestGetRejectsCorruptObject(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	object := filepath.Join(root, "objects", entry.Digest)
	good, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("checksum mismatch", func(t *testing.T) {
		// Same length as the recorded size, different bytes: the checksum
		// check must fire, not the size check.
		if err := os.WriteFile(object, []byte("XXXXXXX"), 0o644); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "out.txt")
		err := store.Get("a.txt", output)
		if err == nil || !strings.Contains(err.Error(), "object "+entry.Digest+" is corrupted") || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("expected checksum-mismatch error, got %v", err)
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed get created an output file")
		}
	})
	t.Run("size mismatch", func(t *testing.T) {
		if err := os.WriteFile(object, []byte("short"), 0o644); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "out.txt")
		err := store.Get("a.txt", output)
		if err == nil || !strings.Contains(err.Error(), "object "+entry.Digest+" is corrupted") || !strings.Contains(err.Error(), "record says 7") {
			t.Fatalf("expected size-mismatch error, got %v", err)
		}
	})
	if err := os.WriteFile(object, good, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGetRejectsNonRegularObject(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	object := filepath.Join(root, "objects", entry.Digest)
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", object); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.txt")
	err := store.Get("a.txt", output)
	if err == nil || !strings.Contains(err.Error(), "object "+entry.Digest+" is a symbolic link") {
		t.Fatalf("expected symlink-object error, got %v", err)
	}
}

func TestGetRejectsOutputInsideRepository(t *testing.T) {
	root, store, _ := getVault(t, "payload")
	cases := map[string]string{
		"index.json":        filepath.Join(root, "index.json"),
		"object file":       filepath.Join(root, "objects", digestOf("payload")),
		"not yet created":    filepath.Join(root, "new-output.txt"),
		"nested not created": filepath.Join(root, "sub", "new.txt"),
	}
	for label, output := range cases {
		t.Run(label, func(t *testing.T) {
			err := store.Get("a.txt", output)
			if err == nil || !strings.Contains(err.Error(), "inside the repository") {
				t.Fatalf("expected inside-repository error, got %v", err)
			}
		})
	}
}

func TestGetRejectsOutputThroughSymlinkedParent(t *testing.T) {
	root, store, _ := getVault(t, "payload")
	// A symlink outside the repository that points into it.
	link := filepath.Join(t.TempDir(), "vault-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(link, "evil.txt")
	err := store.Get("a.txt", output)
	if err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Fatalf("expected inside-repository error through symlink, got %v", err)
	}
}

func TestGetRejectsOutputParentMissing(t *testing.T) {
	_, store, _ := getVault(t, "payload")
	output := filepath.Join(t.TempDir(), "no", "such", "out.txt")
	err := store.Get("a.txt", output)
	if err == nil || !strings.Contains(err.Error(), "parent directory is not accessible") {
		t.Fatalf("expected parent-missing error, got %v", err)
	}
}

func TestGetRejectsNonRegularOutput(t *testing.T) {
	_, store, _ := getVault(t, "payload")
	t.Run("directory", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "outdir")
		if err := os.Mkdir(output, 0o755); err != nil {
			t.Fatal(err)
		}
		err := store.Get("a.txt", output)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected non-regular error, got %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target.txt")
		if err := os.WriteFile(target, []byte("target"), 0o644); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, output); err != nil {
			t.Fatal(err)
		}
		err := store.Get("a.txt", output)
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("expected symlink error, got %v", err)
		}
		// The link target must be untouched.
		if got := readOutput(t, target); string(got) != "target" {
			t.Fatalf("symlink target changed: %q", got)
		}
	})
}

func TestGetRejectsHardlinkToRepositoryFile(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"index":    filepath.Join(root, "index.json"),
		"object":   filepath.Join(root, "objects", entry.Digest),
		"snapshot": filepath.Join(root, "snapshots", "snap.json"),
		"lock":     filepath.Join(root, ".lock"),
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
			err = store.Get("a.txt", output)
			if err == nil || !strings.Contains(err.Error(), "hard link to repository file") {
				t.Fatalf("expected hardlink error, got %v", err)
			}
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

func TestFailedGetPreservesExistingOutput(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	object := filepath.Join(root, "objects", entry.Digest)
	good, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(output, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Get("a.txt", output); err == nil {
		t.Fatal("expected failure")
	}
	if got := readOutput(t, output); string(got) != "ORIGINAL" {
		t.Fatalf("existing output changed after failed get: %q", got)
	}
	if err := os.WriteFile(object, good, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFailedGetLeavesNoOutput(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := store.Get("a.txt", output); err == nil {
		t.Fatal("expected failure")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed get left an output file behind")
	}
}

func TestGetRetryAfterLeftoverTemp(t *testing.T) {
	_, store, _ := getVault(t, "payload")
	output := filepath.Join(t.TempDir(), "out.txt")
	// Simulate a temporary file left behind by an interrupted process.
	leftover := filepath.Join(filepath.Dir(output), ".download-123456789")
	if err := os.WriteFile(leftover, []byte("partial"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Get("a.txt", output); err != nil {
		t.Fatalf("get after leftover temp failed: %v", err)
	}
	if got := readOutput(t, output); string(got) != "payload" {
		t.Fatalf("content=%q", got)
	}
}

func TestGetDoesNotModifyRepository(t *testing.T) {
	root, store, _ := getVault(t, "payload")
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(root, "index.json"),
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
	output := filepath.Join(t.TempDir(), "out.txt")
	if err := store.Get("a.txt", output); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		after, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before[p]) {
			t.Fatalf("repository file %s changed across get", p)
		}
	}
}

func TestGetConcurrentWithPutAndGCConsistent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("base.txt", writeFile(t, "base")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*3)
	for i := 0; i < workers; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			if _, err := New(root).Put(fmt.Sprintf("art-%d.txt", i), writeFile(t, fmt.Sprintf("payload-%d", i))); err != nil {
				errs <- err
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			out := filepath.Join(t.TempDir(), fmt.Sprintf("out-%d.txt", i))
			if err := New(root).Get("base.txt", out); err != nil {
				errs <- err
				return
			}
			if got := readOutput(t, out); string(got) != "base" {
				errs <- fmt.Errorf("get observed mixed content %q", got)
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
}

func TestGetLargeFileContentCorrect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large file in short mode")
	}
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	// 5 MiB of deterministic content, streamed without buffering in memory.
	size := 5 << 20
	src := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	pattern := []byte("0123456789abcdef")
	for written := 0; written < size; written += len(pattern) {
		if _, err := f.Write(pattern); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	entry, err := store.Put("big.bin", src)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Size != int64(size) {
		t.Fatalf("size=%d, want %d", entry.Size, size)
	}
	output := filepath.Join(t.TempDir(), "big.out")
	if err := store.Get("big.bin", output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != size {
		t.Fatalf("output size=%d, want %d", len(got), size)
	}
	for i := 0; i < size; i++ {
		if got[i] != pattern[i%len(pattern)] {
			t.Fatalf("content differs at byte %d", i)
		}
	}
}
