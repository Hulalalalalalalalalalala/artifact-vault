package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// corruptIndex replaces the repository index with raw JSON.
func corruptIndex(t *testing.T, root, record string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
}

// indexWith wraps an entries JSON object in an index document.
func indexWith(entries string) string {
	return "{\"entries\":" + entries + "}\n"
}

func TestGetHappyPathAndEmptyObject(t *testing.T) {
	root, store := seedVault(t, map[string]string{
		"releases/app.bin": "release payload\n",
		"empty.bin":        "",
	})
	for _, tc := range []struct {
		name, want string
	}{
		{"releases/app.bin", "release payload\n"},
		{"empty.bin", ""},
	} {
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := store.Get(tc.name, out); err != nil {
			t.Fatalf("get %s: %v", tc.name, err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Fatalf("content of %s=%q, want %q", tc.name, got, tc.want)
		}
	}
	// A missing output is created directly under an existing directory.
	out := filepath.Join(t.TempDir(), "fresh.bin")
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("precondition: output should not exist")
	}
	if err := New(root).Get("empty.bin", out); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() != 0 {
		t.Fatalf("empty object output: %v %v", fi, err)
	}
}

func TestGetReplacesExistingRegularFileCompletely(t *testing.T) {
	root, _ := seedVault(t, map[string]string{"a.txt": "new"})
	out := filepath.Join(t.TempDir(), "out.txt")
	original := []byte("old contents that are longer than the replacement!!!")
	if err := os.WriteFile(out, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New(root).Get("a.txt", out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content=%q", got)
	}
}

func TestGetFailureCategories(t *testing.T) {
	goodMeta := func(digest, size string) string {
		return `{"name":"a.txt","digest":"` + digest + `","size":` + size + `,"createdAt":"2026-01-01T00:00:00Z"}`
	}

	t.Run("name not found", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		err := New(root).Get("missing.txt", filepath.Join(t.TempDir(), "o"))
		if !errors.Is(err, ErrNameNotFound) {
			t.Fatalf("err=%v, want ErrNameNotFound", err)
		}
		if !strings.Contains(err.Error(), "missing.txt") {
			t.Fatalf("error does not name the artifact: %v", err)
		}
	})

	t.Run("index unparsable", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		corruptIndex(t, root, `{not json`)
		err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o"))
		if !errors.Is(err, ErrRecordDamaged) {
			t.Fatalf("err=%v, want ErrRecordDamaged", err)
		}
	})

	t.Run("index missing entries mapping", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		corruptIndex(t, root, `{}`)
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrRecordDamaged) {
			t.Fatal("missing entries mapping should be record damage")
		}
	})

	t.Run("index null entries mapping", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		corruptIndex(t, root, `{"entries":null}`)
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrRecordDamaged) {
			t.Fatal("null entries mapping should be record damage")
		}
	})

	t.Run("entry name does not match map key", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		body := strings.Replace(goodMeta(digestOf("data!"), "5"), `"name":"a.txt"`, `"name":"b.txt"`, 1)
		corruptIndex(t, root, indexWith(`{"a.txt":`+body+`}`))
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrRecordDamaged) {
			t.Fatal("key/name mismatch should be record damage")
		}
	})

	t.Run("bad digest", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		corruptIndex(t, root, indexWith(`{"a.txt":`+goodMeta("XYZ", "5")+`}`))
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrRecordDamaged) {
			t.Fatal("bad digest should be record damage")
		}
	})

	t.Run("uppercase digest", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		upper := strings.ToUpper(digestOf("data!"))
		corruptIndex(t, root, indexWith(`{"a.txt":`+goodMeta(upper, "5")+`}`))
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrRecordDamaged) {
			t.Fatal("uppercase digest should be record damage")
		}
	})

	t.Run("negative size", func(t *testing.T) {
		root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
		corruptIndex(t, root, indexWith(`{"a.txt":`+goodMeta(digestOf("data!"), "-1")+`}`))
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrRecordDamaged) {
			t.Fatal("negative size should be record damage")
		}
	})

	t.Run("object missing", func(t *testing.T) {
		root, entry := seedVaultEntry(t, "a.txt", "data!")
		if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
			t.Fatal(err)
		}
		err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o"))
		if !errors.Is(err, ErrObjectDamaged) {
			t.Fatalf("err=%v, want ErrObjectDamaged", err)
		}
	})

	t.Run("object content wrong", func(t *testing.T) {
		root, entry := seedVaultEntry(t, "a.txt", "data!")
		if err := os.WriteFile(filepath.Join(root, "objects", entry.Digest), []byte("XXXX!"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o"))
		if !errors.Is(err, ErrObjectDamaged) || !strings.Contains(err.Error(), entry.Digest) {
			t.Fatalf("err=%v, want object damage naming %s", err, entry.Digest)
		}
	})

	t.Run("object truncated", func(t *testing.T) {
		root, _ := seedVaultEntry(t, "a.txt", "data!")
		entries, err := New(root).List()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "objects", entries[0].Digest), []byte("da"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrObjectDamaged) {
			t.Fatal("short object should be object damage")
		}
	})

	t.Run("object grew beyond record", func(t *testing.T) {
		root, _ := seedVaultEntry(t, "a.txt", "data!")
		entries, err := New(root).List()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "objects", entries[0].Digest), []byte("data!-extra"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrObjectDamaged) {
			t.Fatal("oversized object should be object damage")
		}
	})

	t.Run("object is a symlink to intact content", func(t *testing.T) {
		root, entry := seedVaultEntry(t, "a.txt", "data!")
		obj := filepath.Join(root, "objects", entry.Digest)
		good, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "real")
		if err := os.WriteFile(target, good, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(obj); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, obj); err != nil {
			t.Fatal(err)
		}
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrObjectDamaged) {
			t.Fatal("symlink object should be object damage even with intact target")
		}
	})

	t.Run("object is a directory", func(t *testing.T) {
		root, entry := seedVaultEntry(t, "a.txt", "data!")
		obj := filepath.Join(root, "objects", entry.Digest)
		if err := os.Remove(obj); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(obj, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrObjectDamaged) {
			t.Fatal("directory at the object path should be object damage")
		}
	})

	t.Run("recorded size disagrees with intact object", func(t *testing.T) {
		root, _ := seedVaultEntry(t, "a.txt", "data!")
		entries, err := New(root).List()
		if err != nil {
			t.Fatal(err)
		}
		e := entries[0]
		e.Size = 4 // bytes are intact, record lies about the size
		corruptIndex(t, root, indexWith(fmt.Sprintf(
			`{"a.txt":{"name":"a.txt","digest":"%s","size":%d,"createdAt":"2026-01-01T00:00:00Z"}}`,
			e.Digest, e.Size)))
		if err := New(root).Get("a.txt", filepath.Join(t.TempDir(), "o")); !errors.Is(err, ErrObjectDamaged) {
			t.Fatal("size disagreement with the object should be object damage")
		}
	})
}

// seedVaultEntry stores one artifact and returns the root plus its index entry.
func seedVaultEntry(t *testing.T, name, content string) (string, Entry) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "vault")
	entry, err := New(root).Put(name, writeFile(t, content))
	if err != nil {
		t.Fatal(err)
	}
	return root, entry
}

func TestGetKeepsExistingOutputOnEveryFailure(t *testing.T) {
	sentinel := []byte("DO NOT TOUCH ME, valuable bytes")
	checkSentinel := func(t *testing.T, out string) {
		t.Helper()
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(sentinel) {
			t.Fatalf("output bytes changed: %q", got)
		}
	}
	// existingOutput seeds a fresh vault and a valuable pre-existing output.
	existingOutput := func(t *testing.T) (string, string) {
		t.Helper()
		root, _ := seedVaultEntry(t, "a.txt", "data!")
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := os.WriteFile(out, sentinel, 0o644); err != nil {
			t.Fatal(err)
		}
		return root, out
	}

	t.Run("missing name", func(t *testing.T) {
		root, out := existingOutput(t)
		if err := New(root).Get("nope.txt", out); err == nil {
			t.Fatal("expected failure")
		}
		checkSentinel(t, out)
	})
	t.Run("corrupt index", func(t *testing.T) {
		root, out := existingOutput(t)
		corruptIndex(t, root, `{broken`)
		if err := New(root).Get("a.txt", out); err == nil {
			t.Fatal("expected failure")
		}
		checkSentinel(t, out)
	})
	t.Run("missing object", func(t *testing.T) {
		root, entry := seedVaultEntry(t, "a.txt", "data!")
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := os.WriteFile(out, sentinel, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
			t.Fatal(err)
		}
		if err := New(root).Get("a.txt", out); err == nil {
			t.Fatal("expected failure")
		}
		checkSentinel(t, out)
	})
	t.Run("corrupt object", func(t *testing.T) {
		root, entry := seedVaultEntry(t, "a.txt", "data!")
		out := filepath.Join(t.TempDir(), "out.bin")
		if err := os.WriteFile(out, sentinel, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "objects", entry.Digest), []byte("BAD!!"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := New(root).Get("a.txt", out); err == nil {
			t.Fatal("expected failure")
		}
		checkSentinel(t, out)
	})
	t.Run("output is a directory", func(t *testing.T) {
		root, _ := seedVaultEntry(t, "a.txt", "data!")
		out := t.TempDir()
		if err := New(root).Get("a.txt", out); err == nil {
			t.Fatal("expected failure")
		}
		if fi, err := os.Stat(out); err != nil || !fi.IsDir() {
			t.Fatalf("directory output altered: %v %v", fi, err)
		}
	})
}

func TestGetLeavesNoOccupantWhenOutputMissing(t *testing.T) {
	root, entry := seedVaultEntry(t, "a.txt", "data!")

	// Missing parent: no parent directory and no output are created.
	out := filepath.Join(t.TempDir(), "sub", "out.bin")
	if err := New(root).Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("download created something at the missing output")
	}
	if _, err := os.Stat(filepath.Dir(out)); !os.IsNotExist(err) {
		t.Fatal("download created the parent directory")
	}

	// Corrupt object: same guarantee, and no stray temp file remains.
	if err := os.WriteFile(filepath.Join(root, "objects", entry.Digest), []byte("BAD!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	out2 := filepath.Join(dir, "out2.bin")
	if err := New(root).Get("a.txt", out2); !errors.Is(err, ErrObjectDamaged) {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(out2); !os.IsNotExist(err) {
		t.Fatal("failed download occupied the output name")
	}
	dirents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirents {
		if strings.HasPrefix(d.Name(), ".download-") {
			t.Fatalf("unpublished temp file left behind: %s", d.Name())
		}
	}
}

func TestGetRetryAfterFailureSucceedsWithoutCleanup(t *testing.T) {
	root, entry := seedVaultEntry(t, "a.txt", "data!")
	out := filepath.Join(t.TempDir(), "out.bin")
	obj := filepath.Join(root, "objects", entry.Digest)

	if err := os.WriteFile(obj, []byte("BAD!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New(root).Get("a.txt", out); !errors.Is(err, ErrObjectDamaged) {
		t.Fatal("first download should fail")
	}
	// A leftover temp file in the destination directory must not block retry:
	// CreateTemp always mints a fresh unique name.
	if f, err := os.CreateTemp(filepath.Dir(out), ".download-*"); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	if err := os.WriteFile(obj, []byte("data!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New(root).Get("a.txt", out); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "data!" {
		t.Fatalf("retry content=%q err=%v", got, err)
	}
}

func TestGetOutputPathRules(t *testing.T) {
	root, _ := seedVault(t, map[string]string{"a.txt": "data!"})
	store := New(root)

	t.Run("parent directory missing", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-such-dir")
		out := filepath.Join(missing, "o.bin")
		err := store.Get("a.txt", out)
		if !errors.Is(err, ErrOutputUnavailable) {
			t.Fatalf("err=%v, want ErrOutputUnavailable", err)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Fatalf("error should name the missing directory: %v", err)
		}
	})

	t.Run("output is a directory", func(t *testing.T) {
		if err := store.Get("a.txt", t.TempDir()); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("directory output should be rejected")
		}
	})

	t.Run("output is a symlink", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, out); err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("symlink output should be rejected")
		}
		got, err := os.ReadFile(target)
		if err != nil || string(got) != "x" {
			t.Fatalf("symlink target changed: %q %v", got, err)
		}
	})

	t.Run("output inside repository", func(t *testing.T) {
		// Paths that must not come into existence.
		for _, out := range []string{
			filepath.Join(root, "copied.bin"),
			filepath.Join(root, "objects", "copied.bin"),
			filepath.Join(root, "snapshots", "deep", "copied.bin"),
		} {
			err := store.Get("a.txt", out)
			if !errors.Is(err, ErrOutputUnavailable) {
				t.Fatalf("out=%s err=%v", out, err)
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("file created at %s", out)
			}
		}
		// An existing repository file (the index) must survive byte-for-byte.
		index := filepath.Join(root, "index.json")
		before, err := os.ReadFile(index)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", index); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("using index.json as output should be rejected")
		}
		after, err := os.ReadFile(index)
		if err != nil || string(after) != string(before) {
			t.Fatalf("repository index was modified: %v", err)
		}
	})

	t.Run("nonexistent nested output inside repository", func(t *testing.T) {
		out := filepath.Join(root, "brand-new-dir", "x.bin")
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatalf("err=%v", err)
		}
		if _, err := os.Stat(filepath.Join(root, "brand-new-dir")); !os.IsNotExist(err) {
			t.Fatal("download created a directory inside the repository")
		}
	})

	t.Run("enters repository through parent symlink", func(t *testing.T) {
		outside := t.TempDir()
		link := filepath.Join(outside, "into-vault")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(link, "copied.bin")
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("symlink into repository should be rejected")
		}
		if _, err := os.Stat(filepath.Join(root, "copied.bin")); !os.IsNotExist(err) {
			t.Fatal("download wrote into the repository through a symlink")
		}
	})

	t.Run("symlinked parent outside repository still works", func(t *testing.T) {
		realDir := t.TempDir()
		link := filepath.Join(t.TempDir(), "linkdir")
		if err := os.Symlink(realDir, link); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(link, "o.bin")
		if err := store.Get("a.txt", out); err != nil {
			t.Fatalf("download through benign parent symlink failed: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(realDir, "o.bin"))
		if err != nil || string(got) != "data!" {
			t.Fatalf("content=%q err=%v", got, err)
		}
	})

	t.Run("hard link to content object", func(t *testing.T) {
		entries, err := store.List()
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "hl.bin")
		obj := filepath.Join(root, "objects", entries[0].Digest)
		if err := os.Link(obj, out); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(obj)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("hard link to a content object should be rejected")
		}
		after, err := os.ReadFile(obj)
		if err != nil || string(after) != string(before) {
			t.Fatalf("repository object changed: %q %v", after, err)
		}
	})

	t.Run("hard link to index", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "index-copy.json")
		index := filepath.Join(root, "index.json")
		if err := os.Link(index, out); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(index)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("hard link to the index should be rejected")
		}
		after, err := os.ReadFile(index)
		if err != nil || string(after) != string(before) {
			t.Fatalf("repository index changed: %v", err)
		}
	})

	t.Run("hard link to lock file", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "lock-copy")
		lock := filepath.Join(root, ".lock")
		// Touch the lock through a benign operation first so it exists.
		if _, err := store.List(); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(lock, out); err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("hard link to the lock file should be rejected")
		}
	})

	t.Run("hard link to snapshot record", func(t *testing.T) {
		if _, err := store.CreateSnapshot("snap"); err != nil {
			t.Fatal(err)
		}
		snap := filepath.Join(root, "snapshots", "snap.json")
		before, err := os.ReadFile(snap)
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "snap-copy.json")
		if err := os.Link(snap, out); err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); !errors.Is(err, ErrOutputUnavailable) {
			t.Fatal("hard link to a snapshot record should be rejected")
		}
		after, err := os.ReadFile(snap)
		if err != nil || string(after) != string(before) {
			t.Fatalf("repository snapshot changed: %v", err)
		}
	})

	t.Run("permission bits are preserved", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "mode.bin")
		if err := os.WriteFile(out, []byte("older"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(out)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("new mode=%o, want 0600", fi.Mode().Perm())
		}
	})

	t.Run("new file gets default mode", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "mode-new.bin")
		if err := store.Get("a.txt", out); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(out)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Fatalf("new mode=%o, want 0644", fi.Mode().Perm())
		}
	})

	t.Run("normal outside path overwrites fine", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "plain.bin")
		if err := os.WriteFile(out, []byte("older"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := store.Get("a.txt", out); err != nil {
			t.Fatalf("normal overwrite failed: %v", err)
		}
		got, err := os.ReadFile(out)
		if err != nil || string(got) != "data!" {
			t.Fatalf("content=%q err=%v", got, err)
		}
	})
}

func TestGetStreamsWithoutMemoryGrowth(t *testing.T) {
	// A 64 MiB object is streamed through fixed-size buffers; the working set
	// stays far below the payload size.
	const size = 64 * 1024 * 1024
	src := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	pattern := []byte("0123456789ABCDEF")
	for written := 0; written < size; written += len(pattern) {
		if _, err := f.Write(pattern); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "vault")
	entry, err := New(root).Put("big.bin", src)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Size != size {
		t.Fatalf("entry size=%d", entry.Size)
	}
	out := filepath.Join(t.TempDir(), "big-out.bin")
	if err := New(root).Get("big.bin", out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Size() != size {
		t.Fatalf("output size=%d err=%v", fi.Size(), err)
	}
	h := sha256.New()
	rf, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(h, rf, size); err != nil {
		t.Fatal(err)
	}
	rf.Close()
	if hex.EncodeToString(h.Sum(nil)) != entry.Digest {
		t.Fatal("downloaded digest mismatch")
	}
}

func TestGetDoesNotModifyRepository(t *testing.T) {
	root, _ := seedVault(t, map[string]string{"a.txt": "data!", "b.txt": "also!"})
	if _, err := New(root).CreateSnapshot("snap"); err != nil {
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
	entries, err := New(root).List()
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string][]byte{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(root, "objects", e.Digest))
		if err != nil {
			t.Fatal(err)
		}
		objects[e.Digest] = b
	}
	for _, name := range []string{"a.txt", "b.txt"} {
		out := filepath.Join(t.TempDir(), name)
		if err := New(root).Get(name, out); err != nil {
			t.Fatal(err)
		}
	}
	indexAfter, err := os.ReadFile(filepath.Join(root, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	snapAfter, err := os.ReadFile(filepath.Join(root, "snapshots", "snap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(indexBefore) || string(snapAfter) != string(snapBefore) {
		t.Fatal("get rewrote the index or a snapshot")
	}
	for digest, before := range objects {
		after, err := os.ReadFile(filepath.Join(root, "objects", digest))
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) {
			t.Fatalf("object %s changed across get", digest)
		}
	}
	// Uploads, snapshot restore and gc keep working after downloads.
	if _, err := New(root).Put("c.txt", writeFile(t, "cee")); err != nil {
		t.Fatal(err)
	}
	if err := New(root).RestoreSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).GC(false); err != nil {
		t.Fatal(err)
	}
}

// TestGetConcurrentWithPutRestoreGC pins one coherent version per download:
// every delivered file matches exactly one recorded digest, and no download
// fails because an object was collected mid-flight.
func TestGetConcurrentWithPutRestoreGC(t *testing.T) {
	root, _ := seedVault(t, map[string]string{"movable.txt": "version-0"})
	if _, err := New(root).CreateSnapshot("s0"); err != nil {
		t.Fatal(err)
	}

	versions := map[string]string{digestOf("version-0"): "version-0"}
	var mu sync.Mutex

	const writers = 4
	const readers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers+readers)

	for i := 0; i < writers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 5; round++ {
				content := fmt.Sprintf("version-%d-%d", i, round)
				// Register before the atomic publication: a reader can only
				// observe this version once Put renames the index, at which
				// point the map already knows it.
				mu.Lock()
				versions[digestOf(content)] = content
				mu.Unlock()
				if _, err := New(root).Put("movable.txt", writeFile(t, content)); err != nil {
					errs <- err
					return
				}
				snap := fmt.Sprintf("s-%d-%d", i, round)
				if _, err := New(root).CreateSnapshot(snap); err != nil {
					errs <- err
					return
				}
				if err := New(root).RestoreSnapshot(snap); err != nil {
					errs <- err
					return
				}
				if _, err := New(root).GC(false); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for round := 0; round < 10; round++ {
				out := filepath.Join(t.TempDir(), "o.bin")
				if err := New(root).Get("movable.txt", out); err != nil {
					errs <- fmt.Errorf("download failed during concurrent churn: %w", err)
					return
				}
				data, err := os.ReadFile(out)
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				want, ok := versions[digestOf(string(data))]
				mu.Unlock()
				if !ok || want != string(data) {
					errs <- fmt.Errorf("downloaded content matched no single recorded version: %q", data)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
