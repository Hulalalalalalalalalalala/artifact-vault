package vault

import (
	"os"
	"path/filepath"
	"strings"
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

// writeInput writes content to a fresh temp file and returns its path.
func writeInput(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// objectPathOf returns the repository object path for content stored in root.
func objectPathOf(root string, content []byte) string {
	return filepath.Join(root, "objects", digestOf(string(content)))
}

// entriesOf loads the current name mapping.
func entriesOf(t *testing.T, store *Store) map[string]Entry {
	t.Helper()
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]Entry{}
	for _, entry := range entries {
		idx[entry.Name] = entry
	}
	return idx
}

// uploadTemps lists leftover staged-upload temp files in the objects dir.
func uploadTemps(t *testing.T, root string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "objects", ".upload-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func TestPutReusesHealthySharedObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	content := []byte("shared payload\n")
	input := writeInput(t, content)

	first, err := store.Put("a/one.bin", input)
	if err != nil {
		t.Fatal(err)
	}
	object := objectPathOf(root, content)
	// Distinctive permissions prove the reuse path neither rewrites nor
	// re-permissions the existing object.
	if err := os.Chmod(object, 0o640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(object)
	if err != nil {
		t.Fatal(err)
	}

	second, err := store.Put("b/two.bin", input)
	if err != nil {
		t.Fatal(err)
	}
	if second.Digest != first.Digest || second.Size != first.Size {
		t.Fatalf("entries disagree: %+v vs %+v", first, second)
	}
	after, err := os.Stat(object)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o640 {
		t.Fatalf("object permissions changed to %v", after.Mode().Perm())
	}
	if !os.SameFile(before, after) {
		t.Fatal("object was replaced instead of reused")
	}
	got, err := os.ReadFile(object)
	if err != nil || string(got) != string(content) {
		t.Fatalf("object content=%q err=%v", got, err)
	}
	entries := entriesOf(t, store)
	if len(entries) != 2 || entries["a/one.bin"].Digest != first.Digest || entries["b/two.bin"].Digest != first.Digest {
		t.Fatalf("entries=%v", entries)
	}
}

func TestPutEmptyFileReusesEmptyObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	input := writeInput(t, nil)
	entry, err := store.Put("empty/one", input)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Size != 0 {
		t.Fatalf("size=%d", entry.Size)
	}
	if _, err := store.Put("empty/two", input); err != nil {
		t.Fatal(err)
	}
	if len(entriesOf(t, store)) != 2 {
		t.Fatalf("entries=%v", entriesOf(t, store))
	}
}

// expectReuseFailure corrupts or replaces the object for content, then
// confirms that re-uploading the healthy content fails, names the upload and
// digest, and leaves the mapping, the object, and the staging area untouched.
func expectReuseFailure(t *testing.T, root string, store *Store, content []byte, want string) {
	t.Helper()
	digest := digestOf(string(content))
	input := writeInput(t, content)
	before := entriesOf(t, store)

	_, err := store.Put("new/name.bin", input)
	if err == nil {
		t.Fatal("expected put to fail")
	}
	if !strings.Contains(err.Error(), "new/name.bin") || !strings.Contains(err.Error(), digest) {
		t.Fatalf("error should name the upload and digest: %v", err)
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v should mention %q", err, want)
	}

	after := entriesOf(t, store)
	if len(after) != len(before) {
		t.Fatalf("mapping changed: %v -> %v", before, after)
	}
	for name, entry := range before {
		if after[name] != entry {
			t.Fatalf("entry %q changed: %+v -> %+v", name, entry, after[name])
		}
	}
	if temps := uploadTemps(t, root); len(temps) != 0 {
		t.Fatalf("staged upload left behind: %v", temps)
	}
}

func TestPutRejectsTruncatedExistingObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	content := []byte("full healthy payload\n")
	if _, err := store.Put("old/name.bin", writeInput(t, content)); err != nil {
		t.Fatal(err)
	}
	object := objectPathOf(root, content)
	if err := os.Truncate(object, 4); err != nil {
		t.Fatal(err)
	}
	expectReuseFailure(t, root, store, content, "bytes")
	// The damaged object is left as it was; the upload must not repair it.
	info, err := os.Stat(object)
	if err != nil || info.Size() != 4 {
		t.Fatalf("object size=%v err=%v", info.Size(), err)
	}
}

func TestPutRejectsSameSizeDifferentContentObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	content := []byte("original bytes here")
	if _, err := store.Put("old/name.bin", writeInput(t, content)); err != nil {
		t.Fatal(err)
	}
	object := objectPathOf(root, content)
	if err := os.WriteFile(object, []byte("modified bytes here"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectReuseFailure(t, root, store, content, "checksum")
}

func TestPutRejectsSymlinkObject(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "vault")
		store := New(root)
		content := []byte("symlink target test\n")
		if _, err := store.Put("old/name.bin", writeInput(t, content)); err != nil {
			t.Fatal(err)
		}
		object := objectPathOf(root, content)
		if err := os.Remove(object); err != nil {
			t.Fatal(err)
		}
		target := writeInput(t, content) // healthy content at the link target
		if dangling {
			target = filepath.Join(t.TempDir(), "missing")
		}
		if err := os.Symlink(target, object); err != nil {
			t.Fatal(err)
		}
		expectReuseFailure(t, root, store, content, "symbolic link")
		// The link itself must survive; it is never replaced by the upload.
		info, err := os.Lstat(object)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("dangling=%v: object is no longer a symlink: %v", dangling, err)
		}
	}
}

func TestPutRejectsDirectoryObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	content := []byte("directory collision\n")
	if _, err := store.Put("old/name.bin", writeInput(t, content)); err != nil {
		t.Fatal(err)
	}
	object := objectPathOf(root, content)
	if err := os.Remove(object); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(object, 0o755); err != nil {
		t.Fatal(err)
	}
	expectReuseFailure(t, root, store, content, "not a regular file")
}

func TestPutFailureKeepsExistingNameRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	good := []byte("currently mapped content\n")
	first, err := store.Put("shared/name.bin", writeInput(t, good))
	if err != nil {
		t.Fatal(err)
	}
	// Damage the object a second upload of the same name would reuse.
	other := []byte("other content entirely\n")
	if _, err := store.Put("other/name.bin", writeInput(t, other)); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(objectPathOf(root, other), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("shared/name.bin", writeInput(t, other)); err == nil {
		t.Fatal("expected put to fail")
	}
	entry := entriesOf(t, store)["shared/name.bin"]
	if entry != first {
		t.Fatalf("existing record replaced: %+v -> %+v", first, entry)
	}
}

func TestPutStoresNewObjectWhenDigestAbsent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	content := []byte("fresh content\n")
	entry, err := store.Put("new/name.bin", writeInput(t, content))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(objectPathOf(root, content))
	if err != nil || string(got) != string(content) {
		t.Fatalf("object content=%q err=%v", got, err)
	}
	if entry.Digest != digestOf(string(content)) || entry.Size != int64(len(content)) {
		t.Fatalf("entry=%+v", entry)
	}
	if temps := uploadTemps(t, root); len(temps) != 0 {
		t.Fatalf("staged upload left behind: %v", temps)
	}
}
