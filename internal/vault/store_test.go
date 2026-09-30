package vault

import (
	"os"
	"path/filepath"
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
