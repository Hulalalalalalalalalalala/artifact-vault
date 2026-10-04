package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a temp file and returns
// everything it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	tmp, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = tmp
	defer func() { os.Stdout = orig }()
	fn()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestPutCLIRejectsCorruptIndexSilently applies the strict mapping
// precondition at the command line: a healthy put keeps its existing success
// line, but a put over a damaged index fails naming the upload and the index
// problem, prints no stored success line, and leaves the mapping and objects
// untouched.
func TestPutCLIRejectsCorruptIndexSilently(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	input := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", "--root", root}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := run([]string{"put", "--root", root, "--name", "keep.txt", "--file", input}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "stored keep.txt ") {
		t.Fatalf("a healthy put must keep its existing success line, got %q", out)
	}

	indexPath := filepath.Join(root, "index.json")
	indexBefore, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate artifact key: corruption, never a mapping to overwrite.
	corrupt := []byte(`{"entries":{` +
		`"keep.txt":{"name":"keep.txt","digest":"` + strings.Repeat("a", 64) + `","size":7,"createdAt":"2026-01-01T00:00:00Z"},` +
		`"keep.txt":{"name":"keep.txt","digest":"` + strings.Repeat("a", 64) + `","size":7,"createdAt":"2026-01-01T00:00:00Z"}` +
		`}}`)
	if err := os.WriteFile(indexPath, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}

	var putErr error
	out = captureStdout(t, func() {
		putErr = run([]string{"put", "--root", root, "--name", "new.txt", "--file", input})
	})
	if putErr == nil {
		t.Fatal("expected put over a corrupt index to fail")
	}
	if !strings.Contains(putErr.Error(), `cannot store "new.txt"`) {
		t.Fatalf("error %q does not name the upload", putErr)
	}
	if !strings.Contains(putErr.Error(), "current index is corrupt") ||
		!strings.Contains(putErr.Error(), `duplicate key "keep.txt"`) {
		t.Fatalf("error %q does not name the corrupt index and duplicated key", putErr)
	}
	if out != "" {
		t.Fatalf("failed put must print no stored success line, got %q", out)
	}

	indexAfter, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(indexAfter) != string(corrupt) {
		t.Fatalf("corrupt index was rewritten\nwas: %s\nnow: %s", corrupt, indexAfter)
	}
	if string(indexAfter) == string(indexBefore) {
		t.Fatal("test setup did not damage the index")
	}
}

// TestSnapshotCreateCLIRejectsCorruptIndex applies the same rules at the
// command line as the Go API: a healthy create keeps its existing success
// line, while an unusable current mapping fails with an error naming the
// snapshot and the index, prints no success line, and leaves no snapshot.
func TestSnapshotCreateCLIRejectsCorruptIndex(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	input := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", "--root", root}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "--root", root, "--name", "a.txt", "--file", input}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := run([]string{"snapshot", "create", "--root", root, "--name", "good"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "snapshot good created with 1 entries") {
		t.Fatalf("successful create must keep its existing success line, got %q", out)
	}

	// A null entries mapping is corruption, never an empty snapshot.
	if err := os.WriteFile(filepath.Join(root, "index.json"),
		[]byte(`{"entries":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var createErr error
	out = captureStdout(t, func() {
		createErr = run([]string{"snapshot", "create", "--root", root, "--name", "bad"})
	})
	if createErr == nil {
		t.Fatal("expected create over a corrupt index to fail")
	}
	if !strings.Contains(createErr.Error(), `cannot create snapshot "bad"`) {
		t.Fatalf("error %q does not name the snapshot being created", createErr)
	}
	if !strings.Contains(createErr.Error(), "missing entries mapping") {
		t.Fatalf("error %q does not say why the index is unusable", createErr)
	}
	if out != "" {
		t.Fatalf("failed create must print nothing, got %q", out)
	}

	listOut := captureStdout(t, func() {
		if err := run([]string{"snapshot", "list", "--root", root}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(listOut, "good\t1\n") || strings.Contains(listOut, "bad") {
		t.Fatalf("failed create left a snapshot behind: %q", listOut)
	}
}

// TestSnapshotRestoreCLI confirms the command-line entry point follows the
// same restore rules as the Go API: a damaged record fails (the caller exits
// non-zero and no success line is printed), while a healthy record restores
// and prints the success line.
func TestSnapshotRestoreCLI(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	input := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"init", "--root", root}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "--root", root, "--name", "a.txt", "--file", input}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"snapshot", "create", "--root", root, "--name", "s"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("changed payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "--root", root, "--name", "b.txt", "--file", input}); err != nil {
		t.Fatal(err)
	}

	// Damage the record: null entries must not be treated as an empty snapshot.
	if err := os.WriteFile(filepath.Join(root, "snapshots", "s.json"),
		[]byte(`{"name":"s","entries":null}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var restoreErr error
	out := captureStdout(t, func() {
		restoreErr = run([]string{"snapshot", "restore", "--root", root, "--name", "s"})
	})
	if restoreErr == nil {
		t.Fatal("expected CLI restore of a damaged record to fail")
	}
	if !strings.Contains(restoreErr.Error(), `snapshot "s" is corrupted`) {
		t.Fatalf("error %q does not identify the damaged snapshot", restoreErr)
	}
	if strings.Contains(out, "restored snapshot") {
		t.Fatalf("damaged restore printed a success line: %q", out)
	}

	// The current mapping is intact: both artifacts remain listed.
	listOut := captureStdout(t, func() {
		if err := run([]string{"list", "--root", root}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(listOut, "a.txt") || !strings.Contains(listOut, "b.txt") {
		t.Fatalf("mapping changed after failed CLI restore: %q", listOut)
	}

	// Repair the record through the API-identical CLI path and restore. The
	// freshly created snapshot captures the current two-artifact mapping.
	if err := os.Remove(filepath.Join(root, "snapshots", "s.json")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"snapshot", "create", "--root", root, "--name", "s2"}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		restoreErr = run([]string{"snapshot", "restore", "--root", root, "--name", "s2"})
	})
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if !strings.Contains(out, "restored snapshot s2") {
		t.Fatalf("successful CLI restore did not print the success line: %q", out)
	}
}

// TestSnapshotListCLIAtomicOnCorruption confirms the command line applies
// the same rules as the Go API: healthy snapshots print one
// "name<TAB>count" line sorted by their full name, but a damaged record
// aborts the whole command with no prior snapshot lines on stdout.
func TestSnapshotListCLIAtomicOnCorruption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := run([]string{"init", "--root", root}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "--root", root, "--name", "a.txt", "--file", input}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"releases/stable", "zeta", "alpha"} {
		if err := run([]string{"snapshot", "create", "--root", root, "--name", name}); err != nil {
			t.Fatal(err)
		}
	}

	out := captureStdout(t, func() {
		if err := run([]string{"snapshot", "list", "--root", root}); err != nil {
			t.Fatal(err)
		}
	})
	want := "alpha\t1\nreleases/stable\t1\nzeta\t1\n"
	if out != want {
		t.Fatalf("list output=%q, want %q", out, want)
	}

	// A healthy explicit empty-entries snapshot lists with zero entries.
	if err := run([]string{"snapshot", "create", "--root", root, "--name", "empty"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshots", "empty.json"),
		[]byte(`{"name":"empty","entries":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := run([]string{"snapshot", "list", "--root", root}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "empty\t0\n") {
		t.Fatalf("empty snapshot not listed with zero entries: %q", out)
	}

	// Damage one record: the command must fail and print nothing at all, even
	// though three healthy snapshots were read alongside it.
	if err := os.WriteFile(filepath.Join(root, "snapshots", "zeta.json"),
		[]byte(`{"name":"zeta"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var listErr error
	out = captureStdout(t, func() {
		listErr = run([]string{"snapshot", "list", "--root", root})
	})
	if listErr == nil {
		t.Fatal("expected list with a damaged record to fail")
	}
	if !strings.Contains(listErr.Error(), `snapshot "zeta" is corrupted`) {
		t.Fatalf("error %q does not identify the damaged snapshot", listErr)
	}
	if out != "" {
		t.Fatalf("a failed list must leave no snapshot lines on stdout, got %q", out)
	}

	// A repository that has never held a snapshot succeeds with empty output.
	fresh := filepath.Join(t.TempDir(), "vault")
	if err := run([]string{"init", "--root", fresh}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := run([]string{"snapshot", "list", "--root", fresh}); err != nil {
			t.Fatal(err)
		}
	})
	if out != "" {
		t.Fatalf("fresh repository listed output: %q", out)
	}
}

// TestSnapshotImportCLIRejectsRecordSizeMismatch confirms the command line
// fails (non-zero error, no "imported" success line) when a package's target
// record sizes an artifact differently from the carried content, and that no
// content object or snapshot is left behind in the destination.
func TestSnapshotImportCLIRejectsRecordSizeMismatch(t *testing.T) {
	src := filepath.Join(t.TempDir(), "vault")
	in := filepath.Join(t.TempDir(), "a.txt")
	const content = "abcdefg" // 7 bytes
	if err := os.WriteFile(in, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", "--root", src}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"put", "--root", src, "--name", "a.txt", "--file", in}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"snapshot", "create", "--root", src, "--name", "s"}); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "s.pkg")
	if err := run([]string{"snapshot", "export", "--root", src, "--name", "s", "--output", pkg}); err != nil {
		t.Fatal(err)
	}

	// Corrupt only the snapshot record's size (8) while the carried object
	// honestly stays 7 bytes. The entry is the unique size field followed by a
	// createdAt, distinct from the object record's size/data pair.
	raw, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	got := string(raw)
	// The entry size is the one followed by createdAt (the object record's is
	// followed by data), so the rewrite hits only the snapshot record.
	entrySize := regexp.MustCompile(`("size": )7(,\s+"createdAt")`)
	objectSize := regexp.MustCompile(`("size": )7(,\s+"data":)`)
	if entrySize.FindString(got) == "" {
		t.Fatalf("test package did not contain the expected entry record: %s", got)
	}
	got = entrySize.ReplaceAllString(got, `${1}8${2}`)
	if err := os.WriteFile(pkg, []byte(got), 0o644); err != nil {
		t.Fatal(err)
	}
	// The carried object record stays truthful (7 bytes + matching base64), so
	// the failure is a record-size mismatch rather than bad content.
	if objectSize.FindString(got) == "" ||
		!strings.Contains(got, `"data": "`+base64.StdEncoding.EncodeToString([]byte(content))+`"`) {
		t.Fatal("test setup damaged the object record instead of the snapshot entry")
	}

	dst := filepath.Join(t.TempDir(), "vault")
	if err := run([]string{"init", "--root", dst}); err != nil {
		t.Fatal(err)
	}
	var importErr error
	out := captureStdout(t, func() {
		importErr = run([]string{"snapshot", "import", "--root", dst, "--file", pkg})
	})
	if importErr == nil {
		t.Fatal("expected import of a mis-sized record to fail")
	}
	msg := importErr.Error()
	for _, want := range []string{`snapshot "s"`, "a.txt", digest, "8", "7"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q does not report %q", msg, want)
		}
	}
	if strings.Contains(out, "imported snapshot") {
		t.Fatalf("failed import printed a success line: %q", out)
	}

	// No snapshot and no content object may remain.
	listOut := captureStdout(t, func() {
		if err := run([]string{"snapshot", "list", "--root", dst}); err != nil {
			t.Fatal(err)
		}
	})
	if listOut != "" {
		t.Fatalf("snapshot left behind: %q", listOut)
	}
	if entries, err := os.ReadDir(filepath.Join(dst, "objects")); err != nil {
		t.Fatal(err)
	} else {
		for _, ent := range entries {
			if !strings.HasPrefix(ent.Name(), ".") {
				t.Fatalf("content object left behind after failed import: %s", ent.Name())
			}
		}
	}
}

// TestSnapshotRestoreCLIMissingName fails without a success line when the
// snapshot does not exist, distinguishing "not found" from corruption.
func TestSnapshotRestoreCLIMissingName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := run([]string{"init", "--root", root}); err != nil {
		t.Fatal(err)
	}
	var restoreErr error
	out := captureStdout(t, func() {
		restoreErr = run([]string{"snapshot", "restore", "--root", root, "--name", "absent"})
	})
	if restoreErr == nil {
		t.Fatal("expected restore of a missing snapshot to fail")
	}
	if !strings.Contains(restoreErr.Error(), `snapshot "absent" not found`) {
		t.Fatalf("error %q is not a not-found error", restoreErr)
	}
	if strings.Contains(out, "restored snapshot") {
		t.Fatalf("missing-snapshot restore printed a success line: %q", out)
	}
}
