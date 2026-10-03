package main

import (
	"os"
	"path/filepath"
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

// TestVerifyCLI confirms the command line follows the Go API: a healthy
// repository prints "verified N artifacts" counted by artifact name, while a
// corrupt current index fails the command and prints no success line.
func TestVerifyCLI(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	input := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", "--root", root}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.bin", "b.bin"} {
		if err := run([]string{"put", "--root", root, "--name", name, "--file", input}); err != nil {
			t.Fatal(err)
		}
	}
	out := captureStdout(t, func() {
		if err := run([]string{"verify", "--root", root}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "verified 2 artifacts") {
		t.Fatalf("healthy verify did not count both names: %q", out)
	}

	// Damage the mapping: a null entries field is corruption, not an empty
	// repository, and must not produce a success line.
	if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(`{"entries":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var verifyErr error
	out = captureStdout(t, func() {
		verifyErr = run([]string{"verify", "--root", root})
	})
	if verifyErr == nil {
		t.Fatal("expected verify of a corrupt index to fail")
	}
	if !strings.Contains(verifyErr.Error(), "current index") {
		t.Fatalf("error does not identify the current index: %v", verifyErr)
	}
	if strings.Contains(out, "verified") {
		t.Fatalf("failed verify printed a success line: %q", out)
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
