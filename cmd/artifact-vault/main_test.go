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
