package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCLI compiles the artifact-vault binary into a temp directory and
// returns its path.
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "artifact-vault")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/artifact-vault")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cli: %v\n%s", err, out)
	}
	return bin
}

// runCLI executes the vault CLI with the given arguments, returning combined
// output and the exit error.
func runCLI(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestCLIExportRefusesUnsafeOutput(t *testing.T) {
	bin := buildCLI(t)
	root := filepath.Join(t.TempDir(), "vault")
	if out, err := runCLI(t, bin, "init", "--root", root); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	input := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLI(t, bin, "put", "--root", root, "--name", "a.txt", "--file", input); err != nil {
		t.Fatalf("put: %v\n%s", err, out)
	}
	if out, err := runCLI(t, bin, "snapshot", "create", "--root", root, "--name", "snap"); err != nil {
		t.Fatalf("snapshot create: %v\n%s", err, out)
	}

	cases := map[string]string{
		"index.json":      filepath.Join(root, "index.json"),
		"object":          filepath.Join(root, "objects", digestOf("payload")),
		"not yet created": filepath.Join(root, "new.pkg"),
	}
	for label, output := range cases {
		t.Run(label, func(t *testing.T) {
			out, err := runCLI(t, bin, "snapshot", "export", "--root", root, "--name", "snap", "--output", output)
			if err == nil {
				t.Fatalf("export to %q succeeded, want failure", output)
			}
			if !strings.Contains(out, "inside the repository") {
				t.Fatalf("expected inside-repository error, got %q", out)
			}
		})
	}
}

func TestCLIExportWritesValidPackage(t *testing.T) {
	bin := buildCLI(t)
	root := filepath.Join(t.TempDir(), "vault")
	if out, err := runCLI(t, bin, "init", "--root", root); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	input := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(input, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runCLI(t, bin, "put", "--root", root, "--name", "a.txt", "--file", input); err != nil {
		t.Fatalf("put: %v\n%s", err, out)
	}
	if out, err := runCLI(t, bin, "snapshot", "create", "--root", root, "--name", "snap"); err != nil {
		t.Fatalf("snapshot create: %v\n%s", err, out)
	}
	output := filepath.Join(t.TempDir(), "out.pkg")
	out, err := runCLI(t, bin, "snapshot", "export", "--root", root, "--name", "snap", "--output", output)
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	if !strings.Contains(out, "exported snapshot snap with 1 entries, 1 objects") {
		t.Fatalf("unexpected success summary: %q", out)
	}
	// The package imports into a fresh initialized vault.
	dst := filepath.Join(t.TempDir(), "vault")
	if out, err := runCLI(t, bin, "init", "--root", dst); err != nil {
		t.Fatalf("init dst: %v\n%s", err, out)
	}
	if out, err := runCLI(t, bin, "snapshot", "import", "--root", dst, "--file", output); err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
}

func TestCLIExportRefusesMissingRepository(t *testing.T) {
	bin := buildCLI(t)
	root := filepath.Join(t.TempDir(), "vault")
	output := filepath.Join(t.TempDir(), "out.pkg")
	out, err := runCLI(t, bin, "snapshot", "export", "--root", root, "--name", "snap", "--output", output)
	if err == nil {
		t.Fatal("export into missing repository succeeded, want failure")
	}
	if !strings.Contains(out, "does not exist") {
		t.Fatalf("expected missing-repo error, got %q", out)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("export created the missing repository")
	}
}
