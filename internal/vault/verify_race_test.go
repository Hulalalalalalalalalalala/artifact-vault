package vault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestVerifyConcurrentPutAndGC races Verify against another Store instance
// (a stand-in for a second process: each operation takes its own flock on the
// shared lock file) that continuously overwrites every artifact and collects
// the superseded objects. Every Verify pass must observe one complete
// generation of the repository: it must never see an object vanish because a
// put+gc cycle landed between reading the name mapping and reading the
// objects that mapping referenced.
func TestVerifyConcurrentPutAndGC(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	const artifacts = 12
	const payloadSize = 2 << 20 // large enough that a pass reads for a while
	srcDir := t.TempDir()
	writeSource := func(iter, i int) string {
		path := filepath.Join(srcDir, fmt.Sprintf("src-%d-%d.bin", iter, i))
		content := bytes.Repeat([]byte{byte(iter), byte(i)}, payloadSize)
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	name := func(i int) string { return fmt.Sprintf("releases/artifact-%d.bin", i) }
	for i := 0; i < artifacts; i++ {
		if _, err := store.Put(name(i), writeSource(0, i)); err != nil {
			t.Fatal(err)
		}
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		writer := New(root)
		for iter := 1; ; iter++ {
			select {
			case <-stop:
				return
			default:
			}
			for i := 0; i < artifacts; i++ {
				if _, err := writer.Put(name(i), writeSource(iter, i)); err != nil {
					return
				}
			}
			if _, err := writer.GC(false); err != nil {
				return
			}
		}
	}()

	for i := 0; i < 20; i++ {
		count, err := store.Verify()
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("verify failed while put+gc ran concurrently: %v", err)
		}
		if count != artifacts {
			close(stop)
			wg.Wait()
			t.Fatalf("verify counted %d artifacts, want %d", count, artifacts)
		}
	}
	close(stop)
	wg.Wait()

	// Once the writer is done the repository must still verify cleanly.
	if count, err := store.Verify(); err != nil || count != artifacts {
		t.Fatalf("final verify: count=%d err=%v", count, err)
	}
}

// TestVerifyConcurrentReaders confirms a Verify in progress does not exclude
// other read-only operations: list, get, and a second verify all proceed
// while one verify holds its shared lock.
func TestVerifyConcurrentReaders(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "input.bin")
	if err := os.WriteFile(src, []byte("shared read payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("app.bin", src); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := New(root).Verify(); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 5; j++ {
			if _, err := New(root).List(); err != nil {
				errs <- err
				return
			}
			out := filepath.Join(t.TempDir(), "out.bin")
			if err := New(root).Get("app.bin", out); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent reader failed: %v", err)
	}
}
