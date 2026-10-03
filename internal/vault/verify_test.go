package vault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyEmptyRepository(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	if err := New(root).Init(); err != nil {
		t.Fatal(err)
	}
	count, err := New(root).Verify()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("count=%d, want 0", count)
	}
}

func TestVerifyCountsNamesNotObjects(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	input := writeFile(t, "shared by two names\n")
	if _, err := store.Put("one/a.bin", input); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("two/b.bin", input); err != nil {
		t.Fatal(err)
	}
	count, err := store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("count=%d, want 2 (one per name, not one per digest)", count)
	}
}

func TestVerifyZeroByteObject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	if _, err := store.Put("empty.bin", writeFile(t, "")); err != nil {
		t.Fatal(err)
	}
	count, err := store.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count=%d, want 1", count)
	}
}

func TestVerifyScopeIsCurrentMappingOnly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	// a.txt at digest d1; the snapshot keeps d1 alive after the overwrite.
	oldEntry, err := store.Put("a.txt", writeFile(t, "one"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	// Overwrite a.txt: d2 is current, d1 snapshot-only.
	if _, err := store.Put("a.txt", writeFile(t, "two")); err != nil {
		t.Fatal(err)
	}
	// A stray unreferenced object whose name is not even a valid digest.
	stray := filepath.Join(root, "objects", "not-a-digest")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	count, err := store.Verify()
	if err != nil {
		t.Fatalf("verify should ignore snapshot-only and unreferenced objects: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d, want 1", count)
	}
	// Removing the snapshot-only object must not affect verify either: the
	// current mapping references d2, not d1.
	if err := os.Remove(filepath.Join(root, "objects", oldEntry.Digest)); err != nil {
		t.Fatal(err)
	}
	if count, err := store.Verify(); err != nil || count != 1 {
		t.Fatalf("snapshot-only object removal affected verify: count=%d err=%v", count, err)
	}
}

func TestVerifyFailureModes(t *testing.T) {
	t.Run("missing object", func(t *testing.T) {
		root, store, entry := getVault(t, "payload")
		if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
			t.Fatal(err)
		}
		err := expectVerifyFailure(t, store)
		if !strings.Contains(err.Error(), `verify "a.txt"`) ||
			!strings.Contains(err.Error(), entry.Digest) ||
			!strings.Contains(err.Error(), "is missing") {
			t.Fatalf("error should name artifact, digest, and missing object: %v", err)
		}
	})

	t.Run("size mismatch", func(t *testing.T) {
		root, store, entry := getVault(t, "payload")
		if err := os.Truncate(filepath.Join(root, "objects", entry.Digest), 3); err != nil {
			t.Fatal(err)
		}
		err := expectVerifyFailure(t, store)
		if !strings.Contains(err.Error(), `verify "a.txt"`) ||
			!strings.Contains(err.Error(), "is corrupted") ||
			!strings.Contains(err.Error(), "record says 7") {
			t.Fatalf("error should name artifact and size mismatch: %v", err)
		}
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		root, store, entry := getVault(t, "payload")
		// Same length, different bytes: checksum error must win.
		if err := os.WriteFile(filepath.Join(root, "objects", entry.Digest), []byte("XXXXXXX"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := expectVerifyFailure(t, store)
		if !strings.Contains(err.Error(), `verify "a.txt"`) ||
			!strings.Contains(err.Error(), "checksum") {
			t.Fatalf("error should name artifact and checksum mismatch: %v", err)
		}
	})

	t.Run("symlink object", func(t *testing.T) {
		root, store, entry := getVault(t, "payload")
		object := filepath.Join(root, "objects", entry.Digest)
		if err := os.Remove(object); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), object); err != nil {
			t.Fatal(err)
		}
		err := expectVerifyFailure(t, store)
		if !strings.Contains(err.Error(), `verify "a.txt"`) ||
			!strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("error should name artifact and symlink object: %v", err)
		}
	})

	t.Run("directory object", func(t *testing.T) {
		root, store, entry := getVault(t, "payload")
		object := filepath.Join(root, "objects", entry.Digest)
		if err := os.Remove(object); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(object, 0o755); err != nil {
			t.Fatal(err)
		}
		err := expectVerifyFailure(t, store)
		if !strings.Contains(err.Error(), `verify "a.txt"`) ||
			!strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("error should name artifact and non-regular object: %v", err)
		}
	})

	t.Run("unreadable object", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		root, store, entry := getVault(t, "payload")
		object := filepath.Join(root, "objects", entry.Digest)
		if err := os.Chmod(object, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(object, 0o644) })
		err := expectVerifyFailure(t, store)
		if !strings.Contains(err.Error(), `verify "a.txt"`) {
			t.Fatalf("error should name the artifact: %v", err)
		}
	})

	t.Run("corrupt index", func(t *testing.T) {
		d := digestOf("payload")
		cases := map[string]string{
			"bad json":      `{broken`,
			"no entries":    `{}`,
			"null entries":  `{"entries":null}`,
			"bad digest":    `{"entries":{"a.txt":{"name":"a.txt","digest":"XYZ","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			"negative size": `{"entries":{"a.txt":{"name":"a.txt","digest":"` + d + `","size":-1,"createdAt":"2026-01-01T00:00:00Z"}}}`,
			"key mismatch":  `{"entries":{"a.txt":{"name":"b.txt","digest":"` + d + `","size":7,"createdAt":"2026-01-01T00:00:00Z"}}}`,
		}
		for label, data := range cases {
			t.Run(label, func(t *testing.T) {
				root, store, _ := getVault(t, "payload")
				if err := os.WriteFile(filepath.Join(root, "index.json"), []byte(data), 0o644); err != nil {
					t.Fatal(err)
				}
				expectVerifyFailure(t, store)
			})
		}
	})

	t.Run("missing index", func(t *testing.T) {
		root, store, _ := getVault(t, "payload")
		if err := os.Remove(filepath.Join(root, "index.json")); err != nil {
			t.Fatal(err)
		}
		expectVerifyFailure(t, store)
	})
}

// expectVerifyFailure asserts that Verify fails, returns a zero count, and
// its error names the artifact involved.
func expectVerifyFailure(t *testing.T, store *Store) error {
	t.Helper()
	count, err := store.Verify()
	if err == nil {
		t.Fatal("expected verify to fail")
	}
	if count != 0 {
		t.Fatalf("failed verify returned count=%d, want 0", count)
	}
	return err
}

func TestVerifyDoesNotModifyRepository(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	if _, err := store.CreateSnapshot("snap"); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(root, "index.json"),
		filepath.Join(root, "snapshots", "snap.json"),
		filepath.Join(root, "objects", entry.Digest),
	}
	snapshot := map[string][]byte{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		snapshot[p] = data
	}
	if _, err := store.Verify(); err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, snapshot[p]) {
			t.Fatalf("successful verify modified %s", p)
		}
	}

	// A failed verify must be equally non-mutating. The corruption is ours;
	// re-baseline on the damaged state and confirm verify leaves it as-is.
	if err := os.Truncate(filepath.Join(root, "objects", entry.Digest), 2); err != nil {
		t.Fatal(err)
	}
	damaged := map[string][]byte{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		damaged[p] = data
	}
	if _, err := store.Verify(); err == nil {
		t.Fatal("expected verify to fail")
	}
	for _, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, damaged[p]) {
			t.Fatalf("failed verify modified %s", p)
		}
	}
}

func TestVerifyReleasesLockAfterFailure(t *testing.T) {
	root, store, entry := getVault(t, "payload")
	if err := os.Remove(filepath.Join(root, "objects", entry.Digest)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(); err == nil {
		t.Fatal("expected verify to fail")
	}
	// A failed verify must not leave the repository locked: an exclusive
	// operation on a freshly opened Store has to proceed (with a timeout that
	// only fires if the lock leaked).
	done := make(chan error, 1)
	go func() {
		_, err := New(root).Put("other.txt", writeFile(t, "other"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("repository stayed locked after a failed verify")
	}
}

// withVerifyPaused runs fn with a verify pass frozen after it has read the
// mapping and before it reads the first object, while the pass holds the
// shared repository lock. The frozen pass is resumed and awaited when fn
// returns. Separate Store instances used from fn contend through flock,
// exactly as separate OS processes would.
func withVerifyPaused(t *testing.T, store *Store, fn func()) {
	t.Helper()
	gotLock := make(chan struct{})
	proceed := make(chan struct{})
	var once sync.Once
	store.verifyHook = func() {
		once.Do(func() { close(gotLock) })
		<-proceed
	}
	defer func() { store.verifyHook = nil }()

	verifyDone := make(chan struct{})
	var count int
	var err error
	go func() {
		count, err = store.Verify()
		close(verifyDone)
	}()
	<-gotLock
	fn()
	close(proceed)
	<-verifyDone
	if err != nil {
		t.Fatalf("paused verify failed: %v", err)
	}
	if count == 0 {
		t.Fatal("paused verify reported zero artifacts")
	}
}

// TestVerifyBlocksWritersButNotReaders is the core of the fix: while one
// verify pass holds the mapping and is still reading objects, another
// process's put, gc, or snapshot create cannot complete, while list, get, and
// a second verify proceed concurrently as shared-lock readers. When the pass
// ends, the blocked operations all complete successfully.
func TestVerifyBlocksWritersButNotReaders(t *testing.T) {
	root, store, _ := getVault(t, "first payload\n")
	if _, err := store.Put("b.txt", writeFile(t, "second payload")); err != nil {
		t.Fatal(err)
	}

	var blockedPut, blockedGC, blockedSnapshot <-chan error
	withVerifyPaused(t, store, func() {
		// Exclusive operations on separate Store instances must wait for the
		// verify to release the lock.
		blockedPut = startExclusive(func() error {
			_, err := New(root).Put("a.txt", writeFile(t, "overwritten payload"))
			return err
		})
		blockedGC = startExclusive(func() error {
			_, err := New(root).GC(false)
			return err
		})
		blockedSnapshot = startExclusive(func() error {
			_, err := New(root).CreateSnapshot("during-verify")
			return err
		})
		assertBlocked(t, "put", blockedPut)
		assertBlocked(t, "gc", blockedGC)
		assertBlocked(t, "snapshot create", blockedSnapshot)

		// Read-only operations must not be queued behind the verify.
		entries, err := New(root).List()
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Fatalf("list saw %d entries, want 2", len(entries))
		}
		out := filepath.Join(t.TempDir(), "a.txt")
		if err := New(root).Get("a.txt", out); err != nil {
			t.Fatal(err)
		}
		if got := readOutput(t, out); string(got) != "first payload\n" {
			t.Fatalf("get observed %q mid-verify", got)
		}
		if n, err := New(root).Verify(); err != nil || n != 2 {
			t.Fatalf("concurrent verify: n=%d err=%v", n, err)
		}

		// Nothing blocked may have leaked through before the verify ends.
		assertBlocked(t, "put", blockedPut)
		assertBlocked(t, "gc", blockedGC)
		assertBlocked(t, "snapshot create", blockedSnapshot)
	})

	// After the verify ends every waiting change completes and the
	// repository is immediately usable again.
	for what, done := range map[string]<-chan error{
		"put":             blockedPut,
		"gc":              blockedGC,
		"snapshot create": blockedSnapshot,
	} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s after verify: %v", what, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not complete after verify released the lock", what)
		}
	}
	// The post-change mapping is complete and self-consistent.
	if n, err := New(root).Verify(); err != nil || n != 2 {
		t.Fatalf("verify after waiting writers: n=%d err=%v", n, err)
	}
}

func startExclusive(fn func() error) <-chan error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	return done
}

func assertBlocked(t *testing.T, what string, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s completed while verify was in flight: %v", what, err)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestVerifyWritersCompleteAfterVerify doubles down on the ordering: the
// operations blocked by an in-flight verify complete once it releases, and a
// subsequent verify observes the finished state, never a mixture.
func TestVerifyWritersCompleteAfterVerify(t *testing.T) {
	root, store, _ := getVault(t, "first payload\n")

	var blockedPut, blockedGC <-chan error
	withVerifyPaused(t, store, func() {
		blockedPut = startExclusive(func() error {
			_, err := New(root).Put("a.txt", writeFile(t, "overwritten payload"))
			return err
		})
		blockedGC = startExclusive(func() error {
			_, err := New(root).GC(false)
			return err
		})
		assertBlocked(t, "put", blockedPut)
		assertBlocked(t, "gc", blockedGC)
	})
	for what, done := range map[string]<-chan error{"put": blockedPut, "gc": blockedGC} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s after verify: %v", what, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not complete after verify released the lock", what)
		}
	}
	out := filepath.Join(t.TempDir(), "a.txt")
	if err := New(root).Get("a.txt", out); err != nil {
		t.Fatal(err)
	}
	if got := readOutput(t, out); string(got) != "overwritten payload" {
		t.Fatalf("get after blocked put observed %q", got)
	}
	if n, err := New(root).Verify(); err != nil || n != 1 {
		t.Fatalf("verify after waiting writers: n=%d err=%v", n, err)
	}
}

// TestVerifyChangeObservedWhenItFinishesFirst checks the other ordering: if
// an overwrite plus GC has fully completed before verify reads the mapping,
// verify certifies the new state (new name mapping, new object) without
// reporting the collected old object as missing.
func TestVerifyChangeObservedWhenItFinishesFirst(t *testing.T) {
	root, _, old := getVault(t, "original content")
	overwriteAndGC := func() {
		if _, err := New(root).Put("a.txt", writeFile(t, "replacement content")); err != nil {
			t.Fatal(err)
		}
		if _, err := New(root).GC(false); err != nil {
			t.Fatal(err)
		}
		if objectExists(root, old.Digest) {
			t.Fatal("old object was not collected")
		}
	}
	overwriteAndGC()
	count, err := New(root).Verify()
	if err != nil {
		t.Fatalf("verify after completed overwrite+gc reported a false loss: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d, want 1", count)
	}
}

// TestVerifyRacesWithOverwriteRestoreAndGC hammers verify with exactly the
// scenario from the bug report: other processes continuously overwrite an
// artifact and run GC (plus snapshot restores), while readers verify, list,
// and download. A healthy repository can never be reported as losing an
// object, and a download can never see bytes that do not match any one
// complete mapping.
func TestVerifyRacesWithOverwriteRestoreAndGC(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	store := New(root)
	alpha := "alpha"
	gamma := strings.Repeat("g", 256<<10) // large enough to widen the read window
	if _, err := store.Put("a.txt", writeFile(t, alpha)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("b.txt", writeFile(t, "beta")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	scratch, err := os.MkdirTemp(t.TempDir(), "scratch")
	if err != nil {
		t.Fatal(err)
	}
	var fileSeq int64
	writeScratch := func(content string) string {
		n := atomic.AddInt64(&fileSeq, 1)
		path := filepath.Join(scratch, fmt.Sprintf("in-%d.bin", n))
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	const mutators, iterations, readers = 2, 25, 4
	errs := make(chan error, mutators*iterations*3+readers*iterations*8)
	var mutatorWG sync.WaitGroup
	for m := 0; m < mutators; m++ {
		mutatorWG.Add(1)
		go func(m int) {
			defer mutatorWG.Done()
			for i := 0; i < iterations; i++ {
				content := alpha
				if i%2 == 1 {
					content = gamma
				}
				if _, err := New(root).Put("a.txt", writeScratch(content)); err != nil {
					errs <- fmt.Errorf("put: %w", err)
					return
				}
				if i%4 == 0 {
					if err := New(root).RestoreSnapshot("base"); err != nil {
						errs <- fmt.Errorf("restore: %w", err)
						return
					}
				}
				if _, err := New(root).GC(false); err != nil {
					errs <- fmt.Errorf("gc: %w", err)
					return
				}
			}
		}(m)
	}

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	for r := 0; r < readers; r++ {
		readerWG.Add(1)
		go func(r int) {
			defer readerWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				switch r % 3 {
				case 0:
					if _, err := New(root).Verify(); err != nil {
						errs <- fmt.Errorf("verify: %w", err)
						return
					}
				case 1:
					out := filepath.Join(scratch, fmt.Sprintf("out-%d.bin", atomic.AddInt64(&fileSeq, 1)))
					if err := New(root).Get("a.txt", out); err != nil {
						errs <- fmt.Errorf("get: %w", err)
						return
					}
					got, err := os.ReadFile(out)
					if err != nil {
						errs <- err
						return
					}
					if string(got) != alpha && string(got) != gamma {
						errs <- fmt.Errorf("get observed %d bytes matching no complete mapping", len(got))
						return
					}
				case 2:
					if _, err := New(root).List(); err != nil {
						errs <- fmt.Errorf("list: %w", err)
						return
					}
				}
			}
		}(r)
	}

	mutatorWG.Wait()
	close(stop)
	readerWG.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// Final state is complete and usable.
	if _, err := New(root).Verify(); err != nil {
		t.Fatal(err)
	}
	if err := store.RestoreSnapshot("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(root).Verify(); err != nil {
		t.Fatal(err)
	}
	if report, err := New(root).GC(false); err != nil {
		t.Fatal(err)
	} else if dry, err := New(root).GC(true); err != nil {
		t.Fatal(err)
	} else if len(dry.Candidates) != 0 {
		t.Fatalf("unreachable objects remain: %+v (deleted %d)", dry.Candidates, report.Deleted)
	}
}
