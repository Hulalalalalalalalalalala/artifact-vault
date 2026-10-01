package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Get downloads the artifact recorded under name in the current index to the
// output path. Nothing is delivered unless the stored object is complete and
// the destination is safe:
//
//   - the index and the selected record must be usable (parseable, with a
//     name mapping, the recorded name matching its key, a 64-character
//     lowercase-hex digest, and a non-negative size);
//   - the object must exist, be a regular file, and its actual size and
//     SHA-256 must match the record;
//   - the output must be outside the repository (including through a
//     symlinked parent), its parent directory must exist, and an existing
//     output must be a regular file that is not a hard link to any repository
//     file.
//
// The object is streamed and hashed into a temporary file beside the output;
// only after the complete, verified bytes are flushed is the output renamed
// into place. A failed download therefore leaves an existing output
// byte-for-byte intact and a missing output absent; an interrupted process
// leaves at most an unreferenced temporary file that a later download
// replaces without manual cleanup.
func (s *Store) Get(name, output string) error {
	if err := validateName(name); err != nil {
		return err
	}
	if output == "" {
		return errors.New("output is required")
	}
	return s.withLock(false, func() error {
		return s.getLocked(name, output)
	})
}

func (s *Store) getLocked(name, output string) error {
	// The index and every record it holds must be usable before any object is
	// read. A missing or malformed record is reported as record corruption,
	// distinct from a name that simply does not exist.
	idx, err := s.loadStrict()
	if err != nil {
		return fmt.Errorf("artifact %q: record is corrupted: %w", name, err)
	}
	for key, entry := range idx.Entries {
		if err := validateEntryRecord(key, entry); err != nil {
			return fmt.Errorf("artifact %q: record is corrupted: %w", name, err)
		}
	}
	entry, ok := idx.Entries[name]
	if !ok {
		return fmt.Errorf("artifact %q not found", name)
	}

	absOut, mode, err := s.checkOutputSafe(output)
	if err != nil {
		return fmt.Errorf("artifact %q: %w", name, err)
	}
	if err := s.downloadObject(entry, absOut, mode); err != nil {
		return fmt.Errorf("artifact %q: %w", name, err)
	}
	return nil
}

// checkOutputSafe validates the destination of a download without opening the
// object. It returns the absolute output path and the permission bits a new
// file should have.
func (s *Store) checkOutputSafe(output string) (string, os.FileMode, error) {
	absOut, err := filepath.Abs(output)
	if err != nil {
		return "", 0, fmt.Errorf("output %q: cannot resolve path: %w", output, err)
	}
	mode := os.FileMode(0o644)
	if info, err := os.Lstat(absOut); err == nil {
		// Symlinks are never followed; anything that is not a regular file
		// (directory, device, socket, ...) is refused.
		if info.Mode()&os.ModeSymlink != 0 {
			return "", 0, fmt.Errorf("output %q is a symbolic link", output)
		}
		if !info.Mode().IsRegular() {
			return "", 0, fmt.Errorf("output %q is not a regular file", output)
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, err
	}

	absRoot, err := filepath.Abs(s.root)
	if err != nil {
		return "", 0, fmt.Errorf("cannot resolve repository root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", 0, fmt.Errorf("cannot resolve repository root: %w", err)
	}
	// Path-based containment first: this works even when the output or its
	// parent does not exist yet, so a not-yet-created destination inside the
	// repository is refused before any symlink is followed.
	if rel, err := filepath.Rel(resolvedRoot, absOut); err == nil {
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", 0, fmt.Errorf("output %q is inside the repository", output)
		}
	}
	// Resolve every symlink in the path so a destination that reaches into the
	// repository through a symlinked parent cannot hide.
	resolved, err := filepath.EvalSymlinks(absOut)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", 0, fmt.Errorf("output %q: cannot resolve path: %w", output, err)
		}
		// The final component may simply not exist yet; its parent must.
		parent := filepath.Dir(absOut)
		resolvedParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", 0, fmt.Errorf("output %q: parent directory is not accessible: %w", output, err)
		}
		resolved = filepath.Join(resolvedParent, filepath.Base(absOut))
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil {
		return "", 0, fmt.Errorf("output %q: %w", output, err)
	}
	// A path inside the repository resolves from the root without ever going
	// up: rel is "." or a descendant. Only a rel that is exactly ".." or
	// starts with "../" leaves the repository.
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", 0, fmt.Errorf("output %q is inside the repository", output)
	}

	if err := s.checkOutputNotRepoHardlink(absOut, output); err != nil {
		return "", 0, err
	}
	return absOut, mode, nil
}

// checkOutputNotRepoHardlink refuses an existing output that is a hard link to
// any repository file (the index, the lock, an object, or a snapshot record).
// Replacing such a link would rewrite the repository file's contents through
// the link.
func (s *Store) checkOutputNotRepoHardlink(absOut, output string) error {
	info, err := os.Lstat(absOut)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	outID, ok := fileIDOf(info)
	if !ok {
		return nil
	}
	for id, repoPath := range s.repoFileIDs() {
		if id == outID {
			return fmt.Errorf("output %q is a hard link to repository file %q", output, repoPath)
		}
	}
	return nil
}

type fileID struct {
	dev uint64
	ino uint64
}

func fileIDOf(info os.FileInfo) (fileID, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

// repoFileIDs collects the device/inode identity of every repository file an
// output must not be hard-linked to: the index, the lock, every object, and
// every snapshot record.
func (s *Store) repoFileIDs() map[fileID]string {
	ids := map[fileID]string{}
	add := func(path string) {
		info, err := os.Lstat(path)
		if err != nil {
			return
		}
		if id, ok := fileIDOf(info); ok {
			ids[id] = path
		}
	}
	add(s.indexPath())
	add(s.lockPath())
	if entries, err := os.ReadDir(filepath.Join(s.root, "objects")); err == nil {
		for _, entry := range entries {
			add(filepath.Join(s.root, "objects", entry.Name()))
		}
	}
	_ = filepath.WalkDir(s.snapshotsDir(), func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			add(path)
		}
		return nil
	})
	return ids
}

// downloadObject streams the verified object into a temporary file beside the
// output and renames it into place only after the complete bytes match the
// record. It never truncates or writes the output directly, and it never
// buffers the whole object in memory.
func (s *Store) downloadObject(entry Entry, absOut string, mode os.FileMode) error {
	objPath := s.objectPath(entry.Digest)
	info, err := os.Lstat(objPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("object %s is missing", entry.Digest)
		}
		return fmt.Errorf("cannot stat object %s: %w", entry.Digest, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("object %s is a symbolic link", entry.Digest)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("object %s is not a regular file", entry.Digest)
	}

	in, err := os.Open(objPath)
	if err != nil {
		return fmt.Errorf("cannot read object %s: %w", entry.Digest, err)
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(absOut), ".download-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary file for output: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot prepare output file: %w", err)
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, hash), in)
	readErr := in.Close()
	if copyErr != nil {
		tmp.Close()
		return fmt.Errorf("cannot read object %s: %w", entry.Digest, copyErr)
	}
	if readErr != nil {
		tmp.Close()
		return fmt.Errorf("cannot read object %s: %w", entry.Digest, readErr)
	}
	if n != entry.Size {
		tmp.Close()
		return fmt.Errorf("object %s is corrupted: content is %d bytes, record says %d", entry.Digest, n, entry.Size)
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != entry.Digest {
		tmp.Close()
		return fmt.Errorf("object %s is corrupted: content checksum is %s, want %s", entry.Digest, actual, entry.Digest)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	if err := os.Rename(tmpName, absOut); err != nil {
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	committed = true
	// Best-effort directory sync so the rename survives a crash; failure here
	// does not undo an already atomic replacement.
	if dir, err := os.Open(filepath.Dir(absOut)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
