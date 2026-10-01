package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// checkRepositoryReady verifies that s.root names an initialized repository
// without creating anything. Export must never conjure a repository: a missing
// root or a missing index.json is an error, not an invitation to run init.
func (s *Store) checkRepositoryReady() error {
	info, err := os.Stat(s.root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("repository %q does not exist; run init first", s.root)
	case err != nil:
		return err
	case !info.IsDir():
		return fmt.Errorf("repository root %q is not a directory", s.root)
	}
	if _, err := os.Stat(s.indexPath()); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("repository %q is not initialized; run init first", s.root)
	} else if err != nil {
		return err
	}
	return nil
}

// checkExportOutput validates an export destination before any package bytes
// are assembled or written. It returns the absolute output path and the
// permission bits the file should have.
//
// The destination must be outside the source repository — including a
// not-yet-created path, a path reached through a symlinked parent, or a root
// that is itself a symlink — and its parent directory must already exist and
// be accessible; it is never created. An existing output must be a regular
// file; symlinks (even dangling ones), directories, and other special files
// are refused rather than replaced. An output outside the repository that is a
// hard link to any repository file — the index, the lock, any content object
// (including unreferenced and non-digest-named files), or any snapshot record
// — is refused too.
//
// Every piece of information needed to confirm safety must be readable; a
// permission error or a platform without inode identity is reported, never
// silently treated as safe.
func (s *Store) checkExportOutput(output string) (string, os.FileMode, error) {
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
		return "", 0, fmt.Errorf("output %q: cannot inspect file: %w", output, err)
	}

	absRoot, err := filepath.Abs(s.root)
	if err != nil {
		return "", 0, fmt.Errorf("cannot resolve repository root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", 0, fmt.Errorf("cannot resolve repository root: %w", err)
	}
	// Lexical containment first: this works even when the output or its parent
	// does not exist yet, so a not-yet-created destination inside the
	// repository is refused before any symlink is followed.
	if rel, err := filepath.Rel(resolvedRoot, absOut); err == nil {
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", 0, fmt.Errorf("output %q is inside the repository", output)
		}
	}
	// Resolve every symlink in the path so a destination that reaches into the
	// repository through a symlinked parent (or a symlinked root) cannot hide.
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

	if err := s.checkOutputNotRepoHardlinkStrict(absOut, output); err != nil {
		return "", 0, err
	}
	return absOut, mode, nil
}

// checkOutputNotRepoHardlinkStrict refuses an existing output that is a hard
// link to any repository file. Unlike the download path, a failure to read the
// information needed to confirm safety is an error, not a silent pass: an
// output that cannot be checked is assumed dangerous.
func (s *Store) checkOutputNotRepoHardlinkStrict(absOut, output string) error {
	info, err := os.Lstat(absOut)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("output %q: cannot inspect file: %w", output, err)
	}
	outID, ok := fileIDOf(info)
	if !ok {
		return fmt.Errorf("output %q: cannot determine file identity", output)
	}
	ids, err := s.repoFileIDsStrict()
	if err != nil {
		return fmt.Errorf("output %q: cannot confirm the output is not linked to a repository file: %w", output, err)
	}
	for id, repoPath := range ids {
		if id == outID {
			return fmt.Errorf("output %q is a hard link to repository file %q", output, repoPath)
		}
	}
	return nil
}

// repoFileIDsStrict collects the device/inode identity of every repository
// file an output must not be hard-linked to: the index, the lock, every object
// (including unreferenced and non-digest-named files), and every snapshot
// record. Any unreadable path aborts the enumeration: a link that cannot be
// checked is assumed dangerous.
func (s *Store) repoFileIDsStrict() (map[fileID]string, error) {
	ids := map[fileID]string{}
	add := func(path string) error {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		id, ok := fileIDOf(info)
		if !ok {
			return fmt.Errorf("cannot determine file identity of %q", path)
		}
		ids[id] = path
		return nil
	}
	if err := add(s.indexPath()); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if err := add(s.lockPath()); err != nil {
		return nil, fmt.Errorf("lock: %w", err)
	}
	objectsDir := filepath.Join(s.root, "objects")
	if err := filepath.WalkDir(objectsDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		return add(path)
	}); err != nil {
		return nil, fmt.Errorf("objects: %w", err)
	}
	if err := filepath.WalkDir(s.snapshotsDir(), func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		return add(path)
	}); err != nil {
		return nil, fmt.Errorf("snapshots: %w", err)
	}
	return ids, nil
}

// writePackageAtomic writes the package bytes to a temporary file beside the
// output and renames it into place only after a final safety re-check. The
// re-check matters because another process may replace the output's parent
// (or the output itself) while the package was being assembled: a parent that
// now points into the repository must never receive the rename, and an
// existing output that has been swapped for a symlink or a hard link to a
// repository file must not be replaced. A failed write leaves an existing
// output byte-for-byte intact and a missing output absent.
func (s *Store) writePackageAtomic(absOut string, mode os.FileMode, output string, data []byte) error {
	// Re-check before creating anything: the parent directory or the output
	// itself may already have been swapped to point into the repository.
	if _, _, err := s.checkExportOutput(output); err != nil {
		return err
	}
	dir := filepath.Dir(absOut)
	tmp, err := os.CreateTemp(dir, ".package-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary file for output %q: %w", output, err)
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
		return fmt.Errorf("cannot prepare output %q: %w", output, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write output %q: %w", output, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write output %q: %w", output, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write output %q: %w", output, err)
	}
	// Final re-check immediately before the rename: the parent directory or
	// the output itself may have been swapped since the last check.
	if _, _, err := s.checkExportOutput(output); err != nil {
		return err
	}
	if err := os.Rename(tmpName, absOut); err != nil {
		return fmt.Errorf("cannot write output %q: %w", output, err)
	}
	committed = true
	// Best-effort directory sync so the rename survives a crash; failure here
	// does not undo an already atomic replacement.
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}
