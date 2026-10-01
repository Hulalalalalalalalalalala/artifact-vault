package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// preparedOutput is the validated download destination: TempDir is the real
// directory the unpublished file is assembled in (physically next to the
// destination), Pattern names it, and Mode is the permission set it is
// published with.
type preparedOutput struct {
	TempDir string
	Pattern string
	Mode    os.FileMode
}

// prepareOutput validates the download destination without changing anything.
// The rules it enforces:
//
//   - the parent directory must already exist (no directories are created);
//   - an existing destination must be a regular file, never a directory,
//     symbolic link, or other special file;
//   - no path inside the repository may be used as the destination, including
//     paths that do not exist yet and paths that enter the repository through
//     a symbolic link in a parent directory;
//   - an existing destination outside the repository must not be a hard link
//     to the index, a snapshot record, the lock file, or a content object, so
//     replacing it can never alter a repository file.
func (s *Store) prepareOutput(output string) (preparedOutput, error) {
	// Normalize both paths to absolute so containment checks cannot be
	// defeated by mixing relative roots with relative destinations.
	rootAbs, err := filepath.Abs(s.root)
	if err != nil {
		return preparedOutput{}, fmt.Errorf("%w: cannot resolve repository %q: %v", ErrOutputUnavailable, s.root, err)
	}
	outputAbs, err := filepath.Abs(output)
	if err != nil {
		return preparedOutput{}, fmt.Errorf("%w: cannot resolve output %q: %v", ErrOutputUnavailable, output, err)
	}
	outDir := filepath.Dir(outputAbs)
	// The parent must exist and be a directory. Symlinks are followed here; a
	// symlinked parent that redirects the destination into the repository is
	// caught by the resolved containment check below.
	parentInfo, err := os.Stat(outDir)
	if err != nil {
		return preparedOutput{}, fmt.Errorf("%w: output directory %q: %v", ErrOutputUnavailable, outDir, err)
	}
	if !parentInfo.IsDir() {
		return preparedOutput{}, fmt.Errorf("%w: output directory %q is not a directory", ErrOutputUnavailable, outDir)
	}

	// Resolve the repository root. A not-yet-created repository falls through
	// to index loading, which reports the unreadable record; only genuine
	// resolution failures are output problems.
	repoReal, err := filepath.EvalSymlinks(rootAbs)
	if errors.Is(err, os.ErrNotExist) {
		repoReal = rootAbs
	} else if err != nil {
		return preparedOutput{}, fmt.Errorf("%w: cannot resolve repository %q: %v", ErrOutputUnavailable, s.root, err)
	}
	// Resolve every existing component of the output path so a symlink in a
	// parent directory cannot smuggle a destination into the repository.
	outReal, err := resolveExisting(outputAbs)
	if err != nil {
		return preparedOutput{}, fmt.Errorf("%w: %v", ErrOutputUnavailable, err)
	}
	if withinPath(outReal, repoReal) || withinPath(outputAbs, rootAbs) {
		return preparedOutput{}, fmt.Errorf("%w: %s lies within the repository %q", ErrOutputUnavailable, output, s.root)
	}

	// Temp files must be physically next to the destination for rename(2) to
	// be atomic, so resolve the parent's real path too.
	dirReal, err := filepath.EvalSymlinks(outDir)
	if err != nil {
		return preparedOutput{}, fmt.Errorf("%w: output directory %q: %v", ErrOutputUnavailable, outDir, err)
	}

	mode := os.FileMode(0o644)
	if info, lerr := os.Lstat(outputAbs); lerr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return preparedOutput{}, fmt.Errorf("%w: %s is a symbolic link", ErrOutputUnavailable, output)
		}
		if !info.Mode().IsRegular() {
			return preparedOutput{}, fmt.Errorf("%w: %s is not a regular file", ErrOutputUnavailable, output)
		}
		mode = info.Mode().Perm()
		if err := rejectHardlinkToRepository(output, repoReal, info); err != nil {
			return preparedOutput{}, err
		}
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return preparedOutput{}, fmt.Errorf("%w: cannot inspect %s: %v", ErrOutputUnavailable, output, lerr)
	}
	return preparedOutput{TempDir: dirReal, Pattern: ".download-*", Mode: mode}, nil
}

// resolveExisting resolves symlinks in path, tolerating a nonexistent final
// component (which is then appended lexically). All existing components must
// resolve successfully, so symlinked parent directories are followed here and
// caught by the within-repository check.
func resolveExisting(path string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("cannot resolve output path %q: %v", path, err)
	}
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("cannot resolve output directory %q: %v", parent, err)
	}
	return filepath.Join(resolvedParent, base), nil
}

// withinPath reports whether target is path itself or lies beneath base. Both
// arguments should be cleaned lexical paths; the comparison is
// component-wise so "/repo-evil" is not treated as lying beneath "/repo".
func withinPath(target, base string) bool {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// rejectHardlinkToRepository refuses an existing outside destination that
// shares an inode with a repository file Get must never modify: the index, the
// lock file, snapshot records, and content objects. A file with a single link
// cannot share an inode, so the repository tree is only walked when it could
// actually match.
func rejectHardlinkToRepository(output, repoReal string, outInfo os.FileInfo) error {
	outDev, outIno := fileIdentity(outInfo)
	if outDev == 0 && outIno == 0 {
		// No usable inode on this platform; the lexical repository check and
		// regular-file requirement still apply.
		return nil
	}
	matches := func(repoFile string) (bool, error) {
		info, err := os.Stat(repoFile)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		dev, ino := fileIdentity(info)
		return dev == outDev && ino == outIno, nil
	}
	for _, guarded := range []string{
		filepath.Join(repoReal, "index.json"),
		filepath.Join(repoReal, ".lock"),
	} {
		ok, err := matches(guarded)
		if err != nil {
			return fmt.Errorf("%w: cannot inspect repository while checking %s: %v", ErrOutputUnavailable, output, err)
		}
		if ok {
			return fmt.Errorf("%w: %s is a hard link to the repository file %s", ErrOutputUnavailable, output, guarded)
		}
	}
	if linkCount(outInfo) <= 1 {
		return nil
	}
	for _, sub := range []string{"objects", "snapshots"} {
		dir := filepath.Join(repoReal, sub)
		walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			dev, ino := fileIdentity(info)
			if dev == outDev && ino == outIno {
				return errHardlinkGuard{path: path}
			}
			return nil
		})
		var guard errHardlinkGuard
		if errors.As(walkErr, &guard) {
			return fmt.Errorf("%w: %s is a hard link to the repository file %s", ErrOutputUnavailable, output, guard.path)
		}
		if walkErr != nil {
			return fmt.Errorf("%w: cannot inspect repository while checking %s: %v", ErrOutputUnavailable, output, walkErr)
		}
	}
	return nil
}

// errHardlinkGuard stops the repository walk as soon as the shared inode is
// found; it carries the matching repository path for the error message.
type errHardlinkGuard struct{ path string }

func (e errHardlinkGuard) Error() string { return "hard link to " + e.path }

func fileIdentity(info os.FileInfo) (dev, ino uint64) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), uint64(stat.Ino)
	}
	return 0, 0
}

func linkCount(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Nlink)
	}
	return 1
}
