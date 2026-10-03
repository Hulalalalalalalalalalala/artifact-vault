package vault

import (
	"crypto/rand"
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
	"unsafe"
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
	idx, err := s.loadCurrentIndex()
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

	absOut, mode, pin, err := s.checkOutputSafe(output)
	if err != nil {
		return fmt.Errorf("artifact %q: %w", name, err)
	}
	defer pin.Close()
	if err := s.downloadObject(entry, absOut, mode, pin); err != nil {
		return fmt.Errorf("artifact %q: %w", name, err)
	}
	return nil
}

// parentPin is an open file descriptor on the resolved directory an output is
// committed into. Committing through the descriptor (renameat) instead of a
// path means a parent directory replaced by a symlink after the check cannot
// redirect the final rename.
type parentPin struct {
	f    *os.File
	path string
}

func (p *parentPin) Close() error {
	if p == nil || p.f == nil {
		return nil
	}
	return p.f.Close()
}

// checkOutputSafe validates a destination path without opening any repository
// content. It returns the absolute, symlink-resolved output path, the
// permission bits a replacement should carry, and an open descriptor on the
// output's resolved parent directory used for the final atomic commit.
//
// The destination must be outside the repository:
//
//   - judged on actual locations, so neither a repository root reached
//     through a symlink nor a symlinked parent that leads back into the
//     repository can hide an inside path;
//   - including a path that does not exist yet, so a not-yet-created file
//     inside the repository is refused before anything is written;
//   - with every ".." in a relative path honored, while an unrelated
//     directory sharing a textual prefix with the repository stays allowed;
//
// its parent directory must already exist and be accessible (it is never
// created, though a symlinked parent resolving to a normal directory outside
// the repository is fine); and an existing output must be a regular file
// (never a symlink, including a dangling one, a directory, or another special
// file) that is not a hard link to any repository file — the index, the lock,
// any snapshot record, or any content object, including ones the current
// operation does not reference.
//
// Any information needed to confirm these relationships that cannot be read is
// reported as an error rather than assumed safe.
func (s *Store) checkOutputSafe(output string) (string, os.FileMode, *parentPin, error) {
	absOut, err := filepath.Abs(output)
	if err != nil {
		return "", 0, nil, fmt.Errorf("output %q: cannot resolve path: %w", output, err)
	}
	mode := os.FileMode(0o644)
	if info, err := os.Lstat(absOut); err == nil {
		// Symlinks are never followed; anything that is not a regular file
		// (directory, device, socket, ...) is refused.
		if info.Mode()&os.ModeSymlink != 0 {
			return "", 0, nil, fmt.Errorf("output %q is a symbolic link", output)
		}
		if !info.Mode().IsRegular() {
			return "", 0, nil, fmt.Errorf("output %q is not a regular file", output)
		}
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, nil, fmt.Errorf("output %q: cannot inspect path: %w", output, err)
	}

	absRoot, err := filepath.Abs(s.root)
	if err != nil {
		return "", 0, nil, fmt.Errorf("cannot resolve repository root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", 0, nil, fmt.Errorf("cannot resolve repository root: %w", err)
	}
	// Path-based containment first: this works even when the output or its
	// parent does not exist yet, so a not-yet-created destination inside the
	// repository is refused before any symlink is followed.
	if isWithin(resolvedRoot, absOut) {
		return "", 0, nil, fmt.Errorf("output %q is inside the repository", output)
	}
	// Resolve every symlink in the path so a destination that reaches into the
	// repository through a symlinked parent cannot hide.
	resolved, err := filepath.EvalSymlinks(absOut)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", 0, nil, fmt.Errorf("output %q: cannot resolve path: %w", output, err)
		}
		// The final component may simply not exist yet; its parent must.
		parent := filepath.Dir(absOut)
		resolvedParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", 0, nil, fmt.Errorf("output %q: parent directory is not accessible: %w", output, err)
		}
		resolved = filepath.Join(resolvedParent, filepath.Base(absOut))
	}
	if isWithin(resolvedRoot, resolved) {
		return "", 0, nil, fmt.Errorf("output %q is inside the repository", output)
	}

	// Open and pin the resolved parent directory. The output's parent must be a
	// real, accessible directory; the descriptor is reused for the commit so a
	// later swap of any path component (replacing the directory with a symlink
	// to the repository, for example) cannot redirect the rename.
	resolvedParent := filepath.Dir(resolved)
	pin, err := pinDirectory(resolvedParent)
	if err != nil {
		return "", 0, nil, fmt.Errorf("output %q: parent directory is not accessible: %w", output, err)
	}

	if err := s.checkOutputNotRepoHardlink(resolved, output); err != nil {
		pin.Close()
		return "", 0, nil, err
	}
	return resolved, mode, pin, nil
}

// isWithin reports whether target is root itself or lies beneath root. Both
// arguments must be cleaned absolute paths; lexical containment here is exact
// (".." segments are real separators), so a sibling sharing a name prefix
// (e.g. /vault-backup next to /vault) is not considered inside.
func isWithin(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// pinDirectory opens a directory directly (O_NOFOLLOW refuses a terminal
// symlink) and returns a descriptor used both as the location anchor for *at
// operations and for fsync. It is immune to later renames or symlink
// replacements of the path it was opened on.
func pinDirectory(dir string) (*parentPin, error) {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return &parentPin{f: os.NewFile(uintptr(fd), dir), path: dir}, nil
}

// checkOutputNotRepoHardlink refuses an existing output that is a hard link to
// any repository file (the index, the lock, an object, or a snapshot record).
// Replacing such a link would rewrite the repository file's contents through
// the link. Every repository file identity must be readable; an unreadable
// directory or stat failure is reported rather than skipped.
func (s *Store) checkOutputNotRepoHardlink(absOut, output string) error {
	info, err := os.Lstat(absOut)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("output %q: cannot inspect path: %w", output, err)
	}
	outID, ok := fileIDOf(info)
	if !ok {
		return nil
	}
	ids, err := s.repoFileIDs()
	if err != nil {
		return fmt.Errorf("output %q: cannot verify it is not linked to a repository file: %w", output, err)
	}
	for id, repoPath := range ids {
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
// output must not be hard-linked to: the index, the lock, every content
// object (including unreferenced and temp-named ones, since replacing any file
// in the repository is forbidden), and every file under snapshots/. A
// directory that should be present but cannot be read is an error: protection
// must never silently narrow to the files that happened to be stat-able.
func (s *Store) repoFileIDs() (map[fileID]string, error) {
	ids := map[fileID]string{}
	// The index may legitimately be absent from a freshly initialized
	// repository; the lock is created by the time an operation runs. Missing
	// files simply contribute no identity.
	if err := addIfExists(s.indexPath(), ids); err != nil {
		return nil, err
	}
	if err := addIfExists(s.lockPath(), ids); err != nil {
		return nil, err
	}
	objectsDir := filepath.Join(s.root, "objects")
	if entries, err := os.ReadDir(objectsDir); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("cannot read objects directory: %w", err)
		}
	} else {
		for _, entry := range entries {
			if err := addIfExists(filepath.Join(objectsDir, entry.Name()), ids); err != nil {
				return nil, err
			}
		}
	}
	if err := filepath.WalkDir(s.snapshotsDir(), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		return addIfExists(path, ids)
	}); err != nil {
		return nil, err
	}
	return ids, nil
}

// addIfExists records the identity of an existing file, ignoring only a
// genuinely missing path.
func addIfExists(path string, ids map[fileID]string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if id, ok := fileIDOf(info); ok {
		ids[id] = path
	}
	return nil
}

// downloadObject streams the verified object into a temporary file beside the
// output and renames it into place only after the complete bytes match the
// record. It never truncates or writes the output directly, and it never
// buffers the whole object in memory.
func (s *Store) downloadObject(entry Entry, absOut string, mode os.FileMode, pin *parentPin) error {
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

	// The temporary file is created through the pinned parent descriptor; even
	// if a path component is replaced by a symlink while the copy runs, the
	// descriptor stays attached to the original directory, the temporary bytes
	// land there and nowhere else, and the final rename is performed through
	// the pin rather than the path.
	tmp, tmpBase, err := createTempIn(pin, ".download-")
	if err != nil {
		return fmt.Errorf("cannot create temporary file for output: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			removeTempIn(pin, tmpBase)
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
	if err := s.commitOutput(pin, tmpBase, absOut); err != nil {
		return err
	}
	committed = true
	// Best-effort directory sync so the rename survives a crash; failure here
	// does not undo an already atomic replacement.
	_ = syncDirectory(pin.f)
	return nil
}

// commitOutput atomically replaces absOut with tmpPath through the pinned
// parent directory descriptor. Immediately before the rename it revalidates
// everything established by checkOutputSafe, since another process may have
// changed the filesystem while the content was being prepared:
//
//   - the pinned directory must still be the same physical directory reached
//     by its (fully resolved) path, must still be outside the repository, and
//     no path component may have become a symlink;
//   - an existing destination must still be missing or a regular file;
//   - an existing destination must still not be a hard link to any repository
//     file.
//
// If any condition no longer holds the rename is refused, so a parent swapped
// for a symlink into the repository can never cause the package to land on an
// index, snapshot, lock, or object.
func (s *Store) commitOutput(pin *parentPin, tmpPath, absOut string) error {
	if err := s.pinStillPointsOutsideRepo(pin, absOut); err != nil {
		return err
	}
	base := filepath.Base(absOut)
	var st syscall.Stat_t
	if err := fstatatNoFollow(pin.f.Fd(), base, &st); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("output %q: cannot inspect destination: %w", absOut, err)
		}
	} else {
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFLNK:
			return fmt.Errorf("output %q is a symbolic link", absOut)
		case syscall.S_IFREG:
		default:
			return fmt.Errorf("output %q is not a regular file", absOut)
		}
		outID := fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}
		ids, err := s.repoFileIDs()
		if err != nil {
			return fmt.Errorf("output %q: cannot verify it is not linked to a repository file: %w", absOut, err)
		}
		for id, repoPath := range ids {
			if id == outID {
				return fmt.Errorf("output %q is a hard link to repository file %q", absOut, repoPath)
			}
		}
	}

	if err := renameAt(pin.f.Fd(), filepath.Base(tmpPath), pin.f.Fd(), base); err != nil {
		return fmt.Errorf("cannot write output %q: %w", absOut, err)
	}
	return nil
}

// pinStillPointsOutsideRepo revalidates the pinned output directory at commit
// time. It must remain the exact directory the pin was opened on (compared by
// device/inode), its path must still resolve with no symlink components to the
// same physical directory, and that directory must still lie outside the
// resolved repository tree.
func (s *Store) pinStillPointsOutsideRepo(pin *parentPin, absOut string) error {
	var pinStat syscall.Stat_t
	if err := syscall.Fstat(int(pin.f.Fd()), &pinStat); err != nil {
		return fmt.Errorf("output %q: cannot verify destination directory: %w", absOut, err)
	}
	info, err := os.Lstat(pin.path)
	if err != nil {
		return fmt.Errorf("output %q: destination directory is no longer accessible: %w", absOut, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("output %q is unsafe: destination directory was replaced", absOut)
	}
	if id, ok := fileIDOf(info); !ok || id.dev != uint64(pinStat.Dev) || id.ino != uint64(pinStat.Ino) {
		return fmt.Errorf("output %q is unsafe: destination directory was replaced", absOut)
	}
	resolved, err := filepath.EvalSymlinks(pin.path)
	if err != nil {
		return fmt.Errorf("output %q: destination directory is no longer accessible: %w", absOut, err)
	}
	if resolved != pin.path {
		return fmt.Errorf("output %q is unsafe: destination directory now resolves through a symbolic link", absOut)
	}
	absRoot, err := filepath.Abs(s.root)
	if err != nil {
		return fmt.Errorf("cannot resolve repository root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return fmt.Errorf("cannot resolve repository root: %w", err)
	}
	if isWithin(resolvedRoot, pin.path) {
		return fmt.Errorf("output %q is unsafe: destination directory is inside the repository", absOut)
	}
	return nil
}

// atSymlinkNoFollow is the AT_SYMLINK_NOFOLLOW flag for fstatat.
const atSymlinkNoFollow = 0x100

// fstatatNoFollow stats a path relative to dirfd without following a terminal
// symlink. A missing file is reported with os.ErrNotExist.
func fstatatNoFollow(dirfd uintptr, name string, st *syscall.Stat_t) error {
	pathPtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_FSTATAT, dirfd, uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(st)), uintptr(atSymlinkNoFollow), 0, 0)
	if errno != 0 {
		if errno == syscall.ENOENT {
			return os.ErrNotExist
		}
		return errno
	}
	return nil
}

// renameAt renames within directories given by file descriptors, so the
// operation cannot be redirected by a later path-component replacement.
func renameAt(oldDir uintptr, oldName string, newDir uintptr, newName string) error {
	oldPtr, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPtr, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_RENAMEAT,
		oldDir, uintptr(unsafe.Pointer(oldPtr)),
		newDir, uintptr(unsafe.Pointer(newPtr)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// createTempIn creates a new, exclusively owned temporary file with a unique
// name directly inside the pinned directory (via openat, never by path) and
// returns the open file together with its basename for the commit rename.
func createTempIn(pin *parentPin, prefix string) (*os.File, string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, "", err
	}
	for i := 0; i < 100; i++ {
		if i > 0 {
			if _, err := rand.Read(random[:]); err != nil {
				return nil, "", err
			}
		}
		name := prefix + hex.EncodeToString(random[:])
		fd, errno := syscall.Openat(int(pin.f.Fd()), name,
			syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
		if errno == syscall.EEXIST {
			continue
		}
		if errno != nil {
			return nil, "", errno
		}
		return os.NewFile(uintptr(fd), filepath.Join(pin.path, name)), name, nil
	}
	return nil, "", errors.New("could not find an unused temporary file name")
}

// removeTempIn unlinks a staged temporary file through the pinned directory.
func removeTempIn(pin *parentPin, name string) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return
	}
	_, _, _ = syscall.Syscall6(syscall.SYS_UNLINKAT, pin.f.Fd(),
		uintptr(unsafe.Pointer(namePtr)), 0, 0, 0, 0)
}

func syncDirectory(dir *os.File) error {
	return dir.Sync()
}
