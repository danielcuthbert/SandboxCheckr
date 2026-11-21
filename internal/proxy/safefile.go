package proxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// The proxy runs OUTSIDE the sandbox but writes its log, CA bundle and ready
// file into the workdir, which the sandboxed program can write to. A program
// that plants a symlink there — proxy.log -> ~/.zshrc, or the scratch
// directory itself -> ~/.ssh — would otherwise have the unconfined proxy write
// wherever it pointed on the next run. So these writes refuse to follow a
// symlink at the file or at its parent directory.

// checkNoSymlink refuses a path whose final component, or whose parent
// directory, is a symlink, and a final component that is not a regular file.
// A symlinked parent owned by root (macOS's /tmp -> /private/tmp) is accepted:
// the sandboxed program cannot have created it.
func checkNoSymlink(path string) error {
	dir := filepath.Dir(path)
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 && !ownedByRoot(fi) {
		return fmt.Errorf("refusing to write %s: its directory %s is a symlink", path, dir)
	}
	fi, err = os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write %s: it is a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to write %s: not a regular file", path)
	}
	return nil
}

// OpenAppendNoFollow opens path for appending, creating it with perm, without
// following a symlink at the file or its parent directory.
func OpenAppendNoFollow(path string, perm os.FileMode) (*os.File, error) {
	if err := checkNoSymlink(path); err != nil {
		return nil, err
	}
	// O_NOFOLLOW closes the gap between the check and the open, where the OS
	// supports it.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|oNoFollow, perm)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("refusing to write %s: not a regular file", path)
	}
	return f, nil
}

// WriteFileNoFollow replaces path with data, creating its directory if
// needed, without following a symlink at the file or its parent directory.
//
// It writes a fresh temporary file (created exclusively, so it cannot be a
// planted link), syncs it, and renames it into place; rename replaces a symlink
// rather than writing through it.
func WriteFileNoFollow(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := checkNoSymlink(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	// The rename is durable only if the data is: a crash just after a
	// replacement can otherwise leave the file zero-length, which for the
	// callers that write a policy file means a policy silently gone.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
