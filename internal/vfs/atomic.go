package vfs

import (
	"os"
	"path"
)

// ReplaceFile durably replaces name with data (SPEC §2.1.1): write a
// temporary file in the same directory, fsync it, rename it over name, and
// fsync the directory. After a crash, name holds either the old or the new
// content in full, never a mix.
func ReplaceFile(fsys FS, name string, data []byte) error {
	dir := path.Dir(name)
	tmp := name + ".tmp"
	f, err := fsys.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := fsys.Rename(tmp, name); err != nil {
		return err
	}
	return fsys.SyncDir(dir)
}

// ReadFile reads a whole small file (root, allocator, index header). max
// bounds the size so a corrupt file cannot force a large allocation.
func ReadFile(fsys FS, name string, max int64) ([]byte, error) {
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	n, err := f.Size()
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, &os.PathError{Op: "read", Path: name, Err: errTooLarge}
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, 0); err != nil && n > 0 {
		return nil, err
	}
	return b, nil
}

type tooLarge struct{}

func (tooLarge) Error() string { return "file larger than allowed" }

var errTooLarge error = tooLarge{}
