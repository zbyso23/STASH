// Package vfs is the storage abstraction under every persistent write
// (SPEC §18: crash-injection tests need a filesystem that can drop
// unflushed writes and tear page writes, not only kill the process).
//
// OS is the production implementation. CrashFS is an in-memory
// implementation that models what survives a power loss.
package vfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// File is the subset of *os.File the archive needs. Reads and writes are
// positional (pread/pwrite): no shared file offset, safe for concurrent use
// of distinct regions.
type File interface {
	io.ReaderAt
	io.WriterAt
	Truncate(size int64) error
	Sync() error
	Size() (int64, error)
	Close() error
}

// FS is a filesystem rooted at an archive directory. Names use '/'.
type FS interface {
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	Remove(name string) error
	Rename(oldName, newName string) error
	MkdirAll(name string, perm fs.FileMode) error
	// SyncDir makes creations, renames and removals in dir durable.
	SyncDir(dir string) error
	Stat(name string) (fs.FileInfo, error)
	ReadDir(name string) ([]fs.DirEntry, error)
	// Lock takes an exclusive, non-blocking lock on name (created if
	// absent) for the single-writer rule (§12.1). It fails with ErrLocked
	// when another holder exists. The returned function releases it.
	Lock(name string) (unlock func() error, err error)
}

// ErrLocked reports a lock held by another writer.
var ErrLocked = errors.New("lock held by another writer")

// OS is an FS on the host filesystem below Root.
type OS struct{ Root string }

type osFile struct{ *os.File }

func (f osFile) Size() (int64, error) {
	st, err := f.File.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

func (o OS) path(name string) string { return filepath.Join(o.Root, filepath.FromSlash(name)) }

func (o OS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	f, err := os.OpenFile(o.path(name), flag, perm)
	if err != nil {
		return nil, err
	}
	return osFile{f}, nil
}

func (o OS) Remove(name string) error                   { return os.Remove(o.path(name)) }
func (o OS) Rename(a, b string) error                   { return os.Rename(o.path(a), o.path(b)) }
func (o OS) MkdirAll(n string, p fs.FileMode) error     { return os.MkdirAll(o.path(n), p) }
func (o OS) Stat(name string) (fs.FileInfo, error)      { return os.Stat(o.path(name)) }
func (o OS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(o.path(name)) }

// SyncDir fsyncs the directory (POSIX). Windows needs MoveFileEx with
// MOVEFILE_WRITE_THROUGH instead (§18); not supported yet.
func (o OS) SyncDir(dir string) error {
	d, err := os.Open(o.path(dir))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
