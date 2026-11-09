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

// OS is an FS on the host filesystem below Root. On Unix every name is
// resolved component by component from an open Root with O_NOFOLLOW and
// the *at system calls: a symbolic link anywhere inside the archive is
// refused (ErrSymlink), never followed, so neither a write nor a removal
// can reach outside Root through a planted link, and only regular files
// and directories are opened. Root itself is trusted configuration.
type OS struct{ Root string }

// ErrSymlink reports a symbolic link (or another non-regular entry) where
// the archive has a file or directory: refused, never followed.
var ErrSymlink = errors.New("symbolic link or special file inside the archive refused")

type osFile struct{ *os.File }

func (f osFile) Size() (int64, error) {
	st, err := f.File.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}
