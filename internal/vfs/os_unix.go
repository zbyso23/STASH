//go:build unix

package vfs

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// split validates a relative archive name and returns its components.
func split(op, name string) ([]string, error) {
	c := path.Clean(name)
	if c == "." || c == "" {
		return nil, nil
	}
	if path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	return strings.Split(c, "/"), nil
}

func pathErr(op, name string, err error) error {
	if err == unix.ELOOP || err == unix.EMLINK {
		err = ErrSymlink
	}
	return &fs.PathError{Op: op, Path: name, Err: err}
}

// openDir opens the directory made of the components below Root without
// following links, creating missing ones when create is set. The caller
// closes the descriptor.
func (o OS) openDir(op, name string, parts []string, create bool) (int, error) {
	fd, err := unix.Open(o.Root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, pathErr(op, o.Root, err)
	}
	for _, c := range parts {
		n, err := unix.Openat(fd, c, dirFlags, 0)
		if err == unix.ENOENT && create {
			if err = unix.Mkdirat(fd, c, 0o755); err == nil || err == unix.EEXIST {
				n, err = unix.Openat(fd, c, dirFlags, 0)
			}
		}
		unix.Close(fd)
		if err != nil {
			return -1, pathErr(op, name, err)
		}
		fd = n
	}
	return fd, nil
}

// parent opens the parent directory of name and returns its last
// component ("." for Root itself).
func (o OS) parent(op, name string) (int, string, error) {
	parts, err := split(op, name)
	if err != nil {
		return -1, "", err
	}
	if len(parts) == 0 {
		fd, err := o.openDir(op, name, nil, false)
		return fd, ".", err
	}
	fd, err := o.openDir(op, name, parts[:len(parts)-1], false)
	return fd, parts[len(parts)-1], err
}

func (o OS) full(name string) string { return filepath.Join(o.Root, filepath.FromSlash(name)) }

// openFile opens a regular file without following links; O_NONBLOCK keeps
// a planted FIFO from blocking the open (it is then refused).
func (o OS) openFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	dfd, base, err := o.parent("open", name)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	fd, err := unix.Openat(dfd, base, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(perm.Perm()))
	if err != nil {
		return nil, pathErr("open", name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if err == nil {
			err = ErrSymlink
		}
		return nil, pathErr("open", name, err)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, pathErr("open", name, err)
	}
	return os.NewFile(uintptr(fd), o.full(name)), nil
}

func (o OS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	f, err := o.openFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osFile{f}, nil
}

// Remove removes a file, an empty directory, or a link itself (unlinkat
// never follows the last component).
func (o OS) Remove(name string) error {
	dfd, base, err := o.parent("remove", name)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	err = unix.Unlinkat(dfd, base, 0)
	if err == unix.EISDIR || err == unix.EPERM {
		if err2 := unix.Unlinkat(dfd, base, unix.AT_REMOVEDIR); err2 == nil || err2 != unix.ENOTDIR {
			err = err2
		}
	}
	if err != nil {
		return pathErr("remove", name, err)
	}
	return nil
}

func (o OS) Rename(a, b string) error {
	da, ba, err := o.parent("rename", a)
	if err != nil {
		return err
	}
	defer unix.Close(da)
	db, bb, err := o.parent("rename", b)
	if err != nil {
		return err
	}
	defer unix.Close(db)
	if err := unix.Renameat(da, ba, db, bb); err != nil {
		return &os.LinkError{Op: "rename", Old: a, New: b, Err: err}
	}
	return nil
}

func (o OS) MkdirAll(name string, _ fs.FileMode) error {
	parts, err := split("mkdir", name)
	if err != nil {
		return err
	}
	fd, err := o.openDir("mkdir", name, parts, true)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// Stat describes name itself: a link is reported as a link, never
// followed.
func (o OS) Stat(name string) (fs.FileInfo, error) {
	dfd, base, err := o.parent("stat", name)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, pathErr("stat", name, err)
	}
	return statInfo{name: path.Base(name), size: st.Size, mode: modeOf(uint32(st.Mode))}, nil
}

func (o OS) ReadDir(name string) ([]fs.DirEntry, error) {
	f, err := o.dir("readdir", name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return ents, err
}

// SyncDir fsyncs the directory (POSIX). Windows needs MoveFileEx with
// MOVEFILE_WRITE_THROUGH instead (§18); not supported yet.
func (o OS) SyncDir(dir string) error {
	f, err := o.dir("sync", dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (o OS) dir(op, name string) (*os.File, error) {
	parts, err := split(op, name)
	if err != nil {
		return nil, err
	}
	fd, err := o.openDir(op, name, parts, false)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), o.full(name)), nil
}

func modeOf(m uint32) fs.FileMode {
	perm := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		return perm | fs.ModeDir
	case unix.S_IFREG:
		return perm
	case unix.S_IFLNK:
		return perm | fs.ModeSymlink
	}
	return perm | fs.ModeIrregular
}

type statInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (s statInfo) Name() string       { return s.name }
func (s statInfo) Size() int64        { return s.size }
func (s statInfo) Mode() fs.FileMode  { return s.mode }
func (s statInfo) ModTime() time.Time { return time.Time{} }
func (s statInfo) IsDir() bool        { return s.mode.IsDir() }
func (s statInfo) Sys() any           { return nil }
