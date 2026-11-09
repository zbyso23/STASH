//go:build !unix

package vfs

import (
	"io/fs"
	"os"
	"path/filepath"
)

// Outside Unix the OS file system resolves names with the host's normal
// rules (links are followed); use it only on trusted storage.

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
func (o OS) Stat(name string) (fs.FileInfo, error)      { return os.Lstat(o.path(name)) }
func (o OS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(o.path(name)) }

func (o OS) SyncDir(dir string) error {
	d, err := os.Open(o.path(dir))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
