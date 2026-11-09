package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// exportRoot writes objects below one directory without ever leaving it:
// every component is opened relative to its parent with O_NOFOLLOW, so a
// symbolic link (or any non-directory) already present in the destination
// is refused instead of followed, and a file is created next to its final
// name and renamed over it, never written through an existing link.
type exportRoot struct{ fd int }

func openExportRoot(dir string) (*exportRoot, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return &exportRoot{fd}, nil
}

func (x *exportRoot) Close() error { return unix.Close(x.fd) }

// errUnsafe reports a destination entry that is not what export creates.
var errUnsafe = errors.New("refusing to follow a symbolic link or replace a non-regular file in the destination")

// write stores r as the '/'-separated relative path p.
func (x *exportRoot) write(p string, r io.Reader) error {
	parts := strings.Split(p, "/")
	for _, c := range parts {
		if c == "" || c == "." || c == ".." { // archive paths never hold these (SPEC §6.4.5)
			return fmt.Errorf("%w: unsafe path %q", errUnsafe, p)
		}
	}
	dir, err := unix.Dup(x.fd)
	if err != nil {
		return err
	}
	defer func() { unix.Close(dir) }()
	for i, c := range parts[:len(parts)-1] {
		fd, err := unix.Openat(dir, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.ENOENT {
			if err = unix.Mkdirat(dir, c, 0o755); err == nil || err == unix.EEXIST {
				fd, err = unix.Openat(dir, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		if err == unix.ELOOP || err == unix.ENOTDIR {
			return fmt.Errorf("%s: %w", strings.Join(parts[:i+1], "/"), errUnsafe)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", strings.Join(parts[:i+1], "/"), err)
		}
		unix.Close(dir)
		dir = fd
	}
	name := parts[len(parts)-1]
	var st unix.Stat_t
	if err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%s: %w", p, errUnsafe)
	} else if err != nil && err != unix.ENOENT {
		return fmt.Errorf("%s: %w", p, err)
	}
	var rb [8]byte
	rand.Read(rb[:])
	tmp := ".stash-" + hex.EncodeToString(rb[:])
	fd, err := unix.Openat(dir, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dir, tmp, dir, name)
	}
	if err != nil {
		unix.Unlinkat(dir, tmp, 0)
		return fmt.Errorf("%s: %w", p, err)
	}
	return nil
}
