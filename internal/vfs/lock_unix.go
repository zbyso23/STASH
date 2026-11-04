//go:build unix

package vfs

import (
	"errors"
	"os"
	"syscall"
)

// Lock uses flock(LOCK_EX|LOCK_NB). The lock belongs to the open file
// description, so it is released when the process dies.
func (o OS) Lock(name string) (func() error, error) {
	f, err := os.OpenFile(o.path(name), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() error {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}, nil
}
