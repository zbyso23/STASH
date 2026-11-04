//go:build !unix

package vfs

import "errors"

// Lock is not implemented on this platform yet (Windows needs LockFileEx).
func (o OS) Lock(name string) (func() error, error) {
	return nil, errors.New("vfs: writer lock not supported on this platform")
}
