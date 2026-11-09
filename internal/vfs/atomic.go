package vfs

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
)

// ReplaceFile durably replaces name with data (SPEC §2.1.1): write a
// temporary file in the same directory, fsync it, rename it over name, and
// fsync the directory. After a crash, name holds either the old or the new
// content in full, never a mix.
func ReplaceFile(fsys FS, name string, data []byte) error {
	return ReplaceFileStream(fsys, name, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// ReplaceFileStream is ReplaceFile for content produced by fill, which may
// be larger than memory should hold at once (index rebuilds, §10.5). If
// fill fails, the temporary file is removed and name is untouched. The
// temporary file has an unpredictable name and is created exclusively
// (O_EXCL; OS also refuses links), so nothing planted beforehand is opened
// or truncated; the rename replaces name itself, never what a link at
// name points to.
func ReplaceFileStream(fsys FS, name string, fill func(io.Writer) error) error {
	dir := path.Dir(name)
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	tmp := name + ".tmp-" + hex.EncodeToString(r[:])
	f, err := fsys.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	fw := &fileWriter{f: f}
	bw := bufio.NewWriterSize(fw, 1<<20)
	err = fill(bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fsys.Remove(tmp)
		return err
	}
	if err := fsys.Rename(tmp, name); err != nil {
		return err
	}
	return fsys.SyncDir(dir)
}

// fileWriter adapts positional writes to io.Writer.
type fileWriter struct {
	f   File
	off int64
}

func (w *fileWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.off)
	w.off += int64(n)
	return n, err
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

// RemoveAll removes name and everything below it, then syncs the parent
// directory. A crash part way leaves a partially removed tree. Stat does
// not follow links, so a link inside the tree is removed itself and what
// it points to is never touched.
func RemoveAll(fsys FS, name string) error {
	st, err := fsys.Stat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if st.IsDir() {
		ents, err := fsys.ReadDir(name)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := RemoveAll(fsys, path.Join(name, e.Name())); err != nil {
				return err
			}
		}
	}
	if err := fsys.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsys.SyncDir(path.Dir(name))
}
