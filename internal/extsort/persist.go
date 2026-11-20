package extsort

import (
	"io"
	"os"

	"stash/internal/vfs"
)

// WriteRunFile durably replaces name with a run filled by fill (temporary
// file, fsync, rename, directory fsync). After a crash name holds the old
// run or the new one in full; either way a reader verifies it.
func WriteRunFile(fsys vfs.FS, name string, tag Tag, cmp Compare, fill func(*RunWriter) error) error {
	return vfs.ReplaceFileStream(fsys, name, func(w io.Writer) error {
		rw, err := NewRunWriter(w, tag, cmp)
		if err != nil {
			return err
		}
		if err := fill(rw); err != nil {
			return err
		}
		return rw.Finish()
	})
}

// RunFile is an open run file.
type RunFile struct {
	*RunReader
	f vfs.File
}

// OpenRunFile opens name and checks its header against tag.
func OpenRunFile(fsys vfs.FS, name string, tag Tag, cmp Compare) (*RunFile, error) {
	f, err := fsys.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	size, err := f.Size()
	var rr *RunReader
	if err == nil {
		rr, err = OpenRun(f, size, tag, cmp)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return &RunFile{RunReader: rr, f: f}, nil
}

// Close closes the file.
func (r *RunFile) Close() error { return r.f.Close() }
