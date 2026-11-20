package archive

import (
	"errors"
	"io/fs"
	"os"
	"sync"

	"stash/internal/index"
	"stash/internal/membudget"
	"stash/internal/vfs"
)

// ScratchDir is the writer's scratch space below the archive root: session
// index runs and external-sort spills. It is implementation-defined, never
// read by another session, removed when a writer opens and closes, and
// ignored by readers and by other implementations.
const ScratchDir = "scratch"

// testDeltaMax overrides the in-memory index delta (tests force spills).
var testDeltaMax int

// cacheShare is the part of the memory limit given to the index page cache.
const cacheShare = 8

// writerEnv prepares the bounded-memory environment of a writer: the
// budget, the page cache and the scratch directory (whatever an earlier
// session left there is removed; the writer lock is held).
func writerEnv(fsys vfs.FS, limit int64) (*index.Env, error) {
	if err := removeScratch(fsys); err != nil {
		return nil, err
	}
	b := membudget.New(limit)
	return &index.Env{
		Budget:   b,
		Cache:    index.NewPageCache(b, b.Limit()/cacheShare),
		Scratch:  func() (vfs.FS, string, error) { return fsys, ScratchDir, nil },
		DeltaMax: testDeltaMax,
	}, nil
}

// readerEnv prepares the environment of a reader, which never writes into
// the archive: its scratch space is a private temporary directory below
// tempDir (os.TempDir() when empty), created on first use and removed by
// the returned cleanup.
func readerEnv(limit int64, tempDir string) (*index.Env, func()) {
	b := membudget.New(limit)
	var (
		once sync.Once
		mu   sync.Mutex
		dir  string
		derr error
	)
	scratch := func() (vfs.FS, string, error) {
		once.Do(func() {
			d, err := os.MkdirTemp(tempDir, "stash-scratch-")
			mu.Lock()
			dir, derr = d, err
			mu.Unlock()
		})
		mu.Lock()
		defer mu.Unlock()
		if derr != nil {
			return nil, "", derr
		}
		return vfs.OS{Root: dir}, "s", nil
	}
	env := &index.Env{Budget: b, Cache: index.NewPageCache(b, b.Limit()/cacheShare), Scratch: scratch, DeltaMax: testDeltaMax}
	return env, func() {
		env.Cache.Close()
		mu.Lock()
		d := dir
		mu.Unlock()
		if d != "" {
			os.RemoveAll(d)
		}
	}
}

// memOpts are the memory options of a reader.
type memOpts struct {
	limit   int64
	tempDir string
}

func removeScratch(fsys vfs.FS) error {
	if err := vfs.RemoveAll(fsys, ScratchDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
