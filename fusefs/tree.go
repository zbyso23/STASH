package fusefs

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stash"
)

// snapshot is one read-only view of the archive as a directory tree.
// Object paths become files; their '/'-separated components become
// directories. When a path is both an object and a directory prefix of
// other objects ("a" and "a/b"), the directory wins and the object is
// listed in Shadowed (it stays readable with stash get).
type snapshot struct {
	r        *stash.Reader
	at       time.Time
	dirs     map[string]*dirEntry // by directory path; "" is the root
	files    map[string]stash.Info
	shadowed []string
	bytes    int64

	refs    atomic.Int64 // 1 while current, +1 per open file
	closeMu sync.Once
}

type dirEntry struct {
	names []string        // sorted
	isDir map[string]bool // by name
}

func newSnapshot(r *stash.Reader) (*snapshot, error) {
	s := &snapshot{r: r, at: time.Now(), dirs: map[string]*dirEntry{"": {isDir: map[string]bool{}}}, files: map[string]stash.Info{}}
	s.refs.Store(1)
	paths := r.List()
	isPrefix := map[string]bool{}
	for _, p := range paths {
		for i := strings.IndexByte(p, '/'); i >= 0; {
			isPrefix[p[:i]] = true
			j := strings.IndexByte(p[i+1:], '/')
			if j < 0 {
				break
			}
			i += 1 + j
		}
	}
	add := func(dir, name string, d bool) {
		e := s.dirs[dir]
		if _, ok := e.isDir[name]; !ok {
			e.names = append(e.names, name)
		}
		e.isDir[name] = e.isDir[name] || d
	}
	for _, p := range paths {
		if isPrefix[p] {
			s.shadowed = append(s.shadowed, p)
			continue
		}
		in, err := r.Stat(p)
		if err != nil {
			return nil, err
		}
		s.files[p] = in
		s.bytes += in.Size
		parent := ""
		for _, c := range strings.Split(p, "/")[:strings.Count(p, "/")] {
			dir := join(parent, c)
			if s.dirs[dir] == nil {
				s.dirs[dir] = &dirEntry{isDir: map[string]bool{}}
				add(parent, c, true)
			}
			parent = dir
		}
		add(parent, p[strings.LastIndexByte(p, '/')+1:], false)
	}
	for _, e := range s.dirs {
		sort.Strings(e.names)
	}
	return s, nil
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// acquire takes a reference for an open file; it fails when the snapshot
// has already been released.
func (s *snapshot) acquire() bool {
	for {
		n := s.refs.Load()
		if n <= 0 {
			return false
		}
		if s.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// release drops a reference; the last one closes the reader.
func (s *snapshot) release() {
	if s.refs.Add(-1) == 0 {
		s.closeMu.Do(func() { s.r.Close() })
	}
}
