package fusefs

import (
	"errors"
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
// counted as shadowed (it stays readable with stash get).
//
// Nothing per path is held in memory: directories are listed on demand
// from the sorted state (SPEC §16.1), and a lookup is a state lookup. Only
// the totals for statfs and the shadowed count are computed once, by one
// streaming walk at mount.
type snapshot struct {
	r        *stash.Reader
	at       time.Time
	shadowed []string // the first shadowedSample shadowed paths
	nshadow  int
	bytes    int64
	files    int64

	refs    atomic.Int64 // 1 while current, +1 per open file
	closeMu sync.Once
}

const shadowedSample = 1000

func newSnapshot(r *stash.Reader) (*snapshot, error) {
	s := &snapshot{r: r, at: time.Now()}
	s.refs.Store(1)
	// a file f is shadowed by any path in [f+"/", f+"0"); the open
	// intervals nest, so a stack as deep as the path depth tracks them
	type open struct {
		path string
		size int64
	}
	var stack []open
	err := r.Walk("", "", func(in stash.Info) bool {
		p := in.Path
		for len(stack) > 0 && p >= stack[len(stack)-1].path+"0" {
			stack = stack[:len(stack)-1]
		}
		for i, f := range stack {
			if strings.HasPrefix(p, f.path+"/") {
				if s.nshadow < shadowedSample {
					s.shadowed = append(s.shadowed, f.path)
				}
				s.nshadow++
				s.bytes -= f.size
				s.files--
				stack = append(stack[:i], stack[i+1:]...)
				break
			}
		}
		stack = append(stack, open{p, in.Size})
		s.bytes += in.Size
		s.files++
		return true
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(s.shadowed)
	return s, nil
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

func prefixOf(dir string) string {
	if dir == "" {
		return ""
	}
	return dir + "/"
}

// isDir reports whether p is a directory: the root, or a prefix of a path.
func (s *snapshot) isDir(p string) (bool, error) {
	if p == "" {
		return true, nil
	}
	found := false
	err := s.r.Walk(p+"/", "", func(stash.Info) bool { found = true; return false })
	return found, err
}

// file returns the object at p unless a directory of the same name
// hides it.
func (s *snapshot) file(p string) (stash.Info, bool, error) {
	if d, err := s.isDir(p); err != nil || d {
		return stash.Info{}, false, err
	}
	in, err := s.r.Stat(p)
	if errors.Is(err, stash.ErrNotFound) {
		return stash.Info{}, false, nil
	}
	return in, err == nil, err
}

type child struct {
	name  string
	isDir bool
}

// children lists a directory in name order. Each subdirectory costs one
// seek past its subtree, so the walk is proportional to the entries of
// this directory, not to everything below it.
func (s *snapshot) children(dir string) ([]child, error) {
	pfx := prefixOf(dir)
	var out []child
	at := map[string]int{}
	start := ""
	for {
		var next string
		err := s.r.Walk(pfx, start, func(in stash.Info) bool {
			rest := in.Path[len(pfx):]
			i := strings.IndexByte(rest, '/')
			if i < 0 {
				if _, ok := at[rest]; !ok {
					at[rest] = len(out)
					out = append(out, child{name: rest})
				}
				return true
			}
			name := rest[:i]
			if j, ok := at[name]; ok {
				out[j].isDir = true // a shadowed object of the same name
			} else {
				at[name] = len(out)
				out = append(out, child{name: name, isDir: true})
			}
			next = pfx + name + "0" // the first path after name/...
			return false
		})
		if err != nil {
			return nil, err
		}
		if next == "" {
			break
		}
		start = next
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
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
