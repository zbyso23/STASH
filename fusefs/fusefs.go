// Package fusefs mounts a STASH archive as a read-only file system
// (Linux FUSE). Objects appear as regular files, the components of their
// '/'-separated paths as directories. Reads go through a pinned reader
// snapshot (SPEC §13.1.1), so compaction never removes data an open file
// still reads; every byte is verified as usual, damaged data is repaired
// from parity or fails the read with EIO, never returned as zeros.
package fusefs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"stash"
)

// Options configure Mount.
type Options struct {
	// Read opens the archive (key, anchor of a HARDENED archive).
	Read stash.ReadOptions
	// Refresh, when positive, opens a new snapshot at this interval, so
	// the mount follows commits of a writer. A file opened before keeps
	// reading the version it opened. Zero mounts one fixed snapshot.
	Refresh time.Duration
	// AllowOther lets other users access the mount (needs
	// user_allow_other in /etc/fuse.conf for a non-root user).
	AllowOther bool
	// Debug logs every FUSE request.
	Debug bool
	// Log receives notices (shadowed paths, refresh failures); nil: none.
	Log func(string)
}

// Server is a mounted archive.
type Server struct {
	srv    *fuse.Server
	root   *root
	closed sync.Once
}

type root struct {
	dirNode
	archive string
	opt     Options

	mu   sync.RWMutex
	snap *snapshot

	inoMu sync.Mutex
	inos  map[string]uint64 // "d:path" / "f:path" -> inode number
	next  uint64

	stop chan struct{}
	done chan struct{}
}

// Mount opens a snapshot of the archive in dir and mounts it read-only at
// mountpoint. Call Unmount (or unmount the directory) to end it, and Wait
// to block until then.
func Mount(dir, mountpoint string, o Options) (*Server, error) {
	r, err := stash.OpenReadOnlyWith(dir, o.Read)
	if err != nil {
		return nil, err
	}
	s, err := newSnapshot(r)
	if err != nil {
		r.Close()
		return nil, err
	}
	rt := &root{archive: dir, opt: o, snap: s, inos: map[string]uint64{}, next: 2, stop: make(chan struct{}), done: make(chan struct{})}
	rt.dirNode.root = rt
	rt.logShadowed(s)
	timeout := time.Hour
	if o.Refresh > 0 {
		timeout = min(o.Refresh, time.Second)
	}
	srv, err := fs.Mount(mountpoint, rt, &fs.Options{
		EntryTimeout: &timeout, AttrTimeout: &timeout, NegativeTimeout: &timeout,
		MountOptions: fuse.MountOptions{
			FsName: "stash:" + dir, Name: "stash", AllowOther: o.AllowOther, Debug: o.Debug,
			Options: []string{"ro", "default_permissions"}, DirectMount: true, MaxReadAhead: 1 << 20,
		},
	})
	if err != nil {
		s.release()
		return nil, err
	}
	sv := &Server{srv: srv, root: rt}
	if o.Refresh > 0 {
		go rt.refresher()
	} else {
		close(rt.done)
	}
	return sv, nil
}

// Unmount unmounts the file system and closes the snapshot once no file
// is open any more.
func (s *Server) Unmount() error {
	err := s.srv.Unmount()
	s.close()
	return err
}

// Wait blocks until the file system is unmounted (also from outside, by
// fusermount -u or umount).
func (s *Server) Wait() {
	s.srv.Wait()
	s.close()
}

func (s *Server) close() { s.closed.Do(s.doClose) }

func (s *Server) doClose() {
	close(s.root.stop)
	<-s.root.done
	s.root.mu.Lock()
	snap := s.root.snap
	s.root.snap = nil
	s.root.mu.Unlock()
	if snap != nil {
		snap.release()
	}
}

// Shadowed lists objects of the current snapshot hidden by a directory of
// the same name.
func (s *Server) Shadowed() []string {
	snap := s.root.current()
	if snap == nil {
		return nil
	}
	defer snap.release()
	return append([]string(nil), snap.shadowed...)
}

// Refresh opens a new snapshot now (a mount with Options.Refresh does
// this periodically).
func (s *Server) Refresh() error { return s.root.refresh() }

func (rt *root) logShadowed(s *snapshot) {
	if rt.opt.Log != nil && len(s.shadowed) > 0 {
		rt.opt.Log(fmt.Sprintf("%d objects are hidden by directories of the same name (e.g. %q); read them with stash get", len(s.shadowed), s.shadowed[0]))
	}
}

func (rt *root) refresher() {
	defer close(rt.done)
	t := time.NewTicker(rt.opt.Refresh)
	defer t.Stop()
	for {
		select {
		case <-rt.stop:
			return
		case <-t.C:
			if err := rt.refresh(); err != nil && rt.opt.Log != nil {
				rt.opt.Log("refresh: " + err.Error() + " (the previous snapshot stays mounted)")
			}
		}
	}
}

func (rt *root) refresh() error {
	r, err := stash.OpenReadOnlyWith(rt.archive, rt.opt.Read)
	if err != nil {
		return err
	}
	s, err := newSnapshot(r)
	if err != nil {
		r.Close()
		return err
	}
	rt.mu.Lock()
	old := rt.snap
	if old == nil { // unmounted meanwhile
		rt.mu.Unlock()
		s.release()
		return nil
	}
	rt.snap = s
	rt.mu.Unlock()
	rt.logShadowed(s)
	old.release()
	return nil
}

// current returns the current snapshot with a reference, or nil after
// unmount.
func (rt *root) current() *snapshot {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.snap == nil || !rt.snap.acquire() {
		return nil
	}
	return rt.snap
}

// ino returns the stable inode number of a directory or file path: the
// same path keeps its number across snapshots, distinct paths never share
// one.
func (rt *root) ino(dir bool, p string) uint64 {
	k := "f:" + p
	if dir {
		k = "d:" + p
	}
	rt.inoMu.Lock()
	defer rt.inoMu.Unlock()
	n, ok := rt.inos[k]
	if !ok {
		n = rt.next
		rt.next++
		rt.inos[k] = n
	}
	return n
}

// ---- directories

type dirNode struct {
	fs.Inode
	root *root
	path string
}

var (
	_ fs.NodeLookuper    = (*dirNode)(nil)
	_ fs.NodeReaddirer   = (*dirNode)(nil)
	_ fs.NodeGetattrer   = (*dirNode)(nil)
	_ fs.NodeStatfser    = (*dirNode)(nil)
	_ fs.NodeGetattrer   = (*fileNode)(nil)
	_ fs.NodeOpener      = (*fileNode)(nil)
	_ fs.NodeGetxattrer  = (*fileNode)(nil)
	_ fs.NodeListxattrer = (*fileNode)(nil)
	_ fs.FileReader      = (*handle)(nil)
	_ fs.FileReleaser    = (*handle)(nil)
)

func (d *dirNode) Getattr(ctx context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	s := d.root.current()
	if s == nil {
		return syscall.ENOENT
	}
	defer s.release()
	e := s.dirs[d.path]
	if e == nil {
		return syscall.ENOENT
	}
	dirAttr(&out.Attr, s, d.root.ino(true, d.path), len(e.names))
	return 0
}

func dirAttr(a *fuse.Attr, s *snapshot, ino uint64, n int) {
	a.Ino = ino
	a.Mode = fuse.S_IFDIR | 0o555
	a.Nlink = 2
	a.Size = uint64(n)
	setTimes(a, s)
}

func fileAttr(a *fuse.Attr, s *snapshot, ino uint64, in stash.Info) {
	a.Ino = ino
	a.Mode = fuse.S_IFREG | 0o444
	a.Nlink = 1
	a.Size = uint64(in.Size)
	a.Blocks = (a.Size + 511) / 512
	a.Blksize = 1 << 16
	setTimes(a, s)
}

// setTimes: objects carry no timestamps (SPEC §9); every entry shows the
// time its snapshot was opened.
func setTimes(a *fuse.Attr, s *snapshot) {
	t := s.at
	a.SetTimes(&t, &t, &t)
}

func (d *dirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	s := d.root.current()
	if s == nil {
		return nil, syscall.ENOENT
	}
	defer s.release()
	e := s.dirs[d.path]
	if e == nil {
		return nil, syscall.ENOENT
	}
	isDir, ok := e.isDir[name]
	if !ok {
		return nil, syscall.ENOENT
	}
	p := join(d.path, name)
	if isDir {
		ino := d.root.ino(true, p)
		dirAttr(&out.Attr, s, ino, len(s.dirs[p].names))
		return d.NewInode(ctx, &dirNode{root: d.root, path: p}, fs.StableAttr{Mode: fuse.S_IFDIR, Ino: ino}), 0
	}
	ino := d.root.ino(false, p)
	fileAttr(&out.Attr, s, ino, s.files[p])
	return d.NewInode(ctx, &fileNode{root: d.root, path: p}, fs.StableAttr{Mode: fuse.S_IFREG, Ino: ino}), 0
}

func (d *dirNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	s := d.root.current()
	if s == nil {
		return nil, syscall.ENOENT
	}
	defer s.release()
	e := s.dirs[d.path]
	if e == nil {
		return nil, syscall.ENOENT
	}
	out := make([]fuse.DirEntry, 0, len(e.names))
	for _, n := range e.names {
		mode := uint32(fuse.S_IFREG)
		if e.isDir[n] {
			mode = fuse.S_IFDIR
		}
		out = append(out, fuse.DirEntry{Name: n, Mode: mode, Ino: d.root.ino(e.isDir[n], join(d.path, n))})
	}
	return fs.NewListDirStream(out), 0
}

func (d *dirNode) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	s := d.root.current()
	if s == nil {
		return syscall.ENOENT
	}
	defer s.release()
	out.Bsize = 4096
	out.Frsize = 4096
	out.Blocks = uint64(s.bytes+4095) / 4096
	out.Files = uint64(len(s.files))
	out.NameLen = 255
	return 0
}

// ---- files

type fileNode struct {
	fs.Inode
	root *root
	path string
}

func (f *fileNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if h, ok := fh.(*handle); ok { // the version this handle reads
		fileAttr(&out.Attr, h.snap, f.root.ino(false, f.path), h.info)
		return 0
	}
	s := f.root.current()
	if s == nil {
		return syscall.ENOENT
	}
	defer s.release()
	in, ok := s.files[f.path]
	if !ok {
		return syscall.ENOENT
	}
	fileAttr(&out.Attr, s, f.root.ino(false, f.path), in)
	return 0
}

// handle is an open file: one object version of one snapshot.
type handle struct {
	snap *snapshot
	info stash.Info
	obj  *stash.Object
}

func (f *fileNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	if flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_TRUNC|syscall.O_APPEND) != 0 {
		return nil, 0, syscall.EROFS
	}
	s := f.root.current()
	if s == nil {
		return nil, 0, syscall.ENOENT
	}
	in, ok := s.files[f.path]
	if !ok {
		s.release()
		return nil, 0, syscall.ENOENT
	}
	o, err := s.r.OpenObject(f.path)
	if err != nil {
		s.release()
		return nil, 0, errno(err)
	}
	var fl uint32
	if f.root.opt.Refresh == 0 {
		fl = fuse.FOPEN_KEEP_CACHE // versions are immutable (SPEC §9.5)
	}
	return &handle{snap: s, info: in, obj: o}, fl, 0
}

func (h *handle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off >= h.info.Size {
		return fuse.ReadResultData(nil), 0
	}
	n, err := h.obj.ReadAt(dest, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errno(err)
	}
	return fuse.ReadResultData(dest[:n]), 0
}

func (h *handle) Release(ctx context.Context) syscall.Errno {
	h.obj.Close()
	h.snap.release()
	return 0
}

// errno maps archive errors: damaged or missing committed data is EIO.
func errno(err error) syscall.Errno {
	switch {
	case errors.Is(err, stash.ErrNotFound):
		return syscall.ENOENT
	default:
		return syscall.EIO
	}
}

// Extended attributes: user.stash.version is the object's file_ver,
// user.stash.extents its number of extents.
var xattrs = []string{"user.stash.version", "user.stash.extents"}

func (f *fileNode) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	s := f.root.current()
	if s == nil {
		return 0, syscall.ENOENT
	}
	defer s.release()
	in, ok := s.files[f.path]
	if !ok {
		return 0, syscall.ENOENT
	}
	var v string
	switch attr {
	case xattrs[0]:
		v = strconv.FormatUint(in.FileVer, 10)
	case xattrs[1]:
		v = strconv.Itoa(in.Extents)
	default:
		return 0, syscall.ENODATA
	}
	if len(dest) < len(v) {
		return uint32(len(v)), syscall.ERANGE
	}
	return uint32(copy(dest, v)), 0
}

func (f *fileNode) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	var b []byte
	for _, x := range xattrs {
		b = append(append(b, x...), 0)
	}
	if len(dest) < len(b) {
		return uint32(len(b)), syscall.ERANGE
	}
	return uint32(copy(dest, b)), 0
}
