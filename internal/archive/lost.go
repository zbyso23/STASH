package archive

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"

	"stash/internal/kvtab"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// UNRECOVERABLE markers. A version an Emergency Pruning gave up leaves
// the live state, but its path must not read as "never existed" or
// "deleted": tools that sync or replicate would spread the loss as a
// deletion. While a marker stands, Get, Stat and Open of a path with no
// live version fail with *UnrecoverableError, which matches
// ErrUnrecoverable and ErrMissingData but not ErrNotFound.
//
// A new Put shadows the marker (the live version wins); Delete of the
// path clears it for good. Markers live in two files per generation in
// HealthDir:
//
//	unrecoverable-<gen>.idx  "STUNREC2", generation, count (uint64 LE),
//	                          count records sorted by digest: digest[32]
//	                          file_ver[8] pruned_into[8] (LE), then
//	                          SHA-256 of all before; looked up by binary
//	                          search, nothing per marker held in memory
//	cleared-<gen>.log        appended by Delete: digest[32] crc32c[4]
//
// The digest is HMAC-SHA-256(path) under a key derived from the DEK in an
// encrypted archive (seal.InfoHealthMAC), SHA-256("STASH-UNRECOVERABLE" ||
// path) otherwise. Compaction folds both into the destination's index.
//
// Once a prune committed, every later generation has an index, empty when
// every loss was acknowledged: a missing index while a committed prune
// record exists fails the open (ErrCorrupt) instead of reading the losses
// as absences. Acknowledged digests are kept in a budgeted table that
// spills to scratch files, not in memory per entry.

// ErrUnrecoverable reports a path whose version an Emergency Pruning
// gave up (§13.9). It also matches ErrMissingData.
var ErrUnrecoverable = errors.New("version UNRECOVERABLE (given up by an emergency prune)")

// UnrecoverableError names the version given up and the generation the
// prune switched to (its record is health/prune-<PrunedInto>.jsonl).
type UnrecoverableError struct {
	Path       string
	FileVer    uint64
	PrunedInto uint64
}

func (e *UnrecoverableError) Error() string {
	return fmt.Sprintf("%s: version %d is UNRECOVERABLE: an emergency prune into generation %d gave it up (record %s; restore it from another copy, or delete the path to acknowledge)",
		e.Path, e.FileVer, e.PrunedInto, pruneName(e.PrunedInto, false))
}

func (e *UnrecoverableError) Is(target error) bool {
	return target == ErrUnrecoverable || target == ErrMissingData
}

var lostMagic = [8]byte{'S', 'T', 'U', 'N', 'R', 'E', 'C', '2'}

const (
	lostRec     = 48
	clearedRec  = 36
	lostHdrSize = 24
	clearedMem  = 256 << 10 // in-memory delta of the acknowledged set
)

// ErrMarkersMissing: a committed prune record exists but the generation's
// marker index does not; the losses cannot be told from absences.
var ErrMarkersMissing = fmt.Errorf("%w: UNRECOVERABLE marker index missing although an emergency prune committed", wire.ErrCorrupt)

func lostIndexName(gen uint64) string {
	return fmt.Sprintf("%s/unrecoverable-%016x.idx", HealthDir, gen)
}
func clearedName(gen uint64) string { return fmt.Sprintf("%s/cleared-%016x.log", HealthDir, gen) }

func pathDigest(k *seal.Keys, p string) [32]byte {
	if k != nil {
		return k.HealthMAC([]byte(p))
	}
	return sha256.Sum256(append([]byte("STASH-UNRECOVERABLE"), p...))
}

// lostSet is the marker set of one generation.
type lostSet struct {
	k   *seal.Keys
	gen uint64
	idx vfs.File // nil: no markers
	n   int64

	mu       sync.Mutex
	kv       kvtab.Config
	cleared  *kvtab.Table // acknowledged digests; nil: none
	nCleared int64
	clog     vfs.File // writer only
	clogEnd  int64
	// fsys and dirSynced: the log's name is made durable (a sync of
	// HealthDir) before the first acknowledgement of this open; a log
	// created by O_CREATE is not durable by its own Sync
	fsys      vfs.FS
	dirSynced bool
}

// openLostSet opens the markers of generation gen; a writer also opens
// the cleared log for appending (its torn tail truncated). kv configures
// the table of acknowledged digests.
func openLostSet(fsys vfs.FS, k *seal.Keys, gen uint64, writer bool, kv kvtab.Config) (*lostSet, error) {
	s := &lostSet{k: k, gen: gen, kv: kv, fsys: fsys}
	f, err := fsys.OpenFile(lostIndexName(gen), os.O_RDONLY, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// fail closed: after a committed prune every generation has one
		if to, ok, err := committedPruneUpTo(fsys, gen); err != nil {
			return nil, err
		} else if ok {
			return nil, fmt.Errorf("%w: %s (the prune into generation %d recorded losses; restore the file from a copy of the archive)",
				ErrMarkersMissing, lostIndexName(gen), to)
		}
	case err != nil:
		return nil, err
	default:
		s.idx = f
		if s.n, err = checkLostIndex(f, gen); err != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", lostIndexName(gen), err)
		}
	}
	if s.idx == nil {
		return s, nil // nothing to clear
	}
	flag := os.O_RDONLY
	if writer {
		flag = os.O_RDWR | os.O_CREATE
	}
	cf, err := fsys.OpenFile(clearedName(gen), flag, 0o644)
	if errors.Is(err, fs.ErrNotExist) && !writer {
		return s, nil
	}
	if err != nil {
		s.close()
		return nil, err
	}
	size, err := cf.Size()
	if err == nil {
		err = s.loadCleared(cf, size)
	}
	if err == nil && writer {
		if s.clogEnd < size {
			if err = cf.Truncate(s.clogEnd); err == nil {
				err = cf.Sync()
			}
		}
		s.clog = cf
	} else {
		cf.Close()
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// committedPruneUpTo reports a committed prune record into a generation
// up to gen (a prepared record into gen itself counts: a reader does not
// settle records, and the root names gen).
func committedPruneUpTo(fsys vfs.FS, gen uint64) (uint64, bool, error) {
	ents, err := fsys.ReadDir(HealthDir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	for _, e := range ents {
		to, prepared, ok := parsePruneName(e.Name())
		if ok && (to < gen && !prepared || to == gen) {
			return to, true, nil
		}
	}
	return 0, false, nil
}

func checkLostIndex(f vfs.File, gen uint64) (int64, error) {
	size, err := f.Size()
	if err != nil {
		return 0, err
	}
	var hdr [lostHdrSize]byte
	if size < lostHdrSize+32 {
		return 0, fmt.Errorf("%w: marker index truncated", wire.ErrCorrupt)
	}
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return 0, err
	}
	if string(hdr[:8]) == "STUNREC1" {
		// the pre-release format of M20b/M20c, never released
		return 0, fmt.Errorf("%w: marker index in the pre-release format STUNREC1 (M20b/M20c test builds), not supported; reprune from a copy made before the prune, or rebuild the index with that build", wire.ErrCorrupt)
	}
	if [8]byte(hdr[:8]) != lostMagic {
		return 0, fmt.Errorf("%w: marker index magic", wire.ErrCorrupt)
	}
	if g := binary.LittleEndian.Uint64(hdr[8:]); g != gen {
		return 0, fmt.Errorf("%w: marker index of generation %d, expected %d", wire.ErrCorrupt, g, gen)
	}
	n := int64(binary.LittleEndian.Uint64(hdr[16:]))
	if n < 0 || n > (size-lostHdrSize-32)/lostRec || size != lostHdrSize+n*lostRec+32 {
		return 0, fmt.Errorf("%w: marker index header", wire.ErrCorrupt)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, size-32)); err != nil {
		return 0, err
	}
	var sum [32]byte
	if _, err := f.ReadAt(sum[:], size-32); err != nil {
		return 0, err
	}
	if !bytes.Equal(h.Sum(nil), sum[:]) {
		return 0, fmt.Errorf("%w: marker index digest", wire.ErrCorrupt)
	}
	// sorted, no duplicates (checked while streaming)
	br := bufio.NewReaderSize(io.NewSectionReader(f, lostHdrSize, n*lostRec), 1<<16)
	var prev, rec [lostRec]byte
	for i := int64(0); i < n; i++ {
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			return 0, err
		}
		if i > 0 && bytes.Compare(prev[:32], rec[:32]) >= 0 {
			return 0, fmt.Errorf("%w: marker index not sorted", wire.ErrCorrupt)
		}
		prev = rec
	}
	return n, nil
}

func (s *lostSet) loadCleared(f vfs.File, size int64) error {
	br := bufio.NewReader(io.NewSectionReader(f, 0, size))
	var rec [clearedRec]byte
	off := int64(0)
	for {
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			break // a torn tail ends the log
		}
		if binary.LittleEndian.Uint32(rec[32:]) != wire.CRC32C(rec[:32]) {
			if off+clearedRec < size {
				return fmt.Errorf("%w: %s damaged at %d", wire.ErrCorrupt, clearedName(s.gen), off)
			}
			break // a torn last record
		}
		if err := s.ack([32]byte(rec[:32])); err != nil {
			return err
		}
		off += clearedRec
	}
	s.clogEnd = off
	return nil
}

// ack adds d to the acknowledged set (s.mu held, or s not yet shared).
func (s *lostSet) ack(d [32]byte) error {
	if s.cleared == nil {
		cfg := s.kv
		if cfg.MemLimit <= 0 || cfg.MemLimit > clearedMem {
			cfg.MemLimit = clearedMem
		}
		s.cleared = kvtab.New(cfg)
	}
	if _, ok, err := s.cleared.Get(d[:]); err != nil || ok {
		return err
	}
	if err := s.cleared.Put(d[:], nil); err != nil {
		return err
	}
	s.nCleared++
	return nil
}

func (s *lostSet) acked(d [32]byte) (bool, error) {
	s.mu.Lock()
	t := s.cleared
	s.mu.Unlock()
	if t == nil {
		return false, nil
	}
	_, ok, err := t.Get(d[:])
	return ok, err
}

func (s *lostSet) close() {
	if s == nil {
		return
	}
	if s.cleared != nil {
		s.cleared.Close()
	}
	if s.idx != nil {
		s.idx.Close()
	}
	if s.clog != nil {
		s.clog.Close()
	}
}

// find binary-searches the index for a digest.
func (s *lostSet) find(d [32]byte) (ver, gen uint64, ok bool, err error) {
	if s == nil || s.idx == nil {
		return 0, 0, false, nil
	}
	lo, hi := int64(0), s.n
	var rec [lostRec]byte
	for lo < hi {
		mid := (lo + hi) / 2
		if _, err := s.idx.ReadAt(rec[:], lostHdrSize+mid*lostRec); err != nil {
			return 0, 0, false, err
		}
		switch c := bytes.Compare(rec[:32], d[:]); {
		case c == 0:
			return binary.LittleEndian.Uint64(rec[32:]), binary.LittleEndian.Uint64(rec[40:]), true, nil
		case c < 0:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return 0, 0, false, nil
}

// lookup returns the standing marker of path p, if any.
func (s *lostSet) lookup(p string) (*UnrecoverableError, error) {
	if s == nil || s.idx == nil {
		return nil, nil
	}
	d := pathDigest(s.k, p)
	ver, gen, ok, err := s.find(d)
	if err != nil || !ok {
		return nil, err
	}
	if gone, err := s.acked(d); err != nil || gone {
		return nil, err
	}
	return &UnrecoverableError{Path: p, FileVer: ver, PrunedInto: gen}, nil
}

// clear durably removes the marker of p (Delete acknowledges the loss).
func (s *lostSet) clear(p string) error {
	d := pathDigest(s.k, p)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleared != nil {
		if _, ok, err := s.cleared.Get(d[:]); err != nil || ok {
			return err
		}
	}
	if s.clog == nil {
		return fmt.Errorf("%w: markers not writable", wire.ErrInvalid)
	}
	rec := binary.LittleEndian.AppendUint32(append([]byte(nil), d[:]...), wire.CRC32C(d[:]))
	// a failed acknowledgement takes its record back (best effort), so a
	// reopen does not find a Delete that reported an error
	undo := func(err error) error {
		s.clog.Truncate(s.clogEnd)
		s.clog.Sync()
		return err
	}
	if _, err := s.clog.WriteAt(rec, s.clogEnd); err != nil {
		return undo(err)
	}
	if err := s.clog.Sync(); err != nil {
		return undo(err)
	}
	if !s.dirSynced {
		if err := s.fsys.SyncDir(HealthDir); err != nil {
			return undo(err) // not acknowledged; a retry writes it again
		}
		s.dirSynced = true
	}
	s.clogEnd += clearedRec
	return s.ack(d)
}

// each streams the standing markers (digest order).
func (s *lostSet) each(fn func(d [32]byte, ver, gen uint64) error) error {
	if s == nil || s.idx == nil {
		return nil
	}
	br := bufio.NewReaderSize(io.NewSectionReader(s.idx, lostHdrSize, s.n*lostRec), 1<<16)
	var rec [lostRec]byte
	for i := int64(0); i < s.n; i++ {
		if _, err := io.ReadFull(br, rec[:]); err != nil {
			return err
		}
		d := [32]byte(rec[:32])
		if gone, err := s.acked(d); err != nil {
			return err
		} else if gone {
			continue
		}
		if err := fn(d, binary.LittleEndian.Uint64(rec[32:]), binary.LittleEndian.Uint64(rec[40:])); err != nil {
			return err
		}
	}
	return nil
}

// count is the number of standing markers.
func (s *lostSet) count() int64 {
	if s == nil || s.idx == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n - s.nCleared
}

// writeLostIndex writes the marker index of generation gen from sorted
// records produced by next (digest order, no duplicates).
func writeLostIndex(fsys vfs.FS, gen uint64, n int64, next func(yield func(d [32]byte, ver, g uint64) error) error) error {
	if err := fsys.MkdirAll(HealthDir, 0o755); err != nil {
		return err
	}
	return vfs.ReplaceFileStream(fsys, lostIndexName(gen), func(out io.Writer) error {
		h := sha256.New()
		w := io.MultiWriter(out, h)
		hdr := binary.LittleEndian.AppendUint64(append([]byte(nil), lostMagic[:]...), gen)
		hdr = binary.LittleEndian.AppendUint64(hdr, uint64(n))
		if _, err := w.Write(hdr); err != nil {
			return err
		}
		written := int64(0)
		rec := make([]byte, 0, lostRec)
		if err := next(func(d [32]byte, ver, g uint64) error {
			rec = append(rec[:0], d[:]...)
			rec = binary.LittleEndian.AppendUint64(rec, ver)
			rec = binary.LittleEndian.AppendUint64(rec, g)
			written++
			_, err := w.Write(rec)
			return err
		}); err != nil {
			return err
		}
		if written != n {
			return fmt.Errorf("marker index: %d records, expected %d", written, n)
		}
		_, err := out.Write(h.Sum(nil))
		return err
	})
}

// foldLost writes the destination's marker index: the source's standing
// markers (cleared ones dropped) and the versions this prune gave up that
// are still the live version at the freeze (one deleted or rewritten
// during the compaction is SUPERSEDED, not lost). Once a source has an
// index the destination has one too, empty if need be.
func (c *compactor) foldLost(to uint64) error {
	put := func(d [32]byte, ver, g uint64) error {
		v := binary.LittleEndian.AppendUint64(nil, ver)
		return c.tab.Put(append([]byte{'u'}, d[:]...), binary.LittleEndian.AppendUint64(v, g))
	}
	if err := c.src.lost.each(put); err != nil {
		return err
	}
	if c.prune != nil {
		if err := c.eachTag('z', func(key, _ []byte) error {
			rest := key[1:]
			i := bytes.IndexByte(rest, 0)
			if i < 0 || len(rest)-i-1 != 8 {
				return kvtab.ErrTampered
			}
			if _, sup, err := c.tab.Get(append([]byte{'w'}, rest...)); err != nil || sup {
				return err
			}
			return put(pathDigest(c.src.k, string(rest[:i])), binary.BigEndian.Uint64(rest[i+1:]), to)
		}); err != nil {
			return err
		}
	}
	var n int64
	if err := c.eachTag('u', func([]byte, []byte) error { n++; return nil }); err != nil {
		return err
	}
	if n == 0 && c.prune == nil && (c.src.lost == nil || c.src.lost.idx == nil) {
		return nil
	}
	if err := writeLostIndex(c.d.fsys, to, n, func(yield func(d [32]byte, ver, g uint64) error) error {
		return c.eachTag('u', func(k, v []byte) error {
			if len(k) != 33 || len(v) != 16 {
				return kvtab.ErrTampered
			}
			return yield([32]byte(k[1:]), binary.LittleEndian.Uint64(v), binary.LittleEndian.Uint64(v[8:]))
		})
	}); err != nil {
		return err
	}
	l, err := openLostSet(c.d.fsys, c.src.k, to, true, c.d.view.kv)
	if err != nil {
		return err
	}
	c.d.view.lost.close()
	c.d.view.lost = l
	return nil
}

// healthGen parses the generation of a per-generation health file
// (marker index, cleared log).
func healthGen(name string) (uint64, bool) {
	var g uint64
	for _, f := range []string{"unrecoverable-%016x.idx", "cleared-%016x.log"} {
		if n, err := fmt.Sscanf(name, f, &g); err == nil && n == 1 && name == fmt.Sprintf(f, g) {
			return g, true
		}
	}
	return 0, false
}

// unrecoverable streams the standing markers with their paths (from the
// prune records' details) whose path has no live version.
func (v *view) unrecoverable(live func(p string) (bool, error), fn func(UnrecoverableError) bool) error {
	if v.lost.count() == 0 {
		return nil
	}
	recs, _, err := v.PruneRecords()
	if err != nil {
		return err
	}
	stop := errors.New("stop")
	for _, rec := range recs {
		if !rec.Committed {
			continue
		}
		err := v.PruneDetails(rec.Record, func(d PruneDetail) error {
			if d.Kind != "object" {
				return nil
			}
			u, err := v.lost.lookup(d.Path)
			if err != nil || u == nil || u.FileVer != d.FileVer || u.PrunedInto != rec.To {
				return err
			}
			if ok, err := live(d.Path); err != nil || ok {
				return err
			}
			if !fn(*u) {
				return stop
			}
			return nil
		})
		if err == stop {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Unrecoverable streams the paths whose version an Emergency Pruning
// gave up and that were neither written nor deleted since, until fn
// returns false.
func (w *Writer) Unrecoverable(fn func(UnrecoverableError) bool) error {
	w.genMu.RLock()
	defer w.genMu.RUnlock()
	return w.view.unrecoverable(func(p string) (bool, error) {
		w.stateMu.RLock()
		defer w.stateMu.RUnlock()
		_, ok, err := w.journal.State().Lookup(p)
		return ok, err
	}, fn)
}

// Unrecoverable streams the UNRECOVERABLE paths of the snapshot.
func (r *Reader) Unrecoverable(fn func(UnrecoverableError) bool) error {
	return r.view.unrecoverable(func(p string) (bool, error) {
		_, ok, err := r.st.Lookup(p)
		return ok, err
	}, fn)
}
