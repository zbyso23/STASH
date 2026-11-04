package manifest

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sync"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// ErrPathBusy reports a second write to a path whose previous write has not
// committed or aborted yet (§10.2.1).
var ErrPathBusy = errors.New("path has an uncommitted version")

// ErrPoisoned reports a journal that saw a write or sync failure; reopen it
// (cold start aborts its open transactions).
var ErrPoisoned = errors.New("manifest writer failed earlier; reopen required")

// Journal appends records to manifest.jsonl of the current generation. It
// keeps the live state in step, so every record it writes is valid. All
// methods are safe for concurrent use; appends are serialized (one manifest
// commit stream, §10.1).
type Journal struct {
	mu       sync.Mutex
	f        vfs.File
	h        *wire.ArchiveHeader
	st       *State
	end      int64
	busy     map[string]TxID // paths with an open transaction
	nextSeq  func() (uint64, error)
	poisoned error
	buf      []byte
}

// OpenResult reports what OpenJournal found and did.
type OpenResult struct {
	Load LoadInfo
	// Aborted lists transactions closed by the cold-start ADD_ABORT records.
	Aborted []TxID
}

// OpenJournal opens the manifest of genDir for appending (creating an empty
// one if absent), loads the graph, truncates a torn tail and durably
// flushes the truncation (§10.4.2), and appends and flushes ADD_ABORT for
// every open transaction (cold start, §10.3.1).
func OpenJournal(fsys vfs.FS, genDir string, h *wire.ArchiveHeader, opt LoadOptions) (*Journal, *State, OpenResult, error) {
	var res OpenResult
	if h.Encrypted() {
		return nil, nil, res, &wire.Error{Struct: "Manifest", Class: wire.ErrUnsupported, Detail: "encrypted manifest writer needs the encryption layer"}
	}
	name := path.Join(genDir, ManifestName)
	if _, err := fsys.Stat(name); errors.Is(err, fs.ErrNotExist) {
		f, err := fsys.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return nil, nil, res, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, res, err
		}
		f.Close()
		if err := fsys.SyncDir(genDir); err != nil {
			return nil, nil, res, err
		}
	}
	opt.TrackRefs = true
	st, info, err := Load(fsys, genDir, h, opt)
	res.Load = info
	if err != nil {
		return nil, nil, res, err
	}
	f, err := fsys.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, res, err
	}
	if info.Torn > 0 {
		if err := f.Truncate(info.ValidEnd); err != nil {
			f.Close()
			return nil, nil, res, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, res, err
		}
	}
	if opt.BeforeAppend != nil {
		if err := opt.BeforeAppend(st); err != nil {
			f.Close()
			return nil, nil, res, err
		}
	}
	j := &Journal{f: f, h: h, st: st, end: info.ValidEnd, busy: map[string]TxID{}, nextSeq: opt.SeqSource}
	if open := st.OpenTransactions(); len(open) > 0 {
		for _, id := range open {
			if err := j.appendLocked(&Record{Op: OpAddAbort, TxID: id}); err != nil {
				f.Close()
				return nil, nil, res, err
			}
		}
		if err := j.Sync(); err != nil {
			f.Close()
			return nil, nil, res, err
		}
		res.Aborted = open
	}
	return j, st, res, nil
}

// State returns the live state. Callers must not mutate it, and must not
// read it concurrently with appends.
func (j *Journal) State() *State { return j.st }

// Close closes the file without syncing.
func (j *Journal) Close() error { return j.f.Close() }

// appendLocked assigns the next seq, applies r to the state (rejecting it
// if invalid) and writes its canonical line. Not durable until Sync.
func (j *Journal) appendLocked(r *Record) error {
	if j.poisoned != nil {
		return j.poisoned
	}
	if j.nextSeq != nil {
		v, err := j.nextSeq()
		if err != nil {
			return err
		}
		r.Seq = v // Apply rejects a value not above the last seq
	} else {
		r.Seq = j.st.LastSeq() + 1
	}
	b, err := AppendLine(j.buf[:0], r)
	if err != nil {
		return err
	}
	j.buf = b
	if err := j.st.Apply(r, 0); err != nil {
		return err // nothing written, state unchanged
	}
	if _, err := j.f.WriteAt(b, j.end); err != nil {
		j.poisoned = fmt.Errorf("%w: %v", ErrPoisoned, err)
		return err
	}
	j.end += int64(len(b))
	return nil
}

// Sync makes every appended record durable (§10.4: blobs referenced by the
// records must have been synced before they were appended).
func (j *Journal) Sync() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	if err := j.f.Sync(); err != nil {
		j.poisoned = fmt.Errorf("%w: %v", ErrPoisoned, err)
		return err
	}
	return nil
}

// End returns the current length of manifest.jsonl.
func (j *Journal) End() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.end
}

// Add commits a new version of path: one ADD record when the loc fits a
// line, otherwise an ADD_BEGIN / ADD_EXTENT... / ADD_COMMIT transaction with
// extents batched up to MAX_MANIFEST_LINE_BYTES (§10.3). The frames must
// already be durable.
func (j *Journal) Add(p string, fileVer uint64, loc []Loc) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, busy := j.busy[p]; busy {
		return fmt.Errorf("%w: %s", ErrPathBusy, p)
	}
	r := &Record{Op: OpAdd, Path: p, FileVer: fileVer, Loc: loc}
	// Measure with the widest seq so the line also fits once seq is set.
	if _, err := AppendLine(nil, &Record{Op: OpAdd, Seq: ^uint64(0), Path: p, FileVer: fileVer, Loc: loc}); err == nil {
		return j.appendLocked(r)
	}
	t, err := j.beginLocked(p, fileVer)
	if err != nil {
		return err
	}
	for rest := loc; len(rest) > 0; {
		n := extentsPerLine(rest)
		if err := j.extentLocked(t, rest[:n]); err != nil {
			j.abortLocked(t)
			return err
		}
		rest = rest[n:]
	}
	return j.commitLocked(t)
}

// Worst-case encoded sizes, so batching never produces an over-long line.
const (
	maxLocBytes       = len(`[254,"`) + 64 + len(`","18446744073709551615","18446744073709551615"],`)
	extentHeaderBytes = len(`{"seq":"18446744073709551615","op":"ADD_EXTENT","tx_id":"00000000000000000000000000000000","extent_sequence":4294967295,"loc":[]}`)
	maxExtentsPerLine = (MaxLineBytes - extentHeaderBytes) / maxLocBytes
)

func extentsPerLine(rest []Loc) int { return min(len(rest), maxExtentsPerLine) }

// Del commits removal of the current version fileVer of path.
func (j *Journal) Del(p string, fileVer uint64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if _, busy := j.busy[p]; busy {
		return fmt.Errorf("%w: %s", ErrPathBusy, p)
	}
	return j.appendLocked(&Record{Op: OpDel, Path: p, FileVer: fileVer})
}

// Tx is an open transaction for streaming writers that append extents as
// frames become durable.
type Tx struct {
	j     *Journal
	id    TxID
	path  string
	seq   uint32
	count uint64
	done  bool
}

// ID returns the transaction id.
func (t *Tx) ID() TxID { return t.id }

// Begin starts a transaction for a new version of path.
func (j *Journal) Begin(p string, fileVer uint64) (*Tx, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.beginLocked(p, fileVer)
}

func (j *Journal) beginLocked(p string, fileVer uint64) (*Tx, error) {
	if _, busy := j.busy[p]; busy {
		return nil, fmt.Errorf("%w: %s", ErrPathBusy, p)
	}
	var id TxID
	for {
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		if !j.st.IsTxKnown(id) {
			break
		}
	}
	if err := j.appendLocked(&Record{Op: OpAddBegin, TxID: id, Path: p, FileVer: fileVer}); err != nil {
		return nil, err
	}
	j.busy[p] = id
	return &Tx{j: j, id: id, path: p}, nil
}

// Extent appends one ADD_EXTENT record (split into several if loc does not
// fit one line).
func (t *Tx) Extent(loc []Loc) error {
	t.j.mu.Lock()
	defer t.j.mu.Unlock()
	for rest := loc; len(rest) > 0; {
		n := extentsPerLine(rest)
		if err := t.j.extentLocked(t, rest[:n]); err != nil {
			return err
		}
		rest = rest[n:]
	}
	return nil
}

func (j *Journal) extentLocked(t *Tx, loc []Loc) error {
	if t.done {
		return fmt.Errorf("%w: transaction %s already closed", wire.ErrInvalid, t.id)
	}
	if err := j.appendLocked(&Record{Op: OpAddExtent, TxID: t.id, ExtentSequence: t.seq, Loc: loc}); err != nil {
		return err
	}
	t.seq++
	t.count += uint64(len(loc))
	return nil
}

// Commit appends ADD_COMMIT. The version is durable after Journal.Sync.
func (t *Tx) Commit() error {
	t.j.mu.Lock()
	defer t.j.mu.Unlock()
	return t.j.commitLocked(t)
}

func (j *Journal) commitLocked(t *Tx) error {
	if t.done {
		return fmt.Errorf("%w: transaction %s already closed", wire.ErrInvalid, t.id)
	}
	if t.count > MaxTransactionExtents {
		return fmt.Errorf("%w: transaction too large", wire.ErrInvalid)
	}
	err := j.appendLocked(&Record{Op: OpAddCommit, TxID: t.id, ExtentRecordCount: t.seq, ExtentCount: uint32(t.count)})
	if err != nil {
		if j.poisoned == nil {
			// The commit was rejected (for example coverage); the writer
			// must close the transaction before reporting (§10.3.1).
			j.abortLocked(t)
		}
		return err
	}
	t.done = true
	delete(j.busy, t.path)
	return nil
}

// Abort appends ADD_ABORT (§10.3.1).
func (t *Tx) Abort() error {
	t.j.mu.Lock()
	defer t.j.mu.Unlock()
	return t.j.abortLocked(t)
}

func (j *Journal) abortLocked(t *Tx) error {
	if t.done {
		return nil
	}
	if err := j.appendLocked(&Record{Op: OpAddAbort, TxID: t.id}); err != nil {
		return err
	}
	t.done = true
	delete(j.busy, t.path)
	return nil
}
