package archive

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"stash/internal/vfs"
	"stash/internal/wire"
)

// PinDir holds reader pins (§13.1.1), implementation-defined state outside
// the normative names: one file per pin, named
// <16 hex generation_id>-<16 hex random>.pin, holding magic "STPIN\0\0\0",
// the expiry (uint64 Unix nanoseconds) and a CRC32C.
const PinDir = "pins"

// DefaultPinTTL is how long a pin lives without renewal.
const DefaultPinTTL = 10 * time.Minute

var pinMagic = [8]byte{'S', 'T', 'P', 'I', 'N'}

func encodePin(expiry time.Time) []byte {
	b := append([]byte{}, pinMagic[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(expiry.UnixNano()))
	return binary.LittleEndian.AppendUint32(b, wire.CRC32C(b))
}

// Pin keeps a generation from being removed by GC while a reader uses it.
type Pin struct {
	fsys vfs.FS
	name string
	ttl  time.Duration
	stop chan struct{}
	wg   sync.WaitGroup
	mu   sync.Mutex
	err  error
}

// MinPinTTL is the shortest pin lifetime: pins are renewed every third of
// it, which must stay a usable, non-zero period.
const MinPinTTL = 3 * time.Second

func pinGeneration(fsys vfs.FS, gen uint64, ttl time.Duration) (*Pin, error) {
	if ttl == 0 {
		ttl = DefaultPinTTL
	}
	if ttl < MinPinTTL {
		return nil, fmt.Errorf("%w: pin TTL %v below the minimum %v", wire.ErrInvalid, ttl, MinPinTTL)
	}
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	if err := fsys.MkdirAll(PinDir, 0o755); err != nil {
		return nil, err
	}
	p := &Pin{fsys: fsys, name: path.Join(PinDir, fmt.Sprintf("%016X-%s.pin", gen, hex.EncodeToString(r[:]))), ttl: ttl, stop: make(chan struct{})}
	if err := vfs.ReplaceFile(fsys, p.name, encodePin(time.Now().Add(ttl))); err != nil {
		return nil, err
	}
	p.wg.Add(1)
	go p.renew(p.stop)
	return p, nil
}

func (p *Pin) renew(stop <-chan struct{}) {
	defer p.wg.Done()
	t := time.NewTicker(p.ttl / 3)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := vfs.ReplaceFile(p.fsys, p.name, encodePin(time.Now().Add(p.ttl))); err != nil {
				p.mu.Lock()
				p.err = err
				p.mu.Unlock()
			}
		}
	}
}

// Err reports a failed renewal (the pin may then expire).
func (p *Pin) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Release removes the pin.
func (p *Pin) Release() error {
	if p == nil || p.stop == nil {
		return nil
	}
	close(p.stop)
	p.stop = nil
	p.wg.Wait()
	err := p.fsys.Remove(p.name)
	p.fsys.SyncDir(PinDir)
	return err
}

// pinnedGenerations returns the generations with an unexpired pin. A pin
// file that does not decode counts as a pin that never expires: GC must not
// delete what it cannot rule out. Only a missing pin directory or a pin
// removed meanwhile means "no pin"; any other error reading them stops GC
// (§13.1.1: when in doubt, keep the old generation).
func pinnedGenerations(fsys vfs.FS, now time.Time) (map[uint64]bool, error) {
	out := map[uint64]bool{}
	ents, err := fsys.ReadDir(PinDir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil // no pins
	}
	if err != nil {
		return nil, fmt.Errorf("reading reader pins: %w (GC stopped)", err)
	}
	for _, e := range ents {
		n := e.Name()
		if !strings.HasSuffix(n, ".pin") || len(n) < 17 {
			continue
		}
		gen, err := strconv.ParseUint(n[:16], 16, 64)
		if err != nil || n[16] != '-' {
			continue
		}
		b, err := vfs.ReadFile(fsys, path.Join(PinDir, n), 64)
		if errors.Is(err, fs.ErrNotExist) {
			continue // released meanwhile
		}
		if err != nil {
			return nil, fmt.Errorf("reading reader pin %s: %w (GC stopped)", n, err)
		}
		if len(b) == 20 && [8]byte(b[:8]) == pinMagic && binary.LittleEndian.Uint32(b[16:]) == wire.CRC32C(b[:16]) &&
			int64(binary.LittleEndian.Uint64(b[8:])) < now.UnixNano() {
			continue // expired
		}
		out[gen] = true
	}
	return out, nil
}

// GC removes every generation other than the current one that no reader
// pin and no open Object of this writer still uses (§13, §13.1.1):
// generations replaced by compaction and aborted compaction attempts.
func (w *Writer) GC() ([]uint64, error) {
	w.compactMu.Lock()
	defer w.compactMu.Unlock()
	return w.gcLocked()
}

func (w *Writer) gcLocked() ([]uint64, error) {
	if w.hard.failed != nil {
		return nil, w.hard.failed // the anchor may name another generation
	}
	root, err := readRoot(w.fsys)
	if err != nil {
		return nil, err
	}
	gens, err := generations(w.fsys)
	if err != nil {
		return nil, err
	}
	pinned, err := pinnedGenerations(w.fsys, time.Now())
	if err != nil {
		return nil, err
	}
	w.retiredMu.Lock()
	inUse := map[uint64]bool{}
	var keep []*view
	for _, v := range w.retired {
		if v.inUse() {
			inUse[v.h.GenerationID] = true
			keep = append(keep, v)
		}
	}
	w.retired = keep
	w.retiredMu.Unlock()
	var removed []uint64
	for _, g := range gens {
		if g == root.GenerationID || pinned[g] || inUse[g] {
			continue
		}
		if err := vfs.RemoveAll(w.fsys, GenDir(g)); err != nil {
			return removed, err
		}
		removed = append(removed, g)
	}
	return removed, nil
}
