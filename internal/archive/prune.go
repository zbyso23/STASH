package archive

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"stash/internal/kvtab"
	"stash/internal/seal"
	"stash/internal/vfs"
	"stash/internal/wire"
)

// Emergency Pruning (§13.9) is an operator-authorized compaction of a
// GC-blocked generation: committed extents that cannot be found or
// rebuilt are given up, the versions holding them are left out of the
// destination, and a durable EMERGENCY_PRUNE record in HealthDir says
// what was lost before the old generation may be deleted.
//
// The record format is implementation-defined (§13.9), like the policy
// marker and key.check: one JSON object per line,
//
//	{"stash_health":1,"event":"EMERGENCY_PRUNE",...counts...}   header
//	{"kind":"event","operator":...,"reason":...,"time":...}     summary
//	{"kind":"extent",...} {"kind":"object",...} {"kind":"group",...}
//	{"end":{"lines":N,"sha256":"..."}}                          trailer
//
// In an encrypted archive every line between header and trailer is
// sealed ({"sealed":"<hex nonce||ciphertext||tag>"}) with a key derived
// from the DEK (seal.InfoHealth), because it names paths. The trailer's
// digest covers every byte before it.
//
// A record is written as prune-<to>.prepared.jsonl before the switch and
// renamed to prune-<to>.jsonl after it; an open settles a prepared record
// by the root: to == root.current means the switch happened (committed),
// to > root.current means the compaction was aborted (removed).

// HealthDir holds the implementation's health records.
const HealthDir = "health"

// ErrPruneRefused reports an Emergency Pruning that was not authorized as
// required, or whose losses differ from what the operator confirmed; the
// archive is left unchanged.
var ErrPruneRefused = errors.New("emergency prune refused")

// EmergencyPrune authorizes Compact to drop what cannot be found or
// rebuilt (§13.9). It is a data-loss escape hatch for a generation that is
// permanently GC-blocked, never for a resource that is only temporarily
// unreachable: ExpectLostExtents must equal the number of extents the
// failing compaction reported, so a different outcome (a resource that
// came back, or more damage) refuses the prune.
type EmergencyPrune struct {
	Operator, Reason  string
	ExpectLostExtents int
	// Time is recorded as the event time (zero: now).
	Time time.Time
}

// PruneReport describes what an Emergency Pruning gave up.
type PruneReport struct {
	// Record is the health record's name (below the archive root).
	Record string
	// LostExtents committed extents could not be found or rebuilt (the
	// count the operator confirms); the LostVersions holding them are
	// UNRECOVERABLE and not in the destination. SupersededVersions held
	// lost extents too, but were deleted or rewritten while the compaction
	// ran: nothing of the live state is lost and no marker stands.
	LostExtents, LostVersions, SupersededVersions int
	// UnrecoverableGroups lost data members parity could not rebuild;
	// their surviving live members (RegroupedMembers) were rewritten into
	// new, fully protected groups. RebuiltGroups lost members that were
	// rebuilt from parity (DEGRADED in the source, HEALTHY again).
	UnrecoverableGroups, RebuiltGroups, RegroupedMembers int
	// UnavailableBlobs could not be opened in the source generation.
	UnavailableBlobs []uint8
}

// PruneRecord is an EMERGENCY_PRUNE record read back.
type PruneRecord struct {
	PruneReport
	From, To         uint64
	Time             time.Time
	Operator, Reason string
	// Committed: the switch to To happened. A record of an aborted prune
	// is never committed.
	Committed bool
	// Sealed: the archive is encrypted and the record was read without
	// its DEK; only the counts are known.
	Sealed bool
}

// PruneDetail is one detail line of a record.
type PruneDetail struct {
	Kind     string `json:"kind"` // "extent", "object" or "group"
	Path     string `json:"path,omitempty"`
	FileVer  uint64 `json:"file_ver,omitempty"`
	Offset   uint64 `json:"offset,omitempty"`
	Blob     uint8  `json:"blob,omitempty"`
	Hash     string `json:"hash,omitempty"`
	Status   string `json:"status,omitempty"` // UNRECOVERABLE, SUPERSEDED, DEGRADED
	GroupID  uint32 `json:"group_id,omitempty"`
	K        int    `json:"k,omitempty"`
	M        int    `json:"m,omitempty"`
	Present  int    `json:"present,omitempty"`
	HeldLive bool   `json:"held_live,omitempty"`
	// Regrouped surviving live members (UNRECOVERABLE groups), or "REBUILT"
	// in Dest for a DEGRADED group repaired from parity.
	Regrouped int    `json:"regrouped,omitempty"`
	Dest      string `json:"dest,omitempty"`
}

type pruneHeader struct {
	Version             int     `json:"stash_health"`
	Event               string  `json:"event"`
	From                uint64  `json:"from_generation"`
	To                  uint64  `json:"to_generation"`
	Encrypted           bool    `json:"encrypted"`
	LostExtents         int     `json:"lost_extents"`
	LostVersions        int     `json:"lost_versions"`
	SupersededVersions  int     `json:"superseded_versions,omitempty"`
	UnrecoverableGroups int     `json:"unrecoverable_groups"`
	RebuiltGroups       int     `json:"rebuilt_groups"`
	RegroupedMembers    int     `json:"regrouped_members"`
	UnavailableBlobs    []uint8 `json:"unavailable_blobs,omitempty"`
}

type pruneEvent struct {
	Kind     string `json:"kind"`
	Operator string `json:"operator"`
	Reason   string `json:"reason"`
	Time     string `json:"time"`
}

type pruneEnd struct {
	End *struct {
		Lines  int    `json:"lines"`
		SHA256 string `json:"sha256"`
	} `json:"end"`
	Sealed string `json:"sealed"`
}

func pruneName(to uint64, prepared bool) string {
	if prepared {
		return fmt.Sprintf("%s/prune-%016x.prepared.jsonl", HealthDir, to)
	}
	return fmt.Sprintf("%s/prune-%016x.jsonl", HealthDir, to)
}

// parsePruneName returns the target generation of a record name (base
// name inside HealthDir).
func parsePruneName(name string) (to uint64, prepared, ok bool) {
	rest, found := strings.CutPrefix(name, "prune-")
	if !found {
		return 0, false, false
	}
	if r, p := strings.CutSuffix(rest, ".prepared.jsonl"); p {
		rest, prepared = r, true
	} else if r, f := strings.CutSuffix(rest, ".jsonl"); f {
		rest = r
	} else {
		return 0, false, false
	}
	if len(rest) != 16 {
		return 0, false, false
	}
	b, err := hex.DecodeString(rest)
	if err != nil {
		return 0, false, false
	}
	return binary.BigEndian.Uint64(b), prepared, true
}

func healthAAD(archiveID [32]byte, to uint64, line int) []byte {
	b := append([]byte("STASH-HEALTH"), archiveID[:]...)
	b = binary.BigEndian.AppendUint64(b, to)
	return binary.BigEndian.AppendUint64(b, uint64(line))
}

// MaxPruneText bounds EmergencyPrune.Operator and Reason (bytes), so the
// record's event line stays well below the 1 MiB line limit of a reader.
const MaxPruneText = 4096

// maxHealthLine is the longest record line a reader accepts.
const maxHealthLine = 1 << 20

func (p *EmergencyPrune) check() error {
	if strings.TrimSpace(p.Operator) == "" || strings.TrimSpace(p.Reason) == "" {
		return fmt.Errorf("%w: an operator and a reason are required (§13.9)", ErrPruneRefused)
	}
	if len(p.Operator) > MaxPruneText || len(p.Reason) > MaxPruneText {
		return fmt.Errorf("%w: operator and reason are limited to %d bytes each", ErrPruneRefused, MaxPruneText)
	}
	if p.ExpectLostExtents <= 0 {
		return fmt.Errorf("%w: ExpectLostExtents must be the count of extents the failing compaction reported", ErrPruneRefused)
	}
	return nil
}

// ---- the compactor side

func lostVerKey(p string, ver uint64) []byte {
	k := append([]byte{'z'}, p...)
	k = append(k, 0)
	return binary.BigEndian.AppendUint64(k, ver)
}

// lost reports whether a version was given up by the prune.
func (c *compactor) lost(p string, ver uint64) (bool, error) {
	if c.prune == nil {
		return false, nil
	}
	return c.has(lostVerKey(p, ver))
}

// markLost moves the wanted extents nothing could provide ('L') to the
// lost set: 'Z' + the extent, 'z' + its version.
func (c *compactor) markLost() error {
	var keys [][]byte
	for {
		it := c.tab.Iter([]byte{'L'})
		for it.Next() && it.Key()[0] == 'L' && len(keys) < 4096 {
			keys = append(keys, bytes.Clone(it.Key()))
		}
		err := it.Err()
		it.Close()
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}
		for _, k := range keys {
			lk, ok := parseLiveKey(k)
			if !ok {
				return kvtab.ErrTampered
			}
			z := append([]byte{'Z'}, k[1:]...)
			if err := c.tab.Put(z, nil); err != nil {
				return err
			}
			if err := c.tab.Put(lostVerKey(lk.k.Path, lk.k.FileVer), nil); err != nil {
				return err
			}
			if err := c.tab.Delete(k); err != nil {
				return err
			}
		}
		keys = keys[:0]
	}
}

// group statuses in 'G' values
const (
	groupUnrecoverable = 'U'
	groupRebuilt       = 'R'
)

// noteGroup records a group's parity impact ('G' gid → status, k, m,
// present, held live, regrouped members).
func (c *compactor) noteGroup(g uint32, status byte, k, m, present int, heldLive bool, regrouped int) error {
	v := []byte{status, byte(k), byte(m), byte(present), 0}
	if heldLive {
		v[4] = 1
	}
	v = binary.BigEndian.AppendUint32(v, uint32(regrouped))
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tab.Put(binary.BigEndian.AppendUint32([]byte{'G'}, g), v)
}

func (c *compactor) eachTag(tag byte, fn func(k, v []byte) error) error {
	it := c.tab.Iter([]byte{tag})
	defer it.Close()
	for it.Next() {
		if it.Key()[0] != tag {
			break
		}
		if err := fn(it.Key(), it.Value()); err != nil {
			return err
		}
	}
	return it.Err()
}

// settleLost runs at the freeze, against the source's final state: a lost
// version that is no longer the live version of its path (deleted, or
// rewritten, while the compaction ran) is SUPERSEDED ('w'); it gets no
// UNRECOVERABLE marker, because the writer's state already moved past it.
func (c *compactor) settleLost(live func(p string) (uint64, bool, error)) error {
	return c.eachTag('z', func(key, _ []byte) error {
		rest := key[1:]
		i := bytes.IndexByte(rest, 0)
		if i < 0 || len(rest)-i-1 != 8 {
			return kvtab.ErrTampered
		}
		ver, ok, err := live(string(rest[:i]))
		if err != nil {
			return err
		}
		if ok && ver == binary.BigEndian.Uint64(rest[i+1:]) {
			return nil
		}
		return c.tab.Put(append([]byte{'w'}, rest...), nil)
	})
}

// pruneReport counts the lost set and the group impact.
func (c *compactor) pruneReport() (PruneReport, error) {
	var r PruneReport
	if err := c.eachTag('Z', func([]byte, []byte) error { r.LostExtents++; return nil }); err != nil {
		return r, err
	}
	if err := c.eachTag('z', func([]byte, []byte) error { r.LostVersions++; return nil }); err != nil {
		return r, err
	}
	if err := c.eachTag('w', func([]byte, []byte) error { r.SupersededVersions++; return nil }); err != nil {
		return r, err
	}
	r.LostVersions -= r.SupersededVersions
	if err := c.eachTag('G', func(k, v []byte) error {
		if len(k) != 5 || len(v) != 9 {
			return kvtab.ErrTampered
		}
		switch v[0] {
		case groupUnrecoverable:
			r.UnrecoverableGroups++
			r.RegroupedMembers += int(binary.BigEndian.Uint32(v[5:]))
		case groupRebuilt:
			r.RebuiltGroups++
		}
		return nil
	}); err != nil {
		return r, err
	}
	for b, bv := range c.src.blobs {
		if bv == nil {
			r.UnavailableBlobs = append(r.UnavailableBlobs, uint8(b))
		}
	}
	return r, nil
}

// writePruneRecord durably writes the prepared EMERGENCY_PRUNE record
// (§13.9 steps 1-4) with bounded memory.
func (c *compactor) writePruneRecord(fsys vfs.FS, r *PruneReport, from, to uint64) error {
	h := c.src.h
	k := c.src.k
	if err := fsys.MkdirAll(HealthDir, 0o755); err != nil {
		return err
	}
	if err := fsys.SyncDir("."); err != nil {
		return err
	}
	return vfs.ReplaceFileStream(fsys, pruneName(to, true), func(out io.Writer) error {
		sum := sha256.New()
		w := io.MultiWriter(out, sum)
		lines := 0
		emit := func(v any, sealIt bool) error {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			if sealIt && k != nil {
				var nonce [12]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					return err
				}
				st := k.Seal(seal.HealthDomain, nil, nonce, b, healthAAD(h.ArchiveID, to, lines))
				b, _ = json.Marshal(map[string]string{"sealed": hex.EncodeToString(st)})
			}
			if len(b)+1 > maxHealthLine {
				// before the switch: a record a reader refuses is never written
				return fmt.Errorf("%w: a health record line would be %d bytes, over the %d a reader accepts", ErrPruneRefused, len(b)+1, maxHealthLine)
			}
			lines++
			_, err = w.Write(append(b, '\n'))
			return err
		}
		if err := emit(pruneHeader{Version: 1, Event: "EMERGENCY_PRUNE", From: from, To: to, Encrypted: k != nil,
			LostExtents: r.LostExtents, LostVersions: r.LostVersions, SupersededVersions: r.SupersededVersions, UnrecoverableGroups: r.UnrecoverableGroups,
			RebuiltGroups: r.RebuiltGroups, RegroupedMembers: r.RegroupedMembers, UnavailableBlobs: r.UnavailableBlobs}, false); err != nil {
			return err
		}
		t := c.prune.Time
		if t.IsZero() {
			t = time.Now()
		}
		if err := emit(pruneEvent{Kind: "event", Operator: c.prune.Operator, Reason: c.prune.Reason, Time: t.UTC().Format(time.RFC3339Nano)}, true); err != nil {
			return err
		}
		if err := c.eachTag('Z', func(key, _ []byte) error {
			lk, ok := parseLiveKey(append([]byte{'L'}, key[1:]...))
			if !ok {
				return kvtab.ErrTampered
			}
			return emit(PruneDetail{Kind: "extent", Path: lk.k.Path, FileVer: lk.k.FileVer, Offset: lk.k.Offset, Blob: lk.blob,
				Hash: hex.EncodeToString(lk.k.Hash[:])}, true)
		}); err != nil {
			return err
		}
		if err := c.eachTag('z', func(key, _ []byte) error {
			rest := key[1:]
			i := bytes.IndexByte(rest, 0)
			if i < 0 || len(rest)-i-1 != 8 {
				return kvtab.ErrTampered
			}
			st := "UNRECOVERABLE"
			if _, sup, err := c.tab.Get(append([]byte{'w'}, rest...)); err != nil {
				return err
			} else if sup {
				st = "SUPERSEDED"
			}
			return emit(PruneDetail{Kind: "object", Path: string(rest[:i]), FileVer: binary.BigEndian.Uint64(rest[i+1:]), Status: st}, true)
		}); err != nil {
			return err
		}
		if err := c.eachTag('G', func(key, v []byte) error {
			d := PruneDetail{Kind: "group", GroupID: binary.BigEndian.Uint32(key[1:]), K: int(v[1]), M: int(v[2]), Present: int(v[3]), HeldLive: v[4] == 1}
			if v[0] == groupUnrecoverable {
				d.Status, d.Regrouped, d.Dest = "UNRECOVERABLE", int(binary.BigEndian.Uint32(v[5:])), "REGROUPED"
			} else {
				d.Status, d.Dest = "DEGRADED", "REBUILT"
			}
			return emit(d, true)
		}); err != nil {
			return err
		}
		b, _ := json.Marshal(map[string]any{"end": map[string]any{"lines": lines, "sha256": hex.EncodeToString(sum.Sum(nil))}})
		_, err := out.Write(append(b, '\n'))
		return err
	})
}

// ---- settling and reading

// settlePrunes commits prepared records whose switch happened (to ==
// root) and removes those of aborted compactions (to > root). It returns
// the committed records and the names in HealthDir this implementation
// does not know.
func settlePrunes(fsys vfs.FS, root uint64) (committed int, foreign []string, err error) {
	ents, err := fsys.ReadDir(HealthDir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	changed := false
	for _, e := range ents {
		n := e.Name()
		to, prepared, ok := parsePruneName(n)
		if g, hg := healthGen(n); hg {
			// markers of an aborted compaction (g > root) or of a removed
			// generation go; GC removes them with their generation
			if _, err := fsys.Stat(GenDir(g)); g > root || (g < root && errors.Is(err, fs.ErrNotExist)) {
				if err := fsys.Remove(HealthDir + "/" + n); err != nil {
					return committed, foreign, err
				}
				changed = true
			}
			continue
		}
		switch {
		case !ok && strings.Contains(n, ".tmp-"):
			fsys.Remove(HealthDir + "/" + n) // an interrupted replacement
			changed = true
		case !ok:
			foreign = append(foreign, n)
		case !prepared:
			committed++
		case to == root:
			if err := fsys.Rename(pruneName(to, true), pruneName(to, false)); err != nil {
				return committed, foreign, err
			}
			committed++
			changed = true
		case to > root:
			if err := fsys.Remove(pruneName(to, true)); err != nil {
				return committed, foreign, err
			}
			changed = true
		default:
			// to < root with the record still prepared: only possible if
			// the storage was changed behind the writer; kept as is
			foreign = append(foreign, n)
		}
	}
	if changed {
		err = fsys.SyncDir(HealthDir)
	}
	return committed, foreign, err
}

// readPruneFile streams a record: the header, then every line between
// header and trailer (opened when sealed and k is given), after checking
// the trailer's line count and digest.
func readPruneFile(fsys vfs.FS, k *seal.Keys, archiveID [32]byte, name string, fn func(line int, b []byte, sealed bool) error) (pruneHeader, error) {
	var h pruneHeader
	f, err := fsys.OpenFile(name, 0, 0)
	if err != nil {
		return h, err
	}
	defer f.Close()
	size, err := f.Size()
	if err != nil {
		return h, err
	}
	// the trailer is checked first, so nothing unverified is reported
	sum := sha256.New()
	br := bufio.NewReaderSize(io.NewSectionReader(f, 0, size), 1<<16)
	var last []byte
	lines := 0
	for {
		b, err := readLine(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return h, err
		}
		if last != nil {
			sum.Write(last)
			lines++
		}
		last = b
	}
	var end pruneEnd
	if last == nil || json.Unmarshal(last, &end) != nil || end.End == nil || end.End.Lines != lines ||
		end.End.SHA256 != hex.EncodeToString(sum.Sum(nil)) {
		return h, fmt.Errorf("%w: health record %s is damaged", wire.ErrCorrupt, name)
	}
	br.Reset(io.NewSectionReader(f, 0, size))
	for i := 0; i < lines; i++ {
		b, err := readLine(br)
		if err != nil {
			return h, err
		}
		b = bytes.TrimSuffix(b, []byte{'\n'})
		if i == 0 {
			if err := json.Unmarshal(b, &h); err != nil || h.Version != 1 || h.Event != "EMERGENCY_PRUNE" {
				return h, fmt.Errorf("%w: health record %s: unknown header", wire.ErrCorrupt, name)
			}
			continue
		}
		sealed := false
		if h.Encrypted {
			var s pruneEnd
			st, err := hex.DecodeString(func() string { json.Unmarshal(b, &s); return s.Sealed }())
			if err != nil || s.Sealed == "" {
				return h, fmt.Errorf("%w: health record %s line %d not sealed", wire.ErrCorrupt, name, i)
			}
			if k == nil {
				b, sealed = nil, true
			} else if b, err = k.Open(seal.HealthDomain, nil, st, healthAAD(archiveID, h.To, i)); err != nil {
				return h, fmt.Errorf("health record %s line %d: %w", name, i, err)
			}
		}
		if err := fn(i, b, sealed); err != nil {
			return h, err
		}
	}
	return h, nil
}

func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		b, err := br.ReadSlice('\n')
		out = append(out, b...)
		if len(out) > maxHealthLine {
			return nil, fmt.Errorf("%w: health record line over 1 MiB", wire.ErrCorrupt)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(out) > 0 {
			return nil, fmt.Errorf("%w: health record without a final newline", wire.ErrCorrupt)
		}
		return out, err
	}
}

// PruneRecords lists the EMERGENCY_PRUNE records of the archive (oldest
// first) and the HealthDir entries this implementation does not know:
// another implementation's health metadata, whose parity protection state
// must be treated as unknown (§13.9).
func (v *view) PruneRecords() ([]PruneRecord, []string, error) {
	ents, err := v.fsys.ReadDir(HealthDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	root := v.h.GenerationID
	var out []PruneRecord
	var foreign []string
	for _, e := range ents {
		to, prepared, ok := parsePruneName(e.Name())
		if _, hg := healthGen(e.Name()); hg {
			continue
		}
		if !ok {
			if !strings.Contains(e.Name(), ".tmp-") {
				foreign = append(foreign, e.Name())
			}
			continue
		}
		if prepared && to > root {
			continue // an aborted prune, removed by the next writer
		}
		rec := PruneRecord{Committed: !prepared || to == root}
		h, err := readPruneFile(v.fsys, v.k, v.h.ArchiveID, HealthDir+"/"+e.Name(), func(i int, b []byte, sealed bool) error {
			if i != 1 {
				return nil
			}
			if sealed {
				rec.Sealed = true
				return nil
			}
			var ev pruneEvent
			if err := json.Unmarshal(b, &ev); err != nil || ev.Kind != "event" {
				return fmt.Errorf("%w: health record %s: bad event line", wire.ErrCorrupt, e.Name())
			}
			rec.Operator, rec.Reason = ev.Operator, ev.Reason
			rec.Time, _ = time.Parse(time.RFC3339Nano, ev.Time)
			return nil
		})
		if err != nil {
			return out, foreign, err
		}
		if h.To != to {
			return out, foreign, fmt.Errorf("%w: health record %s names generation %d", wire.ErrCorrupt, e.Name(), h.To)
		}
		rec.From, rec.To = h.From, h.To
		rec.Record = HealthDir + "/" + e.Name()
		rec.LostExtents, rec.LostVersions, rec.SupersededVersions = h.LostExtents, h.LostVersions, h.SupersededVersions
		rec.UnrecoverableGroups, rec.RebuiltGroups, rec.RegroupedMembers = h.UnrecoverableGroups, h.RebuiltGroups, h.RegroupedMembers
		rec.UnavailableBlobs = h.UnavailableBlobs
		out = append(out, rec)
	}
	return out, foreign, nil
}

// PruneDetails streams the detail lines of a record named by
// PruneRecord.Record. An encrypted archive's details need its DEK.
func (v *view) PruneDetails(record string, fn func(PruneDetail) error) error {
	if _, _, ok := parsePruneName(strings.TrimPrefix(record, HealthDir+"/")); !ok || !strings.HasPrefix(record, HealthDir+"/") {
		return fmt.Errorf("%w: %q is not a health record", wire.ErrInvalid, record)
	}
	_, err := readPruneFile(v.fsys, v.k, v.h.ArchiveID, record, func(i int, b []byte, sealed bool) error {
		if i == 1 {
			return nil
		}
		if sealed {
			return ErrKeyRequired
		}
		var d PruneDetail
		if err := json.Unmarshal(b, &d); err != nil {
			return fmt.Errorf("%w: %s line %d: %v", wire.ErrCorrupt, record, i, err)
		}
		return fn(d)
	})
	return err
}
