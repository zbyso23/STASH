package archive

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"testing"

	"stash/internal/alloc"
	"stash/internal/blob"
	"stash/internal/index"
	"stash/internal/vfs"
	"stash/internal/wire"
)

func parityCfg(s wire.ParityScheme, k, m, blobs uint8, mode wire.FrameSizeMode) Config {
	c := Config{Mode: mode, HashID: wire.HashSHA256, BlobCount: blobs, MaxFrameQuanta: 4,
		ParityScheme: s, ParityK: k, ParityM: m}
	if mode == wire.ModeVariable {
		c.MaxFrameQuanta = 16
	}
	return c
}

// groupsOf hops every blob and returns the parity groups by frame-local
// metadata (§7.4), as raw recovery sees them.
func groupsOf(t testing.TB, fsys vfs.FS) (map[uint32][]*hopMember, *wire.ArchiveHeader) {
	t.Helper()
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	d := r.dir()
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := r.refresh(d); err != nil {
		t.Fatal(err)
	}
	return d.groups, r.h
}

func blobFile(b int) string { n, _ := blob.Name(uint8(b)); return path.Join(GenDir(0), n) }

// damage flips bytes of the file at off.
func damage(t testing.TB, fsys vfs.FS, name string, off int64, n int) {
	t.Helper()
	f, err := fsys.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, n)
	f.ReadAt(b, off)
	for i := range b {
		b[i] ^= 0x5A
	}
	f.WriteAt(b, off)
	f.Sync()
	f.Close()
}

type parityCase struct {
	name string
	cfg  Config
}

var parityCases = []parityCase{
	{"xor_k3_b4", parityCfg(wire.ParityXOR, 3, 1, 4, wire.ModeVariable)},
	{"rs_k4_m2_b6", parityCfg(wire.ParityRS, 4, 2, 6, wire.ModeVariable)},
	{"rs_k2_m2_b4_fixed", parityCfg(wire.ParityRS, 2, 2, 4, wire.ModeFixed)},
	{"rs_k5_m3_b3", parityCfg(wire.ParityRS, 5, 3, 3, wire.ModeVariable)}, // several members per blob
}

func writeObjects(t testing.TB, fsys vfs.FS, seed int) map[string][]byte {
	t.Helper()
	w := mustOpen(t, fsys)
	defer w.Close()
	want := map[string][]byte{}
	for i, n := range []int{0, 1, 3000, 4096, 8192, 8193, 20000, 40000, 70001} {
		p := fmt.Sprintf("obj/%d", i)
		want[p] = data(seed+i, n)
		if _, err := w.Put(p, want[p]); err != nil {
			t.Fatal(err)
		}
	}
	return want
}

func checkAll(t testing.TB, get func(string) ([]byte, error), want map[string][]byte) {
	t.Helper()
	for p, d := range want {
		got, err := get(p)
		if err != nil || !bytes.Equal(got, d) {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

// Every group obeys §7: k_g data members (<= parity_k) and parity_m PARITY
// frames, equal frame_quanta, indexes 0..k+m-1 once each, at least two
// distinct blobs, and no blob with more than ceil(n / blobs) members.
func TestParityGroupsWellFormed(t *testing.T) {
	for _, c := range parityCases {
		t.Run(c.name, func(t *testing.T) {
			fsys := vfs.NewCrashFS()
			if _, err := Create(fsys, c.cfg); err != nil {
				t.Fatal(err)
			}
			want := writeObjects(t, fsys, 1)
			groups, h := groupsOf(t, fsys)
			if len(groups) == 0 {
				t.Fatal("no groups")
			}
			short := 0
			for g, ms := range groups {
				if !groupUsable(ms) {
					t.Fatalf("group %d not usable", g)
				}
				k, m := int(ms[0].t.GroupK), int(ms[0].t.GroupM)
				if m != int(h.ParityM) || k < 1 || k > int(h.ParityK) || len(ms) != k+m {
					t.Fatalf("group %d: k=%d m=%d with %d members", g, k, m, len(ms))
				}
				if k < int(h.ParityK) {
					short++
				}
				perBlob := map[uint8]int{}
				obj := ""
				for _, mem := range ms {
					perBlob[mem.blob]++
					if mem.t.BlockType == wire.BlockData {
						if obj != "" && obj != mem.entries[0].Path {
							t.Fatalf("group %d spans objects", g)
						}
						obj = mem.entries[0].Path
					}
				}
				limit := (k + m + int(h.BlobCount) - 1) / int(h.BlobCount)
				if len(perBlob) < 2 {
					t.Fatalf("group %d on one blob", g)
				}
				for b, n := range perBlob {
					if n > limit {
						t.Fatalf("group %d: blob %d holds %d members, limit %d", g, b, n, limit)
					}
				}
			}
			if short == 0 {
				t.Fatal("no short group")
			}
			r, err := OpenReader(fsys, nil)
			if err != nil {
				t.Fatal(err)
			}
			checkAll(t, r.Get, want)
			if st := r.Repairs(); st != (RepairStats{}) {
				t.Fatalf("repairs on an intact archive: %+v", st)
			}
			r.Close()
		})
	}
}

// Damaged payload bytes (tail intact) and a damaged tail (frame invisible
// to hop-and-read) are both rebuilt byte-identically from parity.
func TestParityRepairsDamagedFrames(t *testing.T) {
	for _, c := range parityCases {
		for _, where := range []string{"payload", "tail"} {
			t.Run(c.name+"_"+where, func(t *testing.T) {
				fsys := vfs.NewCrashFS()
				if _, err := Create(fsys, c.cfg); err != nil {
					t.Fatal(err)
				}
				want := writeObjects(t, fsys, 2)
				groups, _ := groupsOf(t, fsys)
				// damage one DATA member of every group (at most m per group)
				hit := 0
				for _, ms := range groups {
					for _, mem := range ms {
						if mem.t.BlockType != wire.BlockData {
							continue
						}
						off := mem.off + 16 // first payload byte
						if where == "tail" {
							off = mem.off + int64(wire.FrameSize(mem.quanta)) - 50
						}
						damage(t, fsys, blobFile(int(mem.blob)), off, 3)
						hit++
						break
					}
				}
				r, err := OpenReader(fsys, nil)
				if err != nil {
					t.Fatal(err)
				}
				checkAll(t, r.Get, want)
				st := r.Repairs()
				if st.Rebuilt == 0 || st.Failed != 0 {
					t.Fatalf("repairs %+v after %d damaged frames", st, hit)
				}
				// lazy objects take the same path
				for p, d := range want {
					o, err := r.Open(p)
					if err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(d))
					if _, err := o.ReadAt(got, 0); err != nil && len(d) > 0 {
						t.Fatal(err)
					}
					o.Close()
					if !bytes.Equal(got, d) {
						t.Fatalf("object %s", p)
					}
				}
				r.Close()
				// the writer seals the damaged blobs and still reads everything
				w := mustOpen(t, fsys)
				if len(w.Health().Sealed) == 0 {
					t.Fatal("damaged committed frames did not seal")
				}
				checkAll(t, w.Get, want)
				if _, err := w.Put("after", data(5, 9000)); err != nil && !errors.Is(err, ErrNoWritableBlob) {
					t.Fatal(err)
				}
				w.Close()
			})
		}
	}
}

// Losing a whole blob file is survivable when every group keeps at least k
// members on the remaining blobs (§7.4).
func TestParityLostBlob(t *testing.T) {
	for _, c := range parityCases {
		t.Run(c.name, func(t *testing.T) {
			n, m := int(c.cfg.ParityK+c.cfg.ParityM), int(c.cfg.ParityM)
			tolerant := int(c.cfg.BlobCount) >= (n+m-1)/m
			for lost := 0; lost < int(c.cfg.BlobCount); lost++ {
				fsys := vfs.NewCrashFS()
				if _, err := Create(fsys, c.cfg); err != nil {
					t.Fatal(err)
				}
				want := writeObjects(t, fsys, 3)
				if err := fsys.Remove(blobFile(lost)); err != nil {
					t.Fatal(err)
				}
				r, err := OpenReader(fsys, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := r.Unavailable()[uint8(lost)]; !ok {
					t.Fatal("lost blob not reported")
				}
				failed := 0
				for p, d := range want {
					got, err := r.Get(p)
					switch {
					case err == nil && bytes.Equal(got, d):
					case errors.Is(err, ErrMissingData):
						failed++
					default:
						t.Fatalf("%s: %v", p, err)
					}
				}
				if tolerant && failed > 0 {
					t.Fatalf("blob %d lost: %d objects unreadable", lost, failed)
				}
				r.Close()
				// the writer refuses to open without the blob
				if _, err := OpenWriter(fsys, Options{}); err == nil {
					t.Fatal("writer opened without a blob")
				}
			}
		})
	}
}

// More losses than the code tolerates are reported, never invented.
func TestParityTooManyLosses(t *testing.T) {
	fsys := vfs.NewCrashFS()
	c := parityCfg(wire.ParityXOR, 2, 1, 3, wire.ModeVariable)
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	want := writeObjects(t, fsys, 4)
	fsys.Remove(blobFile(0))
	fsys.Remove(blobFile(1))
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	missing := 0
	for p, d := range want {
		got, err := r.Get(p)
		if errors.Is(err, ErrMissingData) {
			missing++
		} else if err != nil || !bytes.Equal(got, d) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if missing == 0 {
		t.Fatal("two lost blobs of three, XOR, nothing missing")
	}
}

// Without parity, hop-and-read still finds intact frames behind a damaged
// one, which the index rebuild and the streaming scan cannot reach.
func TestHopPastDamage(t *testing.T) {
	fsys := vfs.NewCrashFS()
	one := cfg
	one.BlobCount = 1
	if _, err := Create(fsys, one); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, fsys)
	want := map[string][]byte{}
	for i := 0; i < 5; i++ {
		p := fmt.Sprintf("p%d", i)
		want[p] = data(i, 3000)
		w.Put(p, want[p])
	}
	w.Close()
	iname, _ := index.Name(0)
	if err := fsys.Remove(path.Join(GenDir(0), iname)); err != nil {
		t.Fatal(err)
	}
	damage(t, fsys, blobFile(0), wire.FrameAreaStart+100, 4) // p0's payload
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Get("p0"); !errors.Is(err, ErrMissingData) {
		t.Fatalf("damaged p0: %v", err)
	}
	delete(want, "p0")
	checkAll(t, r.Get, want)
	if st := r.Repairs(); st.Hopped != 4 || st.Failed != 1 {
		t.Fatalf("repairs %+v", st)
	}
}

// A group_id that two inconsistent sets of frames claim is not used for
// reconstruction (§7 raw recovery): the read fails instead of guessing.
func TestParityGroupConflict(t *testing.T) {
	fsys := vfs.NewCrashFS()
	c := parityCfg(wire.ParityXOR, 2, 1, 3, wire.ModeVariable)
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, fsys)
	d := data(7, 3000)
	w.Put("x", d)
	w.Close()
	groups, _ := groupsOf(t, fsys)
	if len(groups) != 1 {
		t.Fatalf("%d groups", len(groups))
	}
	var dataMem, parMem *hopMember
	for _, ms := range groups {
		for _, m := range ms {
			if m.t.BlockType == wire.BlockData {
				dataMem = m
			} else {
				parMem = m
			}
		}
	}
	// a second copy of the PARITY frame in another blob: group_index twice
	src, _ := fsys.OpenFile(blobFile(int(parMem.blob)), os.O_RDONLY, 0)
	fr := make([]byte, wire.FrameSize(parMem.quanta))
	src.ReadAt(fr, parMem.off)
	src.Close()
	other := (int(parMem.blob) + 1) % 3
	if other == int(dataMem.blob) {
		other = (other + 1) % 3
	}
	dst, _ := fsys.OpenFile(blobFile(other), os.O_RDWR, 0)
	size, _ := dst.Size()
	dst.WriteAt(fr, size)
	dst.Sync()
	dst.Close()
	damage(t, fsys, blobFile(int(dataMem.blob)), dataMem.off+20, 2)
	r, err := OpenReader(fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Get("x"); !errors.Is(err, ErrMissingData) {
		t.Fatalf("conflicting group used: %v", err)
	}
}

// group_id values are never reused across crashes (§2.1.3, §7), and a
// rolled-back groups.alloc is refused.
func TestParityCrashAndGroupIDs(t *testing.T) {
	c := parityCfg(wire.ParityRS, 3, 2, 4, wire.ModeVariable)
	for seed := int64(0); seed < 4; seed++ {
		rng := rand.New(rand.NewSource(seed))
		base := vfs.NewCrashFS()
		if _, err := Create(base, c); err != nil {
			t.Fatal(err)
		}
		s := &snapFS{CrashFS: base, rng: rng, every: 9}
		w := mustOpen(t, s)
		type op struct {
			path string
			data []byte
			at   int
		}
		var ops []op
		for i := 0; i < 25; i++ {
			p := fmt.Sprintf("f%d", rng.Intn(5))
			d := data(int(seed)*1000+i, rng.Intn(30000))
			if _, err := w.Put(p, d); err != nil {
				t.Fatal(err)
			}
			ops = append(ops, op{p, d, s.count()})
		}
		w.Close()
		for k, snap := range s.snaps {
			w2, err := OpenWriter(snap, Options{MaxExtent: 8192})
			if err != nil {
				t.Fatalf("seed %d snapshot %d: %v", seed, k, err)
			}
			if len(w2.Health().Sealed) != 0 {
				t.Fatalf("seed %d snapshot %d: sealed %v", seed, k, w2.Health().Sealed)
			}
			exp := map[string][]byte{}
			var next *op
			for i := range ops {
				if ops[i].at <= k {
					exp[ops[i].path] = ops[i].data
				} else if next == nil {
					next = &ops[i]
				}
			}
			for p := range map[string]bool{"f0": true, "f1": true, "f2": true, "f3": true, "f4": true} {
				got, err := w2.Get(p)
				ok := func(want []byte, have bool) bool {
					if !have {
						return errors.Is(err, ErrNotFound)
					}
					return err == nil && bytes.Equal(got, want)
				}
				e, he := exp[p]
				if !ok(e, he) && !(next != nil && next.path == p && ok(next.data, true)) {
					t.Fatalf("seed %d snapshot %d: %s (%v)", seed, k, p, err)
				}
			}
			for i := 0; i < 3; i++ {
				if _, err := w2.Put(fmt.Sprintf("after%d", i), data(i, 9000)); err != nil {
					t.Fatalf("seed %d snapshot %d: %v", seed, k, err)
				}
			}
			w2.Close()
			groups, _ := groupsOf(t, snap)
			for g, ms := range groups {
				if !groupUsable(ms) {
					t.Fatalf("seed %d snapshot %d: group_id %d reused or inconsistent", seed, k, g)
				}
			}
		}
	}
	// rollback of groups.alloc
	fsys := vfs.NewCrashFS()
	if _, err := Create(fsys, c); err != nil {
		t.Fatal(err)
	}
	name := path.Join(GenDir(0), alloc.FileName(wire.AllocGroupID, 0))
	old, _ := vfs.ReadFile(fsys, name, 64)
	w := mustOpen(t, fsys)
	for i := 0; i < 300; i++ { // more groups than one reservation block
		w.Put(fmt.Sprintf("p%d", i), []byte{byte(i)})
	}
	w.Close()
	vfs.ReplaceFile(fsys, name, old)
	if _, err := OpenWriter(fsys, Options{}); !errors.Is(err, alloc.ErrRolledBack) {
		t.Fatalf("rolled-back groups.alloc: %v", err)
	}
}

func TestParitySpreadRules(t *testing.T) {
	fsys := vfs.NewCrashFS()
	if _, err := Create(fsys, parityCfg(wire.ParityXOR, 4, 1, 2, wire.ModeVariable)); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, fsys)
	if w.Health().ParityWarning == "" {
		t.Fatal("k=4 m=1 on 2 blobs: no warning (§7.4)")
	}
	w.Put("a", data(1, 100))
	w.Close()
	fsys = vfs.NewCrashFS()
	if _, err := Create(fsys, parityCfg(wire.ParityRS, 2, 2, 2, wire.ModeVariable)); err != nil {
		t.Fatal(err)
	}
	w = mustOpen(t, fsys)
	if h := w.Health().ParityWarning; h != "" {
		t.Fatal(h)
	}
	w.Put("a", data(1, 100))
	w.Close()
	// one writable blob left: parity spread cannot be met, writes fail
	damage(t, fsys, blobFile(0), wire.FrameAreaStart+20, 2)
	w = mustOpen(t, fsys)
	if _, ok := w.Health().Sealed[0]; !ok {
		t.Fatalf("%+v", w.Health())
	}
	if _, err := w.Put("b", []byte("x")); !errors.Is(err, ErrNoWritableBlob) {
		t.Fatalf("put with one writable blob: %v", err)
	}
	if got, err := w.Get("a"); err != nil || !bytes.Equal(got, data(1, 100)) {
		t.Fatalf("read through parity: %v", err)
	}
	w.Close()
}

func TestParityConcurrentPuts(t *testing.T) {
	fsys := vfs.NewCrashFS()
	if _, err := Create(fsys, parityCfg(wire.ParityRS, 3, 2, 5, wire.ModeVariable)); err != nil {
		t.Fatal(err)
	}
	w := mustOpen(t, fsys)
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		go func() {
			for i := 0; i < 10; i++ {
				p := fmt.Sprintf("g%d", g)
				d := data(g*100+i, 1000+i*7000)
				if _, err := w.Put(p, d); err != nil {
					errs <- err
					return
				}
				got, err := w.Get(p)
				if err != nil || !bytes.Equal(got, d) {
					errs <- fmt.Errorf("%s: %v", p, err)
					return
				}
			}
			errs <- nil
		}()
	}
	for g := 0; g < 8; g++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	groups, _ := groupsOf(t, fsys)
	for g, ms := range groups {
		if !groupUsable(ms) || len(ms) != int(ms[0].t.GroupK)+2 {
			t.Fatalf("group %d malformed", g)
		}
	}
}
