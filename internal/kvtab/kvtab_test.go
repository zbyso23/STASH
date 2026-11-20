package kvtab

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"sync"
	"testing"

	"stash/internal/membudget"
	"stash/internal/vfs"
)

func scratch(t *testing.T) (Config, string) {
	dir := t.TempDir()
	b := membudget.New(64 << 20)
	return Config{Budget: b, Cache: NewCache(b, 1<<20), MemLimit: 1 << 20,
		Scratch: func() (vfs.FS, string, error) { return vfs.OS{Root: dir}, "s", nil }}, dir + "/s"
}

func check(t *testing.T, tab *Table, ref map[string]string, stage string) {
	t.Helper()
	keys := make([]string, 0, len(ref))
	for k := range ref {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	it := tab.Iter(nil)
	i := 0
	for it.Next() {
		if i >= len(keys) || string(it.Key()) != keys[i] || string(it.Value()) != ref[keys[i]] {
			t.Fatalf("%s: iter %d: %q=%q", stage, i, it.Key(), it.Value())
		}
		i++
	}
	it.Close()
	if it.Err() != nil || i != len(keys) {
		t.Fatalf("%s: iter %d of %d: %v", stage, i, len(keys), it.Err())
	}
	rng := rand.New(rand.NewSource(int64(len(keys))))
	for n := 0; n < 2000; n++ {
		k := fmt.Sprintf("k%06d", rng.Intn(60000))
		v, ok, err := tab.Get([]byte(k))
		want, wok := ref[k]
		if err != nil || ok != wok || (ok && string(v) != want) {
			t.Fatalf("%s: Get %s = %q %v %v, want %q %v", stage, k, v, ok, err, want, wok)
		}
	}
	// seek into the middle
	if len(keys) > 10 {
		from := keys[len(keys)/2]
		it := tab.Iter([]byte(from))
		if !it.Next() || string(it.Key()) != from {
			t.Fatalf("%s: seek %s got %q", stage, from, it.Key())
		}
		it.Close()
	}
}

func TestTableAgainstMap(t *testing.T) {
	cfg, dir := scratch(t)
	tab := New(cfg)
	ref := map[string]string{}
	// bulk base
	err := tab.Bulk(func(add func(k, v []byte) error) error {
		for i := 0; i < 40000; i += 2 {
			k := fmt.Sprintf("k%06d", i)
			ref[k] = "base" + k
			if err := add([]byte(k), []byte(ref[k])); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check(t, tab, ref, "base")
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 120000; i++ {
		k := fmt.Sprintf("k%06d", rng.Intn(60000))
		if rng.Intn(4) == 0 {
			delete(ref, k)
			if err := tab.Delete([]byte(k)); err != nil {
				t.Fatal(err)
			}
		} else {
			v := fmt.Sprintf("v%d-%s", i, bytes.Repeat([]byte("x"), rng.Intn(50)))
			ref[k] = v
			if err := tab.Put([]byte(k), []byte(v)); err != nil {
				t.Fatal(err)
			}
		}
		if i%40000 == 39999 {
			check(t, tab, ref, fmt.Sprint("step ", i))
		}
	}
	if tab.Files() < 2 || tab.Files() > 12 {
		t.Fatalf("%d files", tab.Files())
	}
	// an iterator keeps its snapshot while the table changes
	it := tab.Iter(nil)
	snap := len(ref)
	for i := 0; i < 30000; i++ {
		tab.Put([]byte(fmt.Sprintf("z%06d", i)), []byte("new"))
	}
	n := 0
	for it.Next() {
		n++
	}
	it.Close()
	if n != snap {
		t.Fatalf("snapshot saw %d keys, want %d", n, snap)
	}
	tab.Close()
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("files left after Close: %d", len(ents))
	}
}

func TestTableTamper(t *testing.T) {
	cfg, dir := scratch(t)
	tab := New(cfg)
	tab.Bulk(func(add func(k, v []byte) error) error {
		for i := 0; i < 20000; i++ {
			add([]byte(fmt.Sprintf("k%06d", i)), []byte("value"))
		}
		return nil
	})
	ents, _ := os.ReadDir(dir)
	f, _ := os.OpenFile(dir+"/"+ents[0].Name(), os.O_RDWR, 0)
	f.WriteAt([]byte("Z"), 30000)
	f.Close()
	cfg.Cache.Close()
	*cfg.Cache = *NewCache(nil, 1<<20)
	sawErr := false
	for i := 0; i < 20000; i += 50 {
		v, ok, err := tab.Get([]byte(fmt.Sprintf("k%06d", i)))
		if err != nil {
			if !errors.Is(err, ErrTampered) {
				t.Fatal(err)
			}
			sawErr = true
			continue
		}
		if !ok || string(v) != "value" {
			t.Fatalf("tampered file returned %q %v", v, ok)
		}
	}
	if !sawErr {
		t.Fatal("tampering not detected")
	}
	it := tab.Iter(nil)
	for it.Next() {
	}
	if !errors.Is(it.Err(), ErrTampered) {
		t.Fatalf("iterator over tampered file: %v", it.Err())
	}
	it.Close()
	tab.Close()
}

func TestTableConcurrent(t *testing.T) {
	cfg, _ := scratch(t)
	cfg.MemLimit = 1 << 16
	tab := New(cfg)
	defer tab.Close()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				k := []byte(fmt.Sprintf("g%d-%05d", g, i))
				if err := tab.Put(k, k); err != nil {
					t.Error(err)
					return
				}
				if v, ok, err := tab.Get(k); err != nil || !ok || !bytes.Equal(v, k) {
					t.Errorf("get %s: %v %v", k, ok, err)
					return
				}
				if i%1000 == 0 {
					it := tab.Iter(nil)
					for it.Next() {
					}
					it.Close()
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestInMemoryTable(t *testing.T) {
	tab := New(Config{})
	tab.Bulk(func(add func(k, v []byte) error) error { return add([]byte("a"), []byte("1")) })
	tab.Put([]byte("b"), []byte("2"))
	tab.Delete([]byte("a"))
	it := tab.Iter(nil)
	var got []string
	for it.Next() {
		got = append(got, string(it.Key())+"="+string(it.Value()))
	}
	if !slices.Equal(got, []string{"b=2"}) {
		t.Fatal(got)
	}
}
