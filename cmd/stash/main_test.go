package main

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type result struct {
	code           int
	stdout, stderr string
}

func cli(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

func must(t *testing.T, r result, args ...string) result {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("%v: exit %d\n%s%s", args, r.code, r.stdout, r.stderr)
	}
	return r
}

func ok(t *testing.T, args ...string) result {
	t.Helper()
	return must(t, cli(t, "", args...), args...)
}

func tree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{
		"a.txt":         []byte("hello\n"),
		"empty":         nil,
		"sub/text.log":  bytes.Repeat([]byte("log line with words\n"), 30000),
		"sub/deep/rand": func() []byte { b := make([]byte, 400000); rand.New(rand.NewSource(1)).Read(b); return b }(),
		"čeština/ž.txt": []byte("příliš žluťoučký kůň"),
	}
	for p, d := range files {
		f := filepath.Join(dir, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(f), 0o755)
		if err := os.WriteFile(f, d, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func damageBlob(t *testing.T, arch string, gen string, off int64) {
	t.Helper()
	name := filepath.Join(arch, gen, "frames", "blob-01.stash")
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	f.ReadAt(b, off)
	for i := range b {
		b[i] ^= 0xA5
	}
	f.WriteAt(b, off)
	f.Close()
}

// The whole operator workflow on a real directory: create with every
// option, put a tree and stdin, list, get, export, delete, verify, damage
// a blob, verify again (exit 3), compact (repairs from parity), recover,
// salvage, gc.
func TestWorkflow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		create []string
		key    bool
	}{
		{"baseline", nil, false},
		{"fast_fixed_xor", []string{"-profile", "fast", "-mode", "fixed", "-frame-size", "32K", "-parity", "xor", "-k", "2", "-blobs", "3"}, false},
		{"secure_rs_zstd", []string{"-compression", "zstd", "-parity", "rs", "-k", "2", "-m", "1", "-blobs", "3", "-frame-size", "64K"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			arch := filepath.Join(dir, "arch")
			src := filepath.Join(dir, "src")
			files := tree(t, src)
			var kf []string
			if tc.key {
				k := filepath.Join(dir, "k.key")
				ok(t, "keygen", k)
				if fi, _ := os.Stat(k); fi.Mode().Perm() != 0o600 {
					t.Fatalf("key mode %v", fi.Mode())
				}
				if r := cli(t, "", "keygen", k); r.code != exitError {
					t.Fatal("keygen overwrote a key")
				}
				kf = []string{"-key-file", k}
			}
			with := func(args ...string) []string { return append(args, kf...) }
			info := ok(t, append(with("create", arch), tc.create...)...)
			if tc.key != strings.Contains(info.stdout, "AES-256-GCM") {
				t.Fatal(info.stdout)
			}
			ok(t, with("put", arch, src, "-prefix", "backup/")...)
			must(t, cli(t, "from stdin", with("put", arch, "-", "-as", "stdin.txt")...))
			ls := ok(t, with("ls", arch)...)
			if n := strings.Count(ls.stdout, "\n"); n != len(files)+1 {
				t.Fatalf("ls: %d lines\n%s", n, ls.stdout)
			}
			if !strings.Contains(ls.stdout, "backup/src/čeština/ž.txt") {
				t.Fatal(ls.stdout)
			}
			if g := ok(t, with("get", arch, "backup/src/sub/text.log")...); g.stdout != string(files["sub/text.log"]) {
				t.Fatal("get differs")
			}
			if g := ok(t, with("get", arch, "stdin.txt")...); g.stdout != "from stdin" {
				t.Fatal("stdin differs")
			}
			out := filepath.Join(dir, "out")
			ok(t, with("export", arch, out, "-prefix", "backup/")...)
			for p, d := range files {
				got, err := os.ReadFile(filepath.Join(out, "backup", "src", filepath.FromSlash(p)))
				if err != nil || !bytes.Equal(got, d) {
					t.Fatalf("export %s: %v", p, err)
				}
			}
			ok(t, with("rm", arch, "stdin.txt")...)
			if r := cli(t, "", with("get", arch, "stdin.txt")...); r.code != exitError || !strings.Contains(r.stderr, "not") {
				t.Fatalf("deleted object: %+v", r)
			}
			st := ok(t, with("stat", arch, "backup/src/sub/deep/rand")...)
			if !strings.Contains(st.stdout, "400000") {
				t.Fatal(st.stdout)
			}
			if v := ok(t, with("verify", arch)...); !strings.Contains(v.stdout, "result    OK") {
				t.Fatal(v.stdout)
			}
			if tc.key {
				if r := cli(t, "", "ls", arch); r.code != exitError || !strings.Contains(r.stderr, "-key-file") {
					t.Fatalf("no key: %+v", r)
				}
				os.Setenv("STASH_KEY", strings.Repeat("ab", 32))
				r := cli(t, "", "ls", arch)
				os.Unsetenv("STASH_KEY")
				if r.code != exitError || !strings.Contains(r.stderr, "wrong") {
					t.Fatalf("wrong key: %+v", r)
				}
			}
			info = ok(t, "info", arch)
			parity := !strings.Contains(info.stdout, "parity       none")
			// damage a frame payload in blob 01
			damageBlob(t, arch, "generation-0000000000000000", 4096+2000)
			v := cli(t, "", with("verify", arch)...)
			if v.code != exitProblems {
				t.Fatalf("verify after damage: %+v", v)
			}
			rec := cli(t, "", with("recover", arch)...)
			if rec.code != exitProblems || !strings.Contains(rec.stdout, "damaged") {
				t.Fatalf("recover: %+v", rec)
			}
			if parity {
				c := ok(t, with("compact", arch, "-keep-old")...)
				if !strings.Contains(c.stdout, "generation 0 -> ") || !strings.Contains(c.stdout, "rebuilt 1") {
					t.Fatal(c.stdout)
				}
				if v := ok(t, with("verify", arch)...); !strings.Contains(v.stdout, "OK") {
					t.Fatal(v.stdout)
				}
				if g := ok(t, with("gc", arch)...); !strings.Contains(g.stdout, "[0]") {
					t.Fatal(g.stdout)
				}
			}
			salv := filepath.Join(dir, "salvaged")
			s := cli(t, "", with("salvage", arch, salv)...)
			if parity && s.code != 0 {
				t.Fatalf("salvage: %+v", s)
			}
			l := ok(t, with("ls", salv, "-l")...)
			if !strings.Contains(l.stdout, "backup/src/a.txt") {
				t.Fatal(l.stdout)
			}
			if tc.key {
				// keyless recovery reports structure only
				r := cli(t, "", "recover", salv)
				if !strings.Contains(r.stdout, "without the key") || !strings.Contains(r.stdout, "<object ") {
					t.Fatalf("keyless recover: %+v", r)
				}
			}
		})
	}
}

// HARDENED from the command line: create with an anchor, refuse to open
// without it, leave and enroll again.
func TestHardenedCLI(t *testing.T) {
	dir := t.TempDir()
	arch, anc := filepath.Join(dir, "arch"), filepath.Join(dir, "anchor")
	os.MkdirAll(anc, 0o755)
	if i := ok(t, "create", arch, "-anchor", anc); !strings.Contains(i.stdout, "HARDENED") {
		t.Fatal(i.stdout)
	}
	must(t, cli(t, "x", "put", arch, "-", "-as", "x", "-anchor", anc))
	if r := cli(t, "", "ls", arch); r.code != exitError || !strings.Contains(r.stderr, "-anchor") {
		t.Fatalf("without anchor: %+v", r)
	}
	if r := cli(t, "", "leave-hardened", arch); r.code != exitError {
		t.Fatal("leave without operator")
	}
	ok(t, "leave-hardened", arch, "-operator", "zbysek")
	ok(t, "ls", arch)
	anc2 := filepath.Join(dir, "anchor2")
	os.MkdirAll(anc2, 0o755)
	ok(t, "enroll", arch, "-anchor", anc2, "-operator", "zbysek")
	if g := ok(t, "get", arch, "x", "-anchor", anc2); g.stdout != "x" {
		t.Fatal(g.stdout)
	}
}

func TestUsage(t *testing.T) {
	if r := cli(t, ""); r.code != exitUsage {
		t.Fatal(r)
	}
	if r := cli(t, "", "nope"); r.code != exitUsage {
		t.Fatal(r)
	}
	if r := cli(t, "", "get", "only-one"); r.code != exitUsage {
		t.Fatal(r)
	}
	if r := cli(t, "", "create", t.TempDir()+"/a", "-profile", "secure"); r.code != exitError || !strings.Contains(r.stderr, "key") {
		t.Fatal(r)
	}
	if r := ok(t, "help"); !strings.Contains(r.stdout, "salvage") {
		t.Fatal(r)
	}
}

// stash mount serves the archive until its context ends.
func TestMountCommand(t *testing.T) {
	dir := t.TempDir()
	arch, mnt := filepath.Join(dir, "arch"), filepath.Join(dir, "mnt")
	os.MkdirAll(mnt, 0o755)
	ok(t, "create", arch)
	must(t, cli(t, "mounted content", "put", arch, "-", "-as", "d/f.txt"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result)
	go func() {
		var out, errb bytes.Buffer
		code := run(ctx, []string{"mount", arch, mnt}, strings.NewReader(""), &out, &errb)
		done <- result{code, out.String(), errb.String()}
	}()
	var got []byte
	var err error
	for i := 0; i < 100; i++ {
		if got, err = os.ReadFile(filepath.Join(mnt, "d", "f.txt")); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		cancel()
		r := <-done
		if strings.Contains(r.stderr, "fuse") {
			t.Skipf("FUSE not available: %s", r.stderr)
		}
		t.Fatalf("%v %+v", err, r)
	}
	if string(got) != "mounted content" {
		t.Fatalf("%q", got)
	}
	cancel()
	if r := <-done; r.code != 0 || !strings.Contains(r.stderr, "mounted") {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(filepath.Join(mnt, "d")); err == nil {
		t.Fatal("still mounted")
	}
}
