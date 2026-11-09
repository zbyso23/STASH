// Command stash is the command-line interface of the STASH 2.0 R10
// reference implementation (SPEC.md). Run "stash help" for the commands.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"stash"
	"stash/fusefs"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitProblems = 3 // verify or recover found damage
)

type env struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type command struct {
	name, args, help string
	run              func(e *env, fl *flag.FlagSet, args []string) error
	flags            func(fl *flag.FlagSet)
	minArgs, maxArgs int // maxArgs -1: any
}

var commands []*command

func init() {
	commands = []*command{
		{name: "keygen", args: "<keyfile>", help: "write a new random archive key (64 hex digits, mode 0600)", minArgs: 1, maxArgs: 1, run: cmdKeygen},
		{name: "create", args: "<archive>", help: "create a new archive", minArgs: 1, maxArgs: 1, run: cmdCreate, flags: createFlags},
		{name: "info", args: "<archive>", help: "show the archive parameters (no key needed)", minArgs: 1, maxArgs: 1, run: cmdInfo},
		{name: "put", args: "<archive> <file|dir|->...", help: "store files; directories are stored recursively", minArgs: 2, maxArgs: -1, run: cmdPut, flags: putFlags},
		{name: "get", args: "<archive> <path>", help: "write one object to stdout or -o", minArgs: 2, maxArgs: 2, run: cmdGet, flags: getFlags},
		{name: "export", args: "<archive> <dir>", help: "write every live object (under -prefix) into a directory", minArgs: 2, maxArgs: 2, run: cmdExport, flags: exportFlags},
		{name: "ls", args: "<archive> [prefix]", help: "list live objects", minArgs: 1, maxArgs: 2, run: cmdLs, flags: lsFlags},
		{name: "stat", args: "<archive> <path>...", help: "show object versions", minArgs: 2, maxArgs: -1, run: cmdStat},
		{name: "rm", args: "<archive> <path>...", help: "delete objects", minArgs: 2, maxArgs: -1, run: cmdRm},
		{name: "verify", args: "<archive>", help: "read and check everything (exit 3 on damage)", minArgs: 1, maxArgs: 1, run: cmdVerify},
		{name: "compact", args: "<archive>", help: "copy live data into a new generation, repairing damage", minArgs: 1, maxArgs: 1, run: cmdCompact, flags: compactFlags},
		{name: "gc", args: "<archive>", help: "remove unused old generations", minArgs: 1, maxArgs: 1, run: cmdGC},
		{name: "recover", args: "<archive>", help: "raw recovery scan from the blob files (read-only; exit 3 on damage)", minArgs: 1, maxArgs: 1, run: cmdRecover, flags: recoverFlags},
		{name: "salvage", args: "<archive> <new-archive>", help: "recover the current versions into a new archive", minArgs: 2, maxArgs: 2, run: cmdSalvage, flags: recoverFlags},
		{name: "mount", args: "<archive> <mountpoint>", help: "mount a read-only snapshot of the archive (FUSE) until interrupted or unmounted", minArgs: 2, maxArgs: 2, run: cmdMount, flags: mountFlags},
		{name: "enroll", args: "<archive>", help: "make an archive HARDENED with -anchor (after full verification)", minArgs: 1, maxArgs: 1, run: cmdEnroll, flags: operatorFlags},
		{name: "leave-hardened", args: "<archive>", help: "make a HARDENED archive STANDARD again", minArgs: 1, maxArgs: 1, run: cmdLeave, flags: operatorFlags},
		{name: "authorize", args: "<archive>", help: "authorize a verified local state that leads the anchor", minArgs: 1, maxArgs: 1, run: cmdAuthorize, flags: operatorFlags},
	}
}

// common flags of every command that opens an archive
var (
	keyFile    string
	anchorDir  string
	ackRollbak bool
	adopt      bool
	policyName string
)

func commonFlags(fl *flag.FlagSet) {
	fl.StringVar(&keyFile, "key-file", "", "archive key file (or $STASH_KEY, 64 hex digits)")
	fl.StringVar(&anchorDir, "anchor", "", "directory of the file Generation Anchor (HARDENED)")
	fl.BoolVar(&ackRollbak, "acknowledge-allocator-rollback", false, "continue after a reviewed ErrAllocatorRollback (operator decision)")
	fl.BoolVar(&adopt, "adopt-unanchored", false, "keep manifest records written after the last anchor advance (operator decision)")
	fl.StringVar(&policyName, "policy", "", "expected security policy: standard or hardened (or $STASH_POLICY); with -anchor hardened is implied")
}

// policy is the expected security policy from the command line or
// environment, never from the archive's storage (SPEC §15A.2).
func policy() (stash.Policy, error) {
	s := policyName
	if s == "" {
		s = os.Getenv("STASH_POLICY")
	}
	switch strings.ToLower(s) {
	case "":
		return stash.PolicyAuto, nil
	case "standard":
		return stash.PolicyStandard, nil
	case "hardened":
		return stash.PolicyHardened, nil
	}
	return 0, fmt.Errorf("%w: policy %q (standard or hardened)", stash.ErrInvalid, s)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: stash <command> [flags] <args>")
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(tw, "  %s %s\t%s\n", c.name, c.args, c.help)
	}
	tw.Flush()
	fmt.Fprintln(w, "\nRun \"stash <command> -h\" for the flags of a command.")
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		if len(args) == 0 {
			usage(stderr)
			return exitUsage
		}
		usage(stdout)
		return exitOK
	}
	var c *command
	for _, x := range commands {
		if x.name == args[0] {
			c = x
		}
	}
	if c == nil {
		fmt.Fprintf(stderr, "stash: unknown command %q\n", args[0])
		usage(stderr)
		return exitUsage
	}
	keyFile, anchorDir, ackRollbak, adopt, policyName = "", "", false, false, ""
	fl := flag.NewFlagSet("stash "+c.name, flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() {
		fmt.Fprintf(stderr, "usage: stash %s [flags] %s\n  %s\n", c.name, c.args, c.help)
		fl.PrintDefaults()
	}
	if c.name != "keygen" {
		commonFlags(fl)
	}
	if c.flags != nil {
		c.flags(fl)
	}
	rest, err := parseInterspersed(fl, args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if len(rest) < c.minArgs || (c.maxArgs >= 0 && len(rest) > c.maxArgs) {
		fl.Usage()
		return exitUsage
	}
	e := &env{ctx: ctx, stdin: stdin, stdout: stdout, stderr: stderr}
	if err := c.run(e, fl, rest); err != nil {
		var p problems
		if errors.As(err, &p) {
			fmt.Fprintf(stderr, "stash %s: %v\n", c.name, err)
			return exitProblems
		}
		fmt.Fprintf(stderr, "stash %s: %v\n", c.name, explain(err))
		return exitError
	}
	return exitOK
}

// parseInterspersed allows flags after positional arguments ("stash put
// a.stash file -prefix x/"); "--" ends the flags.
func parseInterspersed(fl *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fl.Parse(args); err != nil {
			return nil, err
		}
		args = fl.Args()
		if len(args) == 0 {
			return rest, nil
		}
		if args[0] == "--" {
			return append(rest, args[1:]...), nil
		}
		rest = append(rest, args[0])
		args = args[1:]
		if len(args) > 0 && args[0] == "--" {
			return append(rest, args[1:]...), nil
		}
	}
}

// problems is a successful run that found damage.
type problems struct{ msg string }

func (p problems) Error() string { return p.msg }

// explain adds a hint to errors an operator can act on.
func explain(err error) error {
	switch {
	case errors.Is(err, stash.ErrKeyRequired):
		return fmt.Errorf("%w (pass -key-file or set STASH_KEY)", err)
	case errors.Is(err, stash.ErrAnchorRequired):
		return fmt.Errorf("%w (pass -anchor for a HARDENED archive, none for a STANDARD one)", err)
	case errors.Is(err, stash.ErrLocked):
		return fmt.Errorf("%w (another writer has the archive open)", err)
	case errors.Is(err, stash.ErrNoWritableBlob):
		return fmt.Errorf("%w (run stash compact)", err)
	}
	return err
}

// ---- keys and anchors

func readKey() ([]byte, error) {
	var s string
	switch {
	case keyFile != "":
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		if len(b) == stash.KeySize {
			return b, nil // raw key
		}
		s = string(b)
	case os.Getenv("STASH_KEY") != "":
		s = os.Getenv("STASH_KEY")
	default:
		return nil, nil
	}
	k, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != stash.KeySize {
		return nil, fmt.Errorf("%w: a key is %d raw bytes or %d hex digits", stash.ErrInvalid, stash.KeySize, 2*stash.KeySize)
	}
	return k, nil
}

func openAnchor() (stash.Anchor, error) {
	if anchorDir == "" {
		return nil, nil
	}
	return stash.NewFileAnchor(anchorDir)
}

func cmdKeygen(e *env, _ *flag.FlagSet, args []string) error {
	k, err := stash.NewKey()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, hex.EncodeToString(k)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(e.stderr, "wrote %s; keep a copy outside the archive: without it the encrypted content is lost\n", args[0])
	return nil
}

// ---- open helpers

func openWriter(dir string, extra func(*stash.Options)) (*stash.Archive, error) {
	key, err := readKey()
	if err != nil {
		return nil, err
	}
	a, err := openAnchor()
	if err != nil {
		return nil, err
	}
	pol, err := policy()
	if err != nil {
		return nil, err
	}
	o := stash.Options{Key: key, Anchor: a, AcknowledgeAllocatorRollback: ackRollbak, AdoptUnanchored: adopt, Policy: pol}
	if extra != nil {
		extra(&o)
	}
	return stash.Open(dir, o)
}

func openReader(dir string) (*stash.Reader, error) {
	key, err := readKey()
	if err != nil {
		return nil, err
	}
	a, err := openAnchor()
	if err != nil {
		return nil, err
	}
	pol, err := policy()
	if err != nil {
		return nil, err
	}
	return stash.OpenReadOnlyWith(dir, stash.ReadOptions{Key: key, Anchor: a, Policy: pol})
}

// ---- create / info

var (
	cProfile, cMode, cHash, cCompression, cParity string
	cBlobs, cK, cM                                int
	cFrameSize                                    string
)

func createFlags(fl *flag.FlagSet) {
	fl.StringVar(&cProfile, "profile", "", "baseline, secure (needs a key) or fast; sets hash, compression and encryption")
	fl.StringVar(&cMode, "mode", "variable", "frame mode: variable or fixed")
	fl.StringVar(&cHash, "hash", "", "sha256 (default) or blake3")
	fl.StringVar(&cCompression, "compression", "", "store (default), zstd-fast, zstd or zstd-dense")
	fl.StringVar(&cParity, "parity", "none", "none, xor or rs")
	fl.IntVar(&cK, "k", 0, "data frames per parity group")
	fl.IntVar(&cM, "m", 0, "parity frames per group (rs)")
	fl.IntVar(&cBlobs, "blobs", 0, "number of blob files (default 4)")
	fl.StringVar(&cFrameSize, "frame-size", "", "maximum frame size, e.g. 64K or 4M (default 4M)")
}

func parseSize(s string) (int, error) {
	m := 1
	switch {
	case strings.HasSuffix(strings.ToUpper(s), "K"):
		m, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(strings.ToUpper(s), "M"):
		m, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(strings.ToUpper(s), "G"):
		m, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > (1<<31)/m {
		return 0, fmt.Errorf("%w: size %q", stash.ErrInvalid, s)
	}
	return n * m, nil
}

func cmdCreate(e *env, _ *flag.FlagSet, args []string) error {
	key, err := readKey()
	if err != nil {
		return err
	}
	a, err := openAnchor()
	if err != nil {
		return err
	}
	o := stash.CreateOptions{Key: key, Anchor: a, Blobs: cBlobs}
	switch cProfile {
	case "":
	case "baseline":
		o.Profile = stash.Baseline
	case "secure":
		o.Profile = stash.Secure
	case "fast":
		o.Profile = stash.Fast
	default:
		return fmt.Errorf("%w: profile %q", stash.ErrInvalid, cProfile)
	}
	if o.Profile == stash.Secure && key == nil {
		return fmt.Errorf("%w: the secure profile needs a key (stash keygen, then -key-file)", stash.ErrInvalid)
	}
	switch cMode {
	case "variable":
	case "fixed":
		o.Mode = stash.Fixed
	default:
		return fmt.Errorf("%w: mode %q", stash.ErrInvalid, cMode)
	}
	switch cHash {
	case "", "sha256":
	case "blake3":
		o.Hash = stash.BLAKE3
	default:
		return fmt.Errorf("%w: hash %q", stash.ErrInvalid, cHash)
	}
	switch cCompression {
	case "", "store":
	case "zstd-fast":
		o.Compression = stash.ZstdFast
	case "zstd":
		o.Compression = stash.ZstdDefault
	case "zstd-dense":
		o.Compression = stash.ZstdDense
	default:
		return fmt.Errorf("%w: compression %q", stash.ErrInvalid, cCompression)
	}
	switch cParity {
	case "none":
	case "xor":
		o.Parity = stash.Parity{Scheme: stash.XOR, K: cK, M: cM}
	case "rs":
		o.Parity = stash.Parity{Scheme: stash.ReedSolomon, K: cK, M: cM}
	default:
		return fmt.Errorf("%w: parity %q", stash.ErrInvalid, cParity)
	}
	if cFrameSize != "" {
		if o.MaxFrameSize, err = parseSize(cFrameSize); err != nil {
			return err
		}
	}
	if err := stash.Create(args[0], o); err != nil {
		return err
	}
	return printInfo(e.stdout, args[0])
}

var modeNames = map[stash.FrameMode]string{stash.Variable: "variable", stash.Fixed: "fixed"}
var hashNames = map[stash.Hash]string{stash.SHA256: "sha256", stash.BLAKE3: "blake3"}
var codecNames = map[stash.Compression]string{stash.Store: "store", stash.ZstdFast: "zstd-fast", stash.ZstdDefault: "zstd", stash.ZstdDense: "zstd-dense"}

func printInfo(w io.Writer, dir string) error {
	in, err := stash.Describe(dir)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "archive id\t%x\n", in.ArchiveID)
	fmt.Fprintf(tw, "generation\t%d\n", in.Generation)
	if len(in.Generations) > 1 {
		fmt.Fprintf(tw, "generations on disk\t%v\n", in.Generations)
	}
	fmt.Fprintf(tw, "frame mode\t%s, frames up to %s\n", modeNames[in.Mode], size(int64(in.MaxFrameSize)))
	fmt.Fprintf(tw, "hash\t%s\n", hashNames[in.Hash])
	fmt.Fprintf(tw, "compression\t%s\n", codecNames[in.Compression])
	enc := "no"
	if in.Encrypted {
		enc = "AES-256-GCM"
	}
	fmt.Fprintf(tw, "encryption\t%s\n", enc)
	fmt.Fprintf(tw, "blobs\t%d\n", in.Blobs)
	switch in.Parity.Scheme {
	case stash.NoParity:
		fmt.Fprintf(tw, "parity\tnone\n")
	case stash.XOR:
		fmt.Fprintf(tw, "parity\txor, k=%d\n", in.Parity.K)
	case stash.ReedSolomon:
		fmt.Fprintf(tw, "parity\treed-solomon, k=%d m=%d\n", in.Parity.K, in.Parity.M)
	}
	pol := "STANDARD"
	if in.Hardened {
		pol = "HARDENED"
	}
	fmt.Fprintf(tw, "policy\t%s\n", pol)
	return tw.Flush()
}

func cmdInfo(e *env, _ *flag.FlagSet, args []string) error { return printInfo(e.stdout, args[0]) }

func size(n int64) string {
	const u = "KMGTPE"
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f, i := float64(n)/1024, 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %ciB", f, u[i])
}

// ---- put / get / export

var (
	putAs, putPrefix string
	putQuiet         bool
)

func putFlags(fl *flag.FlagSet) {
	fl.StringVar(&putAs, "as", "", "archive path for a single file or stdin (-)")
	fl.StringVar(&putPrefix, "prefix", "", "archive path prefix for stored files")
	fl.BoolVar(&putQuiet, "q", false, "do not list stored objects")
}

func cmdPut(e *env, _ *flag.FlagSet, args []string) error {
	srcs := args[1:]
	if putAs != "" && len(srcs) != 1 {
		return fmt.Errorf("%w: -as takes exactly one source", stash.ErrInvalid)
	}
	a, err := openWriter(args[0], nil)
	if err != nil {
		return err
	}
	defer a.Close()
	var files, bytes int64
	store := func(name string, r io.Reader) error {
		ver, err := a.PutReader(e.ctx, name, r)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		in, _ := a.Stat(name)
		files++
		bytes += in.Size
		if !putQuiet {
			fmt.Fprintf(e.stdout, "%s\tv%d\t%d\n", name, ver, in.Size)
		}
		return nil
	}
	for _, src := range srcs {
		if src == "-" {
			if putAs == "" {
				return fmt.Errorf("%w: stdin needs -as <path>", stash.ErrInvalid)
			}
			if err := store(putPrefix+putAs, e.stdin); err != nil {
				return err
			}
			continue
		}
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			name := putAs
			if name == "" {
				name = filepath.Base(src)
			}
			if err := storeFile(store, putPrefix+name, src); err != nil {
				return err
			}
			continue
		}
		base := putAs
		if base == "" {
			base = filepath.Base(filepath.Clean(src))
		}
		err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil // directories, symlinks and devices are not objects
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			return storeFile(store, putPrefix+path.Join(base, filepath.ToSlash(rel)), p)
		})
		if err != nil {
			return err
		}
	}
	if err := a.Close(); err != nil {
		return err
	}
	fmt.Fprintf(e.stderr, "stored %d objects, %s\n", files, size(bytes))
	return nil
}

func storeFile(store func(string, io.Reader) error, name, file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	return store(name, f)
}

var getOut string

func getFlags(fl *flag.FlagSet) {
	fl.StringVar(&getOut, "o", "", "output file (default stdout)")
}

func cmdGet(e *env, _ *flag.FlagSet, args []string) error {
	r, err := openReader(args[0])
	if err != nil {
		return err
	}
	defer r.Close()
	o, err := r.OpenObject(args[1])
	if err != nil {
		return err
	}
	defer o.Close()
	if getOut == "" || getOut == "-" {
		_, err = io.Copy(e.stdout, o)
		return err
	}
	return writeFile(getOut, o)
}

// writeFile writes r to name through a temporary file, so a failed read
// never leaves a partial file under the final name.
func writeFile(name string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".stash-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = io.Copy(f, r)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, name)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

var exportPrefix string

func exportFlags(fl *flag.FlagSet) {
	fl.StringVar(&exportPrefix, "prefix", "", "export only paths with this prefix")
}

func cmdExport(e *env, _ *flag.FlagSet, args []string) error {
	r, err := openReader(args[0])
	if err != nil {
		return err
	}
	defer r.Close()
	root, err := openExportRoot(args[1])
	if err != nil {
		return err
	}
	defer root.Close()
	var n int
	var failed []string
	for _, p := range r.List() {
		if !strings.HasPrefix(p, exportPrefix) {
			continue
		}
		o, err := r.OpenObject(p)
		if err == nil {
			err = root.write(p, o)
			o.Close()
		}
		if err != nil {
			fmt.Fprintf(e.stderr, "%s: %v\n", p, err)
			failed = append(failed, p)
			continue
		}
		n++
	}
	fmt.Fprintf(e.stderr, "exported %d objects\n", n)
	if len(failed) > 0 {
		return fmt.Errorf("%d objects could not be read", len(failed))
	}
	return nil
}

// ---- ls / stat / rm

var lsLong bool

func lsFlags(fl *flag.FlagSet) {
	fl.BoolVar(&lsLong, "l", false, "show size and version")
}

func cmdLs(e *env, _ *flag.FlagSet, args []string) error {
	r, err := openReader(args[0])
	if err != nil {
		return err
	}
	defer r.Close()
	prefix := ""
	if len(args) > 1 {
		prefix = args[1]
	}
	tw := tabwriter.NewWriter(e.stdout, 2, 8, 2, ' ', tabwriter.AlignRight)
	for _, p := range r.List() {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		if !lsLong {
			fmt.Fprintln(e.stdout, p)
			continue
		}
		in, err := r.Stat(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(tw, "%d\tv%d\t\t%s\n", in.Size, in.FileVer, p)
	}
	return tw.Flush()
}

func cmdStat(e *env, _ *flag.FlagSet, args []string) error {
	r, err := openReader(args[0])
	if err != nil {
		return err
	}
	defer r.Close()
	for _, p := range args[1:] {
		in, err := r.Stat(p)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.stdout, "path      %s\nversion   %d\nsize      %d (%s)\nextents   %d\n", in.Path, in.FileVer, in.Size, size(in.Size), in.Extents)
	}
	return nil
}

func cmdRm(e *env, _ *flag.FlagSet, args []string) error {
	a, err := openWriter(args[0], nil)
	if err != nil {
		return err
	}
	defer a.Close()
	for _, p := range args[1:] {
		if err := a.Delete(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return a.Close()
}

// ---- verify / compact / gc

func cmdVerify(e *env, _ *flag.FlagSet, args []string) error {
	a, err := openWriter(args[0], func(o *stash.Options) { o.VerifyAll = true })
	if err != nil {
		return err
	}
	defer a.Close()
	rep, err := a.Verify(e.ctx)
	if err != nil {
		return err
	}
	w := e.stdout
	fmt.Fprintf(w, "versions  %d (%s read)\n", rep.Versions, size(rep.Bytes))
	for _, b := range rep.Blobs {
		state := "ok"
		switch {
		case b.Err != nil:
			state = "unavailable: " + b.Err.Error()
		case len(b.Damaged) > 0 || len(b.Unscanned) > 0 || b.Candidates > 0:
			state = fmt.Sprintf("DAMAGED: %d regions, %d unscanned, %d resync candidates", len(b.Damaged), len(b.Unscanned), b.Candidates)
		}
		fmt.Fprintf(w, "blob %02X   %d frames, %s\n", b.Ordinal, b.Frames, state)
	}
	g := rep.Groups
	if g.Total > 0 {
		fmt.Fprintf(w, "groups    %d: %d healthy, %d degraded, %d unrecoverable, %d conflicting, %d inconsistent\n",
			g.Total, g.Healthy, g.Degraded, g.Unrecoverable, g.Conflicting, g.Inconsistent)
	}
	if rp := rep.Repairs; rp.Hopped+rp.Rebuilt+rp.Failed > 0 {
		fmt.Fprintf(w, "repairs   %d hop-and-read, %d rebuilt from parity, %d failed\n", rp.Hopped, rp.Rebuilt, rp.Failed)
	}
	paths := make([]string, 0, len(rep.Failed))
	for p := range rep.Failed {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(w, "FAILED    %s: %v\n", p, rep.Failed[p])
	}
	if !rep.OK() {
		fmt.Fprintln(w, "result    PROBLEMS FOUND (stash compact repairs what parity can rebuild)")
		return problems{"damage found"}
	}
	fmt.Fprintln(w, "result    OK")
	return nil
}

var keepOld bool

func compactFlags(fl *flag.FlagSet) {
	fl.BoolVar(&keepOld, "keep-old", false, "keep the previous generation (stash gc removes it)")
}

func cmdCompact(e *env, _ *flag.FlagSet, args []string) error {
	a, err := openWriter(args[0], nil)
	if err != nil {
		return err
	}
	defer a.Close()
	res, err := a.Compact(e.ctx, stash.CompactOptions{KeepOld: keepOld})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "generation %d -> %d: %d versions, %s -> %s\n", res.From, res.To, res.Versions, size(res.SourceBytes), size(res.DestBytes))
	fmt.Fprintf(e.stdout, "frames copied %d, rebuilt %d, regrouped %d; parity recomputed %d; small objects repacked %d\n",
		res.CopiedFrames, res.RebuiltFrames, res.RewrittenFrames, res.RecomputedParity, res.RepackedObjects)
	if len(res.Removed) > 0 {
		fmt.Fprintf(e.stdout, "removed generations %v\n", res.Removed)
	}
	return a.Close()
}

func cmdGC(e *env, _ *flag.FlagSet, args []string) error {
	a, err := openWriter(args[0], nil)
	if err != nil {
		return err
	}
	defer a.Close()
	removed, err := a.GC()
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "removed generations %v\n", removed)
	return a.Close()
}

// ---- recover / salvage

var (
	rNoManifest bool
	rGeneration string
	rAll        bool
)

func recoverFlags(fl *flag.FlagSet) {
	fl.BoolVar(&rNoManifest, "no-manifest", false, "ignore the manifest")
	fl.StringVar(&rGeneration, "generation", "", "generation id to scan (default: root.current, else the newest)")
	fl.BoolVar(&rAll, "all", false, "recover: list every version found, not only the default selection")
}

func scan(dir string) (*stash.Recovery, error) {
	key, err := readKey()
	if err != nil {
		return nil, err
	}
	o := stash.RecoverOptions{Key: key, NoManifest: rNoManifest}
	if rGeneration != "" {
		g, err := strconv.ParseUint(rGeneration, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: generation %q", stash.ErrInvalid, rGeneration)
		}
		o.Generation = &g
	}
	return stash.Recover(dir, o)
}

func cmdRecover(e *env, _ *flag.FlagSet, args []string) error {
	rc, err := scan(args[0])
	if err != nil {
		return err
	}
	defer rc.Close()
	w := e.stdout
	auth := "root.current"
	if !rc.Authoritative {
		auth = "newest on disk (root.current unusable)"
	}
	fmt.Fprintf(w, "generation %d (%s)\n", rc.Generation, auth)
	switch {
	case rc.Keyless:
		fmt.Fprintln(w, "manifest   not read: encrypted archive scanned without the key (structure only)")
	case rc.Manifest.Loaded:
		fmt.Fprintf(w, "manifest   loaded, %d records\n", rc.Manifest.Records)
	case rNoManifest:
		fmt.Fprintln(w, "manifest   ignored")
	default:
		fmt.Fprintf(w, "manifest   damaged after %d records: %v\n", rc.Manifest.Records, rc.Manifest.Err)
	}
	damaged := false
	for _, b := range rc.Blobs {
		state := "ok"
		switch {
		case b.Err != nil:
			state, damaged = "unavailable: "+b.Err.Error(), true
		case len(b.Damaged) > 0:
			state, damaged = fmt.Sprintf("%d damaged regions, %d resync candidates", len(b.Damaged), b.Candidates), true
		}
		fmt.Fprintf(w, "blob %02X    %d frames, %s\n", b.Ordinal, b.Frames, state)
	}
	if g := rc.Groups; g.Total > 0 {
		fmt.Fprintf(w, "groups     %d: %d intact, %d degraded, %d unrecoverable; %d frames rebuilt\n", g.Total, g.Intact, g.Degraded, g.Unrecoverable, g.RebuiltFrames)
		damaged = damaged || g.Degraded+g.Unrecoverable > 0
	}
	vs := rc.DefaultSelection()
	if rAll || rc.Keyless {
		vs = rc.Versions
	}
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "\nVERSION\tSIZE\tSTATE\tPATH")
	for _, v := range vs {
		var st []string
		if v.Complete {
			st = append(st, "complete")
		} else {
			st = append(st, fmt.Sprintf("%d gaps", len(v.Gaps)))
			damaged = true
		}
		if v.Current {
			st = append(st, "current")
		} else if v.Committed {
			st = append(st, "committed")
		} else {
			st = append(st, "not known committed")
		}
		if v.Unverified {
			st = append(st, "unverified")
		}
		if v.Conflict {
			st = append(st, "CONFLICT")
		}
		name := v.Path
		if v.Opaque {
			name = fmt.Sprintf("<object %x>", v.ObjectID)
		}
		n := v.End
		if v.LengthKnown {
			n = v.Length
		}
		fmt.Fprintf(tw, "v%d\t%d\t%s\t%s\n", v.FileVer, n, strings.Join(st, ", "), name)
	}
	tw.Flush()
	if rc.OpaquePacked > 0 {
		fmt.Fprintf(w, "%d PACKED frames hold small objects that stay unknown without the key\n", rc.OpaquePacked)
	}
	if damaged {
		return problems{"damage found (stash salvage copies what was recovered into a new archive)"}
	}
	return nil
}

func cmdSalvage(e *env, _ *flag.FlagSet, args []string) error {
	rc, err := scan(args[0])
	if err != nil {
		return err
	}
	defer rc.Close()
	res, err := stash.Salvage(e.ctx, rc, args[1], rc.DefaultSelection())
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "salvaged %d versions, %s, into %s\n", res.Written, size(res.Bytes), args[1])
	for p, err := range res.Failed {
		fmt.Fprintf(e.stdout, "FAILED %s: %v\n", p, err)
	}
	if len(res.Failed) > 0 {
		return problems{fmt.Sprintf("%d versions could not be salvaged", len(res.Failed))}
	}
	return nil
}

// ---- HARDENED operator actions

var operator string

func operatorFlags(fl *flag.FlagSet) {
	fl.StringVar(&operator, "operator", "", "operator name recorded with the action (required)")
}

func operatorLog(e *env) func(string) {
	return func(s string) { fmt.Fprintln(e.stderr, s) }
}

func needOperator(needAnchor bool) (stash.Anchor, error) {
	if operator == "" {
		return nil, fmt.Errorf("%w: -operator is required", stash.ErrInvalid)
	}
	if !needAnchor {
		return nil, nil
	}
	if anchorDir == "" {
		return nil, fmt.Errorf("%w: -anchor is required", stash.ErrInvalid)
	}
	return openAnchor()
}

func cmdEnroll(e *env, _ *flag.FlagSet, args []string) error {
	a, err := needOperator(true)
	if err != nil {
		return err
	}
	key, err := readKey()
	if err != nil {
		return err
	}
	st, err := stash.EnrollWithKey(e.ctx, args[0], a, key, operator, operatorLog(e))
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "HARDENED: anchored generation %d, manifest length %d\n", st.GenerationID, st.ManifestLength)
	return nil
}

func cmdLeave(e *env, _ *flag.FlagSet, args []string) error {
	if _, err := needOperator(false); err != nil {
		return err
	}
	if err := stash.LeaveHardened(args[0], operator, operatorLog(e)); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "STANDARD: the archive no longer needs its anchor")
	return nil
}

func cmdAuthorize(e *env, _ *flag.FlagSet, args []string) error {
	a, err := needOperator(true)
	if err != nil {
		return err
	}
	key, err := readKey()
	if err != nil {
		return err
	}
	if err := stash.AuthorizeAnchorTransitionWithKey(e.ctx, args[0], a, key, operator, operatorLog(e)); err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "anchor advanced to the verified local state")
	return nil
}

// ---- mount

var (
	mAllowOther bool
	mDebug      bool
)

func mountFlags(fl *flag.FlagSet) {
	fl.BoolVar(&mAllowOther, "allow-other", false, "let other users access the mount")
	fl.BoolVar(&mDebug, "debug", false, "log every FUSE request")
}

func cmdMount(e *env, _ *flag.FlagSet, args []string) error {
	key, err := readKey()
	if err != nil {
		return err
	}
	a, err := openAnchor()
	if err != nil {
		return err
	}
	pol, err := policy()
	if err != nil {
		return err
	}
	logf := func(s string) { fmt.Fprintln(e.stderr, s) }
	srv, err := fusefs.Mount(args[0], args[1], fusefs.Options{Read: stash.ReadOptions{Key: key, Anchor: a, Policy: pol},
		AllowOther: mAllowOther, Debug: mDebug, Log: logf})
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stderr, "mounted %s on %s (read-only snapshot; mount again to see later commits); Ctrl-C or umount ends it\n", args[0], args[1])
	done := make(chan struct{})
	go func() {
		select {
		case <-e.ctx.Done():
			for {
				if err := srv.Unmount(); err == nil {
					return
				} else {
					logf("unmount: " + err.Error() + " (close open files; retrying)")
				}
				select {
				case <-done:
					return
				case <-time.After(2 * time.Second):
				}
			}
		case <-done:
		}
	}()
	srv.Wait()
	close(done)
	return nil
}
