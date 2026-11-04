// Package canonpath implements canonical object paths (SPEC §6.4.5).
//
// A canonical path is valid UTF-8 in Unicode NFC, relative, uses '/' as the
// only separator, has no empty, "." or ".." component, contains no NUL,
// backslash, C0 or C1 control character, U+007F, surrogate, or code point
// unassigned in Unicode 15.0 (General Category Cn, which includes the
// noncharacters), and is at most 4096 bytes. Ordering is bytewise.
package canonpath

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxLen is the maximum canonical path length in bytes.
const MaxLen = 4096

// ErrInvalid is wrapped by every validation error.
var ErrInvalid = errors.New("stash: invalid canonical path")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func init() {
	// NFC must come from Unicode 15.0 data (§6.4.5). Fail loudly if a
	// dependency upgrade changes it.
	if norm.Version != "15.0.0" {
		panic("canonpath: x/text/unicode/norm tables are " + norm.Version + ", need 15.0.0")
	}
}

// Validate checks that p is already canonical. Readers use it: they never
// normalize media values.
func Validate(p string) error {
	if len(p) == 0 {
		return invalid("empty")
	}
	if len(p) > MaxLen {
		return invalid("%d bytes > %d", len(p), MaxLen)
	}
	if !utf8.ValidString(p) { // also rejects encoded surrogates
		return invalid("not valid UTF-8")
	}
	if p[0] == '/' {
		return invalid("absolute")
	}
	for i, r := range p {
		switch {
		case r < 0x20, r == 0x7F, r >= 0x80 && r <= 0x9F:
			return invalid("control character U+%04X at byte %d", r, i)
		case r == '\\':
			return invalid("backslash at byte %d", i)
		case !Assigned(r):
			return invalid("code point U+%04X unassigned in Unicode 15.0", r)
		}
	}
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "":
			return invalid("empty component")
		case ".", "..":
			return invalid("%q component", c)
		}
	}
	if !norm.NFC.IsNormalString(p) {
		return invalid("not NFC")
	}
	return nil
}

// Normalize converts writer input to NFC and validates the result. It does
// not rewrite separators or strip components: input that is not already a
// clean relative path is rejected, never guessed at.
func Normalize(p string) (string, error) {
	if !utf8.ValidString(p) {
		return "", invalid("not valid UTF-8")
	}
	n := norm.NFC.String(p)
	if err := Validate(n); err != nil {
		return "", err
	}
	return n, nil
}

// Compare orders canonical paths bytewise, shorter prefix first (§6.4.5).
func Compare(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) }

// Assigned reports whether r is assigned (General Category not Cn) in
// Unicode 15.0.0.
func Assigned(r rune) bool {
	i := sort.Search(len(assigned15), func(i int) bool { return assigned15[i][1] >= r })
	return i < len(assigned15) && assigned15[i][0] <= r
}
