package manifest

import (
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"stash/internal/wire"
)

// A strict JSON parser for one manifest line (SPEC §10.1.1). It accepts
// every valid JSON text (insignificant whitespace included) and rejects
// invalid UTF-8, lone surrogate escapes, duplicate object keys and nesting
// deeper than maxDepth. Schema rules are applied afterwards by decode.

const maxDepth = 8

type kind uint8

const (
	kString kind = iota + 1
	kNumber
	kArray
	kObject
	kBool
	kNull
)

func (k kind) String() string {
	return [...]string{"", "string", "number", "array", "object", "boolean", "null"}[k]
}

type value struct {
	kind kind
	s    string // string content, number literal, or "true"/"false"
	arr  []value
	obj  []member
}

type member struct {
	key string
	val value
}

type parser struct {
	b   []byte
	pos int
}

func corrupt(format string, args ...any) error {
	return &wire.Error{Struct: "Manifest", Class: wire.ErrCorrupt, Detail: fmt.Sprintf(format, args...)}
}

func parseJSON(b []byte) (value, error) {
	if !utf8.Valid(b) {
		return value{}, corrupt("line is not valid UTF-8")
	}
	p := parser{b: b}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return value{}, err
	}
	p.ws()
	if p.pos != len(b) {
		return value{}, corrupt("trailing data at byte %d", p.pos)
	}
	return v, nil
}

func (p *parser) ws() {
	for p.pos < len(p.b) {
		switch p.b[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) errAt(what string) error { return corrupt("%s at byte %d", what, p.pos) }

func (p *parser) value(depth int) (value, error) {
	if depth > maxDepth {
		return value{}, p.errAt("nesting too deep")
	}
	if p.pos >= len(p.b) {
		return value{}, p.errAt("unexpected end")
	}
	switch c := p.b[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		return value{kind: kString, s: s}, err
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.lit("true"):
		return value{kind: kBool, s: "true"}, nil
	case p.lit("false"):
		return value{kind: kBool, s: "false"}, nil
	case p.lit("null"):
		return value{kind: kNull}, nil
	}
	return value{}, p.errAt("invalid value")
}

func (p *parser) lit(s string) bool {
	if len(p.b)-p.pos >= len(s) && string(p.b[p.pos:p.pos+len(s)]) == s {
		p.pos += len(s)
		return true
	}
	return false
}

func (p *parser) object(depth int) (value, error) {
	p.pos++ // {
	v := value{kind: kObject}
	p.ws()
	if p.pos < len(p.b) && p.b[p.pos] == '}' {
		p.pos++
		return v, nil
	}
	for {
		p.ws()
		if p.pos >= len(p.b) || p.b[p.pos] != '"' {
			return value{}, p.errAt("expected object key")
		}
		k, err := p.str()
		if err != nil {
			return value{}, err
		}
		for _, m := range v.obj {
			if m.key == k {
				return value{}, corrupt("duplicate key %q", k)
			}
		}
		p.ws()
		if p.pos >= len(p.b) || p.b[p.pos] != ':' {
			return value{}, p.errAt("expected ':'")
		}
		p.pos++
		p.ws()
		val, err := p.value(depth + 1)
		if err != nil {
			return value{}, err
		}
		v.obj = append(v.obj, member{k, val})
		p.ws()
		if p.pos >= len(p.b) {
			return value{}, p.errAt("unterminated object")
		}
		switch p.b[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return v, nil
		default:
			return value{}, p.errAt("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (value, error) {
	p.pos++ // [
	v := value{kind: kArray}
	p.ws()
	if p.pos < len(p.b) && p.b[p.pos] == ']' {
		p.pos++
		return v, nil
	}
	for {
		p.ws()
		e, err := p.value(depth + 1)
		if err != nil {
			return value{}, err
		}
		v.arr = append(v.arr, e)
		p.ws()
		if p.pos >= len(p.b) {
			return value{}, p.errAt("unterminated array")
		}
		switch p.b[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return v, nil
		default:
			return value{}, p.errAt("expected ',' or ']'")
		}
	}
}

func (p *parser) number() (value, error) {
	start := p.pos
	if p.b[p.pos] == '-' {
		p.pos++
	}
	digits := func() int {
		n := 0
		for p.pos < len(p.b) && p.b[p.pos] >= '0' && p.b[p.pos] <= '9' {
			p.pos++
			n++
		}
		return n
	}
	if p.pos < len(p.b) && p.b[p.pos] == '0' {
		p.pos++
	} else if digits() == 0 {
		return value{}, p.errAt("invalid number")
	}
	if p.pos < len(p.b) && p.b[p.pos] == '.' {
		p.pos++
		if digits() == 0 {
			return value{}, p.errAt("invalid fraction")
		}
	}
	if p.pos < len(p.b) && (p.b[p.pos] == 'e' || p.b[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.b) && (p.b[p.pos] == '+' || p.b[p.pos] == '-') {
			p.pos++
		}
		if digits() == 0 {
			return value{}, p.errAt("invalid exponent")
		}
	}
	return value{kind: kNumber, s: string(p.b[start:p.pos])}, nil
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

func (p *parser) u4() (rune, error) {
	if len(p.b)-p.pos < 4 {
		return 0, p.errAt("short \\u escape")
	}
	var r rune
	for i := 0; i < 4; i++ {
		h, ok := hexVal(p.b[p.pos+i])
		if !ok {
			return 0, p.errAt("invalid \\u escape")
		}
		r = r<<4 | h
	}
	p.pos += 4
	return r, nil
}

func (p *parser) str() (string, error) {
	p.pos++ // opening quote
	start := p.pos
	// fast path: no escapes
	for p.pos < len(p.b) {
		c := p.b[p.pos]
		if c == '"' {
			s := string(p.b[start:p.pos])
			p.pos++
			return s, nil
		}
		if c == '\\' {
			break
		}
		if c < 0x20 {
			return "", p.errAt("raw control character in string")
		}
		p.pos++
	}
	out := append([]byte(nil), p.b[start:p.pos]...)
	for p.pos < len(p.b) {
		c := p.b[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", p.errAt("raw control character in string")
		case c != '\\':
			out = append(out, c)
			p.pos++
			continue
		}
		p.pos++
		if p.pos >= len(p.b) {
			break
		}
		e := p.b[p.pos]
		p.pos++
		switch e {
		case '"', '\\', '/':
			out = append(out, e)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, err := p.u4()
			if err != nil {
				return "", err
			}
			if utf16.IsSurrogate(r) {
				if r >= 0xDC00 || len(p.b)-p.pos < 6 || p.b[p.pos] != '\\' || p.b[p.pos+1] != 'u' {
					return "", p.errAt("lone surrogate escape")
				}
				p.pos += 2
				lo, err := p.u4()
				if err != nil {
					return "", err
				}
				if r = utf16.DecodeRune(r, lo); r == utf8.RuneError {
					return "", p.errAt("invalid surrogate pair")
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return "", p.errAt("invalid escape")
		}
	}
	return "", p.errAt("unterminated string")
}
