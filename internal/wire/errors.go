package wire

import (
	"errors"
	"fmt"
)

// Error classes. Every error returned by this package wraps exactly one.
var (
	// ErrCorrupt: bytes violate the format.
	ErrCorrupt = errors.New("corrupt")
	// ErrUnsupported: a reserved or unknown identifier (fail closed).
	ErrUnsupported = errors.New("unsupported")
	// ErrLegacyVersion: a recognized pre-0x0006 wire version (§14).
	ErrLegacyVersion = errors.New("unsupported legacy wire version")
	// ErrResource: a value exceeds a configured or wire ceiling.
	ErrResource = errors.New("resource limit exceeded")
	// ErrInvalid: the caller asked to encode an invalid value.
	ErrInvalid = errors.New("invalid value")
)

// Error describes which structure and field failed.
type Error struct {
	Struct string
	Field  string
	Class  error
	Detail string
}

func (e *Error) Error() string {
	s := "stash: " + e.Struct
	if e.Field != "" {
		s += "." + e.Field
	}
	s += ": " + e.Class.Error()
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func (e *Error) Unwrap() error { return e.Class }

func errf(class error, st, field, format string, args ...any) error {
	return &Error{Struct: st, Field: field, Class: class, Detail: fmt.Sprintf(format, args...)}
}
