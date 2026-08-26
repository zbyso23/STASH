package stash

import (
	"errors"
	"fmt"
)

var (
	// General state.
	ErrClosed          = errors.New("stash: archive closed")
	ErrReadOnly        = errors.New("stash: read-only")
	ErrNotFound        = errors.New("stash: object not found")
	ErrAlreadyExists   = errors.New("stash: object already exists")
	ErrInvalidArgument = errors.New("stash: invalid argument")

	// Archive / wire compatibility.
	ErrInvalidArchive     = errors.New("stash: invalid archive")
	ErrUnsupportedVersion = errors.New("stash: unsupported wire version")
	ErrUnsupportedFeature = errors.New("stash: unsupported feature")

	// Integrity.
	ErrCorruption = errors.New("stash: corruption detected")
	ErrConflict   = errors.New("stash: conflicting archive state")
	ErrIncomplete = errors.New("stash: incomplete archive state")

	// Storage / durability.
	ErrBackend    = errors.New("stash: backend failure")
	ErrDurability = errors.New("stash: durability failure")

	// Security.
	ErrKeyRequired    = errors.New("stash: encryption key required")
	ErrAuthentication = errors.New("stash: authentication failed")
)

type Error struct {
	Op         string
	Kind       error
	Path       string
	Blob       *uint8
	Generation *uint64
	Offset     *uint64
	Err        error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}

	msg := "stash"

	if e.Op != "" {
		msg += ": " + e.Op
	}

	if e.Path != "" {
		msg += ": path=" + e.Path
	}

	if e.Blob != nil {
		msg += fmt.Sprintf(": blob=%d", *e.Blob)
	}

	if e.Generation != nil {
		msg += fmt.Sprintf(": generation=%d", *e.Generation)
	}

	if e.Offset != nil {
		msg += fmt.Sprintf(": offset=0x%x", *e.Offset)
	}

	switch {
	case e.Err != nil:
		msg += ": " + e.Err.Error()
	case e.Kind != nil:
		msg += ": " + e.Kind.Error()
	}

	return msg
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}

	if e.Err != nil {
		return e.Err
	}

	return e.Kind
}

func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}

	return errors.Is(e.Kind, target) || errors.Is(e.Err, target)
}

type IntegrityCode string

const (
	IntegrityPrefixCRC          IntegrityCode = "PREFIX_CRC"
	IntegrityTrailerCRC         IntegrityCode = "TRAILER_CRC"
	IntegrityPayloadHash        IntegrityCode = "PAYLOAD_HASH"
	IntegrityGeometry           IntegrityCode = "GEOMETRY"
	IntegrityPadding            IntegrityCode = "PADDING"
	IntegrityPreTrailer         IntegrityCode = "PRE_TRAILER"
	IntegrityObjectID           IntegrityCode = "OBJECT_ID"
	IntegrityLogicalOverlap     IntegrityCode = "LOGICAL_OVERLAP"
	IntegrityLogicalGap         IntegrityCode = "LOGICAL_GAP"
	IntegrityManifestMismatch   IntegrityCode = "MANIFEST_MISMATCH"
	IntegrityIndexMismatch      IntegrityCode = "INDEX_MISMATCH"
	IntegrityParityGroup        IntegrityCode = "PARITY_GROUP"
	IntegrityGenerationConflict IntegrityCode = "GENERATION_CONFLICT"
)

type IntegrityError struct {
	Code       IntegrityCode
	Blob       *uint8
	Generation *uint64
	Offset     *uint64
	ObjectID   *[16]byte
	Err        error
}

func (e *IntegrityError) Error() string {
	if e == nil {
		return "<nil>"
	}

	if e.Err != nil {
		return fmt.Sprintf("stash: integrity %s: %v", e.Code, e.Err)
	}

	return fmt.Sprintf("stash: integrity %s", e.Code)
}

func (e *IntegrityError) Unwrap() error {
	return e.Err
}

func (e *IntegrityError) Is(target error) bool {
	return target == ErrCorruption
}
