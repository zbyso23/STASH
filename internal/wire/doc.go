// Package wire holds the STASH R10 (wire 0x0006) constants and the codecs of
// the fixed-size binary structures: Archive Header (§2.2), root.current
// (§2.1.1), Allocator State (§2.1.3), Frame Prefix (§6.1), Master Trailer
// (§6.2), and the physical index header and record (§10.5).
//
// Decoders validate everything that can be validated from the structure
// alone and return a value only when it is valid. Checks that need archive
// context (header agreement, block-type rules, parity invariants) are separate
// functions so callers cannot skip them by accident: see ValidateTrailer.
//
// The package is internal so that callers cannot construct partially valid
// frames.
package wire
