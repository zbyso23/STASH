# STASH Go reference implementation — status

Spec: `SPEC.md` (STASH 2.0 R10 with Erratum E1, wire `0x0006`). Go 1.24+.

## Milestone 1 — wire constants and fixed-size structures (done)

| Package | Content | SPEC |
|---|---|---|
| `internal/checked` | overflow-checked add/sub/mul/range helpers | §16.1 |
| `internal/wire` | constants, error classes, CRC32C | §2–§7, §16 |
| | Archive Header codec + validation (legacy versions 0x0002–0x0005 refused as `ErrLegacyVersion`) | §2.2, §2.3, §7, §14 |
| | `root.current` codec | §2.1.1 |
| | Allocator State codec, kinds 0–4, reservation block and SKIP policy | §2.1.3 |
| | Frame Prefix codec with header bounds and FIXED rule | §6.1 |
| | Master Trailer codec + `ValidateTrailer` (block types, placement, STORE length, parity invariants) | §6.2, §6.6, §7 |
| | frame tail reverse parse with outer Pre-Trailer CRC | §6.4.3 |
| | frame grid, FIXED slots, exact payload budget, parity shard length | §3, §6.3, §7.1 |
| | physical index header and record codecs | §10.5 |
| | canonical LEB128 `path_len` | §6.4.1 |

Tests (`go test ./...`):

- golden vectors from `testdata/gen/gen_golden.py`, an independent Python generator (own CRC32C, `struct.pack`); checked encoder→bytes, bytes→decoder, round trip (§17.1);
- every single-bit flip of the Frame Prefix, of the Master Trailer + `pre_trailer_len` + minimal Pre-Trailer, of `root.current` and of Allocator State is rejected (§17.2);
- arithmetic boundaries 0 / max / max+1 / MaxUint32 / MaxUint64 / overflow / truncation (§17.4);
- fuzz targets for every decoder (`go test ./internal/wire -fuzz FuzzDecodeArchiveHeader`, …) (§17.3).

Regenerate golden vectors: `python3 testdata/gen/gen_golden.py`.

## Next milestones

2. Pre-Trailer (plaintext) + canonical paths (NFC, Unicode 15.0 table) + `object_id` + complete frame codec (needs `golang.org/x/text`).
3. Blob I/O with a crash-injection filesystem abstraction.
4. Physical index files. 5. Manifest (strict JSON, transactions, `ADD_ABORT`, live-state fold). Then the order of README.
