# 🌀 STASH

**Self-describing Tagged Archive Streamable Heaps**

🌀 STASH is an open archival format designed for server, enterprise, and datacenter workloads where recovery, integrity, and predictable behavior matter more than minimizing every byte of overhead.

It stores data in immutable, grid-aligned frames distributed across one or more append-only blobs. Frames carry enough physical and recovery metadata to be discovered, validated, and reconstructed without trusting normal indexes or the primary manifest.

> **Project status:** 🌀 STASH 2.0 Revision R8, wire version `0x0006`, is frozen. The project is now in the Go reference-implementation phase, developed with a test-first conformance workflow.

## Why 🌀 STASH exists

Many archive formats are straightforward to write but difficult to recover when indexes, catalogs, filenames, or surrounding metadata are damaged. 🌀 STASH treats disaster recovery as a format-level property rather than an implementation afterthought.

The format is built around these priorities:

1. **Predictable grid geometry** — every physical frame occupies a validated multiple of 4096 bytes.
2. **Immutable Copy-on-Write storage** — committed frames are never modified in place.
3. **Self-describing recovery** — raw blobs retain the information needed to discover frame geometry, integrity state, parity membership, and recoverable logical metadata.
4. **Whole-frame integrity and conservative deduplication** — hashes cover the exact stored payload representation; physical sharing must not destroy independent recovery identity.
5. **Enterprise throughput** — independent blob writers, indexed normal access, parallel recovery where geometry permits it, and bounded streaming processing.

🌀 STASH is intended for archival storage, verifiable replication, incremental backup, disaster recovery, and long-lived datasets. It is not intended to replace ZIP, TAR, or a general-purpose desktop filesystem.

> **Checksums and hashes detect corruption; redundancy repairs it.**

CRC32C, content hashes, and AEAD authentication detect damage or tampering. They do not reconstruct missing bytes. Repair requires parity, another intact copy, external replication, or another recovery source.

## Core design

- Append-only writes and immutable committed frames
- Copy-on-Write logical updates through new frames and manifest records
- One to 255 independently writable blobs per generation
- 4096-byte base quantum
- 64-byte Archive Header at the start of every blob
- 16-byte Frame Prefix at the start of every frame
- 96-byte Master Trailer at the end of every frame
- VARIABLE and FIXED frame-size modes selected at archive creation
- Explicit logical placement for non-packed DATA
- Self-describing parity-group membership
- PACKED frames for small objects
- Rebuildable per-blob physical offset indexes
- Append-only JSONL manifest with bounded transactional records
- XOR and Reed-Solomon parity
- Optional AES-256-GCM authenticated encryption
- Crash-safe generation switching and compaction
- Bounded parsing, checked arithmetic, and streamable archive-scale processing

### Deliberately narrow algorithm surface

🌀 STASH R8 intentionally keeps the algorithm matrix small:

```text
HASH
    SHA-256
    BLAKE3

COMPRESSION
    STORE
    ZSTD_FAST      level 1
    ZSTD_DEFAULT   level 3
    ZSTD_DENSE     level 9

PARITY
    NONE
    XOR
    REED-SOLOMON

ENCRYPTION
    NONE
    AES-256-GCM

KDF
    HKDF-SHA-256
```

Unknown or reserved wire identifiers fail closed.

## Deployment profiles

The profile names are presets over existing archive parameters; no separate `profile_id` is stored on disk.

| Profile | Hash | Compression | Encryption | Intended use |
|---|---|---|---|---|
| **BASELINE** | SHA-256 | STORE | none | Minimum interoperable profile |
| **SECURE** | SHA-256 | STORE | AES-256-GCM | Conservative authenticated archival profile |
| **FAST** | BLAKE3 | ZSTD_FAST | none | High-throughput ingest and recovery |

The Go reference implementation is intended to support all three profiles.

Geometry, parity, blob count, PACKED support, and `MAX_FRAME_SIZE` remain orthogonal archive properties.

## Two immutable frame-size modes

The archive selects its frame-size mode at creation time. The mode is immutable for the lifetime of that archive.

### VARIABLE

`VARIABLE` is the normal/default enterprise mode.

Each frame may choose its physical size as a positive multiple of 4096 bytes, bounded by the archive's configured maximum frame size:

```text
frame_size = frame_quanta * 4096
```

This reduces padding and allows physical allocation to match stored data more closely.

A VARIABLE frame begins with a validated Frame Prefix containing its physical extent, allowing raw recovery to advance deterministically from one valid frame to the next.

VARIABLE geometry does **not** make arbitrary byte insertions free. Non-packed DATA uses explicit absolute logical placement; an insert or delete that shifts later logical offsets may require replacement metadata for affected downstream extents. Committed frames themselves remain immutable.

### FIXED

Every frame occupies exactly `MAX_FRAME_SIZE`.

This restores direct slot arithmetic:

```text
frame_start(n) = 0x40 + n * MAX_FRAME_SIZE
```

FIXED is intended for workloads where deterministic slot geometry, direct physical addressing, and maximum recovery-scan parallelism justify the additional padding.

## Physical layout

Every blob begins with a 64-byte Archive Header:

```text
0x0000  Archive Header, 64 bytes
0x0040  frame area begins
```

Every physical frame has the form:

```text
[ Frame Prefix: 16 B ]
[ stored payload ]
[ zero padding ]
[ Pre-Trailer ]
[ pre_trailer_len: 4 B ]
[ Master Trailer: 96 B ]
```

The complete frame size is always an integral multiple of 4096 bytes.

The Frame Prefix allows VARIABLE-mode recovery to validate frame geometry before reading or allocating the complete frame. The Master Trailer carries immutable frame metadata used for integrity, logical reconstruction, hashing, and parity discovery.

The normative byte layout is defined only by [`SPEC.md`](SPEC.md).

## Integrity and recovery

Normal reads use a mandatory rebuildable physical offset index:

```text
frame_hash -> one or more physical frame candidates
```

The index is maintained for performance but is not authoritative for correctness. If it is missing, stale, or corrupt, 🌀 STASH can rebuild it from raw blob scanning.

Disaster recovery deliberately follows an independent path:

1. discover and validate blob Archive Headers;
2. group compatible blobs by archive and generation identity;
3. scan FIXED slots or VARIABLE 4096-byte-aligned frame boundaries;
4. validate Frame Prefix geometry before large reads or allocations;
5. validate frame integrity and stored payload hashes;
6. rebuild physical indexes;
7. reconstruct logical objects from surviving self-describing metadata;
8. discover parity groups directly from frame metadata;
9. use XOR/Reed-Solomon recovery when sufficient members survive;
10. surface gaps, conflicts, degraded data, or unrecoverable data explicitly.

A corrupt frame must not terminate recovery of unrelated later frames where resynchronization is possible.

### Deduplication semantics

`hash_payload` covers the exact stored payload representation.

A matching payload hash is a **candidate lookup key**, not by itself proof that two frames are interchangeable. Physical sharing is allowed only when the recovery-visible identity required by the format is compatible as well.

This deliberately favors manifest-independent disaster recovery over aggressive payload-only deduplication.

🌀 STASH does not define:

- sub-frame content-defined deduplication;
- convergent encryption;
- cross-archive plaintext deduplication;
- cross-tenant plaintext deduplication.

## Parity and repair

🌀 STASH supports:

```text
NONE
XOR
Reed-Solomon
```

Members of one parity group have identical physical frame geometry and, when parity is enabled, the group must span more than one blob.

Parity operates over a normatively defined recovery representation so that a successfully reconstructed member can recover the data and metadata needed to rebuild a valid frame, rather than only reconstructing an opaque payload fragment.

Parity metadata is self-describing, so group discovery does not depend on the manifest.

## Encryption

Encrypted archives use:

```text
AES-256-GCM
12-byte nonce
16-byte authentication tag
HKDF-SHA-256 key separation
```

The Archive Header explicitly identifies whether encryption is enabled.

Independent derived AEAD keys are used for:

- frame payloads;
- encrypted Pre-Trailer metadata;
- manifest records.

Stored nonces are authoritative for decryption. Normal compaction copies encrypted live frames byte-for-byte and does not decrypt and re-encrypt them merely because their physical location changes.

Without keys, recovery can still perform the keyless structural work permitted by the format, such as discovering physical frame geometry and parity structure. Protected plaintext paths and encrypted logical metadata require the archive key.

A deployment may rotate a KEK/KMS wrapping key without changing frame bytes. Changing the archive DEK requires explicit migration to a new archive.

## Threat model note

🌀 STASH provides strong structural validation, content-integrity checks, authenticated encryption when enabled, and optional erasure recovery.

The format alone is not a trusted external anti-rollback service. A deployment that must detect restoration of an older but previously valid generation should anchor the current archive state in a trusted external system, such as protected control-plane metadata, a KMS-backed state record, or another authenticated monotonic store.

## Manifest and logical state

`manifest.jsonl` is an append-only logical journal.

Manifest processing is bounded and streaming. Large objects use multi-record transactions rather than unbounded JSON lines:

```text
ADD_BEGIN
ADD_EXTENT
...
ADD_COMMIT
```

A large-object transaction becomes visible only after a valid durable commit record.

For encrypted archives, manifest sequence numbers share one generation-wide nonce namespace across the complete manifest graph. A sequence number must not be reused under the same manifest AEAD key.

The normative operation schemas and encodings are defined in `SPEC.md`.

## Compaction and generations

Compaction follows the lifecycle:

```text
Mark
  ↓
Sweep
  ↓
Freeze / Merge
  ↓
Switch
  ↓
GC
```

A new generation is built without modifying the currently authoritative generation in place.

The new generation becomes authoritative only after its required blobs, manifest state, indexes, and root metadata are durable. The root switch is atomic.

Encrypted live frames are copied byte-for-byte during ordinary compaction.

If required live data cannot be verified in the destination, garbage collection is blocked rather than silently discarding the only surviving copy.

Emergency Pruning is an explicit operator-authorized data-loss path and must perform parity-impact analysis and record degraded or unrecoverable state durably.

## Reference implementation architecture

The Go library is the authoritative implementation of wire parsing, validation, manifests, indexing, parity, recovery, compaction, and encryption semantics.

```text
                 +------------------------+
                 |   Go 🌀 STASH library   |
                 |   format + operations   |
                 +-----------+------------+
                             |
                +------------+------------+
                |                         |
         +------v------+           +------v------+
         |  stash CLI  |           | FUSE adapter|
         | thin client |           |  read-only  |
         +-------------+           +-------------+
```

The CLI and FUSE adapter call only the public library API. They must not implement independent wire-format parsers or recovery logic.

### Planned Go library responsibilities

- Create and open archives
- Transactional add, delete, and rename operations
- Streaming object listing
- Sequential and random object reads
- Structural and full-content verification
- Raw disaster recovery
- Physical-index rebuilding
- Compaction and garbage collection
- Storage backend abstraction
- Key-provider integration

Wire structures and binary codecs remain internal packages so callers cannot construct partially valid frames.

## Planned CLI surface

The reference executable is named `stash`.

Planned command families:

```text
stash create
stash add
stash remove
stash rename
stash extract
stash list
stash stat
stash verify
stash recover
stash index rebuild
stash compact
stash gc status
stash gc emergency-prune
stash mount
```

Recommended archive creation surface:

```text
stash create ARCHIVE
    --profile baseline|secure|fast
    --mode variable|fixed
    --max-frame-size SIZE
    --blobs N
    --parity none|xor|rs
    [--parity-k K --parity-m M]
    [--key-provider NAME]
```

These commands describe the intended reference interface; availability depends on the implementation milestone reached.

## Read-only FUSE

The official FUSE adapter is permanently read-only.

A mount pins one validated `generation_id` for its lifetime, providing a stable snapshot even if compaction creates and switches to a newer generation in the background.

All mutation attempts return `EROFS`.

The adapter does not mutate blobs, manifests, persistent indexes, generations, or root metadata.

If persistent indexes are missing, the adapter may construct temporary in-memory lookup state through the public Go library.

## Specification

The normative format definition is:

- [`SPEC.md`](SPEC.md) — **🌀 STASH 2.0 Revision R8**, wire version `0x0006`

The specification defines binary layouts, manifest encoding, invariants, validation order, recovery behavior, concurrency, parity, compaction, encryption, resource limits, and required conformance tests.

If this README and the specification disagree, **the specification wins**.

> **🌀 STASH 2.0 R8 / wire `0x0006` is frozen. Further wire-format changes require evidence from implementation, conformance testing, fuzzing, crash injection, recovery testing, interoperability testing, security analysis, or measured performance results.**

## Development approach

The reference implementation is developed with strict TDD.

Every new behavior follows:

```text
R8 invariant
    ↓
failing test
    ↓
minimum implementation
    ↓
boundary / corruption test
    ↓
refactor
    ↓
fuzz / crash / recovery validation where applicable
    ↓
exit gate
```

The R8 required test matrix is part of the specification and is **not optional implementation guidance**.

Implementation milestones progress approximately through:

```text
wire constants and checked arithmetic
    ↓
Archive Header / Frame Prefix / Master Trailer / Pre-Trailer codecs
    ↓
frame geometry and complete frame codec
    ↓
blob I/O
    ↓
physical offset indexes
    ↓
manifest transactions and durability
    ↓
logical reconstruction and Copy-on-Write
    ↓
PACKED frames
    ↓
raw disaster recovery
    ↓
XOR / Reed-Solomon parity
    ↓
compaction and generation switching
    ↓
cryptography
    ↓
public Go API
    ↓
CLI
    ↓
read-only FUSE
    ↓
fuzzing / crash injection / recovery torture
    ↓
performance baselines
```

Independent golden vectors must not be generated by the production encoder under test.

Every untrusted parser is expected to receive fuzz coverage, and every persistent mutation path is expected to receive crash-injection coverage.

## Intended repository layout

```text
.
├── README.md
├── SPEC.md
├── ROADMAP.md
├── go.mod
├── go.sum
│
├── archive.go
├── create.go
├── open.go
├── transaction.go
├── object.go
├── verify.go
├── recover.go
├── compact.go
├── errors.go
├── types.go
├── options.go
│
├── internal/
│   ├── wire/
│   ├── blob/
│   ├── index/
│   ├── manifest/
│   ├── object/
│   ├── packed/
│   ├── recovery/
│   ├── parity/
│   ├── compact/
│   └── testutil/
│
├── cmd/
│   └── stash/
│
├── fuse/
├── integration/
├── testdata/
└── bench/
```

The repository root is the Go module root. The public library, CLI, read-only FUSE adapter, conformance tests, recovery tests, and specification are versioned together.

Package boundaries should follow dependency direction rather than mirror every specification section mechanically.

## Non-goals for 🌀 STASH 2.0

- General-purpose desktop archive replacement
- Writable POSIX filesystem semantics
- Full POSIX metadata fidelity as a wire-format goal
- In-place committed-frame mutation
- Sub-block or content-defined chunking deduplication
- Convergent or cross-tenant plaintext deduplication
- Dependence on a proprietary catalog for correctness
- Tape-specific optimization
- Mixing frame-size modes inside one archive
- Network protocol or distributed consensus
- IAM/RBAC policy model
- A built-in trusted anti-rollback service

## Contributing

The project is now entering the reference-implementation and conformance phase.

Early contributions are most valuable in:

- independent review of R8 invariants;
- independently constructed binary golden vectors;
- adversarial recovery and corruption fixtures;
- Go binary-codec and bounded-allocation review;
- checked-arithmetic review;
- manifest crash-safety tests;
- parity interoperability tests;
- compaction and generation-switch tests;
- fuzzing and crash-injection infrastructure;
- filesystem and object-storage backend testing;
- reproducible performance benchmarks.

Speculative format additions are not sufficient reason to reopen R8.

A proposed wire-format change should be backed by concrete implementation evidence such as a minimal reproducer, failing conformance test, interoperability failure, security finding, recovery failure, or measured performance result.

## License

🌀 STASH is open-source software licensed under the [MIT License](LICENSE).

**Author:** © 2025-2026 Zbigniew Lipka
