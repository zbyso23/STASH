# 🌀 STASH

**Self-describing Tagged Archive Streamable Heaps**

🌀 STASH is an open archival format designed for server, enterprise, and datacenter workloads where recovery, integrity, and predictable behavior matter more than minimizing every byte of overhead.

It stores data in immutable, grid-aligned frames distributed across one or more append-only blobs. Frames carry enough physical and recovery metadata to be discovered, validated, and reconstructed without trusting normal indexes or the primary manifest.

> **Project status:** 🌀 STASH 2.0 Revision R10 is frozen at wire version `0x0006`. R10 completes R9: it defines encodings R9 left open, closes nonce-reuse and rollback gaps found in review, and keeps the R8/R9 binary structure layouts unchanged. Erratum E1, applied before any implementation existed, is part of R10 (SPEC §20.5). The project is now in the Go reference-implementation phase, developed with a test-first conformance workflow.

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

🌀 STASH R10 intentionally keeps the algorithm matrix small:

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

### Security policies

R10 separates data-processing profiles from deployment security policy.

```text
STANDARD
    no trusted external anti-rollback anchor required

HARDENED
    trusted external Generation Anchor required
```

`BASELINE`, `SECURE`, and `FAST` select hash/compression/encryption behavior. `STANDARD` and `HARDENED` select freshness/anti-rollback guarantees. They are orthogonal.

Common combinations include:

```text
BASELINE + STANDARD
SECURE   + STANDARD
SECURE   + HARDENED
FAST     + STANDARD
FAST     + HARDENED
```

`SECURE + HARDENED` is the recommended configuration for adversarial enterprise storage. `FAST + HARDENED` is valid when freshness matters even though confidentiality is not required.

HARDENED is not a wire feature. Enabling it does not change archive bytes and does not introduce a new `profile_id`, header field, or wire version.

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

VARIABLE geometry does **not** make modifications cheap. Every object version is self-contained: each frame records the path and version it belongs to, so a new version never shares frames with an older one. Changing, appending to, or renaming an object rewrites that object. Committed frames themselves remain immutable.

### FIXED

Every frame occupies exactly `MAX_FRAME_SIZE`.

This restores direct slot arithmetic:

```text
frame_start(n) = 0x40 + n * MAX_FRAME_SIZE
```

FIXED is intended for workloads where deterministic slot geometry, direct physical addressing, and maximum recovery-scan parallelism justify the additional padding.

## Workload fit

Self-contained versions are a deliberate trade-off: they let raw recovery rebuild every version without the manifest, at the cost of rewriting an object whenever it changes.

🌀 STASH is a strong fit for:

- archival objects;
- backups and snapshots;
- append-oriented logs;
- WAL/archive-log retention;
- immutable segments and SSTable-like files;
- media objects;
- versioned datasets;
- data modeled as many immutable objects (segments, chunks, log files), so that a change rewrites only the affected objects.

🌀 STASH is **not** optimized to act as a block store for one large mutable object. Every change to an object, including an append, writes a complete new version of it.

This does not make database workloads categorically unsuitable. Append logs, immutable table segments, checkpoints, dumps, and snapshots can be natural 🌀 STASH workloads; the poor fit is specifically one large object that changes often. Incremental backups fit well when each backup increment is stored as its own objects.

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

The complete frame size is always an integral multiple of 4096 bytes. Frames start at `0x40 + j * 4096`, so frame boundaries sit 64 bytes past absolute 4 KiB boundaries; the last 64 bytes of each frame share a storage page with the start of the next frame, and writers preserve those bytes when appending.

Each archive also keeps small 64-byte **Allocator State** files that reserve generation IDs, object versions, frame ordinals, manifest sequence numbers, and parity group IDs before use, so that no identifier (and, when encrypted, no AES-GCM nonce) is ever reused after a crash.

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
3. scan FIXED slots or VARIABLE frame-grid boundaries (`0x40 + j * 4096`);
4. validate Frame Prefix geometry before large reads or allocations;
5. validate frame integrity and stored payload hashes;
6. rebuild physical indexes;
7. reconstruct logical objects from surviving self-describing metadata;
8. discover parity groups directly from frame metadata;
9. use XOR/Reed-Solomon recovery when sufficient members survive;
10. surface gaps, conflicts, degraded data, or unrecoverable data explicitly.

A corrupt frame must not terminate recovery of unrelated later frames where resynchronization is possible. Frames found only by resynchronization, and every frame after them in that blob, are labeled as unverified provenance, because payload bytes can imitate a frame.

Without a manifest, recovery returns every reconstructable object version, including deleted and superseded ones; it does not claim to know which version was current.

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

Reed-Solomon uses a fixed, fully specified code (GF(2^8) with polynomial `0x11D` and a systematic Vandermonde matrix), so independent implementations produce identical parity. Tolerance counts lost shards; a group survives the loss of a whole blob only when no blob holds more than `m` of its members.

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

Without keys, recovery can still perform the keyless structural work permitted by the format, such as discovering physical frame geometry and parity structure. Protected plaintext paths and encrypted logical metadata require the archive key. The object identifier stored in plaintext frame trailers is keyed in encrypted archives, so paths cannot be confirmed by guessing; object sizes and parity layout remain visible.

A deployment may rotate a KEK/KMS wrapping key without changing frame bytes. Changing the archive DEK requires explicit migration to a new archive.

## Threat model and anti-rollback

🌀 STASH provides strong structural validation, content-integrity checks, authenticated encryption when enabled, and optional erasure recovery.

R10 distinguishes:

```text
integrity
authenticity
freshness
```

CRC32C, hashes, and AEAD can prove that a generation is internally valid and authentic. They cannot by themselves prove that it is the newest generation ever accepted.

A malicious storage administrator who can restore an entire older but previously valid generation, the matching old `root.current`, and its manifest/frame set can therefore present a state that still passes CRC, hash, AEAD, and parity validation.

The same applies inside one generation: the manifest is append-only, so truncating it to an earlier point yields an older valid state with the same generation ID.

HARDENED policy addresses both with a trusted external **Generation Anchor** stored outside the rollback-capable archive namespace.

The anchor binds:

```text
archive_id
generation_id
root_digest
manifest_length
manifest_digest
```

and advances on every reported-durable commit (with group commit) as well as on every generation switch. For encrypted archives it also binds the Allocator State reservations, so rolling back the allocator files cannot force AES-GCM nonce reuse.

Suitable trust domains include KMS/HSM metadata, TPM-backed monotonic state, a write-once audit service, a remote control plane with compare-and-swap/monotonic semantics, or another state store that cannot be rolled back together with the archive.

STANDARD does not require this external freshness proof. HARDENED must fail closed if the anchor is unavailable or indicates rollback; it must not silently degrade to STANDARD.

## Manifest and logical state

`manifest.jsonl` is an append-only logical journal.

Manifest processing is bounded and streaming. Large objects use multi-record transactions rather than unbounded JSON lines:

```text
ADD_BEGIN
ADD_EXTENT
...
ADD_COMMIT
```

A large-object transaction becomes visible only after a valid durable commit record. A transaction that will not commit is closed with `ADD_ABORT`, by the writer on error or on its next start after a crash, so interrupted writes never pile up.

Each path has at most one current version. Object versions come from an archive-wide counter and are never reused, so a re-added path never collides with an old one. Rename is a new object followed by a delete of the old path: it never loses data on a crash, but it is not atomic.

For encrypted archives, every manifest record is an encrypted envelope. Each record also carries a hash of the previous record, which detects deleted, inserted, or reordered records. Manifest sequence numbers share one generation-wide nonce namespace across the complete manifest graph and are reserved durably before use.

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

Under STANDARD policy:

```text
destination generation durable
-> atomically switch root.current
-> fsync root directory
```

Under HARDENED policy:

```text
destination generation durable
-> verify destination generation
-> prepare new root.current
-> durably advance external Generation Anchor
-> atomically switch root.current
-> fsync root directory
```

If a crash happens after anchor advance but before the local root switch, a HARDENED reopen must locate and verify the anchored generation and complete the local switch. If local `root.current` is older than the trusted anchor, the storage is stale/rolled back and must not be accepted as current.

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
- Transactional add and delete; loss-free rename
- Streaming object listing
- Sequential and random object reads
- Structural and full-content verification
- Raw disaster recovery
- Physical-index rebuilding
- Compaction and garbage collection
- Storage backend abstraction
- Key-provider integration
- Optional Generation Anchor integration for HARDENED policy

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
    [--security-policy standard|hardened]
    [--generation-anchor PROVIDER]
```

These commands describe the intended reference interface; availability depends on the implementation milestone reached. `--security-policy hardened` requires a configured Generation Anchor provider and changes no wire bytes.

## Read-only FUSE

The official FUSE adapter is permanently read-only.

A mount pins one validated `generation_id` for its lifetime, providing a stable snapshot even if compaction creates and switches to a newer generation in the background.

All mutation attempts return `EROFS`.

The adapter does not mutate blobs, manifests, persistent indexes, generations, or root metadata.

If persistent indexes are missing, the adapter may construct temporary in-memory lookup state through the public Go library.

## Specification

The normative format definition is:

- [`SPEC.md`](SPEC.md) — **🌀 STASH 2.0 Revision R10** (with Erratum E1), wire version `0x0006`

The specification defines binary layouts, manifest encoding, invariants, validation order, recovery behavior, concurrency, parity, compaction, encryption, resource limits, security policies, and required conformance tests.

R10 keeps the R8/R9 binary on-disk structure layouts unchanged and adds the Allocator State file. Erratum E1 (SPEC §20.5) adds the `ADD_ABORT` manifest operation, Allocator State kind 4, and a keyed object identifier for encrypted archives; it was applied before any implementation or media existed. R10 readers open R9 media, except media that violates rules R10 tightened (listed in SPEC §20.2); R10 writers initialize Allocator State for R9 archives through an explicit step.

If this README and the specification disagree, **the specification wins**.

> **🌀 STASH 2.0 R10 is frozen at wire version `0x0006`. R10 does not change the R8/R9 binary wire format. Any future on-disk format change requires a new wire-version revision backed by implementation or conformance evidence.**

## Development approach

The reference implementation is developed with strict TDD.

Every new behavior follows:

```text
R10 invariant
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

The R10 required test matrix is part of the specification and is **not optional implementation guidance**.

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
Generation Anchor / anti-rollback semantics
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
- A built-in vendor-specific trusted anti-rollback service (R10 defines the abstraction/policy, not a mandatory provider)
- Atomic multi-path transactions (including atomic rename)
- Sharing frames between versions of an object

## Contributing

The project is now entering the reference-implementation and conformance phase.

Early contributions are most valuable in:

- independent review of R10 invariants;
- independently constructed binary golden vectors;
- adversarial recovery and corruption fixtures;
- Go binary-codec and bounded-allocation review;
- checked-arithmetic review;
- manifest crash-safety tests;
- parity interoperability tests;
- compaction, generation-switch, and Generation Anchor crash tests;
- fuzzing and crash-injection infrastructure;
- filesystem and object-storage backend testing;
- reproducible performance benchmarks.

Speculative format additions are not sufficient reason to change the frozen `0x0006` wire format.

A proposed wire-format change should be backed by concrete implementation evidence such as a minimal reproducer, failing conformance test, interoperability failure, security finding, recovery failure, or measured performance result.

## License

🌀 STASH is open-source software licensed under the [MIT License](LICENSE).

**Author:** © 2025-2026 Zbigniew Lipka
