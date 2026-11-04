# 🌀 STASH

## Version 2.0 — Consolidated Specification
### Revision R10 with Erratum E1 — Specification Completion and Crash/Nonce Safety

**Status:** Final / Frozen Specification  
**Target:** Server / enterprise / datacenter / petabyte-scale storage  
**Wire version:** `0x0006`  
**Encoding:** little-endian for every multi-byte integer unless explicitly stated otherwise

R10 is a completion and safety revision over R9. It was produced from an independent review of R9 that found internal contradictions, nonce-reuse hazards after crashes, a gap in HARDENED freshness, and several areas left undefined in a way that prevented two independent implementations from interoperating. The full list of changes and their rationale is §20.

**Erratum E1** (2026-11) closes defects found by a second review of R10, before any implementation or any wire `0x0006` media under the earlier rules existed (§20.5). E1 is therefore folded into R10 at wire `0x0006` rather than published as a new wire version. Besides clarifications, E1 changes three parser-visible semantics: the keyed `object_id` of encrypted archives (§6.5), the `ADD_ABORT` manifest operation (§10.3.1), and Allocator State kind 4 (§2.1.3). It changes no binary structure layout. Wherever this document says R10, it means R10 with E1.

R10 retains wire version `0x0006`. The 64-byte Archive Header, 16-byte Frame Prefix, 96-byte Master Trailer, 4096-byte base quantum, Pre-Trailer encodings, `root.current`, the index container, and the parity recovery-shard encoding remain byte-for-byte unchanged. R10 changes are of three kinds:

1. **Definitions of previously undefined encodings** (encrypted manifest envelope plaintext, Reed-Solomon coding matrix, PACKED manifest references, LINK_MANIFEST hash scope). No interoperable R9 media could depend on these, because R9 did not define them.
2. **New auxiliary durable state** outside the frame/manifest/root/index structures: the 64-byte Allocator State file (§2.1.3). R9 readers never read it; R10 writers require it.
3. **Tightened semantic rules** (file version allocation, live-state fold, `logical_length` ceiling, torn-tail handling, strict JSON, resynchronization). Each is listed in §20.2 together with its effect on existing R9 media.

> **R10 keeps the R8/R9 binary wire format unchanged at wire version `0x0006`. Further changes to binary structures require a future wire-version revision backed by implementation evidence from conformance testing, fuzzing, crash injection, recovery testing, interoperability testing, security analysis, or measured performance results.**

R10 preserves the core 🌀 STASH model:

- append-only storage;
- immutable committed frames;
- whole-frame integrity and recovery-preserving deduplication;
- self-describing manifest-independent recovery;
- per-blob parallel writes;
- parity / erasure recovery;
- crash-safe manifest transactions;
- generation-based compaction;
- encrypted metadata and payload support;
- enterprise / petabyte-scale operation.

---

# 0. Design Priorities

Implementations MUST preserve these priorities in this order:

1. **Predictable grid geometry.** Physical frame boundaries always lie on the frame grid `FRAME_AREA_START + j * BASE_QUANTUM` (that is, at byte offsets congruent to `0x40` modulo 4096; see §3.1.1). In `FIXED` mode, arbitrary frame positions are directly computable in O(1). In `VARIABLE` mode, every frame self-describes its physical extent and the next frame is deterministically reachable from the current frame.
2. **Immutable copy-on-write with bounded physical rewrite scope.** A committed frame is never modified in place. A modification writes a complete new, self-contained object version (§9.5); VARIABLE geometry prevents physical frame-size policy from forcing rewrites of unrelated objects. 🌀 STASH does not claim insertion-stable or version-shared extent identities.
3. **Recovery-preserving whole-frame deduplication.** `hash_payload` is a payload candidate key, but a physical frame MAY be shared by multiple logical references only when the complete frame identity and recovery metadata are equivalent as defined in §4.2. Because recovery identity includes the object version, frames are never shared between two versions of an object (§9.5). 🌀 STASH does not perform sub-frame content-defined chunking.
4. **Self-describing recovery.** Raw frame data MUST contain enough information to identify the logical object, logical placement, physical extent, parity membership, and integrity state without `manifest.jsonl`.
5. **Throughput at enterprise scale.** Normal hot-path reads MUST use a maintained physical offset index rather than repeated linear blob scans. Parallel per-blob writing remains supported.

Encryption is an explicit qualification to priority 4: without the appropriate key, a recovery scanner can still discover frame boundaries, physical extents, hashes, and parity structure, but plaintext paths and encrypted logical metadata are not recoverable.

## 0.1 Detection is not repair

**Integrity detection and error correction are separate mechanisms.**

- CRC32C detects accidental structural corruption.
- `hash_payload` detects mismatch of the exact stored payload representation.
- AEAD authenticates encrypted representations.
- None of those mechanisms reconstruct missing or corrupted data.
- Repair requires parity, another intact copy, external replication, or another recovery source.

> **Checksums and hashes detect corruption; redundancy repairs it. 🌀 STASH never treats CRC32C or content hashes as error-correction mechanisms.**

## 0.2 Threat model and residual risks

R10 protects against accidental corruption, torn/incomplete writes when durability ordering is followed, payload substitution detectable by hashes/AEAD, and loss covered by configured parity or another intact copy.

R10 distinguishes three security properties:

- **integrity** — stored state has not been modified without detection;
- **authenticity** — encrypted/authenticated state was produced under the expected archive key;
- **freshness** — the presented archive state is not an older previously valid generation.

The first two are provided by the core 🌀 STASH format when the relevant checks are enabled. Freshness cannot be proven solely from media stored inside the same rollback-capable storage namespace.

A malicious storage administrator who can restore an entire older but previously valid generation, an older valid `root.current`, and the matching older manifest/frame set can therefore produce a state that still passes CRC, hash, AEAD, and parity validation.

The same holds **inside one generation**: `manifest.jsonl` is append-only, so every byte prefix ending at a record boundary is a previously valid state with the same `generation_id`. Truncating the manifest (and optionally the blob tails) to such a prefix is a rollback even though no generation switch occurred.

Deployments that require rollback detection MUST maintain trusted external monotonic state outside the rollback-capable archive storage namespace. R10 defines this optional capability as a **Generation Anchor** (§2.1.2, §10.4.1 and §13.6.1).

The external anchor MUST bind:

```text
archive_id
generation_id
root_digest
manifest_length
manifest_digest
```

so that it covers both generation switches and every durable manifest commit (§2.1.2). An anchor that binds only `archive_id` and `generation_id` detects generation-level rollback only and MUST NOT be described as HARDENED.

Under STANDARD policy and without encryption, the manifest has no tamper evidence: anyone able to write the storage can delete, insert, or alter records. Under STANDARD policy with encryption, the manifest chain (§15.8.2) detects deletion, insertion, and reordering of records inside a file, but not truncation of the file tail. Only HARDENED detects tail truncation.

Under STANDARD policy, an attacker able to modify the storage can also roll back Allocator State files (§2.1.3) together with uncommitted blob tails and cause AES-GCM nonce reuse for frames written afterwards. Confidentiality of an encrypted archive against the storage administrator therefore requires HARDENED, which binds allocator reservations in the anchor (§2.1.3.5).

In an encrypted archive the Frame Prefix and Master Trailer remain plaintext. `object_id` is keyed (§6.5), so a party without the key cannot confirm a guessed path, but `logical_offset`, `logical_length`, `data_len`, and the parity fields reveal object sizes and layout. Encryption protects payload bytes, paths, and versions, not sizes.

Acceptable implementations include KMS/HSM metadata, a TPM-backed monotonic record, a write-once audit service, a remote control-plane database with compare-and-swap/monotonic semantics, or an equivalent trust domain not rolled back together with the archive storage.

R10 does not define cross-tenant convergent encryption, remote attestation, IAM/RBAC, or a network protocol.

---

# 1. Terminology

R10 uses the following terms normatively:

- **BASE_QUANTUM** — 4096 bytes.
- **Grid-Aligned Variable Frame** — a frame whose physical size is `N * BASE_QUANTUM`, where `N >= 1` and the archive is in `VARIABLE` mode.
- **FIXED frame** — a frame whose physical size is exactly `MAX_FRAME_SIZE`.
- **physical_offset** — absolute byte offset of a frame from the beginning of its blob file.
- **frame_quanta** — physical frame size divided by `BASE_QUANTUM`.
- **logical_offset** — byte offset of a non-packed frame's data within the logical object.
- **logical_length** — number of logical object bytes represented by that frame.
- **Logical Recovery Quantum** — a 4096-byte unit used by recovery/index implementations to map logical extents. It is not a separate wire object.
- **frame_ordinal** — immutable creation-time ordinal used for frame metadata and, for newly encrypted frames, nonce construction within the origin `(generation_id, blob_ordinal)` namespace. Byte-copy compaction preserves it; it is not the current physical slot after compaction.
- **blob_ordinal** — active blob number `0 .. blob_count-1` within one generation. It is not a globally unique historical blob identifier.
- **generation_id** — uint64 generation / compaction-attempt namespace identifier.
- **Generation Anchor** — optional trusted external monotonic state binding an `archive_id` to the newest accepted generation, its `root_digest`, and the anchored manifest prefix (§2.1.2); it is not stored in the 🌀 STASH wire format.
- **STANDARD security policy** — deployment policy with no required external freshness anchor.
- **HARDENED security policy** — deployment policy requiring a trusted Generation Anchor and rollback detection.
- **object_id** — binary identity derived from canonical path and object version, as defined in §6.5. It is not rename-stable.
- **frame_hash** — the value of a frame's `hash_payload` field (§6.2, §4), used as the manifest location-tuple element (§9.1) and as the physical-offset-index lookup key (§10.5). `frame_hash` and `hash_payload` denote the identical 32-byte value; `frame_hash` is the name used in manifest/index contexts, `hash_payload` is the name used in the on-disk Master Trailer field definition.
- **file_ver** — uint64 object version, allocated from the archive-wide file-version allocator (§10.2.1). It is unique per archive, never reused, and strictly increasing in allocation order.
- **current version** — for one canonical path, the single object version made visible by the live-state fold of §10.2.2. A path has at most one current version.
- **Allocator State** — a 64-byte durable reservation record (§2.1.3) that prevents reuse of generation IDs, file versions, frame ordinals, and manifest sequence numbers after a crash.
- **frame grid** — the set of byte offsets `FRAME_AREA_START + j * BASE_QUANTUM`, `j >= 0`, at which frames may start (§3.1.1).
- **torn tail** — bytes at the end of a blob or manifest that were written but never made durable as part of a committed state (§10.4.2).
- **SEALED blob** — a blob of the current generation that may no longer be truncated or appended to, because committed data lies beyond a damaged region (§10.4.2).
- **ABORT** — the `ADD_ABORT` record that closes a transaction without making a version visible (§10.3.1).

The terms `frame_size_class`, global `BLOCK_STRIDE`, and implicit `loc[]` ordering are not valid concepts of this format.

---

# 2. Archive and Generation Layout

## 2.1 Directory model

Normative layout:

```text
archive/
  root.current
  writer.lock                # §12.1 single-writer lock (implementation-defined content)
  alloc/
    generation.alloc         # §2.1.3 kind 0: generation_id reservations
    filever.alloc            # §2.1.3 kind 1: file_ver reservations
  generation-0000000000000000/
    manifest.jsonl
    submanifests/
      ...                    # optional LINK_MANIFEST targets
    manifest.checkpoint      # non-normative; see note below
    alloc/
      manifest.alloc         # §2.1.3 kind 2: manifest seq reservations
      groups.alloc           # §2.1.3 kind 4: parity group_id reservations
      blob-00.alloc          # §2.1.3 kind 3: frame_ordinal reservations for blob 0
      ...
    index/
      blob-00.idx
      blob-01.idx
      ...
    frames/
      blob-00.stash
      blob-01.stash
      ...
  generation-0000000000000001/
    ...
```

The layout is normative, because Allocator State locations (§2.1.3), LINK_MANIFEST paths (§10.6), and the manifest chain (§15.8.2) depend on exact names. Generation directories are named `generation-` followed by exactly 16 uppercase hexadecimal digits of `generation_id`. Blob, index, and allocator files use exactly 2 uppercase hexadecimal digits of `blob_ordinal` (`blob-00` .. `blob-FE`). Readers MUST ignore directory and file names that do not match these forms exactly, so that two names can never alias one generation or blob. `writer.lock`, reader-pin state (§13.1.1), and health metadata (§13.9) MAY add implementation-defined files outside these names.

`archive_id` is 32 bytes from a cryptographically secure random generator, chosen once when the archive is created. It is never derived from content, paths, or time.

`root.current` identifies the authoritative generation. Its exact format and durable replacement protocol are defined in §2.1.1.

`manifest.checkpoint` is shown for layout completeness only. This specification does not define its binary format, update cadence, or any normative reader/writer behavior. An implementation MUST NOT require its presence for correctness, and MUST fall back to full `manifest.jsonl` replay (optionally accelerated by §10.5's physical index) when it is absent. A normative checkpoint format is out of scope for this frozen revision.

The initial archive generation is:

```text
generation_id = 0
```

Each new generation / compaction attempt MUST use a `generation_id` that has never previously been allocated in this archive. IDs MUST NOT be reused after abort, crash, or deletion. Generation IDs are strictly increasing but not necessarily consecutive: an aborted attempt consumes its ID.

A writer MUST allocate generation IDs from `alloc/generation.alloc` (§2.1.3). Discovering the next ID only by scanning existing `generation-XXXXXXXXXXXXXXXX/` names is **not** sufficient, because a deleted aborted attempt leaves no name to observe. When `alloc/generation.alloc` is missing (for example an archive created by an R9 writer), the writer MUST initialize it conservatively per §2.1.3.4 before allocating.

### 2.1.1 `root.current` — 64 bytes

`root.current` is a fixed 64-byte root pointer:

| Offset | Size | Field | Type | Requirement |
|---|---:|---|---|---|
| `0x00` | 8 | magic | bytes | exact ASCII `STROOT8` followed by `0x00` |
| `0x08` | 2 | version | uint16 | `0x0006` |
| `0x0A` | 2 | root_size | uint16 | `64` |
| `0x0C` | 8 | generation_id | uint64 | authoritative generation |
| `0x14` | 32 | archive_id | bytes | MUST match the selected generation |
| `0x34` | 4 | flags | uint32 | MUST be zero |
| `0x38` | 4 | root_crc32c | uint32 | CRC32C over all 64 bytes with this field treated as zero |
| `0x3C` | 4 | reserved | bytes | MUST be zero |

A root update MUST be performed by writing a complete temporary root file in the same directory, flushing it durably, atomically replacing `root.current`, and durably flushing the containing directory (or by a platform-specific mechanism providing equivalent atomic-replace and durability semantics). A partially written or CRC-invalid root MUST NOT become authoritative.

The root CRC detects corruption; it does not prevent rollback to an older valid root. See §0.2.

Every byte of `root.current` is determined by `generation_id` and `archive_id`. `root.current` is written last when an archive is created, after generation 0, its Allocator State files, blobs, and empty `manifest.jsonl` are durable. Under STANDARD policy, a directory that holds generation data but no `root.current` is an incomplete creation that was never opened: a writer reports it and MUST NOT adopt it; the operator deletes it and creates the archive again. Under HARDENED policy, §2.1.2.1 root reconstruction applies. An implementation can therefore rebuild the exact root bytes for a known generation; §2.1.2.1 uses this for HARDENED recovery.

### 2.1.2 Optional Generation Anchor — external, non-wire state

The Generation Anchor is **not** part of the 🌀 STASH on-disk wire format. R9 and R10 do not add fields to `root.current`, the Archive Header, frames, manifests, or indexes.

A Generation Anchor implementation MUST provide monotonic compare-and-advance semantics for one `archive_id`. It stores:

```text
archive_id
generation_id
root_digest       = SHA-256(exact 64-byte root.current naming generation_id)
manifest_length   = uint64 byte length of the committed manifest.jsonl prefix
manifest_digest   = SHA-256(exact bytes manifest.jsonl[0 : manifest_length])
reservations      = encrypted HARDENED archives only (§2.1.3.5)
```

For an encrypted archive under HARDENED policy, `reservations` holds the `reserved_through` value of `alloc/generation.alloc` and of the current generation's `manifest.alloc`, `groups.alloc`, and every `blob-NN.alloc`. For other archives it is empty.

The anchor is advanced in three situations:

1. **commit advance** (§10.4.1): same `generation_id`, larger `manifest_length`, new `manifest_digest`;
2. **switch advance** (§13.6.1): larger `generation_id`, new `root_digest`, and the destination manifest's `manifest_length` and `manifest_digest`, plus the destination's reservations;
3. **reservation advance** (§2.1.3.5): same `generation_id` and `manifest_length`, every reservation greater than or equal to its previous value and at least one greater.

Ordering of anchor states is lexicographic on `(generation_id, manifest_length)`; within an equal pair, a state with componentwise greater-or-equal reservations is newer. Any advance MAY combine a commit advance with a reservation advance. Linked submanifests are covered transitively through the `hash` field of their LINK_MANIFEST record (§10.6), which lies inside the anchored manifest prefix.

`manifest_digest` always uses SHA-256, independent of the archive `hash_id`.

The external anchor MUST reside in a trust domain that is not rolled back together with the archive storage.

An implementation MAY expose anti-rollback support through a library abstraction such as:

```go
type GenerationAnchor interface {
    Create(ctx context.Context, initial Anchor) error
    Load(ctx context.Context, archiveID [32]byte) (Anchor, error)
    Advance(ctx context.Context, previous Anchor, next Anchor) error
}
```

The exact Go API is non-normative. The required semantics are:

0. `Create` stores the first state for an `archive_id` and MUST fail if any state already exists for it.
1. `Load` returns the newest trusted state known for the archive.
2. `Advance` MUST be monotonic and MUST reject stale compare-and-swap attempts.
3. The anchor MUST NOT move backward.
4. An anchor update MUST become durable before the corresponding generation or commit is advertised as authoritative or durable to HARDENED clients.
5. Loss or unavailability of the external anchor is a deployment availability problem, not a reason to silently disable rollback protection.

#### 2.1.2.1 Anchor bootstrap and enrollment

- **Creation.** A HARDENED archive is created by writing generation 0 completely and durably, then calling the provider's initial-create operation for `archive_id` with generation 0's `root_digest`, `manifest_length`, and `manifest_digest`, then writing `root.current`. Initial create MUST fail if an anchor already exists for the `archive_id`.
- **Enrollment of an existing STANDARD archive.** Switching an existing archive to HARDENED trusts the archive state at that moment (trust on first use). It MUST be an explicit operator action that first runs full verification (§11) of the current generation, then creates the anchor from that state, and records the enrollment time and operator identity outside the archive.
- **Leaving HARDENED.** Disabling HARDENED is an explicit operator action. It MUST NOT happen automatically on anchor errors (§15A.2).
- **Root reconstruction.** When the anchor names generation `G` and local `root.current` is missing (a crash between `Create` and the root write) or names a generation lower than `G` (a crash in §13.6.1 between steps 9 and 10), a HARDENED opener verifies generation `G` completely (§11), rebuilds the 64 root bytes for `G` (§2.1.1), requires their SHA-256 to equal the anchored `root_digest`, and installs them with the §2.1.1 replacement protocol. If verification or the digest check fails, §13.6.1 applies: no silent fallback.

R10 security policy behavior:

```text
STANDARD
    external Generation Anchor not required

HARDENED
    external Generation Anchor required
```

Named data-processing profiles (`BASELINE`, `SECURE`, `FAST`) remain orthogonal to these security policies.

A deployment MAY therefore use, for example:

```text
SECURE + HARDENED
FAST   + HARDENED
SECURE + STANDARD
```

although `SECURE + HARDENED` is the recommended configuration for adversarial enterprise storage.

### 2.1.3 Allocator State — 64 bytes

R10 adds one auxiliary durable structure. It reserves ranges of identifiers before they are used, so that an identifier that may have reached storage in a torn or uncommitted write is never handed out again after a crash. For encrypted archives this is what makes the numeric nonce construction of §15.5 safe across crashes.

| Offset | Size | Field | Type | Requirement |
|---|---:|---|---|---|
| `0x00` | 8 | magic | bytes | exact ASCII `STALLOC` followed by `0x00` |
| `0x08` | 2 | version | uint16 | `0x0006` |
| `0x0A` | 1 | kind | uint8 | `0` generation_id, `1` file_ver, `2` manifest seq, `3` frame_ordinal, `4` group_id; other values are rejected |
| `0x0B` | 1 | blob_ordinal | uint8 | kind 3: blob ordinal; otherwise MUST be zero |
| `0x0C` | 4 | alloc_crc32c | uint32 | CRC32C over all 64 bytes with this field treated as zero |
| `0x10` | 8 | generation_id | uint64 | kinds 2, 3 and 4: owning generation; kinds 0 and 1: MUST be zero |
| `0x18` | 8 | reserved_through | uint64 | every value `< reserved_through` may already have been handed out |
| `0x20` | 32 | archive_id | bytes | MUST match the archive |

File locations:

```text
kind 0  archive/alloc/generation.alloc
kind 1  archive/alloc/filever.alloc
kind 2  archive/generation-XXXXXXXXXXXXXXXX/alloc/manifest.alloc
kind 3  archive/generation-XXXXXXXXXXXXXXXX/alloc/blob-NN.alloc
kind 4  archive/generation-XXXXXXXXXXXXXXXX/alloc/groups.alloc
```

An Allocator State file is updated with the same atomic durable replacement protocol as `root.current` (§2.1.1).

#### 2.1.3.1 Reservation rule

A writer holds an in-memory range `[next, limit)` per allocator. Before handing out a value `v` it MUST hold `v < limit`, and `limit` MUST already be durable as `reserved_through` in the corresponding file. To extend the range the writer durably replaces the file with a larger `reserved_through` and only then hands out values from the new block. One replacement MUST NOT extend `reserved_through` by more than `MAX_RESERVATION_BLOCK` values:

```text
kind 0 (generation_id), kind 4 (group_id)   MAX_RESERVATION_BLOCK = 2^8
kinds 1, 2, 3                               MAX_RESERVATION_BLOCK = 2^16
```

On every cold start, the writer MUST set `next = reserved_through` read from the file, never a value derived from scanning media. Values between the last value actually used and `reserved_through` are permanently skipped. Skipping is always safe; reuse is not.

On every cold start the writer MUST also check that `reserved_through` is greater than every value of its kind present in committed state: generation IDs of existing generation directories and `root.current`, `file_ver` values named by any record of the manifest graph (live, dead, aborted, or still open), `seq` values in the manifest graph, frame ordinals of the namespace, and `group_id` values, found through the index plus the lagging-tail scan (§10.5.1), including frames that no manifest record references. In an unencrypted archive whose writer derives `frame_ordinal` from committed state, the frame-ordinal check is skipped, because copied frames cannot be told apart from native ones without a nonce. A failed check means the Allocator State was rolled back or corrupted, and the writer MUST fail closed. This check cannot see identifiers used only by torn writes; protection against a targeted rollback is defined in §2.1.3.5.

#### 2.1.3.2 Required allocators

- kinds 0 and 1 are REQUIRED for every archive, encrypted or not. Generation reuse breaks index staleness detection; file-version reuse breaks raw recovery identity (§6.5).
- kinds 2 and 3 are REQUIRED for encrypted archives. For unencrypted archives they are RECOMMENDED; an unencrypted writer MAY instead derive `seq` and `frame_ordinal` from the last committed state.
- kind 4 is REQUIRED for every archive whose header parity scheme is not NONE. `group_id` reuse would merge two groups during raw recovery (§7).
- every frame of a namespace, DATA, PACKED, and PARITY alike, takes its `frame_ordinal` from that namespace's kind 3 allocator when one is used.
- `reserved_through` MUST never decrease. A file whose value is lower than a value already observed on media (for example a stored nonce, `seq`, or `file_ver`) is corrupt; the writer MUST fail closed and require the conservative re-initialization of §2.1.3.4.

#### 2.1.3.3 Validation

A reader or writer MUST verify magic, version, `kind`, `alloc_crc32c`, `archive_id`, and the zero-field rules before trusting the file. A missing, corrupt, or mismatched Allocator State file MUST NOT be silently recreated from a scan.

#### 2.1.3.4 Conservative initialization

When an allocator file is missing (for example an archive written by an R9 writer) or corrupt, a writer MAY initialize it only through an explicit, logged operation:

```text
reserved_through = max(every value of that kind observable on media) + SKIP

kind 0, kind 4    SKIP = 2^16
kinds 1, 2, 3     SKIP = 2^32
```

saturating to fail-closed exhaustion if the addition overflows the namespace limit. `SKIP` is at least 256 times `MAX_RESERVATION_BLOCK`, so every value a crashed writer could have handed out without leaving a trace is skipped, while the 32-bit `generation_id` space of an encrypted archive and the 32-bit `group_id` space survive 65,536 re-initializations. For kind 3 in an encrypted archive, the observable values are the ordinals encoded in stored nonces whose `(generation_id, blob_ordinal)` prefix matches the namespace (§12). The `2^32` skip covers torn writes whose ciphertext may have reached storage without becoming discoverable.

#### 2.1.3.5 HARDENED binding of reservations

In an encrypted archive under HARDENED policy, a reservation becomes usable only after (1) the Allocator State file is durably replaced and (2) the Generation Anchor has been advanced to include the new `reserved_through` (§2.1.2, reservation advance). A reservation advance occurs at most once per `MAX_RESERVATION_BLOCK` allocations and MAY be combined with a commit advance.

On cold start such a writer sets `next = max(local reserved_through, anchored reserved_through)` for every bound allocator. A local value lower than the anchored value is an Allocator State rollback: the writer reports it as a security incident and fails closed until an operator acknowledges it; it then continues from the anchored value. Because skipping is always safe, continuing from the anchored value never reuses a nonce.

A compactor initializes the destination generation's kind 2, 3, and 4 files before writing into it and includes their values in the switch advance.

## 2.2 Archive Header — 64 bytes

Every blob file MUST begin with the same 64-byte Archive Header for its generation.

```text
ARCHIVE_HEADER_SIZE = 64 = 0x40
FRAME_AREA_START    = 0x40
```

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STSH` |
| `0x04` | 2 | version | uint16 | `0x0006` |
| `0x06` | 1 | frame_size_mode | uint8 | `0x00 VARIABLE`, `0x01 FIXED` |
| `0x07` | 1 | hash_id | uint8 | §4 |
| `0x08` | 1 | codec_id | uint8 | archive default; per-frame override allowed |
| `0x09` | 1 | parity_scheme | uint8 | §7 |
| `0x0A` | 1 | parity_k | uint8 | data members per parity group |
| `0x0B` | 1 | parity_m | uint8 | parity members per parity group |
| `0x0C` | 1 | blob_count | uint8 | `1..255` active blobs in this generation |
| `0x0D` | 1 | flags | uint8 | bit 0 = `ENCRYPTED`; bits 1..7 MUST be zero |
| `0x0E` | 2 | header_size | uint16 | MUST equal `64` |
| `0x10` | 4 | max_frame_quanta | uint32 | `MAX_FRAME_SIZE / 4096` |
| `0x14` | 8 | generation_id | uint64 | generation identity |
| `0x1C` | 4 | reserved | bytes | MUST be zero |
| `0x20` | 32 | archive_id | bytes | immutable archive identifier |

The following fields are immutable for the entire life of one archive instance and MUST be identical across all generations:

- `frame_size_mode`;
- `hash_id`;
- archive default `codec_id` policy;
- `parity_scheme`, `parity_k`, `parity_m`;
- `blob_count` unless an explicit future format revision defines migration semantics;
- `max_frame_quanta`;
- `archive_id`;
- `flags & ENCRYPTED`.

`generation_id` is intentionally generation-specific.

Changing `frame_size_mode` requires creation of a new archive instance. Compaction MUST NOT convert `VARIABLE -> FIXED`, `FIXED -> VARIABLE`, or mix modes between generations of the same archive.

## 2.3 Header validation

A reader MUST validate all available blob headers before allocating frame-sized buffers.

Within one generation, available headers MUST agree on every archive field and on `generation_id`. A disagreement is corruption.

A reader MUST reject unknown `version`, `frame_size_mode`, invalid `max_frame_quanta` (§3.1), unsupported allocation size, any non-zero reserved Header flag bit, any non-zero reserved byte, or inconsistent header copies before using those values for memory allocation.

The Archive Header carries no CRC. To detect a corrupted header that has no second copy to compare against (`blob_count == 1`, or only one surviving blob), a reader MUST additionally verify: `archive_id` equals `root.current` when `root.current` is available; Master Trailer `hash_id` of every validated frame equals the header `hash_id`; parity metadata of every validated frame is consistent with the header parity fields (§7); and the header invariants of §7 hold. Any disagreement is header corruption and fails closed. `flags & 0x01` declares an encrypted archive. In such an archive, DATA/PACKED payloads and their sensitive Pre-Trailers plus sensitive manifest records use §15 encryption. PARITY payloads and the required zero-entry PARITY Pre-Trailer remain plaintext parity structures as defined in §7 so keyless erasure recovery remains possible. The format defines no on-disk `key_id`; key selection is deployment metadata outside the 🌀 STASH wire format and is normally keyed by `archive_id`.

## 2.4 Blob naming

Blob files remain:

```text
frames/blob-00.stash
...
frames/blob-FE.stash
```

`blob_ordinal` is uint8 on disk, but R10 supports at most 255 active blobs, so valid ordinals are `0x00..0xFE` (`0..254`). `0xFF` is not a valid active blob ordinal.

Historical generations MAY reuse the same ordinal values because generation identity separates them. `blob_ordinal` MUST NOT be treated as a globally monotonically increasing archive identifier.

---

# 3. Grid Geometry and Frame Size Modes

## 3.1 Base quantum

```text
BASE_QUANTUM = 4096 bytes
```

Every physical frame size MUST be a positive integral multiple of `BASE_QUANTUM`.

```text
frame_size = frame_quanta * BASE_QUANTUM
frame_quanta >= 1
frame_quanta <= max_frame_quanta
MAX_FRAME_SIZE = max_frame_quanta * BASE_QUANTUM
```

Valid `max_frame_quanta` values are `1 .. 0x00100000` (4 KiB .. 4 GiB), further limited by the implementation's configured allocation ceiling. A writer creating a new archive MUST NOT select `max_frame_quanta < 2`, because a 4096-byte frame cannot hold a DATA Pre-Trailer for a path longer than about 3,900 bytes; readers MUST still accept `max_frame_quanta == 1`.

Production implementations MUST impose a configured safe allocation ceiling before allocating a buffer based on untrusted frame metadata.

The reference implementation SHOULD default to a practical `MAX_FRAME_SIZE` such as 4 MiB for mixed workloads. Production configurations MUST impose a validated allocation ceiling and SHOULD NOT exceed 64 MiB by default; larger values require explicit operator configuration and implementation-specific resource validation.

### 3.1.1 Frame grid and shared sectors

Frames start at `FRAME_AREA_START + j * BASE_QUANTUM`. Because `FRAME_AREA_START == 0x40`, frame boundaries are **not** aligned to absolute 4096-byte file offsets; every frame boundary lies 64 bytes past an absolute 4 KiB boundary. Text in earlier revisions describing frames as "4096-byte aligned" means aligned to this frame grid.

Consequences that implementations MUST handle:

1. The final 64 bytes of every frame (Master Trailer bytes `0x20..0x5F`, which include `hash_payload`) share one absolute 4 KiB storage page with the first 4,032 bytes of the next frame.
2. Appending frame N+1 therefore rewrites a storage page that contains committed bytes of frame N. A writer MUST write that page with the committed bytes of frame N unchanged, and MUST NOT report frame N+1 durable until the whole page is durable.
3. Implementations using direct I/O that requires absolute 4 KiB alignment MUST perform read-modify-write of the shared page from an aligned bounded buffer.
4. On storage that does not guarantee atomic page writes, a power loss during step 2 can damage the tail of an already committed frame. That damage is detected by the outer Pre-Trailer CRC (§6.4) and is repaired only by parity or another copy. Deployments on such storage SHOULD enable parity.

R10 does not change this geometry, because it is part of the frozen `0x0006` wire layout.

## 3.2 VARIABLE mode — `frame_size_mode = 0x00`

A frame MAY use any integral number of 4 KiB quanta from `1` through `max_frame_quanta`.

```text
4096 <= frame_size <= MAX_FRAME_SIZE
frame_size % 4096 == 0
```

There is no global `BLOCK_STRIDE`.

The next physical frame is:

```text
next_frame_offset = current_frame_offset + current_frame_size
```

The frame's fixed Prefix (§6.1) makes `current_frame_size` available before reading the variable-length body.

## 3.3 FIXED mode — `frame_size_mode = 0x01`

Every frame MUST satisfy:

```text
frame_quanta == max_frame_quanta
frame_size   == MAX_FRAME_SIZE
```

Any frame with a different `frame_quanta` is corrupt.

Exact physical addressing is restored:

```text
frame_start(n) = 0x40 + n * MAX_FRAME_SIZE
```

For a frame **newly created natively in this generation** (not byte-copied from an older generation), a writer MAY choose the initial `frame_ordinal` equal to the fixed slot index:

```text
frame_ordinal_at_creation =
    (physical_offset - 0x40) / MAX_FRAME_SIZE
```

After byte-copy compaction this equality is not required and MUST NOT be used to derive the preserved `frame_ordinal`. FIXED mode therefore supports direct random frame positioning and parallel disaster-recovery partitioning without a sequential dependency on previous frames.

The final logical fragment of an object MAY have `logical_length < MAX_FRAME_SIZE`; unused physical capacity is padding.

## 3.4 Physical and logical geometry are independent

Physical frame size and logical object extent are different quantities.

A compressed frame can represent a logical region whose byte length differs from `data_len`. `frame_size` is physical allocation; `data_len` is stored payload representation length; `logical_length` is logical object data length.

Implementations MUST NOT use these fields interchangeably.

---

## 3.5 VARIABLE vs FIXED intent

New archives SHOULD default to `VARIABLE` unless `FIXED` is explicitly selected.

| Mode | Primary purpose |
|---|---|
| `VARIABLE` | General enterprise archival use. Reduces padding and permits frame sizes to match local stored representations while retaining quantum-boundary recovery. Every modification rewrites the modified object version in full (§9.5). |
| `FIXED` | Deterministic direct-slot geometry. Optimized for workloads where maximum recovery-scan parallelism and direct physical arithmetic justify increased padding. |

R10 defines no additional frame-size modes. `frame_size_mode` remains immutable for the entire archive lifetime.

## 3.6 Workload fit

The absolute `logical_offset` model is a deliberate trade-off.

🌀 STASH is well suited to:

- archival objects;
- backups and snapshots;
- append-oriented logs;
- WAL/archive-log retention;
- immutable segments and SSTable-like files;
- media objects;
- versioned datasets;
- data modeled as many immutable objects (segments, chunks) so that a change rewrites only the affected objects.

🌀 STASH is not optimized to act as a block store for one large mutable object. Every modification of an object, including an append, writes a complete new version of that object (§9.5), so the rewrite cost of a change is the size of the object it touches.

This does not make database workloads categorically unsupported: append logs, immutable table segments, checkpoints, dumps, and snapshots can be natural 🌀 STASH workloads. The unsuitable case is specifically a large monolithic object that is modified often.


---

# 4. Hash Algorithms and Hash Scope

R10 deliberately exposes only two payload-hash algorithms:

| Value | Algorithm | Digest |
|---|---|---:|
| `0x00` | reserved | — |
| `0x01` | BLAKE3 | 32 B |
| `0x02` | SHA-256 | 32 B |
| `0x03-0xFF` | reserved | — |

Writers MUST NOT emit reserved values. Readers MUST reject `hash_id == 0x00` and every value other than `0x01` or `0x02`.

`hash_id` is immutable for the lifetime of the archive.

## 4.1 Hash scope

`hash_payload` is computed over the exact stored payload representation:

- plaintext DATA/PACKED: STORE or compressed payload bytes exactly as stored;
- encrypted DATA/PACKED: `nonce[12] || ciphertext || tag[16]` exactly as stored;
- PARITY: the raw parity-shard payload bytes exactly as stored; PARITY payloads are never AEAD-wrapped.

The hash excludes:

- Frame Prefix;
- zero padding (writers MUST emit zeros; structural/full verification SHOULD reject non-zero padding even though padding is outside `hash_payload`);
- Pre-Trailer;
- `pre_trailer_len`;
- Master Trailer;
- Archive Header.

Identical logical plaintext is not guaranteed to have identical `hash_payload`, because compression output and encryption nonce/key context can change the stored representation.

> 🌀 STASH does not define cross-archive or cross-tenant plaintext deduplication. `hash_payload` identifies the exact stored payload representation and is used only as a deduplication/index candidate key.

## 4.2 Recovery-preserving deduplication

A writer MUST NOT reuse one physical frame for two logical extents merely because their `hash_payload` values match. Physical reuse is permitted only when the complete recovery identity is equivalent: block type, stored payload bytes, stored Pre-Trailer bytes, `object_id`, `logical_offset`, `logical_length`, `file_ver`/path metadata, codec, parity metadata, and every other semantically relevant Master Trailer field MUST describe the same recoverable extent. Implementations MAY establish this by byte-for-byte comparison of the complete immutable frame after normalizing only physical-location-independent bytes that this specification explicitly permits to differ.

Therefore equal `hash_payload` values can legitimately map to multiple physical candidates and multiple different logical extents. The offset index is a multimap and `hash_payload` alone is never sufficient proof that two logical extents may share one physical frame. This rule preserves manifest-independent recovery at the cost of intentionally narrower deduplication.

Because recovery identity includes `object_id`, `object_id` includes `file_ver`, and a `file_ver` is never applied twice (§10.2.1), two logical references never qualify for physical sharing in practice. A writer is not required to implement deduplication. The index remains a multimap because unrelated frames can carry equal `hash_payload` values, for example identical all-zero DATA payloads of different objects or identical PARITY shards.

---

# 5. Compression Profiles

`codec_id` identifies a complete compression-strength profile, not merely an algorithm family.

| Value | Profile | Algorithm | Compression level |
|---|---|---|---:|
| `0x00` | STORE | none | — |
| `0x01` | ZSTD_FAST | Zstandard | 1 |
| `0x02` | ZSTD_DEFAULT | Zstandard | 3 |
| `0x03` | ZSTD_DENSE | Zstandard | 9 |
| `0x04-0xFF` | reserved | — | — |

The Archive Header `codec_id` remains the archive default and MAY be overridden per frame by the Master Trailer `codec_id`.

Writers MUST NOT emit reserved codec identifiers. Readers MUST reject unknown non-zero codec identifiers.

## 5.1 Zstandard requirements

For every `ZSTD_*` payload:

- the stored representation MUST contain exactly one independently decodable Zstandard frame;
- no external Zstandard dictionary is permitted;
- decoding MUST NOT depend on another 🌀 STASH frame;
- malformed or truncated compressed input MUST fail closed;
- decompressed output MUST equal the declared logical representation exactly;
- for non-packed DATA, decompressed output MUST equal `logical_length`;
- for PACKED, after the stored Pre-Trailer has been structurally validated (and AEAD-authenticated when encrypted), the decompression ceiling is `packed_logical_length = max(inner_offset + inner_length)` using checked arithmetic; packed entries MUST be non-overlapping, sorted, and densely concatenate from offset zero, so this value also equals the sum of `inner_length`;
- decompressed output MUST exactly equal the applicable validated ceiling.

The writer compression-strength profiles are:

```text
ZSTD_FAST    = level 1
ZSTD_DEFAULT = level 3
ZSTD_DENSE   = level 9
```

R10 does **not** claim that independent Zstandard implementations or library versions necessarily produce byte-identical compressed output from equal logical input.

```text
equal logical data != guaranteed equal compressed bytes
```

Whole-frame deduplication therefore occurs only when the resulting stored representations are byte-identical.

There is no `ZSTD_MAX` profile. Values `0x04-0xFF` are genuinely reserved.

The compression levels above are the writer's RECOMMENDED settings for each profile. Because compressed output is not reproducible across encoder implementations, a reader cannot verify which level produced a payload, and conformance is determined only by `codec_id` and the decoder rules of this section. An encoder that has no exact equivalent of a level (for example a pure-Go encoder without level 9) MAY use its closest documented setting.

### 5.1.1 Zstandard frame constraints

Every `ZSTD_*` stored payload (after AEAD decryption when encrypted) MUST additionally satisfy:

- it is exactly one Zstandard frame (magic `0xFD2FB528`) followed by no further bytes; skippable frames (magic `0x184D2A50..0x184D2A5F`) are forbidden;
- the frame header contains `Frame_Content_Size`, and that value equals the expected logical length (`logical_length` for DATA, `packed_logical_length` for PACKED);
- `Window_Size` does not exceed `MAX_FRAME_SIZE`;
- no dictionary ID is present (`Dictionary_ID` absent or zero).

A reader MUST check these constraints from the frame header before allocating the decompression buffer, and MUST cap decoder memory at the validated expected length.

## 5.2 Named interoperability and deployment profiles

The following names are combinations of existing wire fields. No `profile_id` is stored on disk.

### BASELINE

Purpose: **minimum interoperable 🌀 STASH implementation**.

```text
hash        SHA-256
compression STORE
encryption  NONE
```

A minimal conformant R10 reader/writer MUST support BASELINE and MUST additionally support:

- VARIABLE geometry;
- DATA frames;
- Frame Prefix CRC32C;
- Master Trailer integrity through the mandatory Pre-Trailer CRC32C binding defined in §6.4;
- Pre-Trailer CRC32C;
- manifest reading/writing;
- physical-offset-index rebuild;
- raw physical scanning;
- logical reconstruction of non-packed DATA.

A BASELINE-only implementation MAY omit writing FIXED, PACKED, parity, encryption, and compaction, but it MUST safely recognize and reject unsupported R10 features rather than misparse them.

### SECURE

Purpose: **conservative authenticated enterprise archival profile**.

```text
hash        SHA-256
compression STORE
encryption  AES-256-GCM
```

The cryptographic construction is fully defined by §15. SECURE uses SHA-256 for `hash_payload`, the keyed HMAC-SHA-256 `object_id` of §6.5, STORE compression, and AES-256-GCM; it therefore does not require BLAKE3 or Zstandard.

### FAST

Purpose: **maximum practical ingest and recovery throughput**.

```text
hash        BLAKE3
compression ZSTD_FAST
encryption  NONE
```

FAST is intended for deployments where encryption is unnecessary or is provided by another trusted storage/security layer.

### Security policy scope

Named profiles bind only data-processing choices. Anti-rollback protection is an orthogonal deployment/security policy and is not encoded by `profile_id` or any other new wire field.

Recommended combinations:

```text
BASELINE + STANDARD    common
SECURE   + STANDARD    valid
SECURE   + HARDENED    recommended for adversarial enterprise storage
FAST     + STANDARD    common
FAST     + HARDENED    valid when freshness matters more than confidentiality
```

A HARDENED deployment MUST configure a working Generation Anchor. Enabling HARDENED without an anchor is a configuration error.

### Profile scope

A named profile is a conformance predicate over an archive, not merely a CLI label. The names bind only:

```text
hash
compression
encryption
```

They do not redefine VARIABLE/FIXED, parity, PACKED, `blob_count`, or `MAX_FRAME_SIZE`. Those remain orthogonal archive properties. A writer claiming BASELINE or SECURE conformance MUST use STORE for every frame; a writer claiming FAST conformance MUST use ZSTD_FAST for every compressible frame (STORE MAY be used only when compression is explicitly skipped because the stored representation would not be smaller). Per-frame codec override remains a wire capability for explicitly configured/custom archives, but an override outside a named profile makes that archive non-conformant to the named profile. Because no `profile_id` is stored, readers determine compatibility from actual wire fields and MUST NOT infer a profile name from a single header field.

The 🌀 STASH Go reference implementation MUST support BASELINE, SECURE, and FAST, plus STANDARD and HARDENED security policies.

---

# 6. Frame Binary Format

R10 retains a fixed 16-byte Frame Prefix at the start and a fixed 96-byte Master Trailer at the end of every frame.

```text
[ Frame Prefix: 16 B ]
[ stored payload ]
[ zero padding ]
[ Pre-Trailer body ]
[ pre_trailer_len: 4 B ]
[ Master Trailer: 96 B ]
```

The complete region above is exactly `frame_size` bytes.

## 6.1 Frame Prefix — 16 bytes

The Prefix exists so a VARIABLE-mode recovery scanner can determine the physical extent before reading the complete frame.

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STFR` |
| `0x04` | 4 | frame_quanta | uint32 | physical size / 4096 |
| `0x08` | 4 | prefix_crc32c | uint32 | CRC32C over `magic || frame_quanta || flags` |
| `0x0C` | 4 | flags | uint32 | MUST be zero |

The Prefix CRC is exactly:

```text
prefix_crc32c = CRC32C(prefix_bytes[0x00:0x08] || prefix_bytes[0x0C:0x10])
```

It is **not** a CRC over the first 12 contiguous bytes and is not computed by zeroing the CRC field unless that implementation produces exactly the byte sequence above. A reader MUST validate Prefix magic, require `flags == 0`, validate this CRC, and validate bounds before allocating or reading the full frame.

In FIXED mode it MUST additionally verify:

```text
frame_quanta == max_frame_quanta
```

## 6.2 Master Trailer — 96 bytes

R10 retains the larger self-describing trailer because non-packed DATA frames must carry logical placement information directly in raw storage.

| Offset | Size | Field | Type | Description |
|---|---:|---|---|---|
| `0x00` | 4 | magic | char[4] | `STSH` |
| `0x04` | 1 | hash_id | uint8 | MUST match Archive Header |
| `0x05` | 1 | codec_id | uint8 | codec used by this frame |
| `0x06` | 1 | block_type | uint8 | `0 DATA`, `1 PARITY`, `2 PACKED` |
| `0x07` | 1 | flags | uint8 | MUST be zero |
| `0x08` | 4 | group_id | uint32 | `0` if not in parity group |
| `0x0C` | 1 | group_index | uint8 | group position |
| `0x0D` | 1 | group_k | uint8 | data count |
| `0x0E` | 1 | group_m | uint8 | parity count |
| `0x0F` | 1 | reserved | uint8 | MUST be zero |
| `0x10` | 4 | data_len | uint32 | stored payload representation length |
| `0x14` | 4 | frame_quanta | uint32 | redundant with Prefix; MUST agree |
| `0x18` | 16 | object_id | bytes | logical object identity; zero for PARITY and PACKED frames |
| `0x28` | 8 | logical_offset | uint64 | non-packed logical byte offset |
| `0x30` | 8 | logical_length | uint64 | logical bytes represented |
| `0x38` | 8 | frame_ordinal | uint64 | immutable creation-time ordinal |
| `0x40` | 32 | hash_payload | bytes | §4 |

Trailer and Prefix `frame_quanta` disagreement is corruption.

### Block-type semantics

**DATA:** one non-packed logical object extent. `object_id`, `logical_offset`, `logical_length` are mandatory.

**PACKED:** multiple small logical objects described in the Pre-Trailer. Trailer-level `object_id`, `logical_offset`, and `logical_length` MUST be zero. Packed entry offsets use `inner_offset` semantics (§8).

**PARITY:** parity payload. Object-placement fields MUST be zero unless a future format revision explicitly defines otherwise.

## 6.3 Payload budget

The exact physical constraint is:

```text
data_len
+ FRAME_PREFIX_SIZE
+ zero_padding_len
+ pre_trailer_len
+ 4                       // pre_trailer_len field
+ MASTER_TRAILER_SIZE
= frame_size
```

where:

```text
FRAME_PREFIX_SIZE  = 16
MASTER_TRAILER_SIZE = 96
zero_padding_len >= 0
```

Therefore:

```text
data_len <=
    frame_size
  - 16
  - 4
  - 96
  - pre_trailer_len
```

A writer MUST calculate this exact budget before commit. A reader MUST reject overlap between payload and Pre-Trailer.

## 6.4 Pre-Trailer

Immediately before the 4-byte `pre_trailer_len` field is `pre_trailer_body`. `pre_trailer_len` is always the exact stored byte length of `pre_trailer_body`, not the plaintext length.

### 6.4.1 Canonical unsigned LEB128

`path_len` uses canonical unsigned LEB128: seven low-order value bits per byte, least-significant group first, high bit set on every non-final byte. Only the shortest encoding is valid. Because this specification limits canonical UTF-8 paths to 4096 bytes, `path_len` MUST fit in at most two LEB128 bytes; longer, overlong/non-canonical, truncated, or values greater than 4096 MUST be rejected.

### 6.4.2 Plaintext Pre-Trailer

When the Archive Header `ENCRYPTED` flag is clear, the stored body is:

```text
uint32 entry_count
repeated entry_count times:
    uleb128 path_len
    bytes   canonical_path_utf8
    uint64  inner_offset_or_logical_offset
    uint64  inner_length_or_logical_length
    uint64  file_ver
uint32 outer_crc32c
```

`entry_count MUST be <= MAX_PACKED_ENTRIES (65535)`. For non-packed DATA, `entry_count` MUST equal exactly 1. For PACKED, `1 <= entry_count <= MAX_PACKED_ENTRIES`. For PARITY, `entry_count` MUST equal 0.

### 6.4.3 Encrypted Pre-Trailer

For DATA/PACKED when the Archive Header `ENCRYPTED` flag is set, sensitive Pre-Trailer plaintext is:

```text
uint32 entry_count
repeated entry_count times:
    uleb128 path_len
    bytes   canonical_path_utf8
    uint64  inner_offset_or_logical_offset
    uint64  inner_length_or_logical_length
    uint64  file_ver
```

The stored body is:

```text
nonce[12] || ciphertext || tag[16] || outer_crc32c[4]
```

where AEAD encryption is defined by §15.3/§15.4. The outer CRC remains plaintext so keyless recovery can detect accidental modification of the stored encrypted envelope, `pre_trailer_len`, and Master Trailer before trusting those metadata.

For both plaintext and encrypted forms:

```text
outer_crc32c = CRC32C(
    pre_trailer_body_without_outer_crc
    || uint32_le(pre_trailer_len)
    || master_trailer_bytes[96]
)
```

`pre_trailer_len` includes the outer CRC and, in encrypted mode, includes nonce+ciphertext+tag overhead. A frame with no logical entries still carries the minimum applicable body and the outer CRC.

Reverse parsing order:

1. locate the 96-byte Master Trailer from the validated frame end;
2. read `pre_trailer_len`;
3. validate all bounds using checked arithmetic before allocation;
4. locate the complete stored body;
5. verify `outer_crc32c`, including the complete Master Trailer;
6. if encrypted DATA/PACKED, verify/decrypt AEAD;
7. parse exactly `entry_count` entries with canonical LEB128;
8. validate entry-count, path, offset, length, and block-type semantics.

#### 6.4.4 Alignment note

The format requires physical frame boundaries to lie on the frame grid (§3.1.1) but does **not** require `pre_trailer_body_start` to be 8-byte aligned. Earlier development revisions carried such a rule; it is intentionally absent because the tail-anchored variable-length Pre-Trailer has no independent alignment field. Implementations needing aligned I/O MUST copy metadata through an aligned bounded buffer rather than infer an unstated wire constraint.

### 6.4.5 Canonical paths and DATA recovery metadata

A canonical path is valid UTF-8 normalized to Unicode NFC, uses `/` as the only separator, is relative (no leading `/`), contains no empty component, `.` component, `..` component, NUL, or backslash, and is at most 4096 UTF-8 bytes.

Additionally, a canonical path MUST NOT contain C0 control characters (`U+0000..U+001F`), `U+007F`, C1 control characters (`U+0080..U+009F`), surrogate code points, or code points that are unassigned in Unicode 15.0. Unassigned means General_Category `Cn` in Unicode 15.0.0, which includes the 66 noncharacters; private-use code points are assigned. NFC is evaluated against Unicode 15.0 normalization data. Pinning the Unicode version and rejecting unassigned code points keeps canonicalization stable across library versions: Unicode guarantees that NFC of assigned characters never changes.

Path ordering anywhere in this specification (for example PACKED entry order, §8) is **bytewise** comparison of the canonical UTF-8 bytes, shorter prefix first.

Every non-packed DATA frame MUST carry exactly one Pre-Trailer entry. Its path and `file_ver` identify the logical object; its offset/length fields MUST equal the Master Trailer `logical_offset`/`logical_length`; recomputing `object_id` from that path and `file_ver` MUST equal the Master Trailer `object_id`. This repetition is intentional and is required for manifest-independent named recovery.

For a zero-length object, the single DATA frame uses `logical_offset = 0` and `logical_length = 0`; no other DATA frame for that object version may coexist.

## 6.5 `object_id`

`object_id` is a 16-byte identifier of one object version. Let

```text
msg = ASCII("STASH-OBJECT-ID-V2") || canonical_path_utf8 || uint64_le(file_ver)
```

In an unencrypted archive:

```text
object_id = first_16_bytes(HASH(hash_id, msg))
```

In an encrypted archive (Header `ENCRYPTED` set), whatever the `hash_id`:

```text
object_id = first_16_bytes(HMAC-SHA-256(objectid_key, msg))
```

where `objectid_key` is derived in §15.2. The keyed form prevents a party without the key from confirming a guessed path against plaintext trailers. Without the key, `object_id` stays usable as an opaque grouping key: keyless recovery still groups the extents of one version by equal `object_id`.

`object_id` is **not stable across rename**. BASELINE uses SHA-256, FAST uses BLAKE3, and SECURE uses HMAC-SHA-256; no extra mandatory dependency is introduced by object identity.

A rename changes `canonical_path`, therefore produces a new `object_id`. Rename is modeled as a new logical object/version under copy-on-write semantics. Existing frames under the old identity remain valid until they become unreachable and are reclaimed by GC.

The format does not define a path-independent inode/object UUID alias layer.

## 6.6 Logical placement invariants

For non-packed DATA frames:

```text
logical_offset % BASE_QUANTUM == 0
logical_length >= 0
```

`logical_length == 0` is valid only for the single-frame empty-object representation defined in §6.4.5. Otherwise `logical_length > 0`. A positive `logical_length` MAY be non-4KiB-aligned only for the extent that ends the object; every other extent's `logical_length` is a multiple of 4096 so that the next extent's `logical_offset` stays aligned.

### 6.6.1 Logical length ceiling

To bound decompression and reconstruction work by a value that is already validated before allocation, R10 fixes:

```text
non-packed DATA:  logical_length        <= MAX_FRAME_SIZE
PACKED:           packed_logical_length <= MAX_FRAME_SIZE
```

A reader MUST reject a frame that violates either bound before decompressing it. A writer MUST split logical data so that no frame represents more than `MAX_FRAME_SIZE` logical bytes, whatever the compression ratio.

### 6.6.2 Stored length for STORE

For `codec_id == STORE` the stored payload length is exact:

```text
unencrypted DATA:    data_len == logical_length
unencrypted PACKED:  data_len == packed_logical_length
encrypted DATA:      data_len == logical_length + 28
encrypted PACKED:    data_len == packed_logical_length + 28
```

Any other value is corruption.

A frame represents:

```text
[logical_offset, logical_offset + logical_length)
```

Physical discovery order MUST NOT define object order.

## 6.7 R10 logical object metadata scope

R10 logical objects are byte streams identified by canonical path plus `file_ver`. The format does not define POSIX mode bits, uid/gid, timestamps, symlinks, hardlinks, xattrs, ACLs, device nodes, or sparse-hole semantics. Those are application metadata outside the core format unless a future revision defines them. Zero-byte objects are representable by the single zero-length DATA frame of §6.4.5.

---

# 7. Parity / Erasure Coding

R10 retains exactly two non-zero parity algorithms:

| Value | Scheme | Tolerance |
|---|---|---|
| `0x00` | none | 0 |
| `0x01` | XOR | 1 DATA/PACKED shard per group |
| `0x02` | Reed-Solomon | `parity_m` DATA/PACKED shards per group |
| `0x03-0xFF` | reserved | — |

Writers MUST NOT emit any other non-zero scheme; readers MUST reject every reserved value.

Header invariants:

```text
NONE: parity_k = 0, parity_m = 0
XOR:  parity_k > 0, parity_m = 1
RS:   parity_k > 0, parity_m > 0
active parity: blob_count >= 2, parity_k + parity_m <= 256
```

Per-group invariants (Master Trailer fields of every member):

```text
group_id == 0:  group_index = group_k = group_m = 0          (no parity)
group_id != 0:  1 <= group_k <= parity_k
                group_m == parity_m
                group_index < group_k + group_m
                every member carries identical group_k and group_m
```

A group with `group_k < parity_k` is a **short group**, typically the last group written before a flush. A short group is coded exactly as a full code with `k = group_k` and `m = group_m` (§7.2.1); no virtual zero shards are implied. In an archive whose header parity scheme is NONE, every frame MUST have `group_id == 0`. A PARITY frame MUST have `group_index >= group_k`; a DATA or PACKED member MUST have `group_index < group_k`.

`group_id == 0` means no parity group. Valid group IDs are `1..0xFFFFFFFF`. A `group_id` MUST be unique within one generation; exhaustion within a generation is fatal. A writer allocates group IDs from the generation's kind 4 Allocator State (§2.1.3), never from a scan or from the manifest alone, because members of an interrupted group can survive on media without any manifest record. A compactor byte-copying a group preserves its ID into the destination generation and initializes the destination `groups.alloc` above every copied ID before allocating new ones.

Raw recovery MUST treat frames carrying one `group_id` as one group only if they agree on `group_k` and `group_m`, have equal `frame_quanta`, and no `group_index` occurs twice. Otherwise it reports a `group_id` conflict and uses none of the conflicting members for parity reconstruction. `group_index` values `0..parity_k-1` are data/PACKED shards and `parity_k..parity_k+parity_m-1` are parity shards.

## 7.1 Equal physical geometry and parity shard size

All physical frames in one parity group MUST have identical `frame_quanta` and physical `frame_size = S`.

Every PARITY frame MUST use the minimal zero-entry plaintext Pre-Trailer (`entry_count=0` plus outer CRC), whose stored length is 8 bytes. Therefore the exact parity payload / shard length is:

```text
PARITY_SHARD_LEN(S) = S - FRAME_PREFIX_SIZE - 8 - 4 - MASTER_TRAILER_SIZE
                    = S - 124
```

A PARITY frame has `codec_id = STORE`, `data_len = PARITY_SHARD_LEN(S)`, zero padding length 0, and a normal Prefix, minimal **plaintext** Pre-Trailer, length field, and Master Trailer. This remains true when the archive `ENCRYPTED` flag is set: PARITY payloads and their empty Pre-Trailers are not AEAD-wrapped, because they protect already-stored representations and must remain reconstructable without keys.

## 7.2 Canonical recovery shard

Parity is **not** computed directly over raw physical frame bytes and is not computed only over `data_len`. For each protected DATA or PACKED frame, construct exactly one canonical recovery shard of `PARITY_SHARD_LEN(S)` bytes:

```text
uint32_le(recovery_image_len)
recovery_image[recovery_image_len]
zero bytes until PARITY_SHARD_LEN(S)
```

where:

```text
recovery_image =
    exact stored payload representation
    || exact stored pre_trailer_body
    || uint32_le(pre_trailer_len)
    || exact master_trailer_bytes[96]
```

The Prefix and physical zero-padding are deliberately excluded because they are deterministic/reconstructable. The shard MUST satisfy:

```text
4 + recovery_image_len <= PARITY_SHARD_LEN(S)
```

Because `recovery_image_len = S - 16 - zero_padding_len`, this is equivalent to:

```text
zero_padding_len >= 112
```

Parity-protected DATA/PACKED writers MUST therefore reserve at least 112 bytes of zero padding. A frame that cannot satisfy this inequality at its selected physical size MUST be repartitioned, enlarged in VARIABLE mode if allowed, or left outside that parity group.

XOR computes bytewise XOR across the `group_k` canonical shards. Reed-Solomon operates over the same equal-length canonical shards using the group's `(k, m) = (group_k, group_m)` as defined in §7.2.1. Each resulting parity shard is stored verbatim as the payload of its corresponding PARITY frame.

### 7.2.1 Reed-Solomon code definition

Reed-Solomon parity is defined exactly as follows, so that independent implementations produce byte-identical parity shards.

- **Field.** GF(2^8) with reducing polynomial `x^8 + x^4 + x^3 + x^2 + 1` (`0x11D`). Addition is XOR. Multiplication is polynomial multiplication modulo `0x11D`.
- **Vandermonde matrix.** For `n = k + m`, let `V` be the `n × k` matrix with `V[r][c] = r^c` computed in the field, where `r` is the row index `0..n-1` interpreted as a field element, `c` is `0..k-1`, and `0^0 = 1`.
- **Systematic encoding matrix.** Let `T` be the top `k × k` submatrix of `V`. The encoding matrix is `E = V × T^-1`. Its top `k` rows are the identity.
- **Encoding.** Data shard `i` (member `group_index = i`, `0 <= i < k`) is the canonical recovery shard of §7.2. Parity shard `j` (member `group_index = k + j`) is, byte position by byte position, `sum over i of E[k + j][i] * data_shard_i`.
- **Decoding.** Any `k` surviving shards reconstruct the rest by inverting the corresponding `k` rows of `E`.

This is the construction used by the default (non-Cauchy, non-Leopard) matrix of `github.com/klauspost/reedsolomon` and by Backblaze JavaReedSolomon. Cauchy matrices, PAR1 matrices, and GF(2^16) variants are **not** conformant. Conformance golden vectors (§17.8) fix the result.

For XOR (`parity_scheme == 0x01`), the single parity shard is the bytewise XOR of the data shards. An implementation MUST NOT substitute an RS code with `m = 1` for XOR, because the RS parity row is not all ones.

## 7.3 Full-frame reconstruction

After recovering a missing DATA/PACKED canonical shard:

1. parse and validate `recovery_image_len`;
2. split the recovery image by reading the recovered Master Trailer from its final 96 bytes and `pre_trailer_len` from the preceding four bytes;
3. recover exact stored payload and exact stored Pre-Trailer bytes;
4. regenerate the 16-byte Frame Prefix from known `frame_quanta`, `STFR`, zero Prefix flags, and a new correct Prefix CRC32C;
5. regenerate physical zero-padding as zero bytes so the recovered stored regions occupy their canonical tail positions and the frame reaches exactly `S`;
6. validate the reconstructed frame normally: Prefix, outer Pre-Trailer CRC, hash, AEAD when keys are available, and logical metadata.

Thus parity can reconstruct a completely missing protected frame without the manifest and without requiring the original zero-padding bytes. Encrypted recovery remains byte-preserving because the recovery image carries stored nonce/ciphertext/tag and stored encrypted Pre-Trailer bytes.

### 7.3.1 Writing repairs

A reconstructed frame is never written back into the blob it was lost from, because committed frames are immutable. Repair is performed by compaction (§13): the reconstructed DATA/PACKED frame is written to the destination generation byte-identically, which is a copy and not a new encryption. A lost PARITY frame cannot be restored byte-identically, because its `frame_ordinal` is not part of any shard; it is recomputed from the data shards and written as a new frame with the same `group_id`, `group_index`, `group_k`, and `group_m` and a new `frame_ordinal` from the destination namespace.

## 7.4 Spread and discovery

A parity group MUST span at least two distinct blobs. Every DATA/PACKED/PARITY member carries `group_id`, `group_index`, `group_k`, and `group_m` in its Master Trailer, so group membership is discoverable without the manifest. A redundant manifest `PARITY_GROUP` record MAY exist for operations in unencrypted archives (§10.1.2), but it is not authoritative for raw discovery.

The tolerance column of §7 counts lost **shards**, not lost blobs. A group survives the loss of one whole blob only if no blob holds more than `group_m` of its members. A writer SHOULD place members so that every blob holds at most `group_m` members of a group (**blob-loss-tolerant placement**), and MUST report to the operator when the configuration (`blob_count < ceil((group_k + group_m) / group_m)`) makes blob-loss-tolerant placement impossible.

Integrity detection remains separate from repair: damage must first be identified by structure/hash/AEAD as applicable; parity then reconstructs the canonical shard.

---

# 8. Frame Packing

PACKED frames aggregate small files before compression.

Packing procedure:

1. normalize paths;
2. sort files lexicographically by canonical path;
3. concatenate file bytes into one logical packed buffer;
4. compress the complete buffer using the selected canonical codec profile;
5. write one PACKED frame if physical limits permit.

PACKED `entry_count` MUST be in `1..65535`. Packed entries MUST be sorted by canonical path in bytewise order (§6.4.5), MUST NOT repeat a path, and their logical packed ranges MUST be non-overlapping and densely contiguous from offset zero. An entry with `inner_length == 0` is valid and represents an empty object; its `inner_offset` equals the end of the previous entry.

Packed entries use:

```text
inner_offset
inner_length
```

relative to the **uncompressed packed logical buffer**.

Non-packed DATA frames use:

```text
logical_offset
logical_length
```

relative to the complete logical object.

These semantics MUST NOT be mixed.

PACKED frames are supported identically in VARIABLE and FIXED modes. In FIXED mode the physical container is always `MAX_FRAME_SIZE`; unused capacity is padding.

If a candidate packed file cannot fit into an otherwise-empty frame, the writer MUST fail the packing attempt immediately and route the file through the non-packed multi-frame path. It MUST NOT retry indefinitely.

---

# 9. Logical Object Mapping and Immutable Copy-on-Write

## 9.1 Manifest location tuple

For non-packed extents:

```text
[blob_ordinal, frame_hash, logical_offset, logical_length]
```

For an object stored inside a PACKED frame the same 4-element form is used with exactly one element:

```text
[blob_ordinal, frame_hash, "0", object_length]
```

where `frame_hash` identifies the PACKED frame and `object_length` equals the entry's `inner_length`. The reader resolves the frame, verifies `block_type == PACKED`, and selects the Pre-Trailer entry whose path and `file_ver` equal the record's `path` and `file_ver`. Exactly one entry MUST match. An object version is either entirely PACKED (one element) or entirely non-packed DATA; mixing the two forms in one object version is corruption.

The manifest intentionally does **not** contain `physical_offset`. Physical placement changes during compaction and belongs to the per-generation physical index (§10.5).

`frame_hash` lookup can return multiple physical candidates if payload-identical frames exist. The physical index is therefore a multimap; object/trailer metadata resolves the intended extent.

## 9.2 Ordering

Logical order is determined exclusively by `logical_offset`.

The order of entries inside `loc`, `ADD_EXTENT`, index files, or physical blob discovery MUST NOT be used as an ordering guarantee.

## 9.3 Logical Recovery Grid

R10 retains the R8 conceptual 4 KiB Logical Recovery Grid:

```text
logical_quantum_index = logical_offset / 4096
quantum_count = ceil(logical_length / 4096)
```

A recovery implementation MAY map extents into 4 KiB entries, page tables, interval maps, radix structures, or another equivalent representation.

The in-memory representation is implementation-defined and is not part of the wire format.

## 9.4 Overlap and gap detection

During recovery, two live extents of the same `object_id` claiming overlapping logical byte ranges are a conflict/corruption condition unless an explicit newer manifest transaction resolves the overlap.

A reader MUST NOT silently choose one candidate.

Missing logical regions MUST be surfaced as incomplete/degraded data, not zero-filled silently unless higher-level policy explicitly requests sparse-file semantics.

## 9.5 Immutable copy-on-write

A committed frame MUST NEVER be modified in place. A logical modification creates a new object version: it allocates a new `file_ver` (§10.2.1), writes a complete new set of immutable frames for that version, durably commits it, and leaves the previous version's frames in place until GC reclaims them.

**Every version is self-contained.** Each DATA frame embeds the `object_id`, path, and `file_ver` of exactly one version, and §4.2 allows physical sharing only between identical recovery identities. A new version therefore never references frames of an earlier version, not even unchanged regions. This is the deliberate consequence of design priority 4 (self-describing recovery) ranking above priority 5 (throughput): raw recovery can reconstruct every version from its own frames without the manifest.

Costs that follow, and that deployments MUST plan for:

- a modification of an object of size `L`, including an append, rewrites `L` bytes;
- a rename rewrites the object, because the path is part of recovery identity (§6.5);
- whole-frame deduplication between logical references does not occur in practice (§4.2).

Workloads that modify large data incrementally SHOULD model it as many immutable objects (segments, chunks, log files) rather than one large mutable object, so that a change rewrites only the affected segment. This is the model of the workloads listed in §3.6.

## 9.6 Absolute logical offsets and insert/delete operations

R10 retains the absolute `logical_offset` model and stores absolute `logical_offset` in every non-packed DATA Master Trailer and repeats it in that DATA frame's Pre-Trailer. Within one version, extents are laid out by absolute offset. Because every new version is written in full (§9.5), insert/delete operations do not cause any additional rewrite beyond the full rewrite of the new version; they only determine how the new version's extents are partitioned.

VARIABLE mode does **not** promise insertion-stable frame identity. Its benefit is variable physical allocation, reduced padding, and freedom from fixed physical slot boundaries. R9 text claiming that tail growth or local overwrites "can stay local" is withdrawn: it contradicted §4.2 and §6.5.

`logical_offset` of every non-packed DATA frame MUST remain 4096-byte aligned. A writer MUST partition each version so that only the final extent ends off a 4096-byte boundary.

## 9.7 FIXED-mode rewrite semantics

The same version rule applies in FIXED mode; additionally every newly written physical frame remains exactly `MAX_FRAME_SIZE`. FIXED intentionally trades padding for direct slot geometry.

---

# 10. Manifest and Physical Indexing

## 10.1 Manifest journal

`manifest.jsonl` remains an append-only logical journal.

Every committed record carries a strictly increasing `seq`. `ts` is informational only and MUST NOT define ordering.

Manifest writes are serialized through one logical manifest commit stream even while blob data writes occur in parallel.

`MAX_MANIFEST_LINE_BYTES = 1 MiB`.

Readers MUST reject a line exceeding the bound rather than buffer unbounded data. Unknown `op` values are unsupported R10 semantics and MUST fail closed rather than be ignored.

### 10.1.1 Canonical JSON representation

Manifest text is UTF-8 JSON Lines: exactly one JSON object per line, terminated by LF (`0x0A`); writers MUST NOT emit a UTF-8 BOM. Field order is not semantically significant. Duplicate JSON object keys MUST be rejected.

Strictness rules (readers MUST reject violations):

- the line is valid UTF-8 (no replacement of invalid sequences), and every JSON string decodes to valid Unicode scalar values;
- the top-level value is an object; every key is one of the fields listed for its `op` in §10.1.2, plus the optional `ts`; unknown keys are rejected;
- `MAX_MANIFEST_LINE_BYTES` counts the line's bytes **excluding** the terminating LF;
- writers MUST NOT emit insignificant whitespace; readers MUST accept it.

Writers emit one canonical form, so that encoder golden vectors (§17.1) are exact: keys in the order listed for the `op` in §10.1.2, with `ts` last when present; an envelope emits `seq`, `op`, `enc`; an envelope plaintext emits the op's fields in listed order followed by `prev`. Strings escape only `"` as `\"`, `\` as `\\`, and U+0000..U+001F as `\u00XX` with lowercase hexadecimal digits; every other character, including `/`, is emitted as raw UTF-8. Readers still accept every valid JSON form.

All uint64 wire-semantic values are encoded as **decimal JSON strings**, never JSON numbers: `seq`, `file_ver`, `logical_offset`, `logical_length`, linked-manifest `lines`, and `ts`. This avoids the IEEE-754 2^53 interoperability limit. A decimal string MUST match `0|[1-9][0-9]*` and MUST NOT exceed `18446744073709551615`; leading zeros, signs, exponents, and empty strings are rejected. uint8/uint16/uint32 bounded values (`blob_ordinal`, `hash_id`, `extent_sequence`, `extent_record_count`, `extent_count`, `group_id`, `group_index`) are JSON integers without fraction or exponent, within their type range.

The optional `ts` field is an informational decimal string of Unix nanoseconds. It never affects ordering or state.

A `frame_hash`/manifest `hash` is exactly 64 lowercase hexadecimal characters encoding 32 bytes. A `tx_id` is exactly 32 lowercase hexadecimal characters encoding 16 random bytes. Canonical paths use §6.4.5.

`seq` is one generation-global uint64 namespace across `manifest.jsonl` **and every linked submanifest of the same generation**. No two records of one generation may share a `seq`, regardless of file. Rules:

- each generation's `seq` namespace starts fresh; the first record of a generation MAY use any value `>= 1`;
- within each file, `seq` is strictly increasing in line order;
- gaps are allowed (a reserved but unused `seq` after a crash, §2.1.3, leaves a gap); a gap is never evidence of corruption by itself;
- the logical order of the generation's manifest graph is ascending `seq` across all files; a reader merges the files as sorted streams (bounded memory, one cursor per file);
- `seq` values are allocated through the generation's `manifest.alloc` (§2.1.3) when the archive is encrypted.

A linked submanifest always belongs to the same archive and generation as its parent (§10.6).

### 10.1.2 Normative operation set

R10 recognizes exactly: `ADD`, `DEL`, `ADD_BEGIN`, `ADD_EXTENT`, `ADD_COMMIT`, `ADD_ABORT`, `LINK_MANIFEST`, encrypted envelope counterparts (`ADD_ENC`, `DEL_ENC`, `ADD_BEGIN_ENC`, `ADD_EXTENT_ENC`, `ADD_COMMIT_ENC`, `ADD_ABORT_ENC`, `LINK_MANIFEST_ENC`), and the optional operational redundancy record `PARITY_GROUP`. Emergency-prune audit storage is implementation health metadata, not a logical file-state manifest operation.

Encryption selects the form strictly:

- in an unencrypted archive, only the plaintext operations appear; any `*_ENC` record is corruption;
- in an encrypted archive, **every** record uses an `*_ENC` envelope (§15.8.1); a plaintext `ADD`, `DEL`, `ADD_BEGIN`, `ADD_EXTENT`, `ADD_COMMIT`, `ADD_ABORT`, or `LINK_MANIFEST` record is corruption, and `PARITY_GROUP` MUST NOT be emitted.

Leaving no plaintext records in an encrypted archive ensures every record is authenticated and covered by the manifest chain.

Required logical fields:

- `ADD`: `seq`, `op`, `path`, `file_ver`, `loc`;
- `DEL`: `seq`, `op`, `path`, `file_ver`;
- `ADD_BEGIN`: `seq`, `op`, `tx_id`, `path`, `file_ver`;
- `ADD_EXTENT`: `seq`, `op`, `tx_id`, `extent_sequence`, `loc`;
- `ADD_COMMIT`: `seq`, `op`, `tx_id`, `extent_record_count`, `extent_count`;
- `ADD_ABORT`: `seq`, `op`, `tx_id`;
- `LINK_MANIFEST`: `seq`, `op`, `path`, `hash_id`, `hash`, `lines`;
- `PARITY_GROUP` (unencrypted archives only): `seq`, `op`, `group_id`, `members`, where `members` is a non-empty array of `[blob_ordinal, frame_hash, group_index]`.

A `loc` element is exactly `[blob_ordinal, frame_hash, logical_offset, logical_length]`, where the final two fields are decimal strings. `loc` is a non-empty array. `extent_record_count` counts `ADD_EXTENT` records; `extent_count` counts total `loc` tuples across those records. Both MUST match at commit.

The `loc` elements of one object version (across all its ADD_EXTENT records) MUST cover `[0, object_length)` exactly once, without gaps or overlaps, after sorting by `logical_offset`; the object length is the end of the highest extent. A zero-length object has exactly one element with `logical_offset == "0"` and `logical_length == "0"`.

## 10.2 Normal ADD / DEL

Example non-packed ADD:

```json
{"seq":"1","op":"ADD","path":"db/data.bin","file_ver":"7","loc":[[3,"<64-lower-hex>","0","4194304"]]}
```

Canonical DEL example:

```json
{"seq":"2","op":"DEL","path":"db/data.bin","file_ver":"7"}
```

`DEL` names the version it removes: its `file_ver` MUST equal the path's current version (§10.2.2). It does not physically delete referenced frames. (R9 printed `"8"` in this example, which contradicted its own semantics; the value is corrected here.)

### 10.2.1 File version allocation

`file_ver` values are allocated from the archive-wide allocator `alloc/filever.alloc` (§2.1.3). Every allocated value is used at most once in the archive's lifetime, across all paths and all generations, whether or not the transaction that obtained it commits. Consequences:

- a new version of a path always has a `file_ver` greater than every earlier version of that path;
- a re-added path after DEL never reuses an earlier `object_id`, so raw recovery never sees two different contents under one `object_id`;
- compaction copies existing `file_ver` values unchanged and never allocates replacements for them.

Let `applied_max(path)` be the largest `file_ver` applied for `path` by an `ADD` or `ADD_COMMIT` so far in `seq` order of the generation's manifest graph. Readers MUST reject as corruption an `ADD_BEGIN`, an `ADD`, or an `ADD_COMMIT` whose `file_ver` is not greater than `applied_max(path)`. The check at `ADD_COMMIT` is the one that protects state, because an `ADD_BEGIN` changes no state.

A writer MUST NOT have more than one uncommitted version of one path at a time (one open transaction, or one `ADD` not yet appended). A second write to the same path waits until the first commits or is aborted.

### 10.2.2 Live-state fold

The logical state of a generation is computed by applying its manifest graph in ascending `seq` order (§10.1.1) to a map `path -> current version`:

```text
ADD(path, v, loc)        if path has a current version u: u becomes dead
                         path's current version := (v, loc)
ADD_BEGIN / ADD_EXTENT   staged under tx_id; no visible change
ADD_COMMIT(tx_id)        applies the staged ADD at the ADD_COMMIT's seq,
                         exactly as ADD above
ADD_ABORT(tx_id)         discards the staged transaction; no visible change
DEL(path, v)             requires current version == v; path becomes absent
LINK_MANIFEST            no state change; its file's records join the merge
PARITY_GROUP             no state change
```

A path has at most one current version. Older versions are dead as soon as they are superseded; they are not retained as history. Applications that need history keep it as distinct paths. Compaction liveness (§13.1) is exactly the set of frames referenced by current versions at the Mark snapshot, plus the parity siblings of those frames (§13.7).

A DEL whose `file_ver` does not match the current version, or that names an absent path, is corruption and fails closed.

### 10.2.3 Rename

R10 has no atomic rename. A rename is a new object (§6.5): the writer commits the new path first (ADD or ADD_BEGIN..ADD_COMMIT) and then commits DEL of the old path. A crash between the two leaves both paths present; no crash point loses data. Applications needing atomic multi-path changes MUST implement them above the archive.

## 10.3 Large object transactions: `ADD_BEGIN` / `ADD_EXTENT` / `ADD_COMMIT`

A logical object whose location metadata does not fit in one bounded line MUST use a transactional extent sequence.

Example:

```json
{"seq":"100","op":"ADD_BEGIN","tx_id":"00112233445566778899aabbccddeeff","path":"db/huge.bin","file_ver":"8"}
{"seq":"101","op":"ADD_EXTENT","tx_id":"00112233445566778899aabbccddeeff","extent_sequence":0,"loc":[[0,"<hash1>","0","4194304"],[1,"<hash2>","4194304","4194304"]]}
{"seq":"102","op":"ADD_EXTENT","tx_id":"00112233445566778899aabbccddeeff","extent_sequence":1,"loc":[[2,"<hash3>","8388608","4194304"]]}
{"seq":"103","op":"ADD_COMMIT","tx_id":"00112233445566778899aabbccddeeff","extent_record_count":2,"extent_count":3}
```

One `ADD_EXTENT` line SHOULD batch as many extent tuples as possible without exceeding `MAX_MANIFEST_LINE_BYTES`.

`ADD_EXTENT` does **not** require an `fsync` after every line.

The object becomes logically visible only after a valid durable `ADD_COMMIT`.

A transaction is **ignored** (it never becomes a committed object version, and the manifest stays valid) in exactly these cases: it has no `ADD_COMMIT` or `ADD_ABORT` yet; it ends with `ADD_ABORT` (§10.3.1); or its `ADD_COMMIT` counts do not match the `ADD_EXTENT` records present, including missing or duplicate `extent_sequence`. Every other violation is corruption under §10.4.2 and fails closed, in particular an `ADD_EXTENT`, `ADD_COMMIT`, or `ADD_ABORT` naming a `tx_id` with no open transaction, and a committed transaction whose `loc` elements do not cover `[0, object_length)` exactly once.

Transaction rules:

- `extent_sequence` values are `0 .. extent_record_count-1`, each exactly once;
- every `ADD_EXTENT` and the `ADD_COMMIT` of a transaction have a larger `seq` than its `ADD_BEGIN`, and the `ADD_COMMIT` has a larger `seq` than every `ADD_EXTENT` of that transaction;
- transactions MAY interleave; a `tx_id` MUST NOT be reused within a generation;
- all records of one transaction are in the same file;
- a writer MUST NOT have more than `MAX_OPEN_TRANSACTIONS = 1024` begun but uncommitted transactions, and no single transaction may exceed `MAX_TRANSACTION_EXTENTS = 2^32 - 1` extents. A reader MUST fail closed with a resource error, rather than buffer, when more than `MAX_OPEN_TRANSACTIONS` transactions are open at once;
- a reader MAY spill staged extent state to bounded temporary storage; it MUST NOT hold more than its configured memory ceiling in RAM.

### 10.3.1 `ADD_ABORT`

```json
{"seq":"104","op":"ADD_ABORT","tx_id":"00112233445566778899aabbccddeeff"}
```

`ADD_ABORT` closes an open transaction without making a version visible. After it, the `tx_id` is no longer open, and later records naming it are corruption. It has a larger `seq` than every record of its transaction and lies in the same file.

- A writer MUST append `ADD_ABORT` for every transaction it will not commit (for example after an I/O error or a cancelled write) before it begins another transaction for the same path, and in any case before it reports the failure.
- On every cold start, before appending any other record, a writer MUST append `ADD_ABORT` for every transaction of the current generation's manifest graph that has an `ADD_BEGIN` but neither `ADD_COMMIT` nor `ADD_ABORT`.
- A reader counts a transaction as open from its `ADD_BEGIN` until its `ADD_COMMIT` or `ADD_ABORT`. `MAX_OPEN_TRANSACTIONS` applies to that count. With the two writer rules above, crashes cannot accumulate open transactions across writer sessions.
- Compaction (§13.2.1) never copies aborted or open transactions into the destination.

## 10.4 Durability / group commit

Required ordering:

```text
write all referenced frame bytes
-> flush/fsync affected blob(s)
-> [optional] update affected physical index(es)
-> [optional] flush/fsync index replacement(s)
-> append manifest transaction records
-> append ADD_COMMIT / terminal record
-> flush/fsync manifest
-> report transaction durable
```

Multiple manifest records MAY share one group `fsync` boundary.

A manifest MUST never become durably authoritative before every referenced frame is durably stored.

In an archive with parity, every DATA/PACKED frame referenced by a commit belongs to a closed group whose PARITY frames are written and flushed in the same durability step as the data frames, before the manifest records are appended. A group is closed when its PARITY frames are written; a short group (§7) closes a group early. A commit therefore never reports data whose configured protection does not yet exist.

The physical index steps are RECOMMENDED, not required, at each commit: an index MAY lag behind the blob and is completed by scanning (§10.5.1). The index is never load-bearing for correctness.

### 10.4.1 HARDENED commit anchoring

Under HARDENED policy, a commit is reported durable only after a commit advance of the Generation Anchor (§2.1.2):

```text
write frames -> fsync blobs
-> append manifest records -> fsync manifest
-> Advance anchor to (generation_id, manifest_length, manifest_digest)
-> report transaction durable
```

Group commit applies: one anchor advance MAY cover many transactions. The anchor round trip is therefore part of commit latency; deployments size group-commit intervals accordingly.

On HARDENED open, the reader requires `manifest.jsonl` to be at least `manifest_length` bytes long and requires SHA-256 of its first `manifest_length` bytes to equal `manifest_digest`. A shorter file or a digest mismatch is rollback or tampering and fails closed. Bytes beyond `manifest_length` are **unanchored**: they may be a commit that crashed after the manifest fsync but before the anchor advance. The writer MUST either adopt them, by validating them completely and advancing the anchor, or truncate the file back to `manifest_length` before appending. Adoption of unanchored records in an unencrypted archive is permitted only through an explicit operator-authorized recovery action, because their content is not authenticated.

**Reader snapshot.** A reader's snapshot is the pair `(generation_id, manifest_length)` fixed when it opens. Under STANDARD, `manifest_length` is the end of the last LF-terminated line at that moment; under HARDENED, it is the anchored `manifest_length`. A HARDENED reader never applies bytes beyond the anchored length. A reader MAY move to a newer snapshot only by an explicit refresh; a FUSE mount (§18.2) keeps one snapshot for its lifetime.

### 10.4.2 Torn tails

**Manifest.** A final line that lacks its terminating LF is a torn tail and is ignored by readers. A line that contains a NUL byte (`0x00`) is also the start of a torn tail, together with everything after it: no writer emits a raw NUL (§10.1.1 escapes U+0000), so NUL bytes are file pages of an append that never reached storage, which a filesystem may expose as zeros while a later page of the same append persisted. Before its next append, a writer MUST truncate the file to the end of the last LF-terminated line. A complete LF-terminated line that fails validation is corruption, not a torn tail, and fails closed; this holds for the last line too. Under HARDENED, a writer MUST NOT truncate below the anchored `manifest_length`.

**Blob.** Let `E` be the end of the last frame that is valid in an uninterrupted scan from `FRAME_AREA_START` (§11.2). A `loc` of the manifest graph that names this blob references the frame it resolves to under §9.1: its `frame_hash` together with the record's `path`, `file_ver`, and `logical_offset` (`0` for PACKED), as carried by the frame's Pre-Trailer. If any such referenced frame is not among the valid frames before `E`, committed data lies in `[E, EOF)`, whether or not the frame there still validates (it may have been damaged as described in §3.1.1 item 4), and the blob is SEALED as described below. A payload-identical frame of another object does not satisfy the reference. Otherwise, bytes in `[E, EOF)` are a torn tail **only if** no valid frame starts at any frame-grid offset inside them. In that case the writer MUST truncate the blob to `E` before appending, and durably flush the truncation. If a valid frame exists at a frame-grid offset `>= E`, the writer still MAY truncate to `E` when no frame at or beyond `E` is referenced by a `loc` of the manifest graph (all LF-terminated records, anchored or not) and none of them carries the `group_id` of a frame, in any blob, that a `loc` references. Such frames were never committed, because §10.4 makes every referenced frame durable before its commit; they typically come from pages persisted out of order, or from payload bytes that contain an embedded 🌀 STASH archive.

Otherwise the blob is damaged in the middle and becomes **SEALED**: the writer MUST NOT truncate it or append to it in this generation and records the sealed state in its health metadata; writes continue on other blobs; and the next compaction rewrites the blob's live frames, repaired by parity where needed (§7.3.1), into the destination generation. If no blob remains writable, or parity spread (§7.4) can no longer be met, writes fail until compaction completes.

Truncating a torn tail is not an in-place modification of committed data, because torn bytes were never committed. With Allocator State reservations (§2.1.3), identifiers used by torn frames or records are never reissued.

## 10.5 Mandatory per-generation physical offset index

Normal hot-path operation maintains one index per `(generation_id, blob_ordinal)`. It maps `frame_hash` to one or more candidate physical records and remains fully rebuildable from raw blob scans.

R10 retains the R8 interoperable index container because stale cross-generation indexes must be detectable without guessing. The file begins with a 64-byte header:

| Offset | Size | Field |
|---|---:|---|
| `0x00` | 8 | magic = ASCII `STIDX8` + two zero bytes |
| `0x08` | 2 | version = `0x0006` |
| `0x0A` | 2 | header_size = 64 |
| `0x0C` | 8 | generation_id |
| `0x14` | 32 | archive_id |
| `0x34` | 1 | blob_ordinal |
| `0x35` | 1 | hash_id |
| `0x36` | 2 | record_size = 64 |
| `0x38` | 8 | record_count |

It is followed by exactly `record_count` canonical 64-byte records:

| Offset | Size | Field |
|---|---:|---|
| `0x00` | 32 | frame_hash |
| `0x20` | 8 | physical_offset |
| `0x28` | 4 | frame_quanta |
| `0x2C` | 1 | block_type |
| `0x2D` | 3 | reserved, MUST be zero |
| `0x30` | 8 | frame_ordinal |
| `0x38` | 8 | reserved, MUST be zero |

Records MUST be sorted lexicographically by `frame_hash`, then by `physical_offset`; duplicate hashes are valid. Each `physical_offset` occurs in at most one record, because one frame starts at a given offset; therefore `record_count` never exceeds `(blob_size - 64) / 4096`, and a reader checks that bound before allocating. Header identity MUST match the blob/generation before any record is trusted. Every looked-up candidate is still validated against the actual frame; the index is never authoritative for correctness.

Index rebuild/update MUST write a complete temporary file, durably flush it, atomically replace the destination, and durably flush the containing directory, or use equivalent atomic durable replacement. A missing, malformed, stale, identity-mismatched, or corrupt index is discarded and rebuilt by scan.

### 10.5.1 Index validation and staleness

The index container has no checksum. A reader MUST therefore validate structurally before use:

- file size equals `64 + record_count * 64` exactly;
- header magic, version, `header_size`, `record_size`, `generation_id`, `archive_id`, `blob_ordinal`, `hash_id` match;
- `record_count <= (blob_size - 64) / 4096`, and no `physical_offset` occurs twice;
- records are sorted as required, reserved bytes are zero, `block_type` is valid, `frame_quanta` is valid for the archive mode, and every `physical_offset` lies on the frame grid with `physical_offset + frame_quanta * 4096 <= blob size`;
- any violation discards the whole index.

Let `I` be the largest `physical_offset + frame_quanta * 4096` over all records (or `FRAME_AREA_START` when `record_count == 0`). If the blob contains a valid frame at `I`, the index is **lagging**: the reader MUST scan forward from `I` and treat the scanned frames as part of the index. A lagging index is normal and is not an error.

A lookup that finds no candidate, or whose candidates all fail validation against the actual frame, MUST fall back to a scan of the blob (bounded and streaming) before reporting the frame as missing. A frame validated by such a fallback means the index is defective, and the implementation SHOULD rebuild it.

## 10.6 LINK_MANIFEST

Canonical example:

```json
{"seq":"42","op":"LINK_MANIFEST","path":"submanifests/user-data.jsonl","hash_id":1,"hash":"<64-lower-hex>","lines":"50000"}
```

A LINK_MANIFEST path is relative to the archive generation directory, MUST resolve beneath `submanifests/`, and MUST satisfy canonical relative-path rules; `..` escape is forbidden. Linked manifests are independently verifiable. Compaction liveness MUST evaluate the complete reachable manifest graph.

Exact semantics:

- `hash_id` MUST equal the archive `hash_id`. `hash` is that algorithm's digest of the **exact stored bytes** of the linked file, including every LF, and `lines` is its exact number of LF-terminated lines. The linked file is immutable once linked; a mismatch of either value is corruption;
- the linked file belongs to the same archive and generation, and its records share the generation's `seq` namespace (§10.1.1); every record in it has a `seq` greater than the LINK_MANIFEST record's `seq`;
- a linked file MUST NOT contain LINK_MANIFEST records (maximum link depth 1), so the graph is a tree without cycles; one file MUST NOT be linked twice;
- a linked file is written and durably flushed completely before the LINK_MANIFEST record is appended;
- a generation MAY link at most `MAX_LINKED_MANIFESTS = 65535` files.

R9's sentence about linked manifests "belonging to a different archive/key" is withdrawn; it contradicted the requirement that the target lies beneath this generation's `submanifests/`.

---

# 11. Disaster Recovery — Hop-and-Read

## 11.1 Common recovery start

For every available blob:

1. read the 64-byte Archive Header at `0x00`;
2. validate archive parameters and `frame_size_mode`;
3. begin at `FRAME_AREA_START = 0x40`.

## 11.2 VARIABLE-mode scan

At each current frame offset:

1. read the 16-byte Frame Prefix;
2. validate Prefix CRC and `frame_quanta` bounds;
3. compute `frame_size = frame_quanta * 4096`;
4. read or seek directly to the 96-byte Master Trailer at `current + frame_size - 96`;
5. validate Prefix/Trailer agreement;
6. validate payload and Pre-Trailer boundaries;
7. verify hash / AEAD / CRC as required;
8. recover logical metadata;
9. advance:

```text
current += frame_size
```

This scan is deterministic but sequentially dependent on the previous frame's validated size.

### 11.2.1 Resynchronization after a damaged frame

If the frame at offset `o` fails validation, a recovery scanner MUST NOT stop. It probes the frame-grid offsets `o + 4096, o + 8192, ...` until it finds an offset where a frame validates completely (Prefix CRC, bounds, outer Pre-Trailer CRC, `hash_payload`), and continues the normal scan from there. The bytes skipped are reported as a damaged region `[o, resync_offset)`.

Payload bytes can contain data that looks exactly like a valid frame; in an unencrypted archive anyone who controls stored object content can embed one. Therefore:

- a normal (non-resync) scan never probes inside the extent of a frame it has validated;
- a frame found by resynchronization is a **resync candidate**. Recovery output MUST label objects reconstructed from resync candidates as unverified provenance unless the frame is also referenced by a surviving manifest, or is authenticated by AEAD in an encrypted archive;
- if two candidates' extents overlap, both are reported as a conflict, and neither is silently chosen;
- every frame reached by the normal scan after a resync candidate is itself a resync candidate, for the rest of that blob;
- the scanner continues to probe frame-grid offsets inside the extent of a resync candidate, so that a forged frame with a large `frame_quanta` cannot hide real frames; a valid frame found there is reported together with the candidate as an overlap conflict;
- a probe validates in this order and stops at the first failure: Prefix CRC and bounds, Master Trailer, outer Pre-Trailer CRC, `hash_payload`;
- an implementation MUST bound total resynchronization work by a configured budget of hashed bytes; when the budget is exhausted, the remaining region is reported as unscanned, never as empty.

### 11.2.2 Recovered state versus logical state

Raw recovery reconstructs object **versions**, not the live-state fold. Without a manifest, recovery cannot see DEL records or which version is current, so it reports every reconstructable version, including deleted and superseded ones. A recovery tool MUST present them as versions (path, `file_ver`) and MUST NOT claim that they represent the archive's current logical state. Versions that no surviving manifest record references MUST be labeled "not known to be committed", because valid frames of an interrupted write can survive a crash.

## 11.3 FIXED-mode scan

A reader can directly address any frame slot:

```text
physical_offset(n) = 0x40 + n * MAX_FRAME_SIZE
```

Recovery MAY partition slot ranges across threads/nodes without first walking earlier frames.

Every slot's Prefix MUST still confirm:

```text
frame_quanta == max_frame_quanta
```

## 11.4 Logical reconstruction

For DATA frames, recovery uses `object_id`, `logical_offset`, and `logical_length` from self-describing metadata.

Frames MAY be discovered in arbitrary physical order.

A recovery implementation MAY create a 4 KiB logical map and mark the quanta covered by each recovered extent. For example a 4 MiB logical extent covers 1024 Logical Recovery Quanta.

Discovery order is irrelevant; logical placement is authoritative.

## 11.5 PACKED recovery

PACKED frames are reconstructed by reverse-parsing and validating the Pre-Trailer, then mapping each entry using its packed-buffer `inner_offset` / `inner_length` metadata.

## 11.6 Parity recovery

Parity groups are reconstructed from frame-local `group_id`, `group_index`, `group_k`, and `group_m` metadata. Manifest presence is not required to discover group membership.

## 11.7 Encrypted recovery

The Archive Header `ENCRYPTED` flag identifies encrypted representation before keys are available. The stored AEAD nonce is authoritative for decryption.

Recovery MUST read the nonce directly from:

```text
nonce[12] || ciphertext || tag[16]
```

It MUST NOT derive or guess the decryption nonce from the frame's **current** physical location, because compaction is permitted to byte-copy ciphertext to a different generation/blob/offset.

---

## 11.8 Anti-rollback-aware open and recovery

When STANDARD policy is used, archive opening follows normal R10 validation and no external freshness proof is required.

When HARDENED policy is configured:

1. load the trusted Generation Anchor for `archive_id`;
2. validate local `root.current`;
3. compare local and anchored `generation_id`;
4. if equal, verify `root_digest`, then verify the manifest prefix against `manifest_length` and `manifest_digest` and handle unanchored bytes (§10.4.1);
5. if local `root.current` is missing or names a generation lower than the anchor, locate the anchored generation and perform root reconstruction (§2.1.2.1); this completes both an interrupted creation and an interrupted switch;
6. if the anchored generation is missing or cannot be verified, report rollback/stale storage as an integrity/security incident and fail closed, rather than silently using an older generation;
7. if local `root.current` names a generation higher than the anchor, fail closed unless an authorized recovery flow completes the anchor transition (§13.6.1).

Raw disaster-recovery tooling MAY still inspect older generations for forensic or salvage purposes, but MUST label them non-authoritative under HARDENED policy.

# 12. Concurrency and Writer Allocation

## 12.1 Single writer

At most one process may write an archive at a time. A writer MUST hold an exclusive lock on `archive/writer.lock` (for example `flock`/`fcntl` on POSIX or `LockFileEx` on Windows, or an equivalent lease on object storage) for as long as it may append frames, append manifest records, update Allocator State, or switch generations. Lock acquisition failure is an error, never a reason to proceed. The lock file's content is implementation-defined. Within the single writer process, the rules below apply.

## 12.2 Allocation

Data writers MAY operate concurrently across blobs.

Within one blob, physical extent allocation MUST be serialized so two writers cannot claim overlapping frame regions.

VARIABLE mode allocator advances by the just-committed `frame_size`.

FIXED mode allocator advances by `MAX_FRAME_SIZE`.

Manifest commits remain a separate serialization domain.

For newly created frames, `frame_ordinal` allocation is writer-local to one current `(generation_id, blob_ordinal)` creation namespace. Byte-copied frames can carry preserved historical ordinals and MUST NOT be treated as proof that they were newly encrypted in the destination namespace. PARITY frames take ordinals from the same namespace allocator as DATA and PACKED frames.

For encrypted archives, a writer MUST allocate `frame_ordinal` values from the namespace's `blob-NN.alloc` (§2.1.3) and MUST NOT derive the next ordinal from a media scan, because a torn frame whose ciphertext reached storage may not be discoverable by a scan. It MUST NOT take the maximum trailer `frame_ordinal` across copied frames either, because copied frames carry other namespaces. Scanning stored nonces is permitted only for the conservative initialization of §2.1.3.4. For unencrypted archives, implementations MAY derive ordinals from the last committed state. Reuse within a nonce namespace is fatal.

---

# 13. Compaction / Garbage Collection

Compaction remains:

```text
Mark -> Sweep -> Freeze/Merge -> Switch -> GC
```

## 13.1 Global Mark

Mark liveness over the complete manifest graph reachable from the root, not just the sub-manifest that triggered compaction.

Logical multi-frame files and parity groups are integrity units and MUST NOT be partially forgotten by scoped liveness analysis. Liveness is defined by the live-state fold of §10.2.2.

### 13.1.1 Reader pins

A reader that pins a generation (for example a FUSE mount, §18.2, or a long export) MUST register a pin before it relies on that generation, and GC MUST NOT delete a generation that has a registered, unexpired pin. Pins carry an expiry and are renewed while the reader is active, so that a crashed reader does not block GC forever. The pin mechanism (lease files, a lock service) is implementation-defined, but every implementation sharing an archive MUST use the same one.

## 13.2 Sweep

Write a new generation. Never modify active-generation blob files in place.

Compaction MAY change:

- current `generation_id`;
- current `blob_ordinal`;
- current `physical_offset`;
- current physical ordering.

Byte-copy compaction MUST preserve:

- stored payload bytes;
- ciphertext nonce and tag;
- `hash_payload`;
- object/logical placement metadata;
- frame's immutable creation metadata;
- parity metadata;
- `frame_quanta`.

In VARIABLE mode a normal byte-copy Sweep MUST NOT resize a frame. Resizing/repacking is a rewrite operation, not opaque compaction.

### 13.2.1 Destination manifest

The destination `manifest.jsonl` starts with one committed record per live path of the Mark snapshot, in bytewise path order: an `ADD`, or an `ADD_BEGIN`/`ADD_EXTENT`/`ADD_COMMIT` transaction with a new `tx_id` when the `loc` does not fit one line. `path` and `file_ver` are unchanged; `loc` names destination blob ordinals and the `frame_hash` of the destination frame (unchanged unless the frame was regrouped, §13.7.1). `seq` starts at 1 and is allocated from the destination `manifest.alloc` when encrypted. The destination has no `LINK_MANIFEST` records (the graph is flattened into `manifest.jsonl`) and no open or aborted transactions. In an unencrypted archive the compactor MAY emit `PARITY_GROUP` records for the destination groups. The post-Mark delta (§13.4) follows these records.

## 13.3 Encrypted opaque-copy invariant

Encrypted frames MUST be copied byte-for-byte during normal Sweep.

The new current physical location has no effect on the stored nonce.

A compactor MUST NOT decrypt/re-encrypt a live frame for the purpose of relocation, nonce refresh, dedup optimization, or physical reordering.

## 13.4 Concurrent writes

Writes occurring after the Mark snapshot MUST be captured in a delta manifest or protected during the final Freeze/Merge/Switch interval by an appropriate lock/lease.

The delta is not a separate on-disk format. Post-Mark writes continue to append to the source generation's manifest. During Freeze/Merge the compactor reads the source records with `seq` greater than the Mark snapshot's last `seq`, copies or rewrites the frames they reference into the destination, and appends equivalent records to the destination manifest with destination `seq` values (re-encrypted under the destination nonce namespace when encrypted).

No writer may commit against the old root after the new root becomes authoritative.

## 13.5 Freeze/Merge

Freeze/Merge is the bounded finalization interval between the concurrent Sweep and root Switch. The implementation MUST prevent any writer from committing new state against the old root while it: (1) freezes or redirects the manifest commit stream, (2) drains and durably captures the post-Mark delta, (3) merges that delta into the destination manifest/index state, (4) verifies every resulting frame reference and required parity/object sibling, and (5) durably flushes the complete destination generation. Only after these steps may Switch begin.

## 13.6 Switch

The destination generation, manifest, and physical indices MUST be fully written, verified, and durable before the root pointer is atomically switched.

For STANDARD policy, the ordering is:

```text
destination generation durable
-> atomically replace root.current
-> fsync containing directory
-> report switch durable
```

For HARDENED policy, R10 requires the Generation Anchor protocol of §13.6.1.

Old generations remain intact until the switch is durable.

### 13.6.1 HARDENED anti-rollback switch protocol

In this section `N+1` denotes the destination generation, whose `generation_id` is greater than `N` but need not equal `N + 1` (§2.1). A HARDENED switch from generation `N` to `N+1` MUST use this order:

```text
1. build destination generation N+1
2. durably flush all required blobs
3. durably flush manifest state
4. durably flush required physical indexes
5. verify the complete destination generation
6. prepare the exact new root.current bytes for N+1
7. compute root_digest, manifest_length and manifest_digest of N+1
8. atomically Advance external Generation Anchor from N -> N+1
9. receive durable success from the external anchor
10. atomically replace root.current with N+1
11. durably flush the root directory
12. report switch durable
```

The compare-and-advance in step 8 uses the anchor state last advanced for generation `N`, including its latest commit advance; a writer that is still committing to `N` therefore cannot race the switch, which is also prevented by Freeze/Merge (§13.5).

The Generation Anchor MUST NOT advance before the destination generation is complete, verified, and durable.

If a crash occurs after step 9 but before step 10, the external anchor legitimately names `N+1` while local `root.current` still names `N`. On reopen, a HARDENED implementation MUST detect this state, locate and verify generation `N+1`, and complete the local root switch if the anchored generation is intact.

If the anchored generation is missing or fails verification, the archive MUST NOT silently fall back to `N`; the condition is a security/integrity incident requiring explicit operator policy.

If local `root.current` names a generation lower than the trusted anchor, the storage is stale or rolled back and MUST NOT be accepted as current.

If local `root.current` names a generation greater than the trusted anchor, the implementation MUST NOT silently advance trust based only on local storage. It MUST either complete the expected anchor transition through an authorized recovery flow or fail closed.

A HARDENED reader MUST compare the anchored `root_digest` against SHA-256 of the exact local `root.current` bytes in addition to `generation_id`.

## 13.7 Parity groups during compaction

If any live member of a parity group is copied, the complete required group MUST be present in the new generation before Switch.

### 13.7.1 Parity regrouping

Byte-copying whole groups keeps dead members alive whenever a group has at least one live member. To reclaim that space a compactor MAY **regroup**: it rewrites the live members of sparse groups as new frames in the destination generation, with new `frame_ordinal` values, new group assignments, and new parity frames, and drops the old groups entirely.

For an encrypted archive, regrouping requires the archive key, because the group fields are part of the frame AAD (§15.4). It is a new encryption operation: each rewritten frame gets a fresh destination nonce from the destination namespace allocator. This is permitted; §13.3 and §15.7 forbid re-encryption only for relocation, nonce refresh, dedup optimization, or physical reordering. Without the key, a compactor MUST byte-copy whole groups.

The destination MUST preserve equal `frame_quanta` across group members and the multi-blob spread requirement.

## 13.8 Multi-frame logical object integrity

All live sibling extents of a logical object version MUST be verified in the destination before the old generation containing the only remaining copy of a required extent is deleted.

If a required extent cannot be found or verified, the generation is **GC-blocked** rather than silently deleted.

## 13.9 Emergency Pruning and parity impact

Emergency Pruning is an explicit operator-authorized data-loss escape hatch for a permanently GC-blocked generation.

Before deletion, the implementation MUST perform **Parity Impact Analysis** over every parity group touched by any frame that will be lost.

Each affected parity group MUST be classified as:

- **HEALTHY** — required protection level still intact;
- **DEGRADED** — data remains reconstructable but redundancy is below the configured target;
- **UNRECOVERABLE** — one or more protected logical data extents can no longer be reconstructed.

Emergency Pruning MUST:

1. durably record an `EMERGENCY_PRUNE` event with generation, affected blobs/frames, operator reason, and timestamp;
2. mark every directly incomplete logical object `DEGRADED` or `UNRECOVERABLE`;
3. record every parity group whose protection level changes;
4. create/schedule parity rebuild for repairable surviving groups, or explicitly mark them `UNPROTECTED/DEGRADED` until repair completes;
5. prevent the active manifest/health metadata from claiming original parity protection while the group is degraded;
6. only then permit deletion of the blocked old generation.

Emergency Pruning MUST NOT be used merely because a healthy resource is temporarily unreachable.

The storage format of `EMERGENCY_PRUNE` events and DEGRADED/UNRECOVERABLE health state is implementation-defined in R10. An implementation that opens an archive without understanding another implementation's health metadata MUST treat the parity protection state as **unknown** and MUST NOT report original protection levels as intact; it SHOULD run a full parity verification before claiming any protection level.

---

# 14. Legacy Compatibility

R10 uses the unchanged R8 wire version `0x0006`.

Readers MUST dispatch on Archive Header `version` and MUST NOT parse older layouts using R8 structures.

At minimum:

- `0x0002` — R1/R2 family;
- `0x0003` — R3/R4/R5 family;
- `0x0004` — R6 development wire layout;
- `0x0005` — R7;
- `0x0006` — R8/R9/R10 semantic revision family.

R10 implementations MUST reject unsupported wire versions rather than guess. "Recognize" in §19 means: identify the legacy version and fail with a distinct unsupported-legacy-version error, without parsing any further field. Every legacy layout carries ASCII `STSH` at offset `0x00` and a little-endian uint16 version at offset `0x04`; recognition reads only these six bytes. R8, R9 and R10 are byte-compatible at wire `0x0006`; semantic/security policy differences are implementation/deployment behavior, not new media bytes.

Legacy v1.21 `.sf` and `SUB` syntax remains migration-only and is not valid R10 syntax.

---

# 15. Encryption — Normative Enterprise Profile

R10 retains the R8 encryption algorithm unchanged: AES-256-GCM. Encryption is enabled exactly when Archive Header `flags & 0x01 != 0` (`ENCRYPTED`). When enabled, the following construction is normative.

## 15.1 Archive DEK

An encrypted 🌀 STASH archive uses one cryptographically random 32-byte archive data-encryption key:

```text
archive_DEK = 32 bytes
```

The archive DEK MUST remain fixed for the lifetime of the encrypted archive. It MUST NOT be embedded in blobs, Frame Prefixes, Pre-Trailers, or Master Trailers.

The format does not store a `key_id` in frame/blob wire structures. A deployment MAY store a wrapped DEK and key identifier in protected archive metadata or an external KMS-backed configuration associated with `archive_id`. Loss of that mapping can make encrypted logical content unavailable even though keyless structural recovery still works.

## 15.2 Domain-separated AEAD keys

Four independent 256-bit keys are derived using HKDF-SHA-256:

```text
salt = archive_id[32]
IKM  = archive_DEK
```

Exact derivations:

```text
frame_aead_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-FRAME-AEAD-R8"),
        L    = 32
    )

pretrailer_aead_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-PRETRAILER-AEAD-R8"),
        L    = 32
    )

manifest_aead_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-MANIFEST-AEAD-R8"),
        L    = 32
    )

objectid_key =
    HKDF-SHA256(
        IKM  = archive_DEK,
        salt = archive_id,
        info = ASCII("STASH-OBJECT-ID-KEY-R10"),
        L    = 32
    )
```

The quoted `info` strings are exact ASCII bytes without a trailing NUL; the `-R8` suffix of the first three is part of the constant. The four keys MUST NOT be collapsed into one key. `objectid_key` is used only for the keyed `object_id` of §6.5, never for AEAD.

## 15.3 AES-256-GCM stored representation

```text
algorithm = AES-256-GCM
nonce     = 12 bytes
tag       = 16 bytes
```

Stored payload representation:

```text
payload_ciphertext = nonce[12] || ciphertext || tag[16]
```

Stored encrypted Pre-Trailer representation is the §6.4.3 body:

```text
nonce[12] || ciphertext || tag[16] || outer_crc32c[4]
```

Encrypted manifest fields similarly store `nonce || ciphertext || tag` inside the encoded manifest representation.

Encrypted DATA/PACKED payloads, encrypted DATA/PACKED Pre-Trailers, and encrypted manifest records use their respective independently derived AEAD keys. PARITY payloads are the raw §7 parity shards and are not encrypted. `hash_payload` covers the exact stored payload representation for the applicable block type.

## 15.4 Frame AAD

R10 frame payload and encrypted Pre-Trailer AEAD bind only stable bytes that are available from the frame itself after manifest loss and remain unchanged during byte-preserving compaction.

Canonical AAD is:

```text
archive_id[32]
|| uint16_le(version)              // MUST be 0x0006
|| uint8(archive_header_flags)      // includes ENCRYPTED, reserved bits already validated zero
|| frame_prefix_magic[4]           // exact bytes, normally "STFR"
|| uint32_le(frame_quanta)         // validated Prefix value
|| uint32_le(frame_prefix_flags)
|| master_trailer_bytes[0x00:0x40] // first 64 bytes, ending immediately before hash_payload
```

`master_trailer_bytes[0x00:0x40]` includes the trailer magic, algorithm IDs, block type/flags, parity metadata, `data_len`, redundant `frame_quanta`, `object_id`, `logical_offset`, `logical_length`, and `frame_ordinal`. It deliberately excludes `hash_payload`, because `hash_payload` is calculated over the completed stored payload representation and including it in payload AAD would create a circular dependency.

The Frame Prefix CRC32C itself is not included in AAD; its covered semantic fields are already included explicitly.

The same canonical frame AAD is used with the separately derived `frame_aead_key` and `pretrailer_aead_key`. Key separation prevents the two AEAD domains from collapsing even though their stable AAD bytes are equal.

A byte-preserving compactor MUST retain all AAD-covered frame metadata unchanged. Destination generation, destination blob ordinal, and destination physical offset are intentionally absent from AAD.

## 15.5 Collision-free numeric nonce construction

R10 retains the R8 numeric nonce construction unchanged; BLAKE3-based/truncated-hash nonce derivation remains forbidden.

For encrypted archives only, implementations MUST enforce before encryption:

```text
generation_id <= 0xFFFFFFFF
frame_ordinal <= 0x00FFFFFFFFFFFFFF
```

The physical fields remain uint64. Exceeding the encrypted-profile limit MUST fail before a new encryption operation is attempted.

The numeric values that enter nonces are allocated only through Allocator State reservations (§2.1.3): `generation_id` from `generation.alloc`, `frame_ordinal` from the namespace's `blob-NN.alloc`, and `seq` from `manifest.alloc`. A value is used for at most one encryption, even when the write that used it never became durable.

### 15.5.1 Frame payload nonce

For every newly encrypted frame:

```text
payload_nonce =
    uint32_le(generation_id)
    || uint8(blob_ordinal)
    || uint56_le(frame_ordinal)
```

Exact size:

```text
4 + 1 + 7 = 12 bytes
```

`uint56_le(x)` means the low seven bytes of the canonical little-endian unsigned representation, and is valid only after the bound above has been checked.

### 15.5.2 Pre-Trailer nonce

The Pre-Trailer uses the identical numeric nonce representation:

```text
pretrailer_nonce =
    uint32_le(generation_id)
    || uint8(blob_ordinal)
    || uint56_le(frame_ordinal)
```

Reusing the numeric nonce bytes here is safe because Pre-Trailer and payload use different independently derived AEAD keys.

### 15.5.3 Manifest nonce

For every newly encrypted manifest record:

```text
manifest_nonce =
    uint32_le(generation_id)
    || uint64_le(seq)
```

Exact size:

```text
4 + 8 = 12 bytes
```

### 15.5.4 Nonce uniqueness invariant

Under one derived AEAD key:

- `generation_id` MUST never be reused;
- `frame_ordinal` MUST never be reused within one `(generation_id, blob_ordinal)` namespace;
- manifest `seq` MUST remain unique across the complete same-key manifest graph of its generation, including linked submanifests;
- any wraparound or attempted reuse is fatal.

The construction is injective inside the permitted encrypted namespaces and does not rely on probabilistic collision resistance.

Stored nonces remain part of the ciphertext representation. Readers MUST use the stored nonce for decryption.

## 15.6 Normative frame-construction order

For every newly written encrypted DATA/PACKED frame, the writer MUST perform the following order so lengths, AAD, nonce namespaces, hashes, and CRCs are unambiguous:

1. canonicalize path/object metadata and build logical Pre-Trailer plaintext;
2. compress logical payload according to the selected compression profile;
3. allocate destination `generation_id`, `blob_ordinal`, `frame_ordinal`, and physical extent; encryption MUST NOT occur before these creation coordinates are fixed;
4. compute stored encrypted lengths (`payload_plain_len + 28`, encrypted Pre-Trailer plaintext length + 28 + 4 outer CRC) and choose/validate `frame_quanta`;
5. construct all AAD-covered Prefix/Trailer semantic fields, including final `data_len`, `frame_quanta`, object placement, and `frame_ordinal`;
6. derive numeric nonce(s) and AEAD-encrypt payload and Pre-Trailer plaintext;
7. compute `hash_payload` over the exact stored encrypted payload (`nonce||ciphertext||tag`) and place it in the Master Trailer;
8. compute the outer Pre-Trailer CRC over the stored Pre-Trailer envelope without its outer CRC, stored `pre_trailer_len`, and the now-complete Master Trailer;
9. emit zero padding, stored Pre-Trailer, length, and trailer; then perform normal durability ordering.

For unencrypted frames the analogous order is compression -> allocation/geometry -> Trailer fields -> payload hash -> outer Pre-Trailer CRC -> emission. Parity frame construction follows §7 after canonical data shards exist.

## 15.7 Compaction and encrypted frame identity

A copied frame is not a new encryption operation.

Normal compaction MUST preserve byte-for-byte:

```text
nonce
ciphertext
tag
hash_payload
frame_ordinal
origin frame identity/AAD metadata
```

Current destination `generation_id`, `blob_ordinal`, and `physical_offset` may change, but MUST NOT be used to recompute a nonce or replace authenticated origin identity.

A compactor MUST NOT decrypt/re-encrypt a live frame merely for relocation, nonce refresh, physical reordering, or dedup optimization. Parity regrouping (§13.7.1) is a permitted rewrite with fresh nonces.

## 15.8 Encrypted manifest records

In an encrypted archive every manifest record is an encrypted envelope (§10.1.2).

### 15.8.1 Envelope encoding

The stored line is a JSON object with exactly three keys:

```json
{"seq":"105","op":"ADD_ENC","enc":"<base64(nonce || ciphertext || tag)>"}
```

- `seq` is the record's decimal `seq`;
- `op` is the plaintext operation name with the suffix `_ENC`;
- `enc` is standard base64 (RFC 4648 §4 alphabet, with `=` padding, no line breaks) of `nonce[12] || ciphertext || tag[16]`; non-canonical base64 is rejected;
- the nonce MUST equal `manifest_nonce(generation_id, seq)` of §15.5.3; a reader MUST reject a mismatch before decryption.

The **plaintext** is the UTF-8 JSON object of the corresponding plaintext record (§10.1.2) with these changes:

- `seq` and `op` are omitted, because both are bound by the AAD;
- a field `prev` is added: 64 lowercase hex characters, defined in §15.8.2.

The plaintext obeys every rule of §10.1.1, including the line-length bound applied to the complete stored line.

### 15.8.2 Manifest chain

`prev` is the SHA-256 of the exact bytes of the previous stored line in the same file, excluding its LF. For the first line of a file, `prev` is SHA-256 of the 32-byte `archive_id` concatenated with the UTF-8 bytes of the file's path relative to the generation directory (`manifest.jsonl` or `submanifests/...`). A reader MUST verify `prev` on every record and reject a mismatch.

Because `prev` is inside the authenticated plaintext, the chain detects deletion, insertion, reordering, and cross-file moves of records. It does not detect truncation of a file tail; HARDENED anchoring covers that (§10.4.1).

### 15.8.3 Manifest AAD

Manifest AAD canonically binds:

```text
archive_id[32]
|| uint16_le(version)              // 0x0006
|| uint32_le(generation_id)
|| uint64_le(seq)
|| uint32_le(op_len)
|| exact UTF-8 op bytes
```

`op` here is the envelope's `op` value **including** the `_ENC` suffix (for example `ADD_ENC`).

An AAD mismatch is tampering and MUST be rejected.

## 15.9 Key rotation

### 15.9.1 KEK/KMS rotation

A deployment MAY rotate the KEK/KMS key by unwrapping and rewrapping the unchanged archive DEK:

```text
old KEK
    ↓ unwrap
archive DEK
    ↓ rewrap
new KEK
```

This does not modify 🌀 STASH frames and does not require a new archive.

### 15.9.2 Archive DEK rotation

The archive DEK is immutable for the lifetime of an encrypted 🌀 STASH archive. Changing it requires a new archive plus an explicit decrypt/migrate/re-encrypt operation.

Normal compaction MUST NOT rotate the archive DEK and MUST continue to copy encrypted live frames byte-for-byte. Deployments MUST enforce an operational AES-GCM key-usage policy appropriate to their assurance target; This specification does not claim an unlimited cryptographic lifetime for a single archive DEK. Creating a new archive is the defined DEK-rotation boundary.

## 15.10 Encryption and self-describing recovery

Without keys, the Header `ENCRYPTED` bit identifies the representation. Recovery can validate Header/Prefix geometry, the plaintext outer Pre-Trailer CRC that binds the stored encrypted envelope and complete Master Trailer, frame size, block type, payload hash, plaintext PARITY shards/group metadata, and parity structure. Plaintext object path/version and encrypted Pre-Trailer mappings require the relevant key. Without the key, `object_id` (§6.5) is an opaque grouping value.

With keys, recovery reads the nonce directly from the stored `nonce || ciphertext || tag` representation. It MUST NOT derive a decryption nonce from the frame's current physical location.

## 15.11 Encryption and deduplication

R10 retains the R8 distinction between logical/content identity and ciphertext identity. Standard R10 encryption does not guarantee that identical plaintext written independently produces identical ciphertext.

Convergent/content-derived encryption and cross-tenant plaintext deduplication are outside R10.

---

# 15A. Security Policies — STANDARD and HARDENED

R10 defines two deployment policies. These are not wire identifiers and do not modify the archive bytes.

## 15A.1 STANDARD

STANDARD provides all normal 🌀 STASH integrity, recovery, parity, and optional encryption guarantees but does not require an external freshness anchor.

Rollback of the complete storage namespace to an older internally valid generation can therefore remain undetectable.

## 15A.2 HARDENED

HARDENED adds trusted freshness through the external Generation Anchor.

A HARDENED implementation MUST:

- require a configured Generation Anchor;
- fail configuration if anti-rollback is requested without an anchor;
- verify the anchor during authoritative open, including the manifest prefix (§10.4.1);
- use §10.4.1 commit anchoring for every reported-durable commit;
- use §13.6.1 ordering for every generation switch;
- fail closed on detected rollback;
- distinguish crash-repairable `anchor > root.current` from malicious/invalid stale storage;
- bind allocator reservations of an encrypted archive in the anchor before use (§2.1.3.5);
- never silently downgrade to STANDARD because the anchor service is unavailable.

The Generation Anchor protects freshness only. It does not replace CRC, hash, AEAD, parity, manifest validation, or raw recovery.

# 16. Resource-Exhaustion Hardening and Normative Invariants

## 16.1 General untrusted-input rule

> No untrusted on-disk value may directly cause unbounded memory allocation, recursion, goroutine/task creation, or uncontrolled work amplification before applicable wire and implementation ceilings have been validated.

Readers MUST enforce bounded processing for at least:

- frame size;
- Pre-Trailer size;
- PACKED entry count;
- path length;
- manifest record size;
- pending manifest transaction state;
- recovery concurrency;
- physical-index rebuild concurrency.

Wire and production ceilings include:

```text
blob_count <= 255
MAX_PACKED_ENTRIES = 65535
path_len <= 4096
manifest line <= 1 MiB (excluding LF)
parity_k + parity_m <= 256
1 <= max_frame_quanta <= 0x00100000
production MAX_FRAME_SIZE <= 64 MiB by default
DATA logical_length <= MAX_FRAME_SIZE
PACKED packed_logical_length <= MAX_FRAME_SIZE
zstd Window_Size <= MAX_FRAME_SIZE
MAX_OPEN_TRANSACTIONS = 1024
MAX_LINKED_MANIFESTS = 65535
linked manifest depth = 1
```

Archive-scale collections MUST be streamable rather than requiring archive-sized in-memory slices.

Checked arithmetic is mandatory for all externally influenced:

```text
offset + length
size multiplication
frame end
logical range end
index range
Pre-Trailer boundaries
```

Unsigned overflow MUST fail closed.

## 16.2 Geometry

A conformant R10 implementation MUST preserve:

- `ARCHIVE_HEADER_SIZE == 64` and `FRAME_AREA_START == 0x40`;
- `FRAME_PREFIX_SIZE == 16`;
- `MASTER_TRAILER_SIZE == 96`;
- `BASE_QUANTUM == 4096`;
- `1 <= frame_quanta <= max_frame_quanta`;
- `frame_size == frame_quanta * BASE_QUANTUM` using checked arithmetic;
- in FIXED mode, `frame_quanta == max_frame_quanta` for every frame;
- in both modes, frame start/end lie on the frame grid `0x40 + j * 4096` (§3.1.1);
- `frame_size_mode` is immutable for the archive lifetime;
- new archives SHOULD default to VARIABLE unless FIXED is explicitly selected.

## 16.3 Immutability and logical placement

- A committed frame is never modified in place.
- Edits append a complete new object version and atomically update manifest state; frames are never shared between versions.
- Non-packed DATA carries non-zero `object_id`, explicit `logical_offset`, and `logical_length`.
- Logical reconstruction depends on logical placement, not physical discovery order or JSON array order.
- Packed `inner_offset` semantics are never confused with non-packed `logical_offset` semantics.
- Conflicting overlapping live extents are corruption unless explicitly resolved by version semantics.
- `object_id` remains path/version derived and is intentionally not rename-stable.

## 16.4 Manifest and physical index

- Manifest commits are serialized by `seq` and never reference undurable frames.
- Huge mappings use bounded transactional `ADD_BEGIN` / batched `ADD_EXTENT` / `ADD_COMMIT`.
- Incomplete transactions are ignored after crash.
- The per-generation `frame_hash -> physical_offset` index is mandatory for the normal hot path, is rebuildable from raw scan, and is not load-bearing for correctness.
- Missing/corrupt index state degrades to bounded scan/rebuild rather than data loss.
- An index lookup miss falls back to a scan before a frame is reported missing; a lagging index is completed by a forward scan.
- `file_ver` is allocated archive-wide, never reused, and strictly increasing per path.
- A path has at most one current version; the live-state fold of §10.2.2 is the only definition of liveness.
- Torn manifest and blob tails are truncated only under the rules of §10.4.2; a referenced frame is never truncated, and a blob damaged before a committed frame is SEALED.
- Every transaction a writer will not commit is closed with `ADD_ABORT`; open transactions never accumulate across writer sessions.
- `file_ver` growth is checked where state changes (`ADD`, `ADD_COMMIT`); a writer has at most one uncommitted version per path.

## 16.5 Parity

- R10 retains the R8 parity IDs NONE, XOR, and Reed-Solomon; parity operates over the exact canonical recovery shard defined in §7.2.
- Every parity group is self-describing.
- Group members have identical `frame_quanta`.
- Active parity spans at least two blobs.
- Emergency Pruning performs parity-impact analysis and never silently claims lost redundancy is intact.
- `group_id` comes from the kind 4 allocator; recovery never merges frames whose group metadata conflicts.
- PARITY frames of a group are durable before any commit that references its members.
- Repairs are written through compaction, never into the blob a frame was lost from.

## 16.6 Integrity

- Frame Prefix CRC32C is validated before trusting `frame_quanta`.
- The plaintext outer Pre-Trailer CRC32C is present in both plaintext and encrypted modes and binds the exact stored Pre-Trailer envelope (excluding the CRC itself), `pre_trailer_len`, and the complete Master Trailer before metadata is trusted.
- `hash_payload` verifies the exact stored payload representation.
- AEAD verifies encrypted representations.
- Detection alone never implies repair.

## 16.7 Anti-rollback policy

- STANDARD policy requires no external anchor.
- HARDENED policy requires a trusted Generation Anchor outside the rollback-capable archive storage namespace.
- HARDENED authoritative open MUST compare local root state against the anchor.
- `local_generation < anchored_generation` fails closed as rollback/stale storage unless the anchored generation is present and verifies, in which case root reconstruction (§2.1.2.1) completes the interrupted switch.
- Crash state `anchor == N+1`, `root.current == N` is recoverable only by locating and validating anchored generation `N+1`, then completing the local switch.
- The anchor binds the manifest prefix; a manifest shorter than the anchored length, or with a different digest, is rollback or tampering.
- Loss/unavailability of the anchor service MUST NOT silently disable HARDENED policy.

## 16.8 Encryption

- AES-256-GCM nonce is exactly 12 bytes and tag exactly 16 bytes.
- Payload, Pre-Trailer, and manifest use separately derived HKDF-SHA-256 keys.
- Encrypted-archive `generation_id` and `frame_ordinal` limits are enforced before encryption.
- Numeric nonce layouts are exact and injective in the permitted namespaces.
- Stored nonce is authoritative for decryption.
- Byte-preserving compaction preserves nonce/ciphertext/tag/hash/frame_ordinal.
- Any nonce namespace reuse or wraparound is fatal.
- Every value that enters a nonce comes from a durable Allocator State reservation, never from a media scan.
- In an encrypted archive every manifest record is an `*_ENC` envelope carrying a verified `prev` chain value.
- Archive DEK rotation requires migration to a new archive; ordinary KEK rewrap does not.
- In an encrypted archive `object_id` is keyed with `objectid_key` (§6.5).
- Under HARDENED, allocator reservations of an encrypted archive are bound in the Generation Anchor before use (§2.1.3.5).

---

# 17. Required R10 Conformance Harness and Test Matrix

The R10 required test matrix is part of the specification and is not optional implementation guidance.

## 17.1 Independent golden vectors

The reference implementation MUST include independently constructed golden vectors for:

```text
64-byte Archive Header
64-byte root.current
16-byte Frame Prefix
96-byte Master Trailer
plaintext Pre-Trailer
encrypted Pre-Trailer with outer CRC
manifest records for every normative operation
64-byte index header and 64-byte index record
64-byte Allocator State for every kind
encrypted manifest envelope, plaintext, and prev chain for at least three consecutive records
canonical parity recovery shard and PARITY frame
Reed-Solomon parity for (k,m) = (1,1), (2,1), (4,2), (10,4), and one short group
encrypted representation
keyed object_id (HMAC-SHA-256) of an encrypted archive
ADD_ABORT and ADD_ABORT_ENC records
minimum valid frame
representative VARIABLE frame
representative FIXED frame
```

Golden vectors MUST NOT be generated by the production encoder under test.

Required forms:

```text
structured value -> encoder -> exact golden bytes
exact golden bytes -> decoder -> exact structured value
encoder -> decoder round trip
```

Encoder correctness MUST therefore not rely solely on `Encode(x) -> Decode() -> x`, because encoder and decoder could share the same defect.

For fixed structures, sentinel values SHOULD make byte ordering visually unambiguous, for example `0x11223344` and `0x0102030405060708`.

## 17.2 Exhaustive metadata-corruption tests

For the 16-byte Frame Prefix, flip every individual bit without recomputing its CRC32C and require rejection before altered Prefix fields are trusted.

For the 96-byte Master Trailer, flip every individual bit without recomputing the mandatory Pre-Trailer CRC32C that binds the trailer and require rejection before altered trailer fields are trusted.

The minimal zero-entry Pre-Trailer case MUST be included so trailer-integrity testing does not depend on PACKED metadata being present.

## 17.3 Decoder fuzzing

All untrusted binary and manifest decoders MUST be fuzz-tested. For arbitrary input they MUST:

```text
never panic
never read outside validated bounds
never cause unbounded allocation
never cause uncontrolled concurrency
return either a validated value or an error
```

## 17.4 Arithmetic boundaries

Tests MUST include:

```text
0
maximum valid value
maximum valid value + 1
MaxUint32
MaxUint64
overflowing additions
overflowing multiplications
truncated buffers
```

## 17.5 Geometry and recovery

Required cases include:

- minimum 4 KiB frame;
- representative mixed VARIABLE sizes;
- `MAX_FRAME_SIZE`;
- `MAX_FRAME_SIZE + BASE_QUANTUM` rejection;
- FIXED `frame_quanta != max_frame_quanta` rejection;
- modification, append, and rename each produce a complete new version that shares no frame with the previous version, and raw recovery reconstructs both versions independently;
- MAX-size repartition into multiple grid-aligned immutable frames;
- arbitrary physical discovery order reconstructing the same logical object;
- overlapping live logical ranges producing corruption/conflict;
- missing physical index degrading to scan and rebuilding the same mapping;
- raw recovery with deleted manifest/index;
- lagging index completed by forward scan, and index lookup miss falling back to scan;
- VARIABLE resynchronization after a corrupted Prefix, including a forged frame embedded in a payload that must be labeled as a resync candidate;
- writer append onto a shared 4 KiB page leaving the previous frame's committed bytes unchanged;
- `logical_length = MAX_FRAME_SIZE` accepted and `MAX_FRAME_SIZE + 1` rejected before decompression;
- resynchronization: frames after a resync candidate inherit the label, a forged frame with a large `frame_quanta` does not hide real frames inside its extent, and an exhausted work budget reports the rest as unscanned;
- raw recovery labels a version written by an interrupted, never-committed write as not known to be committed.

## 17.6 Manifest and crash durability

Verify:

- batched `ADD_EXTENT` up to the manifest-line ceiling;
- incomplete transaction ignored after crash;
- group commit does not require one fsync per extent record;
- frame durability precedes committed manifest reference;
- crash injection at frame write, blob flush, manifest append, manifest flush, Allocator State replacement, compaction Sweep, root Switch, and GC deletion boundaries;
- torn manifest line without LF ignored and truncated; complete invalid last line fails closed;
- torn blob tail truncated; valid frame after an invalid region blocks truncation;
- after a crash with torn encrypted frames and torn encrypted records, the next writer never reuses an ordinal or `seq` (verify against every nonce ever produced, including torn ones);
- live-state fold: ADD supersedes, DEL with wrong `file_ver` fails, re-ADD after DEL gets a larger `file_ver`, rename leaves both paths after a crash between its two commits;
- strict JSON: duplicate keys, unknown keys, invalid UTF-8, non-canonical decimals, and over-long lines rejected;
- canonical writer form: key order and string escaping match §10.1.1 byte for byte;
- `ADD_ABORT`: a writer aborts after an injected I/O error; 1,025 crashes in the middle of transactions in one generation leave the manifest readable; a record naming an aborted `tx_id` is rejected;
- version check at commit: `ADD_BEGIN(v8)`, `ADD(v9)`, `ADD_COMMIT(v8)` for one path is rejected, and the writer refuses a second concurrent write to one path;
- torn blob tail containing a valid frame that no `loc` references (pages persisted out of order; a payload holding an embedded 🌀 STASH archive) is truncated; a referenced frame after a damaged region SEALS the blob, and writes continue on other blobs;
- crash between data frames and PARITY frames of a group: no commit references the group's members;
- Allocator State re-initialization (§2.1.3.4) of every kind, including `generation.alloc` of an encrypted archive, leaves the namespace usable.

## 17.7 Compression

Tests MUST verify exact logical round-trip for:

```text
STORE
ZSTD_FAST
ZSTD_DEFAULT
ZSTD_DENSE
```

Unknown compression IDs MUST fail closed. Every ZSTD payload MUST decode independently. Malformed/truncated streams and declared-output-limit violations MUST fail closed.

## 17.8 Parity

Tests MUST include canonical-shard golden vectors, exact full-frame reconstruction from a missing DATA/PACKED member, shard-capacity boundary/rejection, Prefix regeneration, encrypted opaque shard reconstruction, and then verify:

```text
NONE
XOR
Reed-Solomon
```

and reject every reserved parity identifier. Equal member physical size and multi-blob spread invariants MUST be tested. Reed-Solomon parity MUST be byte-identical to the golden vectors of §17.1, which MUST be produced by an implementation independent of the one under test. Short groups, the per-group invariants of §7, parity regrouping (§13.7.1), the 112-byte padding boundary of §7.2, `group_id` conflicts in raw recovery, `group_id` allocation across a crash, and repair through compaction including a lost PARITY frame (§7.3.1) MUST be tested. Emergency Pruning tests MUST verify parity health is downgraded/rebuilt explicitly rather than silently lost.

## 17.9 Cryptography

Tests MUST verify:

- HKDF-SHA-256 golden vectors for all four derived keys;
- keyed `object_id` golden vectors, and a test that a guessed path cannot be confirmed without the key;
- exact numeric frame/pretrailer/manifest nonce byte layouts;
- nonce uniqueness across blob ordinals, frame ordinals, generations, and generation-global manifest-graph `seq` values;
- rejection at encrypted-profile numeric limits before new encryption;
- tag tampering rejection;
- AAD tampering rejection;
- stored nonce tampering rejection;
- byte-identical encrypted compaction across multiple generations;
- recovery after compaction using stored nonce rather than current physical position;
- KEK rewrap leaves 🌀 STASH frame bytes unchanged;
- archive-DEK change is rejected as an in-place operation;
- manifest nonce mismatch with `(generation_id, seq)` rejected before decryption;
- manifest chain detects deletion, insertion, reordering, and cross-file move of records;
- any plaintext record in an encrypted archive rejected.

## 17.10 Hash and integrity separation

Tests MUST verify both BLAKE3 and SHA-256, reject every reserved hash identifier, and demonstrate that CRC/hash/AEAD detection does not cause repair unless an actual parity/copy recovery source exists.

---

## 17.11 Anti-rollback / Generation Anchor

HARDENED conformance tests MUST include:

- initial anchor creation for generation 0, and refusal when an anchor already exists;
- enrollment of an existing STANDARD archive after full verification;
- monotonic `N -> N+1` compare-and-advance with non-consecutive generation IDs;
- commit advance per group commit; open with a manifest truncated below `manifest_length` detected as rollback;
- unanchored manifest bytes after a crash between manifest fsync and commit advance: adopted or truncated, never silently trusted;
- stale/replayed anchor update rejection;
- `local root == anchor` normal open;
- `local root < anchor` rollback detection;
- `local root > anchor` fail-closed behavior;
- crash after destination durability but before anchor advance;
- crash after anchor advance but before local root switch;
- successful reopen that completes the local switch to the already anchored generation;
- anchored generation missing or corrupt -> security/integrity incident, no silent fallback;
- anchor service unavailable -> HARDENED open/write must not silently downgrade;
- `root_digest` mismatch detection;
- root reconstruction after a crash between `Create` and the first root write;
- Allocator State rolled back below the anchored reservations is detected and never reuses a nonce;
- reservation advance before first use of a new reservation block;
- a HARDENED reader ignores unanchored manifest bytes;
- verification that enabling/disabling anti-rollback changes no archive wire bytes.

# 18. Reference Implementation Notes — Go

Recommended packages:

| Function | Package |
|---|---|
| SHA-256 | `crypto/sha256` |
| AES-256-GCM | `crypto/aes` + `crypto/cipher` |
| HKDF-SHA-256 | `crypto/hkdf` |
| CRC32C | `hash/crc32` Castagnoli |
| Binary little-endian encoding | `encoding/binary` |
| BLAKE3 | `zeebo/blake3` or equivalent |
| Zstandard | `klauspost/compress/zstd` or equivalent |
| Reed-Solomon | `klauspost/reedsolomon` default matrix only (§7.2.1); not `WithCauchyMatrix`, `WithPAR1Matrix`, or Leopard |
| HMAC-SHA-256 | `crypto/hmac` + `crypto/sha256` |
| Unicode NFC | `golang.org/x/text/unicode/norm` pinned to Unicode 15.0 data, plus an embedded Unicode 15.0 assigned-code-point table (the standard `unicode` package follows the Go release) |
| Strict JSON | custom streaming tokenizer, or `encoding/json/v2` with duplicate-name and unknown-field rejection; plain `encoding/json` is not sufficient |

BASELINE and SECURE require neither BLAKE3 nor Zstandard: their `hash_id` is SHA-256; BASELINE object identity uses SHA-256 and SECURE uses HMAC-SHA-256 (§6.5). FAST uses BLAKE3 for both payload hashing/object identity and Zstandard for payload compression.

Implementation guidance:

- validate Header and Frame Prefix before frame-sized allocation;
- pool bounded buffers, never buffers sized directly from unvalidated media values;
- serialize physical extent allocation per blob while allowing independent blob writers;
- maintain a single logical manifest commit ordering;
- batch manifest fsyncs at transaction durability boundaries;
- maintain/rebuild physical offset indexes;
- never mutate committed frames;
- treat encrypted frame bodies as opaque during ordinary compaction;
- verify parity-group physical-size compatibility before parity encode/decode;
- stream archive-scale scans and indexes;
- bound recovery/index-rebuild goroutine counts;
- use checked arithmetic helpers for all media-derived offsets/sizes;
- benchmark VARIABLE recovery scan and FIXED direct-slot recovery separately;
- keep anti-rollback anchoring behind a public deployment abstraction; do not place provider-specific KMS/HSM logic inside `internal/wire`;
- HARDENED mode must never silently fall back to STANDARD if the anchor is unavailable.

Go-specific pitfalls:

- `encoding/json` accepts duplicate keys (last wins) and silently replaces invalid UTF-8 with U+FFFD; both violate §10.1.1;
- `zstd.Decoder.DecodeAll` decodes concatenated frames; enforce the single-frame rule of §5.1.1 by parsing the frame header (`zstd.Header`) and checking that no bytes follow the frame, and set `WithDecoderMaxMemory` / `WithDecoderMaxWindow`;
- `klauspost/compress/zstd` has no exact level 9; `EncoderLevelFromZstd(9)` is acceptable (§5.1);
- directory `fsync` is not available on Windows; use `MoveFileEx` with `MOVEFILE_WRITE_THROUGH` as the equivalent replace mechanism;
- object storage without append or atomic rename needs a backend that maps blobs to immutable segments; that mapping is implementation-defined and outside the wire format;
- crash-injection tests need a filesystem abstraction that can drop unflushed writes and tear page writes, not only kill the process.

## 18.1 Planned CLI creation parameters

Recommended creation surface:

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

Advanced explicit creation parameters MAY expose:

```text
--hash blake3|sha256
--codec store|zstd-fast|zstd-default|zstd-dense
```

A profile is a data-processing preset and is not stored as a separate wire identifier. `--security-policy` is orthogonal to the profile. HARDENED requires a configured Generation Anchor provider.

---

## 18.2 Read-only FUSE policy

The reference FUSE adapter is permanently read-only, calls only the public Go library API, pins one validated `generation_id` for the lifetime of a mount (registering a reader pin, §13.1.1), and returns `EROFS` for every mutation attempt. A missing persistent physical index MAY be replaced by a temporary in-memory index built by the library; the FUSE adapter MUST NOT modify archive blobs, manifests, persistent indexes, generations, or root metadata.

# 19. R10 Production Readiness Checklist

- [ ] Every blob Archive Header is exactly 64 bytes and begins with `STSH`.
- [ ] Header wire version is `0x0006`.
- [ ] Header `ENCRYPTED` bit is authoritative; reserved Header/Prefix/Trailer flags are rejected.
- [ ] `root.current` 64-byte golden vector and atomic durable replacement protocol are tested.
- [ ] Manifest uint64 fields use decimal strings; hashes are 64 lowercase hex; duplicate keys and unknown ops fail closed.
- [ ] Manifest `seq` uniqueness is generation-global across same-key linked submanifests.
- [ ] DATA frames carry exactly one recovery path/version Pre-Trailer entry; PACKED count is bounded; PARITY uses zero entries.
- [ ] Canonical unsigned LEB128 is shortest-form only and bounded for `path_len`.
- [ ] Index header identity prevents stale cross-generation index reuse.
- [ ] All headers in one generation agree on generation and immutable archive parameters.
- [ ] Version dispatch recognizes `0x0002`, `0x0003`, reserved development `0x0004`, R7 `0x0005`, and R8 `0x0006` correctly.
- [ ] `frame_size_mode` cannot change through compaction or generation switch.
- [ ] `BASE_QUANTUM` is exactly 4096 bytes.
- [ ] VARIABLE frame boundaries stay on the frame grid across mixed sizes.
- [ ] FIXED frames all equal `MAX_FRAME_SIZE` and reject mismatched `frame_quanta` as corruption.
- [ ] Frame Prefix CRC catches corrupted extent metadata before large allocation.
- [ ] Mandatory Pre-Trailer CRC catches corruption of `pre_trailer_len` and every Master Trailer bit before those fields are trusted.
- [ ] Prefix/Trailer `frame_quanta` mismatch is rejected.
- [ ] `data_len` physical-budget equation is checked exactly with overflow-safe arithmetic.
- [ ] `object_id` uses archive `hash_id` (HMAC-SHA-256 with `objectid_key` when encrypted), changes on rename by design, and DATA Pre-Trailer recovery metadata recomputes to the same ID.
- [ ] PACKED and non-packed offset semantics are never mixed.
- [ ] Logical reconstruction is independent of manifest-list/physical discovery order.
- [ ] Every new object version is self-contained and shares no frame with earlier versions.
- [ ] No committed frame is ever modified in place.
- [ ] Very large extent sets use batched transactional `ADD_EXTENT` records.
- [ ] Manifest durability uses group commit, not one fsync per extent.
- [ ] Incomplete ADD transaction is ignored after crash.
- [ ] Per-generation physical offset index is maintained, rebuildable, and non-load-bearing for correctness.
- [ ] Parity algorithms are only NONE/XOR/Reed-Solomon and reserved IDs fail closed.
- [ ] Parity groups use equal `frame_quanta`, exact canonical recovery shards, and reconstruct complete missing frames without manifest.
- [ ] Emergency Pruning performs parity-impact analysis.
- [ ] Hash algorithms are only SHA-256/BLAKE3 and reserved IDs fail closed.
- [ ] Compression profiles are only STORE/ZSTD_FAST/ZSTD_DEFAULT/ZSTD_DENSE and reserved IDs fail closed.
- [ ] Every ZSTD payload is independently decodable and bounded by declared logical output limits.
- [ ] BASELINE, SECURE, and FAST named profiles are supported by the Go reference implementation.
- [ ] AES-GCM stored nonce is 12 bytes and tag is 16 bytes.
- [ ] HKDF-SHA-256 derives four distinct exact-label 32-byte keys.
- [ ] Encrypted `generation_id` and `frame_ordinal` ceilings are enforced before encryption.
- [ ] Exact numeric nonce layouts match golden vectors.
- [ ] Nonce namespace reuse/wrap is fatal.
- [ ] Encrypted compaction preserves nonce/ciphertext/tag/hash/frame_ordinal byte-for-byte.
- [ ] Disaster recovery reads stored nonce rather than deriving from current placement.
- [ ] KEK rotation rewraps the unchanged DEK without changing 🌀 STASH frames.
- [ ] Archive DEK cannot be rotated in place.
- [ ] FIXED Hop-and-Read supports direct slot arithmetic; VARIABLE Hop-and-Read advances from validated `frame_quanta`.
- [ ] All media-derived sizes/offsets are validated before allocation or concurrency creation.
- [ ] Archive-scale collections are processed streaming rather than materialized as unbounded slices.
- [ ] Golden vectors are independently constructed rather than emitted by the production encoder.
- [ ] Every bit in Frame Prefix and Master Trailer corruption tests is rejected by the applicable CRC binding.
- [ ] Binary decoders and manifest parsers pass fuzzing without panic/OOB/unbounded allocation/uncontrolled concurrency.
- [ ] Crash injection passes all required durability and compaction boundaries.
- [ ] STANDARD and HARDENED security policies are both covered by integration tests.
- [ ] HARDENED requires a Generation Anchor and fails configuration without one.
- [ ] HARDENED detects `root.current` rollback below the trusted anchor.
- [ ] Crash after anchor advance but before local root switch is repaired by validating and selecting the anchored generation.
- [ ] Anchor outage never silently downgrades HARDENED to STANDARD.
- [ ] Anti-rollback enablement changes no `0x0006` archive wire bytes.
- [ ] Allocator State files exist, validate, never decrease, and are the only source of generation IDs, `file_ver`, and (encrypted) ordinals and `seq`.
- [ ] Frame grid is `0x40 + j * 4096`; shared-page appends preserve committed bytes.
- [ ] `logical_length` and `packed_logical_length` are bounded by `MAX_FRAME_SIZE`.
- [ ] Zstd payloads are single frames with content size, bounded window, no dictionary.
- [ ] Reed-Solomon matches §7.2.1 golden vectors; short groups follow §7.
- [ ] PACKED objects are referenced by a single-element `loc`.
- [ ] `file_ver` allocation, DEL semantics, and the live-state fold follow §10.2.
- [ ] Strict JSON rules of §10.1.1 are enforced.
- [ ] Torn tails follow §10.4.2.
- [ ] Index validation, lagging-index scan, and miss fallback follow §10.5.1.
- [ ] LINK_MANIFEST hash scope, depth, and `seq` rules follow §10.6.
- [ ] Encrypted manifests use only `*_ENC` envelopes with verified nonce and `prev` chain.
- [ ] HARDENED anchors the manifest prefix on every reported-durable commit.
- [ ] A single-writer lock protects every write path; GC honors reader pins.
- [ ] Uncommitted transactions are closed with `ADD_ABORT`, including on cold start.
- [ ] `file_ver` growth is checked at `ADD` and `ADD_COMMIT`; one uncommitted version per path.
- [ ] `group_id` comes from the kind 4 allocator; conflicting group metadata is never merged.
- [ ] PARITY frames are durable before a commit references group members.
- [ ] Torn-tail truncation is decided by manifest references; a damaged blob is SEALED.
- [ ] HARDENED encrypted archives bind allocator reservations in the anchor.
- [ ] The directory layout and name forms of §2.1 are enforced.

---

# 20. Summary of R10 Changes

R10 completes R9 and fixes defects found by an independent review. It retains wire version `0x0006` and every binary structure of R8/R9 byte for byte. R9's own additions (Generation Anchor, STANDARD/HARDENED, switch ordering) remain and are extended.

## 20.1 Changes and rationale

| ID | Change | Sections | Defect in R9 |
|---|---|---|---|
| K1 | Every object version is self-contained; frames are never shared between versions; rename rewrites the object | §0, §9.5, §9.6, §10.2.3 | §9.6 claimed local edits while §4.2/§6.5 forbade sharing frames across versions |
| K2 | Anchor binds manifest length and digest; HARDENED commit anchoring | §0.2, §2.1.2, §10.4.1, §11.8, §13.6.1, §15A.2 | Manifest truncation inside one generation was an undetected rollback |
| K3 | Encrypted manifest chain (`prev`) and all-envelope rule | §10.1.2, §15.8 | Deletion of single encrypted records was undetectable |
| K4 | Allocator State reservations for generation IDs, file versions, ordinals, `seq` | §2.1, §2.1.3, §12.2, §15.5 | Torn writes and deleted aborted generations allowed GCM nonce reuse |
| K5 | Frame grid defined as `0x40 + j * 4096`; shared-page write rule | §0, §3.1.1 | Text claimed absolute 4 KiB alignment; shared page risk unaddressed |
| K6 | Parity regrouping allowed as a fresh-nonce rewrite | §13.7.1, §15.7 | Encrypted archives with parity could never reclaim dead group members |
| K7 | `logical_length` and packed length bounded by `MAX_FRAME_SIZE`; zstd frame constraints | §5.1.1, §6.6.1, §16.1 | Decompression ceiling was an unvalidated media value |
| Z1 | Reed-Solomon field and matrix defined | §7.2.1 | "klauspost or equivalent" did not fix the code |
| Z2 | Encrypted envelope plaintext, base64, nonce check, AAD `op` defined | §15.8 | Envelope content undefined |
| Z3 | PACKED objects referenced by a single-element `loc` | §9.1 | No manifest form for PACKED objects |
| Z4 | Archive-wide `file_ver` allocation; DEL names the removed version | §10.2, §10.2.1 | `file_ver` semantics undefined; DEL example inconsistent |
| Z5 | Live-state fold; one current version per path | §10.2.2, §13.1 | Liveness for Mark undefined |
| Z6 | Torn manifest and blob tails | §10.4.2 | Crash tail handling undefined |
| Z7 | VARIABLE resynchronization and resync-candidate labeling | §11.2.1, §11.2.2 | Promised by README, undefined in SPEC; forged-frame risk |
| Z8 | Short parity groups and per-group invariants; blob-loss-tolerant placement | §7, §7.4 | Relation of group fields to header undefined |
| Z9 | LINK_MANIFEST hash scope, depth 1, `seq` rules | §10.6 | Hash scope, nesting, ordering undefined; contradictory sentence |
| Z10 | Rename defined as two commits, loss-free but not atomic | §10.2.3 | README promised a transactional rename the manifest cannot express |
| S | Strict JSON, canonical decimals, transaction bounds, index validation and lag, header cross-checks, path character rules, STORE length, `max_frame_quanta` range, single-writer lock, reader pins, health-metadata fallback, Go notes | §2.3, §3.1, §6.4.5, §6.6.2, §10.1.1, §10.3, §10.5.1, §12.1, §13.1.1, §13.9, §18 | Ambiguities that let implementations diverge |

## 20.2 Effect on existing R9 media

R10 readers open R9 wire-`0x0006` media, with these exceptions, which an R10 reader reports as non-conformant rather than silently accepting:

- frames whose `logical_length` or packed length exceeds `MAX_FRAME_SIZE` (§6.6.1);
- zstd payloads violating §5.1.1;
- manifests violating the strict JSON, `file_ver`, DEL, or LINK rules (§10.1.1, §10.2, §10.6);
- encrypted manifests: R9 never defined the envelope plaintext, so no interoperable R9 encrypted manifest exists. An R10 reader rejects any R9-era encrypted manifest that does not match §15.8;
- encrypted archives: R9 derived `object_id` without a key; an R10 reader reports the DATA frames of an R9 encrypted archive as non-conformant (§6.5).

R9 archives have no Allocator State. An R10 writer that opens one MUST first run the explicit conservative initialization of §2.1.3.4.

## 20.3 Explicitly unchanged in R10

R10 does not alter:

```text
wire version 0x0006
64-byte Archive Header
16-byte Frame Prefix
96-byte Master Trailer
4096-byte base quantum and 0x40 frame area start
root.current binary format
VARIABLE / FIXED geometry
DATA / PACKED / PARITY block types
Pre-Trailer encoding
object_id derivation of unencrypted archives
absolute logical placement model
plaintext manifest record schema of the R9 operations
physical-index binary format
parity recovery-shard encoding
AES-256-GCM / HKDF construction
numeric nonce construction
append-only semantics
compaction byte-copy rules
read-only FUSE policy
```

## 20.4 Final algorithm surface

```text
HASH
    SHA-256
    BLAKE3

COMPRESSION
    STORE
    ZSTD_FAST     level 1
    ZSTD_DEFAULT  level 3
    ZSTD_DENSE    level 9

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

Named data-processing profiles remain:

```text
BASELINE
    SHA-256
    STORE
    NONE

SECURE
    SHA-256
    STORE
    AES-256-GCM

FAST
    BLAKE3
    ZSTD_FAST
    NONE
```

Security policies are orthogonal:

```text
STANDARD
    no external freshness anchor required

HARDENED
    trusted external Generation Anchor required
```

## 20.5 Erratum E1

E1 was applied in 2026-11, before any implementation existed. It fixes defects found by a second review; no wire `0x0006` media written under the earlier rules exists, so E1 stays at wire `0x0006`.

| ID | Change | Sections | Defect in R10 before E1 |
|---|---|---|---|
| E1-1 | `ADD_ABORT` operation; writer aborts on error and on cold start | §10.1.2, §10.2.2, §10.3, §10.3.1 | Every crash inside a transaction left it open forever; after 1,025 the manifest became unreadable |
| E1-2 | Per-kind `MAX_RESERVATION_BLOCK` and `SKIP` | §2.1.3.1, §2.1.3.4 | Re-initializing `generation.alloc` of an encrypted archive exhausted the 32-bit generation space |
| E1-3 | Allocator reservations bound in the anchor; STANDARD nonce caveat | §0.2, §2.1.2, §2.1.3.5 | A storage administrator could roll back `alloc/` and force AES-GCM nonce reuse even under HARDENED |
| E1-4 | `file_ver` checked at `ADD_COMMIT`; one uncommitted version per path | §10.2.1 | Interleaved transactions could make an older version current |
| E1-5 | Allocator kind 4 for `group_id`; group-conflict rule in recovery | §2.1.3, §7 | `group_id` had no allocation rule; reuse after a crash merged two groups |
| E1-6 | Torn-tail truncation decided by manifest references; SEALED blobs | §1, §10.4.2 | Out-of-order page writes or an embedded archive in a payload blocked the writer with no defined exit |
| E1-7 | Resync label inheritance, probing inside candidates, work budget | §11.2.1 | Forged frames could hide real frames; unbounded work amplification |
| E1-8 | Ignore-versus-fail rules for transactions | §10.3 | §10.3 and §10.4.2 disagreed |
| E1-9 | Reader snapshot; HARDENED readers ignore unanchored bytes | §10.4.1, §18.2 | Snapshot and visibility of unanchored records were undefined |
| E1-10 | PARITY durable before commit; repairs through compaction | §7.3.1, §10.4 | Parity timing and repair write-back were undefined |
| E1-11 | Normative layout and name forms; `archive_id` from a CSPRNG | §2.1 | Layout was "recommended" while other sections depended on it |
| E1-12 | `root_digest` mandatory; `Create`; root reconstruction | §1, §2.1.2, §11.8, §13.6.1, §17.11 | Optional in some sections, mandatory in others; creation crash unhandled |
| E1-13 | Destination manifest content of compaction | §13.2.1 | Undefined |
| E1-14 | Deduplication described as it actually behaves | §4.2, §9.5 | §9.5's example contradicted §10.2.1 |
| E1-15 | Canonical writer JSON form | §10.1.1 | Encoder golden vectors could not be exact |
| E1-16 | Keyed `object_id` in encrypted archives; size leakage documented | §0.2, §6.5, §15.2 | An unkeyed `object_id` let anyone confirm guessed paths |
| E1-17 | 112-byte parity padding, `ceil` in placement rule, PARITY ordinals, legacy recognition bytes, orphan-version label, editorial "R8" wording | §7.2, §7.4, §12.2, §14, §11.2.2 | Implicit or ambiguous |
| E1-18 | A referenced frame (by `frame_hash` and object metadata) missing from the valid run before `E` seals the blob, even when it no longer validates | §10.4.2 | A committed frame damaged by a non-atomic shared-page write (§3.1.1) could be truncated as a torn tail; `loc` carries no offsets, so the rule is stated by frame identity |
| E1-19 | Unique `physical_offset` in the index, `record_count` bounded by blob size | §10.5, §10.5.1 | A forged index could declare many records and force a large allocation before rejection |
| E1-20 | A manifest line containing NUL starts the torn tail | §10.4.2 | Pages of an unsynced append persisted out of order left an LF-terminated line of zeros plus a record; the archive failed closed after an ordinary crash |
| E1-21 | Creation order and incomplete STANDARD creation; `file_ver` cold-start check covers every record | §2.1.1, §2.1.3.1 | A crash inside creation under STANDARD was undefined; "live-state fold" omitted dead and aborted versions whose `file_ver` was already used |

# 21. README / Public Specification Requirements

README material describing R10 MUST state:

```text
🌀 STASH 2.0 Revision R10
wire version 0x0006
```

It MUST make clear that R10 does not change the R8/R9 binary structure layouts, that it adds the Allocator State file, and that Erratum E1 is part of R10.

It MUST include:

> **Checksums and hashes detect corruption; redundancy repairs it.**

It SHOULD present:

```text
BASELINE  SHA-256 / STORE     / no encryption
SECURE    SHA-256 / STORE     / AES-256-GCM
FAST      BLAKE3  / ZSTD_FAST / no encryption
```

and:

```text
STANDARD  no external anti-rollback anchor required
HARDENED  trusted external Generation Anchor required
```

It MUST describe:

```text
VARIABLE = normal/default enterprise mode; variable physical allocation
FIXED    = deterministic slot geometry / maximum recovery parallelism
```

It MUST state that every object version is self-contained, so a change or rename of an object rewrites that object, and it SHOULD recommend modeling incrementally changing data as many immutable objects.

It MUST state that the R10 required test matrix is part of the specification and is not optional implementation guidance.

# 22. Freeze

> **🌀 STASH 2.0 R10 is FROZEN at wire version `0x0006`. R10 does not change the R8/R9 binary wire format.**

The next milestone is implementation:

```text
Go reference implementation
    ↓
R10 semantic + 0x0006 wire conformance harness
    ↓
golden vectors
    ↓
fuzzing
    ↓
crash injection
    ↓
anti-rollback Generation Anchor tests
    ↓
raw recovery torture tests
    ↓
performance benchmarks
```

Any future change to on-disk bytes, field semantics required for parsing, manifest wire encoding, root format, index format, Allocator State format, parity shard representation, or crypto wire construction requires a new wire version.

Pure implementation, deployment-provider, or operational-policy changes do not.

Erratum E1 (§20.5) is the single exception to this rule: it was made before any implementation or media existed. From the first published implementation on, every such change requires a new wire version.

## License

🌀 STASH is open-source software licensed under the [MIT License](LICENSE).

**Author:** © 2025-2026 Zbigniew Lipka
