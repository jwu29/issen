# Archive Support for the forensic-vfs Stack — Design

Status: **design settled** (Fable 5 design → Codex critique → fleet-fact verification, 2026-07-17).
Scope target: new `archive-forensic` repo (`archive-core` + `archive-forensic`) + `forensic-vfs`
minor bump + `forensic-vfs-engine` 0.2.0 wiring. `disk-forensic` transitional on-ramp.

## Thesis (accepted)

An archive is a transparent **outer packing "archive layer"** first, a mountable tree second:
`foo.E01.gz` must resolve **identically** to `foo.E01`. Decoders are always compiled
(batteries-included); the layer **activates only at runtime** when the input is actually packed.

## Q1 — Trait: a NEW leaf probe, not `EncryptionLayer`

A single evidence stack can contain **both** a decompressor and an encryption layer at different
depths — `case.zip → disk.E01 → GPT → BitLocker → NTFS`. Decompress and decrypt are orthogonal
1→1 transforms that co-occur, so they **must be independent probe kinds** or the recursive resolver
cannot express both in one chain. Reusing `EncryptionLayer` is therefore structurally wrong (not merely
a provenance-naming lie); renaming it is breaking and conflates key/unlock/decrypted semantics a
decompressor lacks.

**Decision:** Add `ArchiveProbe` to the `forensic-vfs` leaf. Resolution is **not** a terminal
`Tree`; it is `ArchiveOpen { members, provenance, cost, source_for(member) -> Arc<dyn ImageSource> }`
where every member **re-enters normal `resolve()`**. `#[non_exhaustive]`, additive → minor bump.
`EncryptionLayer` untouched.

## Q2 — Peel-vs-tree discriminator

Classify each member by **content magic first** (run container sniffers over member bytes);
extension fallback (`.raw/.dd/.img/.mem/.001`) yields only a **candidate**, not "evidence", unless a
registry probe accepts the bytes or the analyst passes `--archive-mode=peel`. Sidecar noise = an
**allowlist** of ignorable names (dirs, `__MACOSX/*`, `.DS_Store`, `Thumbs.db`) — plus an
"unknown small member present" **finding** (drop Fable's arbitrary <1 MiB threshold; it can suppress
real tiny evidence — boot sectors, config exports, malware samples).

**Peel** iff exactly one non-sidecar member classifies as high-confidence evidence (multi-segment
`.E01`+`.E02…` / `.001`+`.002…` count as one logical member). **Else tree** (safe default —
`PathSpec` keeps every member reachable; a wrong tree costs one path segment, a wrong peel hides
siblings). Verdict **always logged**. `--archive-mode=tree|peel[:member]` overrides both ways.
Bare `.gz/.bz2/.xz` (no member table) always peel; inner bytes re-sniffed by the resolver.

## Q2.5 — Determination model: extension × magic (settled 2026-07-17, Codex-critiqued)

Precedence is assigned **per sub-decision**, not as a blanket "extension-primary" or
"magic-primary". The extension is a first-class signal (aliases fully supported) and is genuinely
primary where magic cannot speak; content is authority for the bytes actually decoded.

| Sub-decision | Authority | Extension's role |
|---|---|---|
| **Compression codec APPLIED** (gzip/bzip2/xz/zstd/.Z — 1→1 wrappers) | **magic** (physics: wrong codec just fails; and detecting an extension "mismatch" already requires reading the magic) | proposes the plan, ratifies, orders probes |
| **Container IDENTITY** (zip/7z/tar — 1→N member lists) | **structural validation** — zip = tail End-of-Central-Directory (+Zip64), *not* offset-0 `PK`; tar = `ustar`@257 or v7 header-checksum; 7z = magic | prior when structure is ambiguous/absent |
| **Inner-structure EXPECTATION** (`.tgz` → expect a tar) | **extension** | primary; a post-decompress probe confirms or corrects |
| **Magic-absent** (v7 tar, SFX/appended zip) | **extension + structural heuristic** | primary — nothing else can speak |

Codec wrappers and containers are **different objects** (Codex): a wrapper peels-and-recurses,
a container is parsed for members — do not lump zip/7z/tar into the "codec" bucket. zstd magic is
`28 B5 2F FD` **plus** skippable frames `0x184D2A50..5F` (LE) that interleave real data.

Normalize the name → parse the *compound* extension right-to-left against the alias table
(`.tgz/.taz`→gz+tar, `.tbz/.tbz2`→bz2+tar, `.txz`→xz+tar, `.tzst`→zst+tar, `.tlz`→lzma+tar) into an
*expected layer plan* → read leading magic (+ a reserved tail read for the zip EOCD) → apply the codec
magic proves (fall to plan + structural validation only when magic is silent) → order the inner probe
from the plan, ratify by probing → reconcile.

**Mismatch findings (severity raised for forensics — Codex; floor configurable):**
- extension **disguises** content (`.jpg` that is really a 7z/zip; executable under a doc extension)
  → **Medium** `ARCH-EXT-CONTENT-MASQUERADE` (a masquerading / anti-forensics signal).
- compression-**alias** mismatch (`.gz` that is actually xz) → **Low** `ARCH-EXT-CODEC-MISMATCH`.
- promised inner structure **absent** (`.tgz` decompresses to a non-tar) → **Info**
  `ARCH-EXT-STRUCT-MISMATCH`.

Extension drives the human-facing label; content drives the bytes decoded; every disagreement is a
logged finding, never silent.

## Q3 — Seekability per format

`ImageSource::read_at` demands random access.

| Format | Strategy | Cost |
|---|---|---|
| zip Stored | `SubRangeReader` (via `zip-forensic-core`) | zero |
| zip Deflate, gzip, tar.gz | `DeflateSeekReader` zran index | RAM: bounded checkpoint index |
| plain tar | `SubRangeReader` per 512-aligned member | zero |
| bzip2, tar.bz2 | block-boundary offset index (blocks independently decodable) | near-zero RAM |
| xz | **spill-only** — `lzma-rs` exposes only streaming `xz_decompress`; no block-index API | disk (once) |
| 7z | own `sevenzip-core` (pure-Rust); solid folder → /tmp spill, else per-member | disk (once, solid) |

Spill: decompress once to `std::env::temp_dir()/forensic-vfs-spill/<uuid>`, **never** near the
source; **free-space preflight** (loud typed error naming needed vs available); delete after last
lease; startup orphan sweep. Every strategy selection logs one line with concrete cost.
**Coverage gate:** if a zran index would exceed its `max_index_bytes` on a huge member (a 4 TiB
member at 1 MiB checkpoints = millions of records), fall back to spill.

## Q4 — Safety (Paranoid Gatekeeper)

Caps enforced on **observed output, never declared sizes** (attacker-controlled), split by resource:
output bytes (4 TiB default — evidence images are legitimately huge), compressed-bytes-consumed,
CPU/decode-time budget, index bytes, spill bytes, member-metadata bytes, per-member output;
**wrapper depth counted separately from resolver-layer depth** (max_archive_wrappers vs
max_resolve_layers — handles `foo.E01.gz.gz`); progressive **ratio cap 1000:1 checked every 64 MiB**
(a bomb trips within its first GiB of lies). `../` traversal names structurally neutralized (we name
spill files) **and flagged as a finding**. CRC/declared-size mismatch → finding, never silently
trusted. Trip → typed loud error `ArchiveBombGuard { cap, observed_value, layer_chain }` + an
`ARCH-BOMB-*` `forensicnomicon::report::Finding` (Category::Threat). Override only via explicit
`ArchiveLimits::for_lab_unbounded_with_reason(&str)` (logged) — no `unrestricted()`, no env backdoor.

## Q5 — Crate placement, naming, codecs

Pattern-A repo **`archive-forensic`** (both names verified unclaimed on crates.io):
- **`archive-core`** — sniff, member tables, seek strategies, `ArchiveLimits`, spill lifecycle, the
  `archive_core::open()` peel entry point (Q7). Owns the **tar walker** + **gz/bz2/xz framing** only.
- **`archive-forensic`** — analyzer: CRC-vs-content mismatch, declared-size lies, cross-member
  timestamp anomalies, traversal names, bomb signatures. May parse below `archive-core`'s API.
- Magic constants → `forensicnomicon`.

Codecs (pure-Rust, forbid-unsafe; all **already in the engine/disk-forensic graph** except 7z):
| codec | crate | note |
|---|---|---|
| zip container | **`zip-forensic-core`** (fleet crate, in-graph) | reuse — do NOT own a 2nd zip parser |
| deflate/gzip | `miniz_oxide` (underlies the existing `DeflateSeekReader`) | reuse |
| bzip2 | `bzip2-rs` (in-graph via DMG; documented `forbid(unsafe)` — reconfirm) | reuse |
| xz/LZMA2 | `lzma-rs` (in-graph via DMG; streaming-only API) | spill-only |
| 7z | **REUSE `sevenz-rust2`** — full coverage (LZMA/LZMA2/BCJ/BCJ2/Delta/Deflate/BZip2/AES/PPMd) | pure-Rust, **no C-FFI**: `libbz2-rs-sys` is a Rust libbz2 *port* (`build=false`, no `.c`, no `links`) — the `-sys` was misread as C bindings; our wrapper stays `forbid(unsafe)` (per-crate; deps don't count); tree audited by cargo-vet/deny. **The own-`sevenzip-core` build was reversed 2026-07-18 and the repo removed** — it only reached 3 codecs and rested on the `-sys` misread. |

## Q6 — Leaf vs engine edit boundary

- **`forensic-vfs` (leaf, minor bump):** `ArchiveProbe`; `ArchiveOpen`; the address/provenance model
  **now** — `ArchiveMemberId`, `ArchiveMemberPath`, `ArchiveCost`, `PathSpec::ArchiveMember{ chain,
  member_id }`; one resolver arm. No decoders, no limits logic, no policy.
- **`forensic-vfs-engine` 0.2.0:** dep `archive-core`; register `ArchiveProbe` in
  `default_registry()` (non-optional, batteries-included); thread `--archive-mode`/`--archive-limits`
  from open options. Wires, doesn't decode.
- **`archive-core`:** everything else.

## Q7 — One shared peel on-ramp

`archive_core::open(source, context) -> ArchiveOpen` (context = source path, temp manager, limits,
registry classifier, override mode). Consumers are thin callers:
- engine `ArchiveProbe` = adapter over `open`.
- `disk-forensic::container::open` calls it **before** its magic sniffer, loops while peeling —
  `evidence.E01.gz` works through the old on-ramp with identical caps/logging/provenance.
- **Same-release migration (not deferred):** the ewf-internal zip peel (`open_zip`/`SegmentBacking`)
  and any ISO/VHDX zip paths fold into `archive-core` **in the 0.2.0 wave**, or `archive-core` is not
  the canonical peel. Two authoritative peel paths with different limits/bomb-behavior is the failure
  mode to avoid.

## Concurrency (must-fix — issen shares `Arc<dyn ImageSource>` across N workers)

Spill-backed source = `Arc<SpillFile { path, file, len, lease_count }>` with **positioned reads only**
(`read_at`, cloned handles) — never one `File` with mutable seek. Delete after last lease (no
drop-race with active cloned readers). Test: parallel random `read_at` across threads.

## Hashing / provenance

Record three distinct hashes when available — container, member-compressed-range, decoded-logical —
with strategy (`stored`/`zran`/`spill`) as **provenance, not identity**. A report must distinguish
"source archive hash" from "peeled byte-stream hash".

## Ship / defer cut for 0.2.0

**Ship:** zip (Stored+Deflate via `zip-forensic-core`), plain tar, gzip/tar.gz (zran), bzip2/tar.bz2
(block index → spill fallback), bare gz/bz2, xz (spill-only), **7z via our own `sevenzip-core`**
(pure-Rust, `forbid(unsafe)` — the `sevenz-rust2` unsafe deferral is retired). Peel + tree modes,
every member resolvable. **7z via `sevenz-rust2` (reuse, full coverage)** — see the Q5 correction;
the own-reader build was reversed and removed 2026-07-18.
**Defer:** xz multi-block random-access fast path (no `lzma-rs` block API); within 7z, PPMd
(refused-loud — no pure-Rust Ppmd7 decoder) and BCJ2 land after the `sevenzip-core` spine.

## Two-phase access: Detect → `AccessPlan` → Peel (2026-07-18)

The archive layer is split into two phases so classification never inflates a payload and so
each evidence shape gets its *best* access path (not a one-size in-memory extract). This
is the VFS probe/open split (ADR 0008) with a richer phase-1 output.

**Phase 1 — `detect(source) -> AccessPlan` (bounded, content-authoritative, name-free).**
Peeks one decompressed block per compression layer (a bounded head sized to the resolver's
`SNIFF_CAP` ~40 KB, reaching the deepest magic — ISO 9660 `CD001` @32769) and reads only the
archive's member *table* (zip EOCD / 7z header / tar headers). It never inflates a payload,
and the file name is not an input to any classification. Five rules:

1. **Magic decides membership both ways** — presence confirms a format, *absence rules it
   out*. A name claiming a magic-absent format can only fail at decode, so it adds nothing.
2. **The peek-decode is the coincidental-magic guard** — a raw disk that merely starts with
   `1F 8B`/`BZh` fails to decode the bounded head → `Direct` (retires the name-based ext guard).
3. **The peek runs the *full* probe set** — the decompressed head is a `SniffWindow` fed to
   every probe (tar `ustar`@257 beside MBR@510 / GPT@512 / NTFS@3 / ext@1080 / APFS@32 /
   HFS+@1024 / ISO@32769), so the answer is *positive* ("inner is a GPT disk / nested zip / tar /
   unknown"), not "not a tar." archive-core owns packing detection only; the forensic magics stay
   in the VFS volume/filesystem probes (knowledge from forensicnomicon).
4. **Prefer the most-seekable `Access` the codec allows — everywhere (bare wrapper, member, each
   segment).** Ladder, best first: `Stored` → `InPlace` (zero-copy); seekable codec
   (Deflate/Deflate64/gzip) → `Zran` (no full inflate); non-seekable (LZMA/7z, bzip2 until a
   block-index) → `SpillToTemp`. So `Zran` covers a bare `.gz` of a disk, any Deflate zip member,
   and a `.tar.gz` member alike — chosen per item, mixed archives use all three at once. Ladder
   extends to bzip2/zstd/xz as their indexes land.
5. **Name absent from detection; irreducible only for split-multipart *ordering*** — a
   linkage-free split (`disk.001/.002/.003`) has no internal "part N of M", so the numeric suffix
   *is* the reassembly data for `SegmentSet { kind: SplitRaw }` (and filename-referenced VMDK
   extents). EWF is reducible (internal segment# + set-GUID). Otherwise the name survives only as
   a display label.

It classifies the most direct route to evidence:

```rust
enum AccessPlan {
    Direct,                                    // raw dd / already a disk image
    Wrapper    { codec: Codec, access: Access },       // bare gz/bz2 over one stream
    Member     { format: Format, index: usize, name: String, access: Access },
    SegmentSet { format: Format, members: Vec<SegmentRef>, kind: SegmentKind }, // E01/E02…, .001/.002, split VMDK
    Collection { format: Format },             // several independent items -> hand back as a tree
}
struct SegmentRef { name: String, index: usize, access: Access } // per-segment access
enum Access {
    InPlace { offset: u64, len: u64 },  // Stored/uncompressed member -> seek a sub-range in place (zero-copy)
    Zran,                               // Deflate/Deflate64/gzip -> checkpoint seek-index, random access, no full inflate
    SpillToTemp,                        // non-seekable codec (LZMA/7z) or tiny -> decompress once to temp
}
```

`Access` is per member **and** per segment, so `SegmentSet` composes with `Zran`: a
segmented E01 set inside a zip with Deflate-compressed members gets **per-segment zran**
random access. The reassembled logical image maps a read at logical offset *O* to
`(segment k, local offset)` and satisfies it via segment *k*'s `Access` — a zran checkpoint
seek into that deflated member (no full inflate), an `InPlace` sub-range for a `Stored`
member, `SpillToTemp` only for a non-seekable codec. So a fully-Deflate `E01`/`E02`/`E03`-in-zip
is randomly accessible with only per-segment checkpoint indexes in RAM — **zero temp spill,
O(1) inflate per seek**. Reassembly (ewf `SegmentBacking`) never means "extract every segment
to temp first."

**Phase 2 — `peel(source, plan) -> DynSource` (execute the chosen strategy).**
`InPlace` sub-ranges the archive; `Zran` builds the checkpoint index (reusing the
`DeflateSeekReader` / `deflate64_seek` work in `zip-forensic-core`); `SpillToTemp`
streams once to a temp file (O(1) RAM, O(evidence) temp); `SegmentSet` reassembles a
split image via the container reader's sibling backing (ewf `SegmentBacking`), pulling
each member on demand. The resulting `DynSource` then re-enters `container::open` /
`resolve()` as usual.

**Why the split is structural, not cosmetic:** phase 1 is *typed* to see only bounded
heads + member tables, so it cannot accidentally inflate a payload to classify — the
whole-stream inflate exists only inside a deliberately-chosen `SpillToTemp` execution.
This is the general form of "don't uncompress the whole bz2 to check the tar magic."

**Reuses, not reinvents:** `Zran` = the deflate64 checkpoint seek; `SegmentSet` = ewf
`SegmentBacking`; `detect`/`peel` = the ADR-0008 `probe`/`open` traits. The only new
surface is the `AccessPlan` type + the phase-1 classifier.

**Build order:** (1) phase-1 `detect` returning `AccessPlan` (bounded, content-authoritative,
name-lie resolution + segment-set naming detection) over the existing readers; (2) phase-2
`InPlace` + `SpillToTemp` executors (subsumes today's `peel_archive`); (3) `Zran` access for
Deflate/Deflate64 members; (4) `SegmentSet` reassembly via ewf `SegmentBacking`. Each phase
is independently TDD-able; today's `peel_archive` keeps working until phase 2 replaces it.

## VFS integration contract — settled (2026-07-18) → **forensic-vfs ADR 0008**

The decision record lives in `forensic-vfs/docs/decisions/0008-archives-as-probes.md`.
Summary: **no dedicated `ArchiveProbe` trait is needed** — archives map onto the two probe
traits already in the leaf (`crates/core/src/registry.rs`, post engine-retirement):

- **Compression wrappers (gz/bz2) → `ContainerDecoder`** (1→1). `open` peels to the inner
  `DynSource`; `resolve()` re-sniffs it, so `E01.gz → E01 → GPT → NTFS` collapses in one call.
  Adds two additive, non-breaking leaf variants: `ContainerFormat::{Gzip,Bzip2}`.
- **Multi-member archives (tar/zip/`.clbx`/7z) → `FileSystemProbe`** (1→N). `open` mounts a
  member tree (`DynFs`); an evidence member re-enters `resolve()`. `FsKind` is an open newtype,
  so no enum change (`FsKind::from("tar"|"zip"|"7z")`).
- **Combos compose for free:** `.tgz` = `GzipDecoder ∘ TarProbe`; `.tbz2` = `Bzip2Decoder ∘ TarProbe`
  — no dedicated probe.
- **Registration:** the consumer's `default_registry()` uses the existing `.container(...)` /
  `.filesystem(...)` builders; every decoder + dep lives in an `archive-core` `vfs` adapter,
  never in the leaf.

**Status:** contract settled; the archive-core `vfs` adapter + the two `ContainerFormat`
variants are a follow-on. No functional gap — disk-forensic + 4n6mount already peel via
`archive_core::peel_archive`. The earlier "hold until the engine retirement settles" note is
obsolete: the retirement has landed (`crates/engine` removed, resolver/registry in core), so
the seam is buildable whenever scheduled, against a registry that has stopped moving.

## Verify before / during build (UNVERIFIED tier)

- `bzip2-rs` `forbid(unsafe)` + multi-stream `.bz2` / false-boundary handling + memory bounds.
- `lzma-rs` xz surface (confirm streaming-only; no hidden block API).
- deflate zran checkpoint RAM on huge members + concurrent readers → the spill fallback threshold.
- spill temp policy: free-space reservation, permissions, orphan sweep, deletion races.
- `PathSpec` archive addressing: stable member IDs across duplicate names / encodings / traversal.
- downstream reachability: `container::open`, `logical::open`, `resolve()` all reach the same peeled
  member through the same code path (Case-001 Szechuan parity).
