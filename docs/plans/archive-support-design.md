# Archive Support for the forensic-vfs Stack — Design

Status: **design settled** (Fable 5 design → Codex critique → fleet-fact verification, 2026-07-17).
Scope target: new `archive-forensic` repo (`archive-core` + `archive-forensic`) + `forensic-vfs`
minor bump + `forensic-vfs-engine` 0.2.0 wiring. `disk-forensic` transitional on-ramp.

## Thesis (accepted)

An archive is a transparent **outer packing "detour"** first, a mountable tree second:
`foo.E01.gz` must resolve **identically** to `foo.E01`. Decoders are always compiled
(batteries-included); the layer **activates only at runtime** when the input is actually packed.

## Q1 — Trait: a NEW leaf probe, not `CryptoLayer`

A single evidence stack can contain **both** a decompressor and a crypto layer at different
depths — `case.zip → disk.E01 → GPT → BitLocker → NTFS`. Decompress and decrypt are orthogonal
1→1 transforms that co-occur, so they **must be independent probe kinds** or the recursive resolver
cannot express both in one chain. Reusing `CryptoLayer` is therefore structurally wrong (not merely
a provenance-naming lie); renaming it is breaking and conflates key/unlock/decrypted semantics a
decompressor lacks.

**Decision:** Add `ArchiveProbe` to the `forensic-vfs` leaf. Resolution is **not** a terminal
`Tree`; it is `ArchiveOpen { members, provenance, cost, source_for(member) -> Arc<dyn ImageSource> }`
where every member **re-enters normal `resolve()`**. `#[non_exhaustive]`, additive → minor bump.
`CryptoLayer` untouched.

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
`archive_core::peel_detour`. The earlier "hold until the engine retirement settles" note is
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
