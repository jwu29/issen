# 0017. Collapse issen's disk access onto forensic-vfs for filesystem-agnostic whole-disk content scanning

Status: Accepted (program — executed in phases across repos)

## Context — the driving need

Browser artifacts (Chromium `History`/`Cookies`/`Login Data`/`Web Data` SQLite DBs,
Firefox `places.sqlite`, LevelDB stores) are **not** confined to canonical profile
paths under `\Users\<user>\…\Chrome\User Data\Default`. They live anywhere:

- **all browser profiles**, not just `Default` (`Profile 1`, `Profile 2`, `Guest`);
- **Electron apps** that embed Chromium (Slack, Discord, Teams, VS Code, …);
- **portable browsers**, custom `--user-data-dir`, secondary drives;
- **copied-out / renamed** evidence and **anti-forensic relocation**;
- **any operating system** — Linux Chrome/Firefox in `~/.config` / `~/.mozilla`
  (ext4/btrfs), macOS in `~/Library/Application Support` (APFS/HFS+), removable
  media (FAT/exFAT).

Two independent gaps make issen miss this today:

1. **Path-based classification.** `classify::browser_history` keys off filename +
   a vendor token *in the path* — so it misses renamed/off-path/Electron DBs on
   *every* input type. The fix is **content-based detection** (SQLite magic +
   `sqlite_master` schema: `urls` → Chromium, `moz_places` → Firefox, …).

2. **NTFS-only, targeted extraction.** The disk leg extracts a fixed set of paths
   from NTFS volumes only. A whole-disk scan on *any* filesystem needs a
   **filesystem-agnostic walk**.

## Decision

Adopt **forensic-vfs** as the fleet's universal filesystem abstraction and collapse
issen's disk access onto it (the roadmap's "issen-collapse"). A whole-disk
content-based artifact scan then runs over `dyn FileSystem`, filesystem-agnostic.

Chosen over a tactical per-FS walk inside issen-disk: forensic-vfs already defines
the abstraction (`FileSystem` trait, `FileSystemProbe`, engine resolver), one
universal walk serves every future whole-disk scan (not just browser), and it
unblocks ADR 0015 (Linux disk-image analysis parity needs a walkable root) and any
carving/timeline-over-unallocated work.

## Architecture

- **`forensic-vfs-core`** (lean leaf): `trait FileSystem: Send + Sync` (`read_dir`,
  `lookup`, `meta`, `read_at`, `extents`, `read_link`, `deleted`, `unallocated`,
  + default-empty forensic surface), the four probe traits (`Container` /
  `VolumeSystem` / `Crypto` / `FileSystemProbe`), and the `FsKind`/`FileId`/
  `StreamId`/`FsMeta` types. `crates/core/tests/contracts.rs` is the adapter spec.
- **`forensic-vfs-engine`**: runs probers over a `SniffWindow`, resolves
  container → volume-system → crypto → filesystem, mounts → `DynFs = Arc<dyn FileSystem>`.
- **Adapters** (`forensic-vfs/crates/adapters/<fs>`): each wraps a fleet reader and
  `impl FileSystem` + `impl FileSystemProbe`, listed in the engine's **explicit**
  registry (not link-time inventory). The reader repos stay untouched; the adapter
  layer deps the readers, the core stays a leaf.
- **issen** mounts a disk image's partitions via the engine and scans over `DynFs`.

## Phases (each ≥1 PR; sequenced, not all at once)

1. **NTFS reference adapter** — `adapters/ntfs` over `ntfs-core`
   (`directory_entries`/`read_file_capped`/`attribute_runlist`/`carve_mft_entries`).
   Validated against `contracts.rs`. The template every other adapter follows.
2. **ext4 / APFS / HFS+ adapters** — over `ext4fs-core` (`read_dir`/`inode_reader`),
   `apfs-core` (`list_dir`/`read_data`), `hfsplus` (`walk`/`list_dir`).
3. **Content-based browser detection** — `detect_browser_artifact(bytes) ->
   Option<BrowserArtifactKind>` (SQLite magic + `sqlite_master` schema), path-independent.
4. **Whole-disk content scan over `dyn FileSystem`** — walk every node (`read_dir`
   recursion / `deleted()` for orphans), magic-gate on the 16-byte SQLite header
   (cheap `read_at`), content-detect, parse matches → timeline. Bounded/capped,
   fail-loud on truncation. Dedup against the canonical selectors (kept as the fast path).
5. **issen disk-leg on the engine** — mount partitions via `forensic-vfs-engine`,
   retire the NTFS-only extraction path; the ext4/APFS legs of ADR 0015 fall out of
   this for free.

## Discovered state (2026-07) — further along, but cross-session

Investigation found the adapter layer **already written**, not yet published:

- **All four `FileSystem` adapters exist in local source** behind a `vfs` feature:
  `ntfs-forensic/core/src/vfs.rs`, `ext4fs-forensic/ext4fs-core/src/vfs.rs`,
  `apfs-forensic/core/src/vfs.rs`, `hfsplus-forensic/src/vfs.rs`
  (`read_dir`/`read_at`/`deleted`/`unallocated` implemented). So Phases 1-2 are
  substantially done by the fleet — the readers adopt the fleet pattern (reader
  deps `forensic-vfs` core + `impl FileSystem` behind `vfs`).
- **But the published crates lack it**: `ntfs-core 0.9.0`, `ext4fs-core 0.2.0`,
  `apfs-core 0.2.0` carry no `vfs` feature. issen deps registry versions, so it
  cannot consume the adapters until a fleet **publish** of the `vfs`-featured readers.
- **`forensic-vfs-engine` is in-flight** on `feat/engine` — another session's active
  work. The auto-detect/mount resolver isn't stable yet.

Consequences for sequencing:

- **Phase 3 (content-based detection) is independent** of all of the above — it is
  issen-side, filesystem-agnostic, and immediately improves the *existing* recursive
  fswalk (catches off-path/Electron/renamed browser DBs the path-based classifier
  misses). Start here. It is also exactly what the future VFS scan will call.
- **Phase 4-5 (whole-disk scan over `dyn FileSystem`, issen on the engine) are
  gated** on (a) publishing the `vfs`-featured readers and (b) the engine landing —
  a coordinated fleet step, not an issen-only change. issen can construct a
  per-partition `Arc<dyn FileSystem>` directly from a `vfs`-featured reader (it
  already detects the FS) without the full engine, once the readers are published.

## Consequences

- Filesystem-agnostic whole-disk artifact discovery — browser data found by *what it
  is*, on *any* filesystem, regardless of where it sits. The forensically-sound posture.
- One universal walk reused fleet-wide (0015 Linux analysis, future carving/timeline).
- Large: 4 rich adapters + engine wiring + an issen disk-leg rewire, across
  `forensic-vfs`, the reader repos' dep graph, and issen — executed phase by phase.
- Each adapter's `deleted()`/`unallocated()` may land minimally (empty streams)
  first and gain real orphan/unallocated enumeration incrementally; `read_dir`/
  `read_at`/`meta`/`lookup` are complete from Phase 1 (they carry the walk + scan).
