# Fleet Duplication Inventory — Current State

**Date:** 2026-07-15
**Companion to:** [`fleet-vfs-consolidation.md`](./fleet-vfs-consolidation.md) (the plan). This doc records the **mess factually** — what is duplicated, where (with `crate/file:line`), and the single canonical home each should collapse to. Every claim was grepped, not assumed; sites confirmed clean are called out so the fix doesn't touch what already works.

## Summary (BLUF)

The fleet has **11 duplication hotspots**, driven by **two structural root causes**:

1. **A parallel VFS stack.** `~/src/forensic-vfs-engine` (standalone) reimplements, over its own `ForensicFs` trait, everything `forensic-vfs` already provides — a second engine (same crate name), a second fs-tree trait, a second byte-window reader, a second detection layer, a second flat-path tree builder, and a **second adapter for every reader crate** (`fs_*.rs`). `4n6mount` depends on it (`4n6mount/Cargo.toml:48`). This is the single largest source of duplication.
2. **A `Read+Seek` container/volume stack outside `forensic-vfs`.** `disk-forensic` (`container::open`, `analyse_disk`, `layout`, `logical::open`) re-wraps the same decoder/partition crates the `forensic-vfs` engine wraps — so E01/VMDK/QCOW2 are decoded up to **three** ways, MBR/GPT/APM parsed **two** ways.

Beneath those, the same **helpers are copy-pasted across the reader crates**: never-panic byte readers (~10 sites), date/epoch converters (`civil_to_unix` ×4, FILETIME ×5), and the `vfs.rs` adapter skeleton (`map_err` ×11, poison-`Mutex` ×8, synthetic-tree builder ×4) — even though canonical homes already exist (`forensic-vfs/core/src/read.rs`, `forensicnomicon::temporal`).

**Already clean (do not touch):** live-disk enumeration (single `livedisk-core`), the extent/run output model (centralized in `forensic_vfs`), and the findings *data model* (centralized in `forensicnomicon` — only its *rendering* is duplicated).

## Ranked hotspots → canonical home

| # | Hotspot | Copies | Canonical home |
|---|---|---|---|
| 1 | **Never-panic byte readers** (`u16/32/64_le`, out-of-range→0) | ~10 sites (ntfs ×5, livedisk, gpt-partition, ad1) | Promote `forensic-vfs/core/src/read.rs:14` `bounded_reader!` into a tiny shared `forensic-bytes` crate; delete the copies |
| 2 | **`vfs.rs` adapter boilerplate** (`map_err` ×11, poison-`Mutex` ×8, `FileId::Opaque` ×11, `Node`/tree ×4) | ~11 reader crates | A `forensic-vfs`-provided `ArchiveFs`/`TreeFs` base + `PoisonMutex` newtype + `map_err!` macro |
| 3 | **Two parallel fs-tree traits + double reader adapters** (`FileSystem` vs `ForensicFs`; reader `vfs.rs` vs engine `fs_*.rs`) | 2 traits; ~8 readers adapted twice | `forensic_vfs::FileSystem` — retire `ForensicFs` + the `fs_*.rs` layer; 4n6mount consumes `FileSystem` |
| 4 | **Filesystem/container magic detection** | 3 fs sniffers + 2 container sniffers + per-reader checks | `forensic-vfs` registry `SniffWindow`/probes, seeded from `forensicnomicon::boot_signatures`/`partition_schemes` |
| 5 | **Date/epoch converters** (`civil_to_unix` ×4, FILETIME ×5, HFS, DOS) | ~11 sites | `forensicnomicon::temporal` (exists; add `days_from_civil`) |
| 6 | **Container-decode facades** (ewf/vmdk/qcow2 wrapped ×3) | 3 stacks | One facade — `forensic_vfs::ContainerDecoder` registry; drop `disk-forensic::container::open` + `issen-ewf/vmdk/qcow2` |
| 7 | **Flat-path→synthetic-tree builders** (`ArchiveTree` + ad1 + dar + zip) | 4 | `forensic-vfs` `ArchiveFs` (folds into #2) |
| 8 | **Two `forensic-vfs-engine` crates** (name collision, same job) | 2 | Merge into `forensic-vfs/crates/engine` |
| 9 | **hex / GUID formatters** (hex ×6, GUID ×4) | 10 sites | Shared util in `forensicnomicon` (or `forensic-bytes`) |
| 10 | **Two `ContainerFormat` enums + two partition parsers** | 2 + 2 | One `ContainerFormat` in forensic-vfs; delete its hand-rolled `Mbr/Gpt/Apm::parse` in favor of `*-partition-forensic` |
| 11 | **Logical-archive double handling** (AD1/DAR via reader `FileSystem` *and* `disk-forensic::logical`→`LogicalFs`) | 2 paths | The reader `FileSystem` adapters; drop the parallel flat-entry path |

## Tier A — architectural parallels

**Two fs-tree traits (§ hotspot 3).** `forensic_vfs::FileSystem` (`forensic-vfs/crates/core/src/fs.rs:318`; `&self`, `FileId`, `read_at`) vs `ForensicFs` (`forensic-vfs-engine/src/lib.rs:61`; `&mut self`, `u64`, `read_file→Vec`). ~80% semantic overlap, incompatible identity/mutability/read models. No third trait in issen/disk-forensic (searched).

**Two byte-source/window models (§2 in audit).** Canonical: `ImageSource` (`source.rs:123`) + `SubRange` window (`adapters.rs:16`). Duplicate: `SlicedReader` (`forensic-vfs-engine/src/sliced_reader.rs:12`) re-does `SubRange`'s math on the `Read+Seek` idiom. Parallel idiom: `disk-forensic`'s `ReadSeek` + `OpenedImage.reader` (`container.rs:21,31`) — never adopts `ImageSource`.

**Two `forensic-vfs-engine` crates (§ hotspot 8).** `forensic-vfs/crates/engine` (`Vfs::open` `lib.rs:68`) and `~/src/forensic-vfs-engine` (`open` `open.rs:29`) — **same Cargo package name**, same job, disjoint implementations. Cannot coexist in one graph.

## Tier B — fleet-wide facade duplication

**Container decode ×3 (§ hotspot 6).** ewf/vmdk/qcow2 wrapped by `forensic-vfs` engine decoders (`engine/src/lib.rs:968,1001,347…`), `disk-forensic::container` (`container.rs:95,108,131…`), and `issen-ewf`/`issen-vmdk`/`issen-qcow2`. All over the same lower-level crates — facade duplication, not reimplementation.

**Partition parse ×2 (§ hotspot 10).** `disk-forensic::analyse_disk` + `layout` (`lib.rs:111`, `layout.rs:58`) wraps the `*-partition-forensic` crates; `forensic-vfs`'s engine **hand-rolls** `Mbr/Gpt/Apm::parse` (`engine/src/lib.rs:656,741,822`) instead of using them. issen reuses `disk_forensic::analyse_disk` (no third parser).

**Detection ×5 (§ hotspot 4).** 3 fs sniffers (`forensic-vfs` `FileSystemProbe` ×8, `forensic-vfs-engine/src/detect.rs:66`, per-reader magic like `ext4fs .../superblock.rs:161`) + 2 container sniffers (`forensic-vfs` `ContainerDecoder::probe`, `disk-forensic/src/container.rs:293`). `forensicnomicon` already owns the boot/partition signature tables (`boot_signatures.rs:36`, `partition_schemes`) but the engines don't consult it for fs/container magic.

**Logical-archive double handling (§ hotspot 11).** AD1/DAR are each readable two ways: the reader's own `FileSystem` (`ad1-core/src/vfs.rs:239` `Ad1Vfs`, `dar-core/src/vfs.rs:275` `DarVfs`, `zip .../vfs.rs:383` `ZipVfs`) **and** `disk-forensic::logical::open` (`logical.rs:172`) → `forensic-vfs-engine::LogicalFs` (`logical.rs:22`).

**Two `ContainerFormat` enums + two `ReadSeek` markers (§17).** `forensic_vfs::registry::ContainerFormat` (`registry.rs:18`) vs `disk_forensic::container::ContainerFormat` (`container.rs:255`); `disk_forensic::…ReadSeek` (`container.rs:21`) + `vmdk::ReadSeek`.

**Findings — model shared, rendering duplicated (§9).** `forensicnomicon::report` owns `Finding`/`TimelineEvent`/`Report` and both `forensic-vfs` (`fs.rs:360`, `volume.rs:58`) and `disk-forensic::normalize` build canonical `Finding`s — good. But `disk-forensic/src/report.rs:79` hand-rolls its own text rendering (`mbr/gpt/apm_structure`) instead of `forensicnomicon::report::render`.

## Tier C — per-crate helper + boilerplate duplication

**Never-panic byte readers ×~10 (§ hotspot 1).** Canonical `bounded_reader!` exists at `forensic-vfs/crates/core/src/read.rs:14` (verified: `pub mod read`, generates `be_u16`/`le_u32`/… returning 0 out-of-range). Reimplemented at: `ntfs-forensic/core` ×5 (`usn_extractor.rs:60`, `carve.rs:238`, `usn/reader.rs:16`, `usn/record.rs:54`, `usn/carver.rs:228`), `livedisk-forensic/core/src/drive_layout.rs:114`, `gpt-partition-forensic/core/src/entry.rs:42` + `header.rs:50`, `ad1-forensic/core/src/bytes.rs:10` (verified copy).

**Date/epoch converters ×~11 (§ hotspot 5).** `civil_to_unix`/`days_from_civil`: `forensic-vfs-engine/src/tree.rs:221` + `fs_iso.rs:326`, `fat-forensic/core/src/time.rs:46`, `iso9660-forensic/iso/src/vfs.rs:261` (×4). FILETIME→unix: canonical `forensicnomicon/src/temporal.rs:18` `filetime_to_unix_secs` (verified), reimplemented at `ntfs-forensic/core/src/time.rs:30` + `usn/record.rs:100`, `zip-forensic/core/src/vfs.rs:234`, `forensic-vfs-engine/src/fs_sevenz.rs:70`. Plus HFS epoch (`hfsplus .../vfs.rs:46`) and DOS time (`zip .../archive.rs:888`).

**`vfs.rs` adapter skeleton (§ hotspot 2).** Re-typed across ~11 reader `vfs.rs`: `map_err(FooError)→VfsError` (fat:72, iso:145, xfs:130, ntfs:63, ext4:68, apfs:182, + ad1/dar/zip/udf ≈ 11); poison-recovering `Mutex` (ad1:53, dar:39, iso:41, udf:44, apfs:197, zip:63, ntfs, ext4 ≈ 8); `Node` + `/`-split synthetic tree + zip-slip guard (ad1:69, dar:55, zip:80 = 3, + `ArchiveTree` §7); `FileId::Opaque(index)` (all 11). The adapter doc-blocks literally say "same shape as AD1/DAR."

**hex / GUID formatting (§ hotspot 9).** hex ×6 (`ad1-forensic/forensic:296`, `ad1-core:293`, `dar-core:1450`, `ewf .../integrity.rs:382`, `aff4 .../lib.rs:207`, `ewf .../ewf_check.rs:339`); GUID ×4 (`livedisk .../drive_layout.rs:97`, `forensic-vfs engine:920`, `forensic-vfs core/src/uri.rs:201`, `vhdx .../integrity.rs:126`).

**Allocation-bomb caps (§17).** Format-specific values, but the guard pattern is copy-pasted (`ad1 lib.rs:51`, `fat fs.rs:15`, `hfsplus lib.rs:95`, `ext4 dir.rs:7`, `udf lib.rs:59`).

**Cross-workspace scaffolding (§16).** Every `*-forensic` repo hand-copies the `*-core`/`*-forensic`/`*-cli` split, per-binary CLI arg/output boilerplate (`disk4n6.rs`, `ewf-forensic/cli`, `ewf_check.rs`), fuzz harnesses, and `deny.toml`/CI/toolchain configs. **No shared `xtask`/template crate** (searched). Proposed home: a shared `forensic-xtask` + `forensic-cli`.

## Verified clean (not hotspots)

- **Live-disk enumeration** — single canonical `livedisk-forensic/core/src/lib.rs:155`; `disk-forensic/src/layout.rs:8` reuses its `PhysicalDisk`. No second enumerator (searched).
- **Extent/run/metadata output model** — centralized in `forensic_vfs` (`ByteRun` `fs.rs:182`, `Extents` `source.rs:67`, `FsMeta` `fs.rs:225`); readers map their on-disk structs into it.
- **Findings data model** — centralized in `forensicnomicon::report`.

## What collapsing these unlocks

Hotspots 3, 6, 7, 8, 11 all dissolve by **retiring the standalone `forensic-vfs-engine` and rebasing `disk-forensic` onto `forensic-vfs`** (the Phase 0–3 work in the plan). Hotspots 1, 2, 5, 9 are **independent, low-risk wins** — a `forensic-bytes` crate, a `forensic-vfs` `ArchiveFs` base + `map_err!`/`PoisonMutex`, and routing date/hex/GUID through `forensicnomicon` — that can proceed in parallel with the architectural consolidation and immediately shrink every reader crate.
