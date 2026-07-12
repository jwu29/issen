# `issen-dmg` test fixtures

Per-file provenance for committed test data used by `issen-dmg` unit tests. The
fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](../../../../docs/corpus-catalog.md); this README
is the co-located human detail — cross-reference, never duplicate.

The repo-root `.gitignore` ignores `tests/data/`, so small, clearly-licensed
fixtures here are committed with `git add -f`.

#### hfsplus_compressed.dmg

- **Source / Identity:** copied verbatim from the `dmg-forensic` repo's
  `core/tests/data/hfsplus_compressed.dmg`. A **real** macOS `hdiutil` UDIF
  image (UDZO / zlib block type `0x80000005`, UDIF version 4, koly trailer at
  `file_size − 512`) virtualising a 4 MiB HFS+ disk. Independent of the Rust
  parser (produced by `hdiutil`, not our code) — a doer-checker (tier-2) oracle.
- **MD5:** `0fbd9940a4435c97c2e5106d5b1b0407`
- **Size:** 13140 bytes
- **Ground truth (confirmed via the `dmg-core` reader, independent of this
  crate):**
  - `virtual_disk_size` = 4194304 (8192 × 512-byte sectors)
  - bytes @ 510   = `55 AA` (protective MBR signature)
  - bytes @ 21504 = `48 2B 00 04` (HFS+ volume-header magic "H+", at
    `40×512 + 1024`)
- **Generator (verbatim, in the upstream `dmg-forensic` repo, run on macOS):**

  ```bash
  hdiutil create -size 4m -fs HFS+ -volname TestVol /tmp/hfsplus.dmg
  hdiutil convert /tmp/hfsplus.dmg.dmg -format UDZO -o hfsplus_compressed.dmg
  ```

- **Used by:** `src/lib.rs` unit tests — drives `DmgDataSource::open` /
  `open_reader` end-to-end (decode the UDIF container, read the HFS+ magic and
  protective-MBR signature back through `DataSource::read_at`).
- **License / redistribution:** self-minted by the Apache-2.0 `dmg-forensic`
  build with Apple `hdiutil`; the disk content is a bare empty HFS+ volume, no
  third-party data.
