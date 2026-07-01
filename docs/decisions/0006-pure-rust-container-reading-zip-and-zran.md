# 0006. Pure-Rust container reading: zip-direct and zran for bounded-RAM DEFLATE

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

Two forces met here. First, the fleet's safety posture is `forbid`/`deny`-unsafe
and a single static binary an analyst can drop on an evidence workstation — which
rules out C-FFI codec crates (`bzip2-sys`, `zstd-sys`, `lzma-sys`) that pull in a
C toolchain and unsafe linkage. Second, forensic images routinely arrive *inside*
a zip (an E01 downloaded as `image.zip`). Inflating a zipped 80 GB image into RAM
to read it is an out-of-memory failure; a naive `read_to_end` on a Deflated zip
entry did exactly that.

## Decision

Container reading is **pure Rust, no C-FFI codecs.** Decompression uses
pure-Rust crates (`miniz_oxide` for DEFLATE, `bzip2-rs` decompress-only) so the
`forbid(unsafe)` / batteries-included guarantee holds.

Two access patterns read an image straight out of its archive without extracting
it whole:

- **zip-direct:** a `Stored` (uncompressed) zip entry is read *in place* as a
  positioned sub-range of the zip file.
- **zran (seekable DEFLATE):** a `Deflated` entry is read through a
  Mark-Adler-`zran.c`-style checkpoint index. `miniz_oxide`'s `DecompressorOxide`
  is `Clone` and supports `STOP_ON_BLOCK_BOUNDARY`, so a checkpoint snapshots
  `(input_pos, output_pos, decompressor state, last 32 KiB window)` at DEFLATE
  block boundaries — no `inflatePrime`, no C FFI. A read decompresses only forward
  from the nearest checkpoint. Building the index costs one streaming decode over
  a sliding 32 KiB window (no full image in RAM); subsequent reads are bounded by
  the checkpoint interval. This is exposed to `ewf` via a `SegmentBacking`
  adapter so a Deflated E01 segment in a zip is read lazily.

## Consequences

An 80 GB image reads directly from its zip at bounded RAM (a full `issen ingest`
of the 80 GB macOS Big Sur image streamed at ~304 MB peak RSS; the wired zran
path moved a Case-001 EWF-from-zip ingest from ~10.5 GB to ~6.4 GB RSS, and the
seekable reader holds only a 32 KiB window plus checkpoints). The whole graph
stays pure-Rust and unsafe-free, so the static-binary and `forbid(unsafe)`
guarantees survive end-to-end. The value was validated Tier-1 (the 80 GB macOS
image MD5-matched against FTK).

The cost is a one-pass index build: the first read of a Deflated stream pays a
full streaming decode to lay down checkpoints, and read cost is bounded by (never
zero within) the checkpoint interval — a deliberate space/time trade against the
checkpoint density. `bzip2-rs` is decompress-only, which is all a read-only
forensic reader needs.

## References

- `CLAUDE.md` — "Batteries-Included" (pure-Rust codec preference), fleet safety posture
- Crate: `crates/issen-unpack` (`deflate_seek.rs` zran reader, `bzseek.rs`, `backing.rs`); the pure-Rust `zip-forensic-core` crate (imports as `zip_core`)
- Crate: `crates/issen-ewf` (`open_zip`, `DeflateBacking` → `ewf::SegmentBacking`)
- Measured: 80 GB Big Sur `issen ingest` at ~304 MB peak RSS; Case-001 EWF-from-zip RSS ~10.5 GB → ~6.4 GB; 80 GB image Tier-1 MD5 match to FTK
