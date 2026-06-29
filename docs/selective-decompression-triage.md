# Selective Decompression for Triage — Block-Indexed Reads over the Filesystem Spine

Status: **bzip2 selective reader implemented** (`issen-unpack::bzseek::Bzip2SeekReader`,
validated against `bzip2-rs`). The spine/extent-map orchestration and the
coverage fallback gate are the remaining integration. Pairs with
[`writing-disk-image-crates.md`](writing-disk-image-crates.md) and the adaptive
spill in `issen-unpack/src/backing.rs`.

## Summary

A timeline ingest needs a **small, scattered** fraction of an image's bytes —
filesystem metadata plus a curated set of small artifacts (registry hives, EVTX,
prefetch, SRUM, browser SQLite, LNK, $MFT/$LogFile/$UsnJrnl, amcache, Biome). The
question is never "how big is the image" but "can I reach those scattered bytes
without inflating everything between them." That depends entirely on the
**random-access unit** of the outer container, and on the image format's own
sparse map — not on the byte size of the working set.

Two things ship here:

1. **The optimized ingestion algorithm** (spine-first, extent-mapped, read in
   physical order, decode only covering units).
2. **`Bzip2SeekReader`** — the one outer format that previously had *no* random
   access and now does: it indexes bzip2's independent blocks and decodes only
   the ~900 KB blocks a read touches.

The matrix below states which **compression formats** and which **image formats**
support a fast path, and which **combinations are fastest** — the headline being
that the *size of the random-access unit* decides efficiency (EWF's 64 KB chunk
beats bzip2's 900 KB block for scattered small artifacts), and that the standard
forensic container (E01) is already the practical winner.

## The optimized ingestion algorithm

Given a backing that supports cheap random access, issen already reads only the
working set — the parsers request an artifact's clusters, never the whole disk.
The algorithm that minimizes decompression is therefore:

1. **Read the spine first.** Boot sector / superblock / FAT → locate the bulk
   metadata. The *pointers* are front-loaded; the bulk is not — $MFT fragments,
   ext4 inode tables are distributed one-per-block-group, $UsnJrnl sits wherever
   it was allocated.
2. **Decode the metadata, build the file→extent map** (NTFS data runs / ext4
   extents). This is the only unavoidable "decode a region you didn't ask for"
   step, and it is small.
3. **Translate the selected artifact set to random-access units** (EWF chunks /
   bzip2 blocks / qcow2 clusters / vmdk grains), and **deduplicate** — many small
   artifacts share a unit.
4. **Read units in physical-offset order.** Once reads are coalesced and ordered,
   full traveling-salesman optimality buys little; offset order captures ~all of
   it and is what minimizes both seeks and unit re-decoding.
5. **Cache decoded units** (bounded LRU) and **gate on coverage**: if the covered
   fraction of units is high (most of the image is touched anyway), fall back to
   decode-once-and-spill — selective decode only pays when coverage is sparse.

`Bzip2SeekReader` implements steps 3–5 for bzip2 (`partition_point` over the
block offset map → decode only covering blocks → 8-block move-to-front LRU). EWF
implements them already inside `ewf` (`read_at` inflates only covering chunks).

## Fast-path support — by outer (compression/container) format

The fast path = the outer format exposes a **bounded random-access unit**, so a
scattered read inflates only the units it overlaps.

| Outer format | Random-access unit | Fast path | Notes |
|---|---|---|---|
| raw / `.dd` | byte (none to decode) | ✅ | direct seek |
| zip-`Stored` | byte (in-place window) | ✅ | `SubRangeReader` over the entry |
| **E01 / EWF** | ~32–64 KB zlib chunk | ✅ | already selective in `ewf` |
| AFF4 | image-stream chunk | ✅ | chunked like EWF |
| **bzip2** (`.bz2`) | ~900 KB block | ✅ | `Bzip2SeekReader` (this work) |
| zip-`Deflated` | — (one DEFLATE stream/entry) | — | materialize (spill) |
| tar.gz | — (one gzip stream) | — | materialize (spill) |
| tar.bz2 | block, per member (in principle) | partial | selective possible, **not yet wired** — currently spill |
| 7z solid | — (one LZMA stream) | — | materialize (spill) |
| 7z non-solid | per-file LZMA stream | partial | random per file, **not yet wired** |

A single-stream codec (gzip, solid 7z) has no random-access unit short of a
prebuilt sync-point index, so it stays on the spill floor.

## Fast-path support — by image (inner container) format

This is the *other* axis: given a random-access byte backing, does the image
format let you read only the clusters you need? **All of them do** — each carries
a sparse map, and each already decodes only the clusters requested:

| Image format | Sparse map | Selective read |
|---|---|---|
| raw / `.dd` | identity (offset == LBA) | ✅ |
| E01 / EWF | chunk offset table | ✅ |
| VMDK (sparse) | grain directory / grain tables | ✅ |
| VHD (dynamic) | Block Allocation Table | ✅ |
| VHDX | BAT + region table | ✅ |
| QCOW2 | L1/L2 cluster tables | ✅ |
| AFF4 | image-stream index | ✅ |

So the image format is **not** the bottleneck — the outer compression is. A
sparse VMDK inside a `tar.gz` loses all of its selectivity, because the gzip layer
has no random-access unit; the same VMDK loose, or in a zip-`Stored`, keeps it.

## Which combinations are fastest

Fast path requires **both** axes: a random-access outer unit **and** a sparse
image format. Since every image format is sparse, the ranking is driven by the
outer unit — specifically its **size**, because a scattered small artifact forces
decoding the *whole* unit it lands in (over-decode = unit_size − artifact_size).

Ranked for a sparse triage workload (fastest first):

1. **raw / zip-`Stored` + any image format** — zero decompression, pure seeks.
   The ceiling; e.g. a `.dd`, or an uncompressed image in a zip-`Stored`.
2. **E01 / EWF** — ~32–64 KB chunks. Small unit → little over-decode per
   artifact, and the chunk index is built into the format (no separate index
   pass). For real evidence this is the **practical winner**: near-raw speed on
   the working set with the storage savings of compression. (AFF4 sits here too.)
3. **bzip2 `.bz2` via `Bzip2SeekReader`** — selective, but two costs make it
   slower than EWF: the ~900 KB block is ~14–28× larger than an EWF chunk (more
   wasted decompression per scattered 64 KB artifact), and bzip2 stores no output
   length, so the offset map costs **one full decode** up front (parallelizable,
   no temp writes). Beats decode-once-and-spill only when the working set is
   sparse *and* temp is slow/absent (e.g. a read-only or tmpfs-only host).
4. **non-solid 7z** (when wired) — per-file LZMA; random at file granularity but
   LZMA decode is costlier than zlib.

Not on the fast path (materialize once, then free seeks off the spill):
**zip-`Deflated`, tar.gz, solid 7z, single-stream gzip.**

The one-line rule: **prefer a format whose random-access unit is small and
indexed.** EWF wins because 64 KB ≪ 900 KB and its index is free; bzip2 is the
fallback that rescues an otherwise-unseekable `.bz2`; gzip/solid-7z can't be
rescued without a full index pass and stay on spill.

## `Bzip2SeekReader` — how it works

bzip2's blocks each carry their own CRC and share **no** inter-block dictionary,
so a single block can be rebuilt into a standalone one-block stream and decoded in
isolation — the `bzip2recover` technique, no decoder-state injection. (gzip's
DEFLATE and solid 7z's LZMA both carry cross-unit state, which is why neither can
do this.)

1. **Index:** one streaming, rolling 48-bit bit-scan records every block magic
   (`0x314159265359`) and the EOS magic (`0x177245385090`).
2. **Lengths:** bzip2 stores no per-block output length, so each block is decoded
   once to learn its decompressed span and build the offset map (one full decode,
   no temp).
3. **Extract:** for block *k*, emit `BZh<level>` + the block's bits verbatim + the
   EOS magic + the block's stored CRC (a one-block stream's combined CRC *is* that
   block's CRC), and hand the synthetic stream to `bzip2-rs`.
4. **Serve:** `read_at` finds covering blocks via `partition_point` on the offset
   map and decodes only those, behind an 8-block LRU.

Limitation: block boundaries are found by a 48-bit magic, so a payload that
happens to contain the magic is a ~2⁻⁴⁸ false-positive per bit position — a bogus
boundary makes a block fail to decode, which surfaces **loudly** at index build
(never a silent wrong read). Multi-stream `.bz2` (concatenated `BZh` headers, e.g.
`pbzip2`) is untested.

## Integration status & next steps

- **Done:** `Bzip2SeekReader` (random-access bzip2), TDD against `bzip2-rs`.
- **Deliberately not done:** swapping the default `archive_backing` for bzip2 to
  the seek reader. `open` decodes all blocks once and re-decodes on eviction, so a
  *full sequential* read (whole-image hash/carve) thrashes vs spill — full-image
  ops stay on the spill floor by design.
- **Next:** a triage entry point that (a) builds the spine + extent map, (b)
  engages `Bzip2SeekReader` (or the EWF/qcow2/vmdk native sparse path) for the
  selected artifact set, and (c) applies the coverage gate to fall back to spill
  when most units are touched. Wire non-solid-7z and per-member tar.bz2 the same
  way.

## Validation plan (for the integration)

Tier-2 against an independent oracle: decode the selected artifact set via the
selective path and via full decompression + parse, asserting byte-identical
extents. Measure **unit coverage** and wall-clock against `spill_from` on a real
bzip2-wrapped image (not a synthetic round-trip) before claiming a speedup, and
report the coverage number alongside any timing — the win is coverage-bound.
