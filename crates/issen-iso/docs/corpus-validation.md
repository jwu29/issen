# ISO Corpus Validation

Corpus tests for `IsoDataSource` against a real Ubuntu Linux ISO image.

## Test Environment

| Component | Version |
|-----------|---------|
| OS | macOS (Apple Silicon) |
| Rust | (see workspace `rust-toolchain.toml`) |
| hadris-iso | (see `Cargo.lock`) |

## Corpus Files

### ubuntu-20.04-mini.iso — Ubuntu 20.04 (Focal) netboot installer

| Field | Value |
|-------|-------|
| Format | ISO 9660 |
| Size | 77,594,624 bytes (74 MiB) |
| Creator | `genisoimage` (ISO 9660/HFS Filesystem Creator — independent of hadris-iso) |
| Source | Canonical / Ubuntu project |
| URL | `http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/current/legacy-images/netboot/mini.iso` |
| SHA-256 | `0e79e00bf844929d40825b1f0e8634415cda195ba23bae0b041911fde4dfe018` |
| License | GPL and various open source licenses (Ubuntu components) |

This is the official Ubuntu 20.04 LTS netboot installer, created by Canonical.
The PVD application identifier is:
`GENISOIMAGE ISO 9660/HFS FILESYSTEM CREATOR (C) 1993 E.YOUNGDALE (C) 1997-2006 J.PEARSON/J.SCHILLING (C) 2006-2007 CDRKIT TEAM`

The file is NOT committed to git (74 MiB). Tests skip if absent.
Download with: `curl -L <URL> -o crates/issen-iso/tests/data/ubuntu-20.04-mini.iso`

## Test Results

### `corpus_ubuntu_mini_iso_open_and_len`

Opens the Ubuntu ISO via `IsoDataSource::open` (which internally validates
via `hadris_iso`). Verifies `len()` equals the file size. **PASS**.

Exercises: hadris-iso PVD validation on a real-world multi-filesystem ISO.

### `corpus_ubuntu_mini_iso_read_at_matches_direct_file_reads`

Reads at 2 MiB stride + PVD sector (offset 32768) + near-end 512 bytes.
Compares `IsoDataSource::read_at` output against direct `File::read` at the
same offsets. **PASS** (byte-identical at all sampled offsets).

ISO 9660 is a raw-sector format — `IsoDataSource` performs no transformation,
so read_at must return exactly the file bytes at each requested offset.

## Validation Coverage

| Feature | Covered | Notes |
|---------|---------|-------|
| PVD validation (hadris-iso) | Yes | Ubuntu mini ISO |
| Raw sector pass-through | Yes | byte-identical comparison |
| Real-world ISO from independent creator | Yes | genisoimage / Canonical |
| Rock Ridge / Joliet extensions | Implicit | Ubuntu ISOs use both |
| Multi-session | No | not in corpus |
| UDF | No | not in scope for ISO 9660 |

## Reproducing

```sh
# Download corpus (74 MiB, not committed)
curl -L \
  "http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-amd64/current/legacy-images/netboot/mini.iso" \
  -o crates/issen-iso/tests/data/ubuntu-20.04-mini.iso

# Verify
shasum -a 256 crates/issen-iso/tests/data/ubuntu-20.04-mini.iso
# expected: 0e79e00bf844929d40825b1f0e8634415cda195ba23bae0b041911fde4dfe018

# Run corpus tests
cargo test -p issen-iso --test corpus
```
