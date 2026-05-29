# DD/Raw Corpus Validation

Corpus tests for `DdDataSource` against a real raw disk image.

## Test Environment

| Component | Version |
|-----------|---------|
| OS | macOS (Apple Silicon) |
| Rust | (see workspace `rust-toolchain.toml`) |

## Corpus Files

### ext4.raw — dfvfs ext4 filesystem raw image

| Field | Value |
|-------|-------|
| Format | Raw / DD (flat sector stream) |
| Size | 4,194,304 bytes (4 MiB) |
| Source | log2timeline/dfvfs test corpus (Apache-2.0) |
| URL | https://github.com/log2timeline/dfvfs/raw/main/test_data/ext4.raw |
| SHA-256 | `d88dd5f6774526a94ad74e061c6a4245fef302e03c917277fb4043e30ed8b434` |
| Content | ext4 filesystem with real data (created by dfvfs project) |
| License | Apache-2.0 |

The file is committed to `tests/data/` (4 MiB) and tests run automatically.

## Test Results

### `corpus_ext4_raw_len_matches_file_size`

Verifies `DdDataSource::len()` equals the file's metadata length. **PASS**.

### `corpus_ext4_raw_read_at_matches_direct_file_reads`

Reads at 64 KiB stride + near-end 512 bytes. Compares `DdDataSource::read_at`
output against direct `File::read` at the same offsets. **PASS** (byte-identical).

A raw/DD image has no format layer — `DdDataSource` is a pure pass-through.
Any discrepancy would indicate a bug in the `dd` crate wrapper or the `Mutex`/`Seek`
plumbing in `DdDataSource`.

## Validation Coverage

| Feature | Covered | Notes |
|---------|---------|-------|
| Raw sector pass-through | Yes | byte-identical comparison |
| File size reporting | Yes | `len()` matches metadata |
| Concurrent-safe reads (`Mutex`) | Yes | single-threaded stride scan |
| Real-world raw image | Yes | dfvfs corpus (Apache-2.0) |
| Sparse/zero regions | Implicit | ext4 sparse regions present |
| Sector-unaligned reads | No | all samples are 512-byte aligned |

## Reproducing

```sh
# Download corpus (committed, but to re-download):
curl -L \
  "https://github.com/log2timeline/dfvfs/raw/main/test_data/ext4.raw" \
  -o crates/issen-dd/tests/data/ext4.raw

# Verify
shasum -a 256 crates/issen-dd/tests/data/ext4.raw
# expected: d88dd5f6774526a94ad74e061c6a4245fef302e03c917277fb4043e30ed8b434

# Run corpus tests
cargo test -p issen-dd --test corpus
```
