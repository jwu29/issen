//! Seekable bzip2 — block index + independent per-block decode.
//!
//! A read of a few scattered ranges decodes only the ~900 KB blocks that cover
//! them, instead of inflating the whole stream. bzip2's blocks carry their own
//! CRC and share no inter-block dictionary, so a single block can be rebuilt into
//! a standalone one-block stream and decoded in isolation — the `bzip2recover`
//! technique — with no decoder-state injection. (gzip and solid 7z cannot do
//! this; see `docs/selective-decompression-triage.md`.)
//!
//! Economics: the index records every block's bit range; learning each block's
//! *decompressed* length needs one decode (bzip2 stores no output length), so
//! building the offset map costs one full decode (parallelizable, no temp
//! writes). Subsequent scattered reads then decode only covering blocks. The win
//! over decode-once-and-spill is avoiding the full temp write/read-back when the
//! working set is sparse; the caller gates on coverage.

use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bzip2_rs::DecoderReader;

use crate::backing::ReadSeekSend;

/// 48-bit bzip2 block-start magic (BCD digits of pi).
const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
/// 48-bit bzip2 end-of-stream magic (BCD digits of sqrt(pi)).
const EOS_MAGIC: u64 = 0x1772_4538_5090;
/// 48-bit mask for the rolling magic window.
const MAGIC_MASK: u64 = 0xFFFF_FFFF_FFFF;
/// Decoded blocks kept resident (LRU); a block is ≤ level·100 KB.
const DEFAULT_CACHE_BLOCKS: usize = 8;

/// One bzip2 block located in the compressed bitstream.
#[derive(Debug, Clone, Copy)]
struct BlockEntry {
    /// Bit offset of this block's magic in the compressed stream.
    bit_start: u64,
    /// Bit offset of the next block's magic / the EOS magic (exclusive).
    bit_end: u64,
    /// This block's CRC32 — also the combined CRC of a one-block stream.
    crc: u32,
    /// First decompressed byte this block contributes.
    decomp_start: u64,
    /// Decompressed bytes this block contributes.
    decomp_len: u64,
}

/// A `Read + Seek` view over a bzip2 stream that inflates only the blocks a read
/// touches. Construct with [`Bzip2SeekReader::open`]; use [`read_at`] for
/// positioned reads or the `Read`/`Seek` impls for a cursor.
///
/// [`read_at`]: Bzip2SeekReader::read_at
pub struct Bzip2SeekReader {
    inner: Mutex<Box<dyn ReadSeekSend>>,
    level: u8,
    blocks: Vec<BlockEntry>,
    total: u64,
    cache: Mutex<Vec<(usize, Arc<Vec<u8>>)>>,
    cache_cap: usize,
    pos: u64,
    decodes: AtomicU64,
}

impl std::fmt::Debug for Bzip2SeekReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bzip2SeekReader")
            .field("level", &self.level)
            .field("blocks", &self.blocks.len())
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

impl Bzip2SeekReader {
    /// Build the block index over a bzip2 stream and return a seekable reader.
    ///
    /// # Errors
    /// Not a bzip2 stream, a truncated/corrupt block, or an underlying I/O error.
    pub fn open(inner: Box<dyn ReadSeekSend>) -> io::Result<Self> {
        let _ = inner;
        Err(io::Error::other("Bzip2SeekReader::open: unimplemented"))
    }

    /// Total decompressed length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.total
    }

    /// True if the stream decompresses to nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Number of bzip2 blocks in the stream.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Total per-block decodes performed so far (test/telemetry instrumentation;
    /// a cache hit does not increment it).
    #[must_use]
    pub fn decode_count(&self) -> u64 {
        self.decodes.load(Ordering::Relaxed)
    }

    /// Read into `buf` starting at decompressed byte `offset`, decoding only the
    /// blocks that cover `[offset, offset + buf.len())`. Returns the number of
    /// bytes read (short only at end of stream).
    ///
    /// # Errors
    /// A decode or underlying I/O failure.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (offset, buf);
        Err(io::Error::other("Bzip2SeekReader::read_at: unimplemented"))
    }
}

impl Read for Bzip2SeekReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Bzip2SeekReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::End(o) => self.total as i128 + o as i128,
            SeekFrom::Current(o) => self.pos as i128 + o as i128,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        (0u8..=255).cycle().take(len).collect()
    }

    /// A real multi-block bzip2 stream: level 1 = 100 KB input blocks, so a
    /// payload over 100 KB spans several blocks. banzai is a pure-Rust encoder.
    fn multiblock_bz2(payload: &[u8]) -> Vec<u8> {
        let mut bz = Vec::new();
        banzai::encode(Cursor::new(payload), io::BufWriter::new(&mut bz), 1).unwrap();
        bz
    }

    /// The oracle: full sequential decode via bzip2-rs.
    fn full_decode(bz: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        DecoderReader::new(Cursor::new(bz))
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    fn reader(bz: Vec<u8>) -> Bzip2SeekReader {
        Bzip2SeekReader::open(Box::new(Cursor::new(bz))).unwrap()
    }

    #[test]
    fn builds_multiblock_index() {
        let payload = pattern(250_000);
        let bz = multiblock_bz2(&payload);
        let r = reader(bz);
        assert_eq!(r.len(), 250_000);
        assert!(
            r.block_count() >= 2,
            "level-1 250 KB should span multiple blocks, got {}",
            r.block_count()
        );
    }

    #[test]
    fn read_at_matches_full_decode_across_boundaries() {
        let payload = pattern(250_000);
        let bz = multiblock_bz2(&payload);
        let want = full_decode(&bz);
        assert_eq!(want, payload, "fixture sanity: oracle == payload");
        let r = reader(bz);
        // Ranges that straddle the 100 KB / 200 KB block boundaries.
        for (off, len) in [(0usize, 16), (99_990, 40), (150_000, 1000), (249_000, 1000)] {
            let mut buf = vec![0u8; len];
            let n = r.read_at(off as u64, &mut buf).unwrap();
            assert_eq!(n, len, "short read at {off}");
            assert_eq!(buf, want[off..off + len], "byte mismatch at {off}");
        }
    }

    #[test]
    fn scattered_read_decodes_only_covering_blocks() {
        let payload = pattern(300_000); // ~3 blocks at level 1
        let bz = multiblock_bz2(&payload);
        let r = reader(bz);
        let base = r.decode_count();
        let mut b = [0u8; 4];
        r.read_at(0, &mut b).unwrap(); // first block only
        assert_eq!(r.decode_count() - base, 1, "one block for the first read");
        let after_first = r.decode_count();
        r.read_at(0, &mut b).unwrap(); // cached → no decode
        assert_eq!(r.decode_count(), after_first, "cache hit decodes nothing");
        r.read_at((payload.len() - 4) as u64, &mut b).unwrap(); // last block only
        assert_eq!(
            r.decode_count() - after_first,
            1,
            "one block for the last read, not the whole stream"
        );
    }

    #[test]
    fn read_past_end_is_short() {
        let payload = pattern(120_000);
        let r = reader(multiblock_bz2(&payload));
        let mut buf = [0u8; 100];
        let n = r.read_at(119_950, &mut buf).unwrap();
        assert_eq!(n, 50, "only 50 bytes remain");
    }

    #[test]
    fn read_seek_cursor_matches_read_at() {
        let payload = pattern(250_000);
        let bz = multiblock_bz2(&payload);
        let want = full_decode(&bz);
        let mut r = reader(bz);
        r.seek(SeekFrom::Start(199_000)).unwrap();
        let mut buf = vec![0u8; 2000];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, want[199_000..201_000]);
    }

    #[test]
    fn open_rejects_non_bzip2() {
        let err = Bzip2SeekReader::open(Box::new(Cursor::new(b"not bzip2".to_vec())));
        assert!(err.is_err());
    }
}
