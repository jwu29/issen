//! Seekable DEFLATE — a "zran"-style checkpoint index + resume.
//!
//! A read of a few scattered ranges decompresses only forward from the nearest
//! checkpoint instead of inflating the whole stream. DEFLATE is one continuous
//! bitstream with no byte-aligned restart points, so the trick (Mark Adler's
//! `zran.c`) is to snapshot the decompressor *state* — bit position + the 32 KiB
//! back-reference window — at intervals, and restore it to resume mid-stream.
//!
//! Pure-Rust: `miniz_oxide`'s `DecompressorOxide` is `Clone` and supports
//! `STOP_ON_BLOCK_BOUNDARY`, so a checkpoint is `(input_pos, output_pos,
//! state.clone(), last-32 KiB)` taken at a DEFLATE block boundary (a clean
//! inter-block point), and a read restores it into a window-prefilled output
//! buffer. No `inflatePrime`, no C FFI.
//!
//! Economics mirror the bzip2 seek reader: building the offset map costs one
//! streaming decode (no full image in RAM — a sliding 32 KiB window); subsequent
//! reads decompress only from the covering checkpoint, bounded by the checkpoint
//! interval.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::backing::ReadSeekSend;

/// DEFLATE's back-reference window.
const WINDOW: usize = 32 * 1024;
/// Decompressed bytes between checkpoints (read cost is bounded by this).
const DEFAULT_INTERVAL: u64 = 1 << 20;
/// Compressed bytes read per chunk while decoding.
const IN_CHUNK: usize = 64 * 1024;

/// A resumable point in the DEFLATE stream, taken at a block boundary.
struct Checkpoint {
    /// Compressed byte offset of the next byte to feed on resume.
    in_pos: u64,
    /// Decompressed byte offset this checkpoint sits at.
    out_pos: u64,
    /// Decompressor state captured at the block boundary (carries the bit
    /// position, so no `inflatePrime` is needed).
    state: miniz_oxide::inflate::core::DecompressorOxide,
    /// Up to 32 KiB of prior output — the back-reference dictionary.
    window: Vec<u8>,
}

/// A `Read + Seek` view over a DEFLATE stream that decodes only forward from the
/// nearest checkpoint. Construct with [`open`](DeflateSeekReader::open).
pub struct DeflateSeekReader {
    inner: Mutex<Box<dyn ReadSeekSend>>,
    /// True if the stream has a zlib header/trailer; false for raw DEFLATE (zip).
    zlib: bool,
    checkpoints: Vec<Checkpoint>,
    total: u64,
    interval: u64,
    pos: u64,
    decodes: AtomicU64,
}

impl std::fmt::Debug for DeflateSeekReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeflateSeekReader")
            .field("zlib", &self.zlib)
            .field("checkpoints", &self.checkpoints.len())
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

impl DeflateSeekReader {
    /// Build the checkpoint index over a DEFLATE stream. `zlib` selects a
    /// zlib-wrapped stream (header + Adler-32) versus raw DEFLATE (zip entries).
    ///
    /// # Errors
    /// A malformed stream or an underlying I/O error.
    pub fn open(inner: Box<dyn ReadSeekSend>, zlib: bool) -> io::Result<Self> {
        Self::open_with_interval(inner, zlib, DEFAULT_INTERVAL)
    }

    /// As [`open`](Self::open) with an explicit checkpoint interval (test hook;
    /// smaller intervals force more checkpoints on small inputs).
    ///
    /// # Errors
    /// A malformed stream or an underlying I/O error.
    pub fn open_with_interval(
        inner: Box<dyn ReadSeekSend>,
        zlib: bool,
        interval: u64,
    ) -> io::Result<Self> {
        let _ = (inner, zlib, interval);
        Err(io::Error::other("DeflateSeekReader::open: unimplemented"))
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

    /// Number of checkpoints in the index.
    #[must_use]
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.len()
    }

    /// Forward-decode invocations so far (test/telemetry; one per `read_at` that
    /// actually decodes).
    #[must_use]
    pub fn decode_count(&self) -> u64 {
        self.decodes.load(Ordering::Relaxed)
    }

    /// Read into `buf` starting at decompressed byte `offset`, decoding only from
    /// the nearest preceding checkpoint. Returns the bytes read (short only at
    /// end of stream).
    ///
    /// # Errors
    /// A decode or underlying I/O failure.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let _ = (offset, buf);
        Err(io::Error::other(
            "DeflateSeekReader::read_at: unimplemented",
        ))
    }
}

impl Read for DeflateSeekReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for DeflateSeekReader {
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
    use std::io::{Cursor, Write};

    /// Raw DEFLATE (no zlib header), as a zip entry stores it.
    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// The oracle: full sequential inflate via flate2.
    fn full_inflate(comp: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::DeflateDecoder::new(Cursor::new(comp))
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    /// Pseudo-random runs interleaved with back-references reaching ~700 bytes —
    /// gives many DEFLATE blocks AND back-refs that cross checkpoints, so the
    /// window restore is actually exercised.
    fn mixed(len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        let mut x = 0x1234_5678u32;
        while v.len() < len {
            for _ in 0..300 {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                v.push((x >> 16) as u8);
                if v.len() >= len {
                    break;
                }
            }
            if v.len() > 700 {
                let start = v.len() - 700;
                for i in 0..200 {
                    if v.len() >= len {
                        break;
                    }
                    v.push(v[start + i]);
                }
            }
        }
        v.truncate(len);
        v
    }

    fn reader(comp: Vec<u8>, interval: u64) -> DeflateSeekReader {
        DeflateSeekReader::open_with_interval(Box::new(Cursor::new(comp)), false, interval).unwrap()
    }

    #[test]
    fn index_spans_multiple_checkpoints_and_total_matches() {
        let data = mixed(2_000_000);
        let comp = raw_deflate(&data);
        assert_eq!(full_inflate(&comp), data, "fixture sanity");
        let r = reader(comp, 64 * 1024);
        assert_eq!(r.len(), data.len() as u64);
        assert!(
            r.checkpoint_count() >= 4,
            "64 KiB interval over 2 MB should give several checkpoints, got {}",
            r.checkpoint_count()
        );
    }

    #[test]
    fn read_at_matches_oracle_scattered() {
        let data = mixed(2_000_000);
        let want = data.clone();
        let r = reader(raw_deflate(&data), 64 * 1024);
        // ranges near checkpoint boundaries + straddling them
        for (off, len) in [
            (0usize, 100),
            (65_500, 2000),
            (130_000, 5000),
            (1_000_000, 4096),
            (1_999_000, 1000),
        ] {
            let mut got = vec![0u8; len];
            let n = r.read_at(off as u64, &mut got).unwrap();
            assert_eq!(n, len, "short read at {off}");
            assert_eq!(got, want[off..off + len], "mismatch at {off}");
        }
    }

    #[test]
    fn read_past_end_is_short() {
        let data = mixed(200_000);
        let r = reader(raw_deflate(&data), 64 * 1024);
        let mut buf = [0u8; 500];
        let n = r.read_at(199_800, &mut buf).unwrap();
        assert_eq!(n, 200, "only 200 bytes remain");
    }

    #[test]
    fn scattered_read_decodes_from_one_checkpoint() {
        let data = mixed(2_000_000);
        let r = reader(raw_deflate(&data), 64 * 1024);
        let base = r.decode_count();
        let mut b = [0u8; 1];
        r.read_at(1_500_000, &mut b).unwrap();
        // one forward-decode for a single scattered read, not a whole-stream pass
        assert_eq!(r.decode_count() - base, 1);
    }

    #[test]
    fn read_seek_cursor_matches() {
        let data = mixed(500_000);
        let want = data.clone();
        let mut r = reader(raw_deflate(&data), 64 * 1024);
        r.seek(SeekFrom::Start(300_000)).unwrap();
        let mut buf = vec![0u8; 2000];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, want[300_000..302_000]);
    }
}
