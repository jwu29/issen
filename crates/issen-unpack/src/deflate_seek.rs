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
        mut inner: Box<dyn ReadSeekSend>,
        zlib: bool,
        interval: u64,
    ) -> io::Result<Self> {
        use miniz_oxide::inflate::core::inflate_flags::{
            TINFL_FLAG_HAS_MORE_INPUT, TINFL_FLAG_IGNORE_ADLER32, TINFL_FLAG_PARSE_ZLIB_HEADER,
            TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        };
        use miniz_oxide::inflate::core::{decompress, DecompressorOxide};
        use miniz_oxide::inflate::TINFLStatus;

        // Decode-ahead segment after the 32 KiB window; the window slides to the
        // front when the buffer fills, so total RAM is ~WINDOW + SEGMENT.
        const SEGMENT: usize = 256 * 1024;

        inner.seek(SeekFrom::Start(0))?;
        let mut state = DecompressorOxide::new();
        let mut buf = vec![0u8; WINDOW + SEGMENT];
        let mut out_pos = WINDOW; // physical write cursor in `buf`
        let mut out_total: u64 = 0;
        let mut in_total: u64 = 0;
        // Start checkpoint: fresh state, empty window (no history at the start).
        let mut checkpoints = vec![Checkpoint {
            in_pos: 0,
            out_pos: 0,
            state: state.clone(),
            window: Vec::new(),
        }];
        let mut last_ckpt: u64 = 0;

        let mut in_buf = vec![0u8; IN_CHUNK];
        let mut in_len = 0usize;
        let mut in_off = 0usize;
        let mut eof = false;
        let mut first = true; // zlib header is parsed on the first call only

        loop {
            if in_off >= in_len && !eof {
                in_len = inner.read(&mut in_buf)?;
                in_off = 0;
                if in_len == 0 {
                    eof = true;
                }
            }
            let mut flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
                | TINFL_FLAG_STOP_ON_BLOCK_BOUNDARY
                | TINFL_FLAG_IGNORE_ADLER32;
            if zlib && first {
                flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;
            }
            if !eof {
                flags |= TINFL_FLAG_HAS_MORE_INPUT;
            }
            let (status, used_in, used_out) = decompress(
                &mut state,
                &in_buf[in_off..in_len],
                &mut buf,
                out_pos,
                flags,
            );
            first = false;
            in_off += used_in;
            in_total += used_in as u64;
            out_pos += used_out;
            out_total += used_out as u64;

            match status {
                TINFLStatus::Done => break,
                TINFLStatus::BlockBoundary => {
                    if out_total - last_ckpt >= interval {
                        let wlen = std::cmp::min(out_total, WINDOW as u64) as usize;
                        let window = buf
                            .get(out_pos - wlen..out_pos)
                            .ok_or_else(|| io::Error::other("deflate_seek: window underflow"))?
                            .to_vec();
                        checkpoints.push(Checkpoint {
                            in_pos: in_total,
                            out_pos: out_total,
                            state: state.clone(),
                            window,
                        });
                        last_ckpt = out_total;
                    }
                }
                TINFLStatus::HasMoreOutput => {
                    // Buffer full mid-stream: slide the last 32 KiB to the front
                    // (the back-reference window) and keep going.
                    buf.copy_within(out_pos - WINDOW..out_pos, 0);
                    out_pos = WINDOW;
                }
                TINFLStatus::NeedsMoreInput => {
                    if eof {
                        return Err(io::Error::other("deflate_seek: truncated stream"));
                    }
                }
                other => {
                    return Err(io::Error::other(format!(
                        "deflate_seek: decode failed ({other:?})"
                    )));
                }
            }
        }

        Ok(Self {
            inner: Mutex::new(inner),
            zlib,
            checkpoints,
            total: out_total,
            pos: 0,
            decodes: AtomicU64::new(0),
        })
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
    pub fn read_at(&self, offset: u64, dst: &mut [u8]) -> io::Result<usize> {
        use miniz_oxide::inflate::core::decompress;
        use miniz_oxide::inflate::core::inflate_flags::{
            TINFL_FLAG_HAS_MORE_INPUT, TINFL_FLAG_IGNORE_ADLER32, TINFL_FLAG_PARSE_ZLIB_HEADER,
            TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        };
        use miniz_oxide::inflate::TINFLStatus;

        if offset >= self.total || dst.is_empty() {
            return Ok(0);
        }
        let end = offset.saturating_add(dst.len() as u64).min(self.total);
        // Nearest checkpoint at or before `offset`.
        let ci = self
            .checkpoints
            .partition_point(|c| c.out_pos <= offset)
            .saturating_sub(1);
        let cp = self
            .checkpoints
            .get(ci)
            .ok_or_else(|| io::Error::other("deflate_seek: no checkpoint"))?;

        let produce = usize::try_from(end - cp.out_pos).unwrap_or(0);
        let wlen = cp.window.len();
        // Window prefix (the back-ref dictionary) + the bytes we must produce.
        let mut out = vec![0u8; wlen + produce];
        out.get_mut(..wlen)
            .ok_or_else(|| io::Error::other("deflate_seek: out too small"))?
            .copy_from_slice(&cp.window);
        let mut state = cp.state.clone();
        let mut out_pos = wlen;
        let target = wlen + produce;

        let mut guard = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("deflate_seek: inner poisoned"))?;
        guard.seek(SeekFrom::Start(cp.in_pos))?;
        let mut in_buf = vec![0u8; IN_CHUNK];
        let mut in_len = 0usize;
        let mut in_off = 0usize;
        let mut eof = false;
        let at_start = cp.in_pos == 0;
        let mut first = true;

        while out_pos < target {
            if in_off >= in_len && !eof {
                in_len = guard.read(&mut in_buf)?;
                in_off = 0;
                if in_len == 0 {
                    eof = true;
                }
            }
            let mut flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF | TINFL_FLAG_IGNORE_ADLER32;
            if self.zlib && at_start && first {
                flags |= TINFL_FLAG_PARSE_ZLIB_HEADER;
            }
            if !eof {
                flags |= TINFL_FLAG_HAS_MORE_INPUT;
            }
            let (status, used_in, used_out) = decompress(
                &mut state,
                &in_buf[in_off..in_len],
                &mut out,
                out_pos,
                flags,
            );
            first = false;
            in_off += used_in;
            out_pos += used_out;
            match status {
                TINFLStatus::Done => break,
                TINFLStatus::HasMoreOutput => {}
                TINFLStatus::NeedsMoreInput => {
                    if eof {
                        break;
                    }
                }
                TINFLStatus::BlockBoundary => {}
                other => {
                    return Err(io::Error::other(format!(
                        "deflate_seek: decode failed ({other:?})"
                    )));
                }
            }
        }
        drop(guard);
        self.decodes.fetch_add(1, Ordering::Relaxed);

        let lo = wlen + usize::try_from(offset - cp.out_pos).unwrap_or(0);
        let produced = out_pos.saturating_sub(lo);
        let n = dst
            .len()
            .min(usize::try_from(end - offset).unwrap_or(0))
            .min(produced);
        dst.get_mut(..n)
            .ok_or_else(|| io::Error::other("deflate_seek: dst slice"))?
            .copy_from_slice(
                out.get(lo..lo + n)
                    .ok_or_else(|| io::Error::other("deflate_seek: out slice"))?,
            );
        Ok(n)
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
