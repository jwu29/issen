//! Bridge an issen [`DataSource`] (random-access `read_at`) to the `Read + Seek`
//! interface every FDE core crate consumes.
//!
//! The FDE crates (`bitlocker-core`, `luks-core`, `veracrypt-core`,
//! `filevault-core`) each take a value `R: Read + Seek` and hold it for the life
//! of the unlocked volume. issen sources expose only `read_at(offset, buf)`, so
//! this owned adapter carries a logical cursor and translates the two `std::io`
//! traits onto `read_at`.

use std::io::{self, Read, Seek, SeekFrom};

use issen_core::plugin::traits::DataSource;

/// Owns a [`DataSource`] and presents it as a `Read + Seek` stream.
///
/// Position arithmetic saturates rather than panicking: a seek past `u64::MAX`
/// or before zero clamps, and reads past the end yield `Ok(0)` (EOF) exactly as
/// `read_at` does.
pub(crate) struct DataSourceReader {
    inner: Box<dyn DataSource>,
    pos: u64,
    len: u64,
}

impl DataSourceReader {
    /// Wrap `source`, positioning the cursor at the start.
    pub(crate) fn new(source: Box<dyn DataSource>) -> Self {
        let len = source.len();
        Self {
            inner: source,
            pos: 0,
            len,
        }
    }
}

impl Read for DataSourceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self
            .inner
            .read_at(self.pos, buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        // read_at never advances the cursor; a short read at EOF is correct.
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for DataSourceReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(off) => off,
            SeekFrom::End(delta) => offset_from(self.len, delta)?,
            SeekFrom::Current(delta) => offset_from(self.pos, delta)?,
        };
        self.pos = new_pos;
        Ok(new_pos)
    }
}

/// Apply a signed `delta` to an unsigned `base`, failing loud on underflow
/// rather than wrapping (a negative seek before byte 0 is an error, per
/// `std::io::Seek`).
fn offset_from(base: u64, delta: i64) -> io::Result<u64> {
    let result = if delta >= 0 {
        base.checked_add(delta.unsigned_abs())
    } else {
        base.checked_sub(delta.unsigned_abs())
    };
    result.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::error::RtError;

    struct MemSource(Vec<u8>);

    impl DataSource for MemSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let offset = offset as usize;
            if offset >= self.0.len() {
                return Ok(0);
            }
            let available = self.0.len() - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&self.0[offset..offset + to_read]);
            Ok(to_read)
        }
    }

    fn reader(bytes: &[u8]) -> DataSourceReader {
        DataSourceReader::new(Box::new(MemSource(bytes.to_vec())))
    }

    #[test]
    fn sequential_read_advances_cursor() {
        let mut r = reader(&[1, 2, 3, 4, 5]);
        let mut b = [0u8; 2];
        assert_eq!(r.read(&mut b).unwrap(), 2);
        assert_eq!(b, [1, 2]);
        assert_eq!(r.read(&mut b).unwrap(), 2);
        assert_eq!(b, [3, 4]);
        assert_eq!(r.read(&mut b).unwrap(), 1);
        assert_eq!(b[0], 5);
        assert_eq!(r.read(&mut b).unwrap(), 0);
    }

    #[test]
    fn seek_start_current_end() {
        let mut r = reader(&[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(r.seek(SeekFrom::Start(4)).unwrap(), 4);
        let mut b = [0u8; 1];
        r.read(&mut b).unwrap();
        assert_eq!(b[0], 4);
        // cursor now 5
        assert_eq!(r.seek(SeekFrom::Current(-2)).unwrap(), 3);
        r.read(&mut b).unwrap();
        assert_eq!(b[0], 3);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 8);
        assert_eq!(r.read(&mut b).unwrap(), 0);
        assert_eq!(r.seek(SeekFrom::End(-1)).unwrap(), 7);
        r.read(&mut b).unwrap();
        assert_eq!(b[0], 7);
    }

    #[test]
    fn seek_before_zero_errors() {
        let mut r = reader(&[0, 1, 2]);
        assert!(r.seek(SeekFrom::Current(-1)).is_err());
        assert!(r.seek(SeekFrom::End(-100)).is_err());
    }
}
