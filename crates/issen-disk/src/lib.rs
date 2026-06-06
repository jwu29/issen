//! Disk-image orchestration: bridge a container [`DataSource`] (VMDK, EWF, raw
//! image, …) to the partition table and the NTFS filesystem inside it, then
//! extract the artifacts a triage pipeline needs.
//!
//! The pipeline is: container `DataSource` → [`DataSourceReader`] (`Read + Seek`)
//! → partition detection → NTFS filesystem → files by path.

use std::io::{Read, Seek, SeekFrom};

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// A `Read + Seek` view over a [`DataSource`].
///
/// `DataSource` exposes random access (`read_at(offset, buf)`); the forensic
/// partition and filesystem parsers want a positional `Read + Seek`. This
/// adapter tracks a cursor and forwards each read to `read_at`.
pub struct DataSourceReader<'a> {
    source: &'a dyn DataSource,
    pos: u64,
}

impl<'a> DataSourceReader<'a> {
    /// Create a reader positioned at the start of `source`.
    #[must_use]
    pub fn new(source: &'a dyn DataSource) -> Self {
        Self { source, pos: 0 }
    }
}

impl Read for DataSourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.source.read_at(self.pos, buf).map_err(rt_to_io)?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for DataSourceReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
        let target: i128 = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(d) => i128::from(self.pos) + i128::from(d),
            SeekFrom::End(d) => i128::from(self.source.len()) + i128::from(d),
        };
        if target < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of data source",
            ));
        }
        self.pos = u64::try_from(target).unwrap_or(u64::MAX);
        Ok(self.pos)
    }
}

/// Map an [`RtError`] into a `std::io::Error` for the `Read`/`Seek` contract.
fn rt_to_io(e: RtError) -> std::io::Error {
    match e {
        RtError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory [`DataSource`] over a byte vector.
    struct VecSource(Vec<u8>);

    impl DataSource for VecSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let start = offset as usize;
            if start >= self.0.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - start);
            buf[..n].copy_from_slice(&self.0[start..start + n]);
            Ok(n)
        }
    }

    #[test]
    fn reads_sequentially() {
        let src = VecSource((0u8..32).collect());
        let mut r = DataSourceReader::new(&src);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0, 1, 2, 3]);
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [4, 5, 6, 7]);
    }

    #[test]
    fn seek_from_start_and_current() {
        let src = VecSource((0u8..32).collect());
        let mut r = DataSourceReader::new(&src);
        r.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 2];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [10, 11]);
        r.seek(SeekFrom::Current(-1)).unwrap();
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [11, 12]);
    }

    #[test]
    fn seek_from_end_is_relative_to_len() {
        let src = VecSource((0u8..32).collect());
        let mut r = DataSourceReader::new(&src);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 32);
        assert_eq!(r.seek(SeekFrom::End(-4)).unwrap(), 28);
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [28, 29, 30, 31]);
    }

    #[test]
    fn rejects_seek_before_start() {
        let src = VecSource(vec![0u8; 8]);
        let mut r = DataSourceReader::new(&src);
        assert!(r.seek(SeekFrom::Current(-1)).is_err());
    }
}
