//! QCOW2 disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`qcow2`] crate to provide a [`DataSource`] implementation for
//! QCOW2 v2/v3 images (QEMU/KVM / libvirt).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to QCOW2 image operations.
#[derive(Debug, thiserror::Error)]
pub enum Qcow2Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("QCOW2 parse error: {0}")]
    Qcow2(String),
}

impl From<qcow2::Qcow2Error> for Qcow2Error {
    fn from(e: qcow2::Qcow2Error) -> Self {
        match e {
            qcow2::Qcow2Error::Io(io) => Self::Io(io),
            other => Self::Qcow2(other.to_string()),
        }
    }
}

impl From<Qcow2Error> for RtError {
    fn from(e: Qcow2Error) -> Self {
        match e {
            Qcow2Error::Io(io) => Self::Io(io),
            Qcow2Error::Qcow2(msg) => Self::Parse { offset: 0, message: format!("qcow2: {msg}") },
        }
    }
}

/// A [`DataSource`] backed by a QCOW2 disk image.
pub struct Qcow2DataSource {
    reader: Mutex<qcow2::Qcow2Reader>,
    size: u64,
}

impl std::fmt::Debug for Qcow2DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Qcow2DataSource").field("size", &self.size).finish()
    }
}

impl Qcow2DataSource {
    /// Open a QCOW2 disk image (v2 or v3, no encryption, no backing file).
    pub fn open(path: &Path) -> Result<Self, Qcow2Error> {
        let reader = qcow2::Qcow2Reader::open(path)?;
        let size = reader.virtual_disk_size();
        Ok(Self { reader: Mutex::new(reader), size })
    }
}

impl DataSource for Qcow2DataSource {
    fn len(&self) -> u64 { self.size }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match guard.read(&mut buf[total..]).map_err(RtError::Io)? {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(Qcow2DataSource::open(Path::new("/tmp/nope.qcow2")).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let img = qcow2::testutil::test_qcow2(&vec![0u8; 512]);
        let f = write_tmp(&img);
        let src = Qcow2DataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), qcow2::testutil::CLUSTER_SIZE as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = qcow2::testutil::test_qcow2(&data);
        let f = write_tmp(&img);
        let src = Qcow2DataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn qcow2_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Qcow2DataSource>();
    }

    #[test]
    fn qcow2_error_converts_to_rt_error() {
        let e = Qcow2Error::Qcow2("bad magic".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }
}
