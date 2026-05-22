//! Legacy VHD disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`vhd`] crate to provide a [`DataSource`] implementation for
//! Fixed and Dynamic VHD images (Microsoft Virtual PC / Hyper-V Gen-1).

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to VHD image operations.
#[derive(Debug, thiserror::Error)]
pub enum VhdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VHD parse error: {0}")]
    Vhd(String),
}

impl From<vhd::VhdError> for VhdError {
    fn from(e: vhd::VhdError) -> Self {
        match e {
            vhd::VhdError::Io(io) => Self::Io(io),
            other => Self::Vhd(other.to_string()),
        }
    }
}

impl From<VhdError> for RtError {
    fn from(e: VhdError) -> Self {
        match e {
            VhdError::Io(io) => Self::Io(io),
            VhdError::Vhd(msg) => Self::Parse { offset: 0, message: format!("vhd: {msg}") },
        }
    }
}

/// A [`DataSource`] backed by a legacy VHD disk image.
pub struct VhdDataSource {
    reader: Mutex<vhd::VhdReader>,
    size: u64,
}

impl std::fmt::Debug for VhdDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdDataSource").field("size", &self.size).finish()
    }
}

impl VhdDataSource {
    /// Open a VHD disk image (Fixed or Dynamic).
    pub fn open(path: &Path) -> Result<Self, VhdError> {
        todo!("implement VhdDataSource::open")
    }
}

impl DataSource for VhdDataSource {
    fn len(&self) -> u64 { self.size }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        todo!("implement VhdDataSource::read_at")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixed_vhd(sector_data: &[u8]) -> Vec<u8> {
        let mut v = sector_data.to_vec();
        v.extend_from_slice(&vhd::footer::test_fixed_footer(sector_data.len() as u64));
        v
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VhdDataSource::open(Path::new("/tmp/nope.vhd")).is_err());
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let vhd = fixed_vhd(&vec![0u8; 512]);
        let f = write_tmp(&vhd);
        let src = VhdDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), 512);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut sector = vec![0u8; 512];
        sector[10] = 0xCA;
        sector[11] = 0xFE;
        let vhd = fixed_vhd(&sector);
        let f = write_tmp(&vhd);
        let src = VhdDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn vhd_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VhdDataSource>();
    }

    #[test]
    fn vhd_error_converts_to_rt_error() {
        let e = VhdError::Vhd("bad cookie".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }
}
