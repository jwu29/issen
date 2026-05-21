//! VHDX container reader for the Issen forensic pipeline.
//!
//! Wraps the [`vhdx`] crate to provide a [`DataSource`] implementation for the
//! Issen pipeline, enabling random-access reads over Microsoft VHDX virtual
//! disk images.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

// ── Error type ───────────────────────────────────────────────────────

/// Errors specific to VHDX image operations.
#[derive(Debug, thiserror::Error)]
pub enum VhdxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VHDX parse error: {0}")]
    Vhdx(String),
}

impl From<vhdx::VhdxError> for VhdxError {
    fn from(e: vhdx::VhdxError) -> Self {
        match e {
            vhdx::VhdxError::Io(io) => Self::Io(io),
            other => Self::Vhdx(other.to_string()),
        }
    }
}

impl From<VhdxError> for RtError {
    fn from(e: VhdxError) -> Self {
        match e {
            VhdxError::Io(io) => Self::Io(io),
            VhdxError::Vhdx(msg) => Self::Parse {
                offset: 0,
                message: format!("vhdx: {msg}"),
            },
        }
    }
}

// ── DataSource implementation ────────────────────────────────────────

/// A [`DataSource`] backed by a VHDX virtual disk image.
///
/// Opens the image at construction time (reads the full file into memory) and
/// wraps the [`vhdx::VhdxReader`] in a [`Mutex`]. Each `read_at` call locks,
/// seeks, and reads the requested bytes.
pub struct VhdxDataSource {
    reader: Mutex<vhdx::VhdxReader>,
    size: u64,
}

impl std::fmt::Debug for VhdxDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhdxDataSource")
            .field("size", &self.size)
            .finish()
    }
}

impl VhdxDataSource {
    /// Open a VHDX virtual disk image.
    ///
    /// Returns [`VhdxError`] if the file cannot be opened or is not a valid
    /// VHDX image. Differencing (parent-linked) disks are not supported.
    pub fn open(path: &Path) -> Result<Self, VhdxError> {
        todo!("implement VhdxDataSource::open")
    }
}

impl DataSource for VhdxDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        todo!("implement VhdxDataSource::read_at")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_nonexistent_path_returns_err() {
        let result = VhdxDataSource::open(Path::new("/tmp/nonexistent_image_99999.vhdx"));
        assert!(result.is_err(), "opening a nonexistent path must fail");
    }

    #[test]
    fn open_non_vhdx_file_returns_err() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tmpfile");
        f.write_all(b"this is not a vhdx file").expect("write");
        let result = VhdxDataSource::open(f.path());
        assert!(result.is_err(), "opening a non-VHDX file must fail");
    }

    #[test]
    fn vhdx_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VhdxDataSource>();
    }

    #[test]
    fn vhdx_error_io_displays_message() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = VhdxError::Io(io_err);
        let display = format!("{err}");
        assert!(display.contains("file not found"));
    }

    #[test]
    fn vhdx_error_parse_displays_message() {
        let err = VhdxError::Vhdx("bad magic".to_string());
        let display = format!("{err}");
        assert!(display.contains("bad magic"));
    }

    #[test]
    fn from_vhdx_error_io_converts_to_issen_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let vhdx_err = VhdxError::Io(io_err);
        let rt_err: RtError = vhdx_err.into();
        assert!(matches!(rt_err, RtError::Io(_)));
    }

    #[test]
    fn from_vhdx_error_parse_converts_to_rt_parse_error() {
        let vhdx_err = VhdxError::Vhdx("corrupt region table".to_string());
        let rt_err: RtError = vhdx_err.into();
        assert!(
            matches!(rt_err, RtError::Parse { ref message, .. } if message.contains("vhdx"))
        );
    }
}
