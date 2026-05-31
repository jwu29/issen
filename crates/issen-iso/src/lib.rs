//! ISO 9660 optical disc image reader for the Issen forensic pipeline.
//!
//! Uses [`hadris_iso`] for format validation and exposes the raw sector
//! stream as a [`DataSource`] for downstream forensic parsers.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// Errors specific to ISO image operations.
#[derive(Debug, thiserror::Error)]
pub enum IsoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a valid ISO 9660 image: {0}")]
    InvalidIso(String),
}

impl From<IsoError> for RtError {
    fn from(e: IsoError) -> Self {
        match e {
            IsoError::Io(io) => Self::Io(io),
            IsoError::InvalidIso(msg) => Self::Parse { offset: 0, message: format!("iso: {msg}") },
        }
    }
}

/// A [`DataSource`] backed by an ISO 9660 optical disc image.
pub struct IsoDataSource {
    reader: Mutex<File>,
    size: u64,
}

impl std::fmt::Debug for IsoDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsoDataSource").field("size", &self.size).finish()
    }
}

impl IsoDataSource {
    /// Open an ISO 9660 image, validating the format with `hadris-iso`.
    ///
    /// Opens the file twice: once for `hadris_iso` validation, once to keep
    /// as a raw sector stream for [`DataSource::read_at`].
    pub fn open(path: &Path) -> Result<Self, IsoError> {
        // Validate: pass a File to hadris-iso; it consumes it.
        let validate_file = File::open(path)?;
        hadris_iso::sync::read::IsoImage::open(validate_file)
            .map_err(|e| IsoError::InvalidIso(e.to_string()))?;

        // Raw read handle for DataSource I/O.
        let raw = File::open(path)?;
        let size = raw.metadata()?.len();
        Ok(Self { reader: Mutex::new(raw), size })
    }
}

impl DataSource for IsoDataSource {
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

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType};

/// Format-recognition and manifest provider for ISO 9660 disc images.
#[derive(Debug, Default)]
pub struct IsoProvider;

impl CollectionProvider for IsoProvider {
    fn name(&self) -> &str {
        "ISO"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::{Read, Seek, SeekFrom};
        // ISO 9660 Primary Volume Descriptor starts at sector 16 (byte 0x8000).
        // Byte 1 of the PVD is the standard identifier "CD001" (5 bytes at 0x8001).
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        if f.seek(SeekFrom::Start(0x8001)).map_err(RtError::Io)? < 0x8001 {
            return Ok(Confidence::None);
        }
        let mut id = [0u8; 5];
        match f.read_exact(&mut id) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(Confidence::None)
            }
            Err(e) => return Err(RtError::Io(e)),
        }
        if &id == b"CD001" {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let source = IsoDataSource::open(path)?;
        let size = source.len();
        let tempdir = tempfile::tempdir().map_err(RtError::Io)?;
        Ok(CollectionManifest::new(
            self.name().to_string(),
            tempdir,
            vec![],
            CollectionMetadata {
                hostname: None,
                collection_time: None,
                os_type: OsType::Unknown,
                tool_version: Some(format!("{size} bytes")),
            },
        ))
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(IsoProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SECTOR: usize = 2048;

    /// Minimal ISO 9660 image: system area + PVD + terminator + one data sector.
    fn make_iso(sector18_data: &[u8]) -> Vec<u8> {
        let mut iso = vec![0u8; 19 * SECTOR];
        let pvd = 16 * SECTOR;
        iso[pvd] = 1;
        iso[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        iso[pvd + 6] = 1;
        let vdt = 17 * SECTOR;
        iso[vdt] = 0xFF;
        iso[vdt + 1..vdt + 6].copy_from_slice(b"CD001");
        iso[vdt + 6] = 1;
        let n = sector18_data.len().min(SECTOR);
        iso[18 * SECTOR..18 * SECTOR + n].copy_from_slice(&sector18_data[..n]);
        iso
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(IsoDataSource::open(Path::new("/tmp/nope.iso")).is_err());
    }

    #[test]
    fn open_non_iso_file_returns_err() {
        let f = write_tmp(&vec![0u8; 40_000]);
        assert!(IsoDataSource::open(f.path()).is_err());
    }

    #[test]
    fn len_matches_file_size() {
        let img = make_iso(&[0u8; 512]);
        let f = write_tmp(&img);
        let src = IsoDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), img.len() as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; SECTOR];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let img = make_iso(&data);
        let f = write_tmp(&img);
        let src = IsoDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at((18 * SECTOR + 10) as u64, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn iso_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<IsoDataSource>();
    }

    #[test]
    fn iso_error_converts_to_rt_error() {
        let e = IsoError::InvalidIso("bad signature".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── IsoProvider tests ─────────────────────────────────────────────

    #[test]
    fn iso_provider_name() {
        assert_eq!(IsoProvider.name(), "ISO");
    }

    #[test]
    fn iso_provider_probe_valid_iso_returns_high() {
        let img = make_iso(&[0u8; SECTOR]);
        let f = write_tmp(&img);
        // RED: stub returns None — FAILS
        assert_eq!(
            IsoProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn iso_provider_probe_wrong_bytes_returns_none() {
        let f = write_tmp(&vec![0u8; 40_000]);
        assert_eq!(
            IsoProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn iso_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(IsoProvider
            .probe(Path::new("/tmp/nonexistent_99999.iso"))
            .is_err());
    }

    #[test]
    fn iso_provider_open_invalid_returns_err() {
        let f = write_tmp(&vec![0u8; 40_000]);
        assert!(IsoProvider.open(f.path()).is_err());
    }

    #[test]
    fn iso_provider_open_nonexistent_returns_err() {
        assert!(IsoProvider
            .open(Path::new("/tmp/nonexistent_99999.iso"))
            .is_err());
    }

    #[test]
    fn iso_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"ISO".to_string()),
            "IsoProvider must be in inventory; got: {names:?}"
        );
    }
}
