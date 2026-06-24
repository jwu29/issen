//! Generic evidence-archive provider for the Issen forensic pipeline.
//!
//! Accepts plain `zip`, `7z`, and `tar.gz` evidence archives that no
//! format-specific provider claims. Probing is by leading magic bytes only
//! (never the extension) and returns [`Confidence::Medium`]: above the
//! last-resort raw-image [`Confidence::Low`], below the SPECIFIC UAC /
//! Velociraptor [`Confidence::High`] so a shaped collection still wins.
//!
//! Extraction is SAFE by construction — see [`extract`]: every written path is
//! validated to stay inside the extraction directory and total uncompressed
//! size is bounded.

pub mod extract;

use std::io::Read;
use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::{
    CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType,
};

/// Archive container shape recognised from the leading magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Zip,
    SevenZ,
    TarGz,
    Tar,
}

impl ArchiveKind {
    /// Human-readable format name used as the manifest `format_name`.
    pub fn format_name(self) -> &'static str {
        match self {
            ArchiveKind::Zip => "Zip",
            ArchiveKind::SevenZ => "7z",
            ArchiveKind::TarGz | ArchiveKind::Tar => "TarGz",
        }
    }
}

/// Recognise the archive container from its leading magic bytes.
///
/// Reads only the header (`>= 512` bytes for the POSIX `ustar` check at offset
/// 257). Returns `None` for an unreadable file or unknown magic.
pub fn detect_kind(_path: &Path) -> Option<ArchiveKind> {
    None
}

/// Generic evidence-archive provider (zip / 7z / tar.gz).
#[derive(Debug, Default)]
pub struct ArchiveProvider;

impl CollectionProvider for ArchiveProvider {
    fn name(&self) -> &'static str {
        "Archive"
    }

    fn probe(&self, _path: &Path) -> Result<Confidence, RtError> {
        Ok(Confidence::None)
    }

    fn open(&self, _path: &Path) -> Result<CollectionManifest, RtError> {
        Err(RtError::UnsupportedFormat("RED".into()))
    }
}

/// Best-effort default metadata for a generic archive (nothing to mine).
fn default_metadata() -> CollectionMetadata {
    CollectionMetadata {
        hostname: None,
        collection_time: None,
        os_type: OsType::Unknown,
        tool_version: None,
    }
}

#[allow(dead_code)]
fn unused_read(_r: &mut dyn Read) {}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(ArchiveProvider),
});

#[cfg(test)]
mod tests;
