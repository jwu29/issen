//! Generic evidence-archive provider for the Issen forensic pipeline.
//!
//! Accepts plain `zip`, `7z`, and `tar.gz` evidence archives that no
//! format-specific provider claims. Probing is by leading magic bytes only
//! (never the extension) and returns [`Confidence::Medium`]: above the
//! last-resort raw-image [`Confidence::Low`], below the SPECIFIC UAC /
//! Velociraptor [`Confidence::High`] so a shaped collection still wins in the
//! registry.
//!
//! Extraction is SAFE by construction — see [`extract`]: every written path is
//! validated to stay inside the extraction directory and total uncompressed
//! size is bounded against a decompression bomb.

pub mod extract;

use std::io::Read;
use std::path::Path;

use issen_core::error::RtError;
use issen_unpack::{
    CollectionManifest, CollectionMetadata, CollectionProvider, Confidence, OsType,
};

/// Bytes read from the file head for magic detection. The POSIX `ustar` tag
/// sits at offset 257, so we need at least 263.
const HEADER_LEN: usize = 512;

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
            // A bare POSIX tar is extracted via the same gzip-or-plain tar path;
            // both report "TarGz" as the format family.
            ArchiveKind::TarGz | ArchiveKind::Tar => "TarGz",
        }
    }
}

/// Recognise the archive container from its leading magic bytes.
///
/// Reads only the header (up to [`HEADER_LEN`] bytes for the `ustar` check at
/// offset 257). Returns `None` for an unreadable file or unknown magic.
///
/// Magic per the respective specs:
/// - zip local-file `50 4B 03 04`, empty-archive end `50 4B 05 06`,
///   spanned `50 4B 07 08` (PKWARE APPNOTE)
/// - 7z `37 7A BC AF 27 1C` (7z format signature)
/// - gzip `1F 8B` (RFC 1952) — treated as a `tar.gz`
/// - POSIX `ustar` at byte 257 (POSIX.1-1988 tar)
pub fn detect_kind(path: &Path) -> Option<ArchiveKind> {
    let mut head = [0u8; HEADER_LEN];
    let read = read_head(path, &mut head)?;
    let head = &head[..read];

    if head.len() >= 4 {
        match head[..4] {
            [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] | [0x50, 0x4B, 0x07, 0x08] => {
                return Some(ArchiveKind::Zip)
            }
            _ => {}
        }
    }
    if head.len() >= 6 && head[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some(ArchiveKind::SevenZ);
    }
    if head.len() >= 2 && head[..2] == [0x1F, 0x8B] {
        return Some(ArchiveKind::TarGz);
    }
    // POSIX tar: "ustar" magic at offset 257 (GNU writes "ustar  \0", POSIX
    // "ustar\000"); match the common 5-byte prefix.
    if head.len() >= 262 && &head[257..262] == b"ustar" {
        return Some(ArchiveKind::Tar);
    }
    None
}

/// Read up to `buf.len()` leading bytes; `None` if the file can't be opened.
fn read_head(path: &Path, buf: &mut [u8]) -> Option<usize> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    Some(filled)
}

/// Generic evidence-archive provider (zip / 7z / tar.gz).
#[derive(Debug, Default)]
pub struct ArchiveProvider;

impl CollectionProvider for ArchiveProvider {
    fn name(&self) -> &'static str {
        "Archive"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        // Magic-only recognition (never the extension). Medium: above the
        // raw-image Low, below UAC/Velociraptor High so a shaped collection
        // still wins. Unreadable or unknown → None (skip cleanly).
        match detect_kind(path) {
            Some(_) => Ok(Confidence::Medium),
            None => Ok(Confidence::None),
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let kind = detect_kind(path).ok_or_else(|| {
            RtError::UnsupportedFormat(format!(
                "Archive: {} is not a recognised zip/7z/tar.gz archive",
                path.display()
            ))
        })?;

        let tempdir = issen_unpack::tempdir::create_extraction_dir()?;
        let report = match kind {
            ArchiveKind::Zip => extract::extract_zip(path, tempdir.path())?,
            ArchiveKind::SevenZ => extract::extract_7z(path, tempdir.path())?,
            ArchiveKind::TarGz | ArchiveKind::Tar => extract::extract_tar_gz(path, tempdir.path())?,
        };

        if !report.refused.is_empty() {
            // Fail-loud surfacing of refused traversal entries: extraction
            // continued (the dir is safe), but the investigator must know which
            // hostile entries were dropped.
            tracing_refused(&report.refused);
        }

        Ok(CollectionManifest::new(
            kind.format_name().into(),
            tempdir,
            // Empty: let the fswalker classify the extracted tree.
            Vec::new(),
            default_metadata(),
        ))
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

/// Record refused path-traversal entries so they are visible, not swallowed.
fn tracing_refused(refused: &[String]) {
    for name in refused {
        eprintln!("issen-archive: refused path-traversal entry (not extracted): {name}");
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(ArchiveProvider),
});

#[cfg(test)]
mod tests;
