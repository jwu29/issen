//! Safe extraction of generic evidence archives (zip / 7z / tar.gz).
//!
//! The binding security requirement: for EVERY entry of EVERY format the
//! written path MUST stay within the extraction directory. Untrusted evidence
//! archives can carry path-traversal ("zip-slip") entries — `../../../etc/x`,
//! absolute `/etc/x`, or `C:\Windows\x` — and decompression bombs that expand
//! far beyond their on-disk size. This module refuses traversal entries
//! (fail-loud, skip + record the offending name) and bounds total uncompressed
//! bytes so a malicious archive cannot escape the dir or exhaust memory.

use std::path::{Component, Path, PathBuf};

use issen_core::error::RtError;

/// Upper bound on total uncompressed bytes extracted from a single archive.
///
/// Caps a decompression bomb: a tiny archive that expands past this errors out
/// instead of filling the disk / RAM. Generous enough for real triage
/// collections (4 GiB) while still bounding a hostile tiny input.
pub const MAX_TOTAL_UNCOMPRESSED: u64 = 4 * 1024 * 1024 * 1024;

/// Outcome of extracting one archive: how many entries were written and the
/// names of any traversal entries that were REFUSED (never written).
#[derive(Debug, Default)]
pub struct ExtractReport {
    pub written: usize,
    pub refused: Vec<String>,
}

/// Resolve `dest.join(rel)` and confirm it stays inside `dest`.
///
/// Returns the safe absolute path, or `None` if the entry would escape via a
/// `..` component or an absolute path. Pure lexical check (no symlink follow):
/// it rejects any `ParentDir`/`RootDir`/`Prefix` component, so a `..` or
/// `C:\`-rooted name can never produce a path outside `dest`.
pub fn safe_join(dest: &Path, rel: &Path) -> Option<PathBuf> {
    let _ = (dest, rel);
    unimplemented!("RED")
}

/// Safe-extract a zip archive into `dest` (uses [`MAX_TOTAL_UNCOMPRESSED`]).
pub fn extract_zip(archive_path: &Path, dest: &Path) -> Result<ExtractReport, RtError> {
    extract_zip_capped(archive_path, dest, MAX_TOTAL_UNCOMPRESSED)
}

/// Safe-extract a zip archive into `dest`, bounding total uncompressed bytes by
/// `cap`. The cap is a parameter so the bomb test can trigger the bound without
/// minting a multi-GiB archive.
pub fn extract_zip_capped(
    _archive_path: &Path,
    _dest: &Path,
    _cap: u64,
) -> Result<ExtractReport, RtError> {
    unimplemented!("RED")
}

/// Safe-extract a gzip-compressed tar (`.tar.gz`) into `dest`.
pub fn extract_tar_gz(_archive_path: &Path, _dest: &Path) -> Result<ExtractReport, RtError> {
    unimplemented!("RED")
}

/// Safe-extract a 7z archive into `dest`.
pub fn extract_7z(_archive_path: &Path, _dest: &Path) -> Result<ExtractReport, RtError> {
    unimplemented!("RED")
}

#[allow(dead_code)]
fn unused_components(_c: Component<'_>) {}
