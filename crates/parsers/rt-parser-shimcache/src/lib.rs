//! AppCompatCache (Shimcache) parser for RapidTriage.
//!
//! The Shimcache resides in the `SYSTEM` registry hive under:
//! `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
//! value `AppCompatCache`.
//!
//! Presence of a path in Shimcache proves the binary existed on disk; it does
//! NOT prove execution (use Prefetch or AmCache for that).

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use std::path::Path;

use rt_core::artifacts::ArtifactType;
use rt_core::plugin::registry::ParserRegistration;
use rt_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};
use rt_core::timeline::event::TimelineEvent;

/// Parse paths out of a raw shimcache binary blob.
///
/// Returns a (possibly empty) list of executable path strings.
/// Never fails — unknown or malformed data returns an empty vec.
pub fn parse_shimcache_blob(data: &[u8]) -> Vec<String> {
    // Stub — GREEN implementation goes here.
    let _ = data;
    vec![]
}

/// Parse a SYSTEM hive file for AppCompatCache (Shimcache) entries.
///
/// On any error or missing key, returns `Ok(vec![])`.
pub fn parse_shimcache(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // Stub — GREEN implementation goes here.
    let _ = (path, source_id);
    Ok(vec![])
}

/// AppCompatCache (Shimcache) parser — reads from the SYSTEM hive.
pub struct ShimcacheParser;

impl ShimcacheParser {
    /// Return `true` when `path`'s filename is `SYSTEM` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "system"
    }
}

impl ForensicParser for ShimcacheParser {
    fn name(&self) -> &str {
        "Shimcache Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Registry]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, rt_core::error::RtError> {
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024), // 256 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(ShimcacheParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── can_parse tests ────────────────────────────────────────────────────

    #[test]
    fn can_parse_system_hive() {
        assert!(
            ShimcacheParser::can_parse(&PathBuf::from(
                "/evidence/C/Windows/System32/config/SYSTEM"
            )),
            "expected can_parse to return true for SYSTEM"
        );
    }

    #[test]
    fn can_parse_system_hive_lowercase() {
        assert!(
            ShimcacheParser::can_parse(&PathBuf::from("/evidence/system")),
            "expected can_parse to return true for lowercase 'system'"
        );
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(
            !ShimcacheParser::can_parse(&PathBuf::from("/evidence/SOFTWARE")),
            "expected can_parse to return false for SOFTWARE"
        );
    }

    #[test]
    fn cannot_parse_amcache() {
        assert!(
            !ShimcacheParser::can_parse(&PathBuf::from("/evidence/Amcache.hve")),
            "expected can_parse to return false for Amcache.hve"
        );
    }

    // ── parse tests ────────────────────────────────────────────────────────

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_shimcache(Path::new("/nonexistent/SYSTEM"), "test");
        assert!(
            result.is_ok(),
            "parse_shimcache must return Ok for a nonexistent path, got: {result:?}"
        );
        assert!(
            result.unwrap().is_empty(),
            "nonexistent path should produce zero events"
        );
    }

    /// This test verifies that the parser returns `Ok(vec![])` when the SYSTEM
    /// hive does not contain an AppCompatCache key (e.g. a zero-byte file).
    /// The stub already returns empty so this test PASSES in RED state.
    /// It remains as a regression guard after GREEN.
    #[test]
    fn parse_system_hive_without_appcompat_key_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Empty file — no valid hive, no AppCompatCache key.
        let result = parse_shimcache(tmp.path(), "test");
        assert!(
            result.is_ok(),
            "parse_shimcache must return Ok for an empty/invalid hive"
        );
        assert!(
            result.unwrap().is_empty(),
            "empty hive must produce zero events"
        );
    }

    // ── parse_shimcache_blob tests ─────────────────────────────────────────

    #[test]
    fn blob_empty_returns_empty() {
        assert!(parse_shimcache_blob(&[]).is_empty());
    }

    #[test]
    fn blob_garbage_returns_empty() {
        // Random bytes with no known signature must not panic and return empty.
        assert!(parse_shimcache_blob(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]).is_empty());
    }

    /// RED test: a minimal Win8+ shimcache blob should produce at least one path.
    /// The stub returns empty, so this FAILS until GREEN.
    #[test]
    fn blob_win8_signature_yields_paths() {
        // Win8+ magic: [0x30, 0x00, 0x00, 0x00]
        // Followed by 4-byte entry count, then entries.
        // Each entry: magic "10ts" (0x74733031), u16 data_len, u16 path_len, UTF-16LE path.
        // Construct a minimal blob with one entry: path = "C:\foo.exe"
        let path_utf16: Vec<u8> = "C:\\foo.exe"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let path_len = path_utf16.len() as u16;

        let mut blob = Vec::new();
        // Header: Win8+ signature
        blob.extend_from_slice(&[0x30, 0x00, 0x00, 0x00]);
        // Entry count (1)
        blob.extend_from_slice(&1u32.to_le_bytes());
        // Entry magic "10ts"
        blob.extend_from_slice(b"10ts");
        // data_len (arbitrary, e.g. 9 extra bytes after the path)
        blob.extend_from_slice(&(path_len + 9).to_le_bytes());
        // path_len
        blob.extend_from_slice(&path_len.to_le_bytes());
        // path bytes (UTF-16LE)
        blob.extend_from_slice(&path_utf16);
        // last-modified FILETIME (8 bytes)
        blob.extend_from_slice(&0u64.to_le_bytes());
        // flags (1 byte padding)
        blob.push(0);

        let paths = parse_shimcache_blob(&blob);

        // Stub returns empty — RED.
        assert!(
            !paths.is_empty(),
            "Win8+ shimcache blob must yield at least one path"
        );
        assert!(
            paths.iter().any(|p| p.contains("foo.exe")),
            "expected 'foo.exe' in extracted paths, got: {paths:?}"
        );
    }
}
