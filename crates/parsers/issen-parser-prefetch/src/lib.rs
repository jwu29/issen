//! Windows Prefetch file parser for Issen.
//!
//! Parses `.pf` Prefetch files and emits [`TimelineEvent`]s via the
//! [`ForensicParser`] trait.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

pub mod parser;

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};

/// Windows Prefetch file parser.
pub struct PrefetchParser;

impl PrefetchParser {
    /// Return `true` when `path` has a `.pf` extension (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("pf"))
    }
}

impl ForensicParser for PrefetchParser {
    fn name(&self) -> &str {
        "Prefetch Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Prefetch]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory.
inventory::submit! {
    ParserRegistration { create: || Box::new(PrefetchParser) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use std::path::PathBuf;

    // ── Extension matching tests ───────────────────────────────────────────

    #[test]
    fn can_parse_returns_true_for_pf_extension() {
        let path = PathBuf::from("/mnt/evidence/C/Windows/Prefetch/NOTEPAD.EXE-ABCD1234.pf");
        assert!(
            PrefetchParser::can_parse(&path),
            "expected can_parse to return true for .pf"
        );
    }

    #[test]
    fn can_parse_returns_true_for_uppercase_pf() {
        let path = PathBuf::from("/mnt/evidence/NOTEPAD.EXE-ABCD1234.PF");
        assert!(
            PrefetchParser::can_parse(&path),
            "expected can_parse to return true for .PF (upper-case)"
        );
    }

    #[test]
    fn can_parse_returns_false_for_exe() {
        let path = PathBuf::from("/mnt/evidence/notepad.exe");
        assert!(
            !PrefetchParser::can_parse(&path),
            "expected can_parse to return false for .exe"
        );
    }

    #[test]
    fn can_parse_returns_false_for_no_extension() {
        let path = PathBuf::from("/mnt/evidence/NOTEPAD");
        assert!(
            !PrefetchParser::can_parse(&path),
            "expected can_parse to return false for file with no extension"
        );
    }

    // ── parse_prefetch tests ───────────────────────────────────────────────

    #[test]
    fn parse_empty_file_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not return Err on empty file");
        assert!(
            events.is_empty(),
            "expected empty vec for zero-byte file, got {} events",
            events.len()
        );
    }

    #[test]
    fn parse_bad_signature_returns_empty() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Write 84 bytes but with wrong signature ("JUNK" instead of "SCCA").
        let mut data = vec![0u8; 84];
        data[0..4].copy_from_slice(b"JUNK");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not Err on bad signature");
        assert!(
            events.is_empty(),
            "expected empty vec for bad signature, got {} events",
            events.len()
        );
    }

    /// A minimal valid Win10 (v30) SCCA payload: `[u32 version][b"SCCA"]`, the
    /// executable name at offset 16, one last-run FILETIME, and a run count.
    /// Empty filename/volume blocks (offsets 0) decode gracefully to nothing.
    fn minimal_scca(exe: &str, run_time: i64, run_count: u32) -> Vec<u8> {
        let mut p = vec![0u8; 84 + 224];
        p[0..4].copy_from_slice(&30u32.to_le_bytes());
        p[4..8].copy_from_slice(b"SCCA");
        for (i, c) in exe.encode_utf16().enumerate() {
            p[16 + i * 2..16 + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        let fi = 84;
        p[fi + 44..fi + 52].copy_from_slice(&run_time.to_le_bytes()); // run time[0]
        p[fi + 124..fi + 128].copy_from_slice(&run_count.to_le_bytes()); // old-format run count
        p
    }

    #[test]
    fn parse_real_layout_scca_emits_run_event() {
        // FILETIME 2020-09-19 (the Stolen Szechuan Sauce era).
        let data = minimal_scca("NOTEPAD.EXE", 132_449_604_494_103_203, 3);
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&data).expect("write");
        tmp.flush().expect("flush");

        let events = parser::parse_prefetch(tmp.path(), "test-source")
            .expect("parse_prefetch must not Err on a valid SCCA");

        assert_eq!(events.len(), 1, "one run time → one event");
        let ev = &events[0];
        assert_eq!(ev.source, ArtifactType::Prefetch);
        assert!(ev.description.contains("NOTEPAD.EXE"), "{}", ev.description);
        assert!(ev.timestamp_ns > 0, "run time must be decoded, not stubbed to 0");
        assert_eq!(
            ev.metadata
                .get("run_count")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            ev.metadata
                .get("executable")
                .and_then(serde_json::Value::as_str),
            Some("NOTEPAD.EXE")
        );
    }
}
