//! AmCache.hve parser for RapidTriage.
//!
//! Parses `Amcache.hve` registry hive files and emits [`TimelineEvent`]s
//! with `EventType::ProcessExec` for every recorded executable entry.

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

/// Parse an Amcache.hve file, returning a list of `TimelineEvent`s.
///
/// On any parse error or empty/corrupt hive, returns `Ok(vec![])`.
pub fn parse_amcache(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // Stub — GREEN implementation goes here.
    let _ = (path, source_id);
    Ok(vec![])
}

/// AmCache.hve forensic parser.
pub struct AmcacheParser;

impl AmcacheParser {
    /// Return `true` when `path`'s filename is `amcache.hve` (case-insensitive).
    pub fn can_parse(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        name == "amcache.hve"
    }
}

impl ForensicParser for AmcacheParser {
    fn name(&self) -> &str {
        "AmCache Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::Amcache]
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
    ParserRegistration { create: || Box::new(AmcacheParser) }
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
    fn can_parse_amcache_hve() {
        assert!(
            AmcacheParser::can_parse(&PathBuf::from("/evidence/Amcache.hve")),
            "expected can_parse to return true for Amcache.hve"
        );
    }

    #[test]
    fn can_parse_case_insensitive() {
        assert!(
            AmcacheParser::can_parse(&PathBuf::from("/evidence/AMCACHE.HVE")),
            "expected can_parse to return true for AMCACHE.HVE"
        );
    }

    #[test]
    fn cannot_parse_other_hive() {
        assert!(
            !AmcacheParser::can_parse(&PathBuf::from("/evidence/SYSTEM")),
            "expected can_parse to return false for SYSTEM"
        );
    }

    // ── parse tests ────────────────────────────────────────────────────────

    #[test]
    fn parse_empty_path_returns_empty() {
        // A nonexistent path must not panic — return Ok(vec![]).
        let result = parse_amcache(Path::new("/nonexistent/Amcache.hve"), "test");
        assert!(
            result.is_ok(),
            "parse_amcache must return Ok for a nonexistent path, got: {result:?}"
        );
        assert!(
            result.unwrap().is_empty(),
            "nonexistent path should produce zero events"
        );
    }

    /// This test verifies that the parser emits `EventType::ProcessExec` events
    /// for entries inside a real AmCache hive. The stub returns `Ok(vec![])`,
    /// so this test is RED until the GREEN implementation is in place.
    #[test]
    fn parse_real_amcache_emits_execution_events() {
        use rt_core::timeline::event::EventType;

        // Write a minimal valid-looking file so the parser opens it.
        // The stub always returns empty, so this will fail (RED).
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Write at least one byte so the parser doesn't short-circuit on size.
        std::fs::write(tmp.path(), b"REGF").expect("write");

        let events = parse_amcache(tmp.path(), "test").expect("parse must not Err");

        // The stub returns vec![], so this assertion fails — that's the RED state.
        assert!(
            !events.is_empty(),
            "parse_amcache must emit at least one ProcessExec event for a non-empty hive"
        );

        // Every event must carry the correct event type.
        for event in &events {
            assert_eq!(
                event.event_type,
                EventType::ProcessExec,
                "all amcache events must be ProcessExec, got {:?}",
                event.event_type
            );
        }
    }
}
