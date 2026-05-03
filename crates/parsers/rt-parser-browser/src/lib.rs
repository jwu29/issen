//! Browser history parsers for RapidTriage.
//!
//! Supports Chromium-family browsers (Chrome, Edge, Brave, Opera) via the
//! `History` SQLite database, and Mozilla Firefox via `places.sqlite`.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unnecessary_literal_bound
)]

pub mod chrome;
pub mod detector;
pub mod firefox;

use std::path::Path;

use detector::{detect_browser, BrowserFamily};
use rt_core::artifacts::ArtifactType;
use rt_core::error::RtError;
use rt_core::plugin::registry::ParserRegistration;
use rt_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseStats, ParserCapabilities,
};

// ── BrowserParser ─────────────────────────────────────────────────────────────

/// Unified parser for Chromium and Firefox browser history databases.
pub struct BrowserParser;

impl BrowserParser {
    /// Return `true` when `path` is a recognised browser history file.
    pub fn can_parse(path: &Path) -> bool {
        detect_browser(path).is_some()
    }
}

impl ForensicParser for BrowserParser {
    fn name(&self) -> &str {
        "BrowserParser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::BrowserHistory]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        // The DataSource/EventEmitter trait does not carry a file path, so we
        // rely on the path-based `parse_by_path` helper for SQLite access.
        // Pipeline callers should use `parse_by_path` directly.
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(256 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(BrowserParser) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rt_core::plugin::registry::all_parsers;
    use std::path::Path;

    #[test]
    fn browser_parser_registered_in_inventory() {
        let parsers = all_parsers();
        let found = parsers.iter().any(|p| p.name() == "BrowserParser");
        assert!(found, "BrowserParser must be registered in the inventory");
    }

    #[test]
    fn browser_parser_can_parse_chrome_history() {
        assert!(
            BrowserParser::can_parse(Path::new("/Users/user/Chrome/Default/History")),
            "Chrome History must be recognised"
        );
    }

    #[test]
    fn browser_parser_can_parse_firefox() {
        assert!(
            BrowserParser::can_parse(Path::new("/Users/user/Firefox/places.sqlite")),
            "Firefox places.sqlite must be recognised"
        );
    }

    #[test]
    fn browser_parser_rejects_random_file() {
        assert!(
            !BrowserParser::can_parse(Path::new("/tmp/foo.txt")),
            "Random files must not be recognised"
        );
    }
}
