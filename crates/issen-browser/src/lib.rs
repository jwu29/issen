#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
pub use browser_chrome::parse_history as parse_chrome_history;
/// Browser forensic integration layer for Issen.
///
/// Wraps browser-core, browser-chrome, and browser-firefox.
pub use browser_core::{detect_browser, ArtifactKind, BrowserEvent, BrowserFamily};
pub use browser_firefox::parse_history as parse_firefox_history;
pub use browser_safari::parse_history as parse_safari_history;

use anyhow::Result;
use std::path::Path;

/// Detect the browser family from `path` and dispatch to the appropriate
/// history parser. Returns an error if the browser cannot be detected or
/// the file cannot be parsed.
///
/// # Errors
///
/// Returns an error if the path cannot be identified as a known browser
/// artifact or if the underlying SQLite query fails.
pub fn parse_browser_history(path: &Path) -> Result<Vec<BrowserEvent>> {
    match detect_browser(path) {
        Some(BrowserFamily::Chromium) => parse_chrome_history(path),
        Some(BrowserFamily::Firefox) => parse_firefox_history(path),
        Some(BrowserFamily::Safari) => parse_safari_history(path),
        None => anyhow::bail!("cannot detect browser family from path: {}", path.display()),
    }
}

/// Issen browser-history parser: recognizes a browser artifact file, dispatches
/// it to the matching family parser, and converts each [`BrowserEvent`] into a
/// [`issen_core::timeline::event::TimelineEvent`] for the correlation timeline.
pub struct BrowserParser;

impl BrowserParser {
    /// `true` if `path` is a recognized browser history artifact.
    #[must_use]
    pub fn can_parse(&self, _path: &Path) -> bool {
        false // stub — implemented in GREEN
    }

    /// Parse a browser history file into timeline events. Returns `Err` if the
    /// browser family cannot be detected or the underlying SQLite read fails.
    pub fn parse_path(
        &self,
        _path: &Path,
    ) -> Result<Vec<issen_core::timeline::event::TimelineEvent>> {
        Ok(Vec::new()) // stub — implemented in GREEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_family_chromium_and_firefox_are_distinct() {
        assert_ne!(BrowserFamily::Chromium, BrowserFamily::Firefox);
    }

    #[test]
    fn detect_browser_chrome_history_path() {
        let p = Path::new("/home/user/.config/google-chrome/Default/History");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Chromium));
    }

    #[test]
    fn detect_browser_firefox_places_path() {
        let p = Path::new("/home/user/.mozilla/firefox/abc.default/places.sqlite");
        assert_eq!(detect_browser(p), Some(BrowserFamily::Firefox));
    }

    #[test]
    fn parse_browser_history_unknown_path_returns_error() {
        let result = parse_browser_history(Path::new("/tmp/unknown_artifact.db"));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("cannot detect browser family"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn parse_chrome_history_empty_db() {
        use rusqlite::Connection;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(f.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT DEFAULT '',
                visit_count INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL
            );",
        )
        .expect("create table");
        drop(conn);

        let events = parse_chrome_history(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_firefox_history_empty_db() {
        use rusqlite::Connection;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().expect("tempfile");
        let conn = Connection::open(f.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                title TEXT,
                visit_count INTEGER DEFAULT 0,
                last_visit_date INTEGER
            );",
        )
        .expect("create table");
        drop(conn);

        let events = parse_firefox_history(f.path()).expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn browser_parser_recognizes_history_files() {
        let p = BrowserParser;
        // Chromium history: path names the vendor, file is `History`.
        assert!(p.can_parse(Path::new(
            "/Users/u/AppData/Local/Google/Chrome/User Data/Default/History"
        )));
        // Firefox: `places.sqlite`.
        assert!(p.can_parse(Path::new(
            "/home/u/.mozilla/firefox/abc.default/places.sqlite"
        )));
        // Non-browser file is rejected.
        assert!(!p.can_parse(Path::new("/tmp/random.db")));
    }

    #[test]
    fn browser_parser_converts_chrome_history_to_timeline_events() {
        use issen_core::artifacts::ArtifactType;
        use issen_core::ActivityCategory;
        use rusqlite::{params, Connection};

        // A Chrome `History` DB under a path containing "Chrome" so
        // detect_browser identifies the Chromium family.
        let dir = tempfile::tempdir().expect("tempdir");
        let chrome_dir = dir.path().join("Chrome").join("User Data").join("Default");
        std::fs::create_dir_all(&chrome_dir).expect("mkdir");
        let db = chrome_dir.join("History");
        let conn = Connection::open(&db).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, \
             title TEXT DEFAULT '', visit_count INTEGER DEFAULT 0 NOT NULL, \
             last_visit_time INTEGER NOT NULL);",
        )
        .expect("schema");
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                "https://example.com/",
                "Example",
                3_i64,
                13_350_000_000_000_000_i64
            ],
        )
        .expect("insert");
        drop(conn);

        let events = BrowserParser.parse_path(&db).expect("parse");
        assert_eq!(events.len(), 1, "one visited URL -> one event");
        let e = &events[0];
        assert_eq!(e.source, ArtifactType::BrowserHistory);
        assert_eq!(e.activity_category, Some(ActivityCategory::BrowserActivity));
        assert!(
            e.description.contains("example.com"),
            "description carries the URL: {}",
            e.description
        );
        assert_eq!(
            e.metadata.get("url").and_then(serde_json::Value::as_str),
            Some("https://example.com/")
        );
        assert!(e.timestamp_ns > 0, "webkit timestamp converted to unix ns");
    }

    #[test]
    fn browser_parser_is_registered_in_inventory() {
        use issen_core::artifacts::ArtifactType;
        use issen_core::plugin::registry::ParserRegistration;
        let found = inventory::iter::<ParserRegistration>
            .into_iter()
            .any(|r| r.selector.artifact_type == ArtifactType::BrowserHistory);
        assert!(
            found,
            "BrowserParser must be registered for ArtifactType::BrowserHistory"
        );
    }
}
