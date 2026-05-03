//! Firefox browser history parser.
//!
//! Reads the `moz_places` table from a Firefox `places.sqlite` database and
//! emits [`TimelineEvent`]s with [`EventType::NetworkConnect`].

use std::path::Path;

use anyhow::Result;
use rt_core::artifacts::ArtifactType;
use rt_core::timeline::event::{EventType, TimelineEvent};

/// Parse a Firefox `places.sqlite` file.
///
/// Queries the `moz_places` table and emits one [`TimelineEvent`] per row.
/// Rows where `last_visit_date` is NULL or zero are skipped.
///
/// # Errors
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_firefox_history(path: &Path) -> Result<Vec<TimelineEvent>> {
    todo!("implement parse_firefox_history")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{detect_browser, BrowserFamily};
    use rusqlite::Connection;
    use std::path::Path;
    use tempfile::NamedTempFile;

    /// Helper: create a Firefox places.sqlite with the `moz_places` schema.
    fn create_firefox_db(file: &NamedTempFile) -> Connection {
        let conn = Connection::open(file.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE moz_places (
                id              INTEGER PRIMARY KEY,
                url             TEXT NOT NULL,
                title           TEXT,
                visit_count     INTEGER DEFAULT 0,
                last_visit_date INTEGER
            );",
        )
        .expect("create schema");
        conn
    }

    #[test]
    fn firefox_can_parse_detects_places_sqlite() {
        let result = detect_browser(Path::new("/Users/user/Firefox/places.sqlite"));
        assert_eq!(result, Some(BrowserFamily::Firefox));
    }

    #[test]
    fn firefox_parse_empty_db_returns_empty() {
        let file = NamedTempFile::new().expect("tempfile");
        let _conn = create_firefox_db(&file);
        let events = parse_firefox_history(file.path()).expect("parse");
        assert!(events.is_empty(), "empty DB should yield no events");
    }

    #[test]
    fn firefox_parse_single_visit_emits_event() {
        let file = NamedTempFile::new().expect("tempfile");
        let conn = create_firefox_db(&file);
        // Firefox stores Unix µs; 1_683_152_400_000_000 µs ≈ 2023-05-04
        conn.execute(
            "INSERT INTO moz_places (url, title, visit_count, last_visit_date)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "https://mozilla.org",
                "Mozilla",
                5,
                1_683_152_400_000_000_i64,
            ],
        )
        .expect("insert");
        drop(conn);

        let events = parse_firefox_history(file.path()).expect("parse");
        assert_eq!(events.len(), 1, "expected one event");

        let ev = &events[0];
        assert_eq!(ev.event_type, EventType::NetworkConnect);
        assert!(
            ev.description.contains("https://mozilla.org"),
            "description must contain URL"
        );
        assert_eq!(ev.source, ArtifactType::BrowserHistory);
        // Unix ns = 1_683_152_400_000_000 * 1000
        assert_eq!(ev.timestamp_ns, 1_683_152_400_000_000_000_i64);
    }

    #[test]
    fn firefox_null_visit_date_skipped() {
        let file = NamedTempFile::new().expect("tempfile");
        let conn = create_firefox_db(&file);
        conn.execute(
            "INSERT INTO moz_places (url, title, visit_count, last_visit_date)
             VALUES (?1, ?2, ?3, NULL)",
            rusqlite::params!["https://example.org", "Example", 1],
        )
        .expect("insert");
        drop(conn);

        // Must not panic; NULL row must be skipped
        let events = parse_firefox_history(file.path()).expect("parse");
        assert!(events.is_empty(), "NULL last_visit_date row must be skipped");
    }
}
