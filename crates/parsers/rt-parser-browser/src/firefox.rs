//! Firefox browser history parser.
//!
//! Reads the `moz_places` table from a Firefox `places.sqlite` database and
//! emits [`TimelineEvent`]s with [`EventType::NetworkConnect`].

use std::path::Path;

use anyhow::Result;
use rt_core::artifacts::ArtifactType;
use rt_core::timeline::event::{EventType, TimelineEvent};
use rusqlite;

/// Parse a Firefox `places.sqlite` file.
///
/// Queries the `moz_places` table and emits one [`TimelineEvent`] per row.
/// Rows where `last_visit_date` is NULL or zero are skipped.
///
/// # Errors
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_firefox_history(path: &Path) -> Result<Vec<TimelineEvent>> {
    let conn = rusqlite::Connection::open(path)?;

    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date",
    )?;

    let path_str = path.display().to_string();

    let events: Vec<TimelineEvent> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let title: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            let visit_count: i64 = row.get::<_, Option<i64>>(2)?.unwrap_or(0);
            let last_visit_date: Option<i64> = row.get(3)?;
            Ok((url, title, visit_count, last_visit_date))
        })?
        .filter_map(std::result::Result::ok)
        .filter(|(_, _, _, last_visit_date)| last_visit_date.is_some_and(|v| v > 0))
        .map(|(url, title, visit_count, last_visit_date)| {
            // Firefox stores Unix microseconds
            let timestamp_ns = last_visit_date.unwrap_or(0) * 1_000;
            let description = format!("[{visit_count} visits] {title} — {url}");
            let mut ev = TimelineEvent::new(
                timestamp_ns,
                timestamp_ns.to_string(),
                EventType::NetworkConnect,
                ArtifactType::BrowserHistory,
                path_str.clone(),
                description,
                "rt-parser-browser".to_string(),
            );
            ev = ev
                .with_metadata("url", serde_json::json!(url))
                .with_metadata("title", serde_json::json!(title))
                .with_metadata("visit_count", serde_json::json!(visit_count))
                .with_metadata("browser", serde_json::json!("firefox"));
            ev
        })
        .collect();

    Ok(events)
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
