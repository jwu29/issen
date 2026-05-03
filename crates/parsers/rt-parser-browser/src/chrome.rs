//! Chromium-family browser history parser.
//!
//! Reads the `urls` table from a Chromium `History` SQLite database and emits
//! [`TimelineEvent`]s with [`EventType::NetworkConnect`].

use std::path::Path;

use anyhow::Result;
use rt_core::artifacts::ArtifactType;
use rt_core::timeline::event::{EventType, TimelineEvent};
use rusqlite;

/// Microseconds from 1601-01-01 to 1970-01-01 (WebKit epoch offset).
const WEBKIT_EPOCH_OFFSET_US: i64 = 11_644_473_600_000_000;

/// Convert a WebKit timestamp (µs since 1601-01-01) to Unix nanoseconds.
#[must_use]
pub fn webkit_to_unix_ns(webkit_time: i64) -> i64 {
    let unix_us = webkit_time - WEBKIT_EPOCH_OFFSET_US;
    unix_us * 1_000
}

/// Parse a Chromium `History` SQLite file.
///
/// Queries the `urls` table and emits one [`TimelineEvent`] per row.
/// Rows with a zero or negative `last_visit_time` are skipped.
///
/// # Errors
/// Returns an error if the SQLite file cannot be opened or queried.
pub fn parse_chrome_history(path: &Path) -> Result<Vec<TimelineEvent>> {
    let conn = rusqlite::Connection::open(path)?;

    let mut stmt = conn.prepare(
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time",
    )?;

    let path_str = path.display().to_string();

    let events: Vec<TimelineEvent> = stmt
        .query_map([], |row| {
            let url: String = row.get(0)?;
            let title: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            let visit_count: i64 = row.get(2)?;
            let last_visit_time: i64 = row.get(3)?;
            Ok((url, title, visit_count, last_visit_time))
        })?
        .filter_map(std::result::Result::ok)
        .filter(|(_, _, _, last_visit_time)| *last_visit_time > 0)
        .map(|(url, title, visit_count, last_visit_time)| {
            let timestamp_ns = webkit_to_unix_ns(last_visit_time);
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
                .with_metadata("browser", serde_json::json!("chromium"));
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

    /// Helper: create a Chromium History SQLite with the `urls` schema.
    fn create_chrome_db(file: &NamedTempFile) -> Connection {
        let conn = Connection::open(file.path()).expect("open");
        conn.execute_batch(
            "CREATE TABLE urls (
                id              INTEGER PRIMARY KEY,
                url             TEXT NOT NULL,
                title           TEXT DEFAULT '',
                visit_count     INTEGER DEFAULT 0 NOT NULL,
                last_visit_time INTEGER NOT NULL
            );",
        )
        .expect("create schema");
        conn
    }

    #[test]
    fn chrome_can_parse_detects_history_file() {
        let result = detect_browser(Path::new("/Users/user/Chrome/Default/History"));
        assert_eq!(result, Some(BrowserFamily::Chromium));
    }

    #[test]
    fn chrome_can_parse_rejects_places_sqlite() {
        let result = detect_browser(Path::new("/Users/user/Firefox/places.sqlite"));
        // Must be Firefox, not Chromium
        assert_eq!(result, Some(BrowserFamily::Firefox));
    }

    #[test]
    fn chrome_parse_empty_db_returns_empty() {
        let file = NamedTempFile::new().expect("tempfile");
        let _conn = create_chrome_db(&file);
        let events = parse_chrome_history(file.path()).expect("parse");
        assert!(events.is_empty(), "empty DB should yield no events");
    }

    #[test]
    fn chrome_parse_single_visit_emits_event() {
        let file = NamedTempFile::new().expect("tempfile");
        let conn = create_chrome_db(&file);
        // webkit time: 13_327_626_000_000_000 µs → approx 2022-03-01
        conn.execute(
            "INSERT INTO urls (url, title, visit_count, last_visit_time)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "https://example.com",
                "Example Domain",
                3,
                13_327_626_000_000_000_i64,
            ],
        )
        .expect("insert");
        drop(conn);

        let events = parse_chrome_history(file.path()).expect("parse");
        assert_eq!(events.len(), 1, "expected one event");

        let ev = &events[0];
        assert_eq!(ev.event_type, EventType::NetworkConnect);
        assert!(
            ev.description.contains("https://example.com"),
            "description must contain URL"
        );
        assert_eq!(ev.source, ArtifactType::BrowserHistory);
        // timestamp must be non-zero
        assert_ne!(ev.timestamp_ns, 0);
    }

    #[test]
    fn chrome_webkit_epoch_converts_correctly() {
        // webkit time 13_327_626_000_000_000 µs
        // unix µs = 13_327_626_000_000_000 - 11_644_473_600_000_000 = 1_683_152_400_000_000
        // unix ns  = 1_683_152_400_000_000 * 1000 = 1_683_152_400_000_000_000
        let webkit: i64 = 13_327_626_000_000_000;
        let expected_ns: i64 = 1_683_152_400_000_000_000;
        assert_eq!(webkit_to_unix_ns(webkit), expected_ns);
    }
}
