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

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseOptions, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};
use issen_core::ActivityCategory;

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
    /// `true` if `path` is a recognized browser history artifact (per
    /// `browser_core::detect_browser`).
    #[must_use]
    pub fn can_parse(&self, path: &Path) -> bool {
        detect_browser(path).is_some()
    }

    /// Parse a browser history file into timeline events. Returns `Err` if the
    /// browser family cannot be detected or the underlying SQLite read fails.
    pub fn parse_path(&self, path: &Path) -> Result<Vec<TimelineEvent>> {
        let evidence_source = path.to_string_lossy().into_owned();
        let events = parse_browser_history(path)?
            .into_iter()
            .map(|e| browser_event_to_timeline(e, &evidence_source))
            .collect();
        Ok(events)
    }
}

/// Convert a browser-forensic [`BrowserEvent`] into a canonical [`TimelineEvent`]
/// tagged with the CADET `BrowserActivity` lens, carrying the browser family,
/// artifact kind, and every source attribute (url/title/visit_count/…) as
/// metadata so nothing the parser recovered is dropped at the wrapper boundary.
fn browser_event_to_timeline(event: BrowserEvent, evidence_source: &str) -> TimelineEvent {
    let ts_display = jiff::Timestamp::from_nanosecond(i128::from(event.timestamp_ns))
        .map(|t| t.to_string())
        .unwrap_or_default();
    let mut te = TimelineEvent::new(
        event.timestamp_ns,
        ts_display,
        EventType::Other(format!("Browser{}", event.artifact)),
        ArtifactType::BrowserHistory,
        evidence_source.to_string(),
        event.description,
        evidence_source.to_string(),
    )
    .with_activity_category(ActivityCategory::BrowserActivity)
    .with_metadata("browser", serde_json::json!(event.browser.to_string()))
    .with_metadata(
        "artifact_kind",
        serde_json::json!(event.artifact.to_string()),
    );
    for (key, value) in event.attrs {
        te = te.with_metadata(key, value);
    }
    te
}

impl ForensicParser for BrowserParser {
    fn name(&self) -> &'static str {
        "Browser History Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::BrowserHistory]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        // Browser history is a SQLite database: the parser seeks across B-tree
        // pages, so it needs random-access *file* semantics, not the streaming
        // byte view. Drive the real parse through the source path; a byte-only
        // source (no path) yields no events rather than failing.
        let Some(path) = input.source_path() else {
            return Ok(ParseStats::new());
        };
        let events = self
            .parse_path(path)
            .map_err(|e| RtError::InvalidData(format!("browser history parse failed: {e}")))?;
        let mut stats = ParseStats::new();
        stats.events_emitted = events.len() as u64;
        stats.bytes_processed = input.len();
        emitter.emit_batch(events)?;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(128 * 1024 * 1024), // 128 MiB
            streaming: false,
            deterministic: true,
        }
    }
}

// Compile-time registration with the parser inventory. Disk-image collection
// pulls the Chrome/Edge `Default` profile History DBs; the `matches` classifier
// catches browser history files from any source (loose files, other profiles,
// Firefox/Safari) during ingestion.
inventory::submit! {
    ParserRegistration { create: || Box::new(BrowserParser), selector: sel::ArtifactSelector {
            artifact_type: ArtifactType::BrowserHistory,
            matches: classify::browser_history,
            priority: 80,
            disk_sources: &[
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep {
                    parent: r"\Users",
                    rel: r"AppData\Local\Google\Chrome\User Data\Default",
                    name: sel::NameMatch::Suffix("History"),
                }),
                sel::DiskSource::Ntfs(sel::NtfsLoc::PerSubdirSweep {
                    parent: r"\Users",
                    rel: r"AppData\Local\Microsoft\Edge\User Data\Default",
                    name: sel::NameMatch::Suffix("History"),
                }),
            ],
            cost: sel::CostTier::Default,
        } }
}

/// `true` if `path`'s base name is a Chromium SNSS session/tab-restore file
/// (case-insensitive): the fixed names `Current Session`/`Last Session`/
/// `Current Tabs`/`Last Tabs`, or the numbered `Session_<n>`/`Tabs_<n>`/
/// `Apps_<n>` variants Chrome/Edge/Brave write under a profile's `Sessions`
/// directory.
///
/// Declared as a bare `fn` (not a closure) so it satisfies the selector's
/// `matches: fn(&Path) -> bool` contract and stays self-contained in this crate.
#[must_use]
pub fn is_snss_session_file(path: &Path) -> bool {
    // RED stub: real classification lands in GREEN.
    let _ = path;
    false
}

/// Issen browser-session parser: recognizes a Chromium SNSS session / tab-restore
/// file and replays it into per-tab [`TimelineEvent`]s, complementing
/// [`BrowserParser`] (history) under the same browser umbrella.
pub struct SessionParser;

impl SessionParser {
    /// `true` if `path` is a recognized SNSS session/tab file.
    #[must_use]
    pub fn can_parse(&self, path: &Path) -> bool {
        is_snss_session_file(path)
    }

    /// Parse an SNSS session/tab-restore file into timeline events.
    ///
    /// RED stub: returns an empty vector until the GREEN implementation.
    pub fn parse_path(&self, path: &Path) -> Result<Vec<TimelineEvent>> {
        let _ = path;
        Ok(Vec::new())
    }
}

impl ForensicParser for SessionParser {
    fn name(&self) -> &'static str {
        "Browser Session Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::BrowserHistory]
    }

    fn parse(
        &self,
        _input: &dyn DataSource,
        _emitter: &dyn EventEmitter,
        _opts: &ParseOptions,
    ) -> Result<ParseStats, RtError> {
        // RED stub.
        Ok(ParseStats::new())
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            max_memory_bytes: Some(64 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
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

    #[test]
    fn session_classifier_recognizes_snss_filenames() {
        // Fixed session/tab names Chromium writes.
        assert!(is_snss_session_file(Path::new(
            "/Users/u/AppData/Local/Google/Chrome/User Data/Default/Sessions/Current Session"
        )));
        assert!(is_snss_session_file(Path::new("Last Tabs")));
        // Numbered variants.
        assert!(is_snss_session_file(Path::new("Session_13")));
        assert!(is_snss_session_file(Path::new("Apps_1")));
        // Non-session files are rejected.
        assert!(!is_snss_session_file(Path::new("History")));
        assert!(!is_snss_session_file(Path::new("/tmp/random.db")));
    }

    #[test]
    fn session_parser_is_registered_in_inventory() {
        use issen_core::artifacts::ArtifactType;
        use issen_core::plugin::registry::ParserRegistration;
        // Both the history parser and the session parser register under
        // BrowserHistory — proving the session artifact is wired alongside history.
        let count = inventory::iter::<ParserRegistration>
            .into_iter()
            .filter(|r| r.selector.artifact_type == ArtifactType::BrowserHistory)
            .count();
        assert!(
            count >= 2,
            "expected >=2 BrowserHistory registrations (history + session), got {count}"
        );
    }

    #[test]
    fn session_parser_graceful_on_truncated_file() {
        // A session file is a Chromium SNSS pickle stream; we do not fabricate
        // its bytes here (the format is easy to get wrong). snss-core's own tests
        // cover deep-parse correctness. The wrapper must merely not panic on a
        // truncated/empty file: Ok(empty) or Err are both acceptable.
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        // Fewer bytes than an SNSS header — truncated by construction.
        f.write_all(b"SN").expect("write");
        let result = SessionParser.parse_path(f.path());
        if let Ok(events) = result {
            assert!(events.is_empty(), "truncated file should yield no events");
        }
    }

    #[test]
    fn session_parser_supports_browser_history_artifact() {
        let p = SessionParser;
        assert_eq!(p.supported_artifacts(), &[ArtifactType::BrowserHistory]);
        assert_eq!(p.name(), "Browser Session Parser");
        assert!(!p.capabilities().streaming);
        assert!(p.capabilities().deterministic);
    }
}
