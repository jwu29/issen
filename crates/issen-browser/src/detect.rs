//! Content-based browser-artifact detection — decided by *what the file is*, not
//! by where it sits or what it is named.
//!
//! The path-based [`browser_core::detect_browser`] and
//! [`issen_core::classify::browser_history`] key off a filename plus a vendor
//! token *in the path*, so they miss browser data that lives off its canonical
//! location: renamed evidence, portable browsers, secondary drives, and Chromium
//! data embedded by Electron apps (Slack, Discord, Teams, VS Code — none of which
//! carry a browser vendor token in their path). This module recognizes such a
//! file by content: the 16-byte SQLite magic gates a read-only `sqlite_master`
//! probe whose signature tables name the family and artifact.
//!
//! It is path-independent and panic-free — a locked, corrupt, partial, or
//! non-SQLite file yields `None`, never an error or panic. The same detector the
//! future forensic-vfs whole-disk scan calls over `dyn FileSystem` (ADR 0017
//! Phase 3): the byte-header variant is the reusable core, the path variant a
//! convenience wrapper.

use std::path::Path;

use rusqlite::OpenFlags;

/// The 16-byte header every SQLite 3 database begins with (`[MS] the header
/// string`), including the trailing NUL.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// A browser artifact identified purely by content — the family and the kind,
/// derived from the SQLite schema, independent of path or filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserArtifactKind {
    /// Chromium `History` (`urls` / `visits` tables).
    ChromiumHistory,
    /// Chromium `Cookies` (`cookies` table).
    ChromiumCookies,
    /// Chromium `Login Data` (`logins` table).
    ChromiumLoginData,
    /// Chromium `Web Data` (`autofill` table).
    ChromiumWebData,
    /// Firefox `places.sqlite` (`moz_places` table).
    FirefoxPlaces,
    /// Firefox `cookies.sqlite` (`moz_cookies` table).
    FirefoxCookies,
}

impl BrowserArtifactKind {
    /// `true` when this is a *history* artifact — the kind issen's browser parser
    /// currently reads into the timeline (Chromium `History` / Firefox
    /// `places.sqlite`). The other kinds are recognized for the whole-disk scan
    /// but not yet parsed by issen's history-only wrapper.
    #[must_use]
    pub fn is_history(self) -> bool {
        matches!(self, Self::ChromiumHistory | Self::FirefoxPlaces)
    }
}

/// Detect a browser artifact from a file's `header` (its first bytes) and the
/// `body` needed to open it as SQLite. The header gates the expensive open: a
/// file that does not start with the SQLite magic is rejected before any parse.
///
/// This takes a `path` to a readable copy of the file because SQLite is opened by
/// path (read-only); `header` is passed separately so a caller that already has
/// the first bytes (a VFS `read_at` of the sniff window) pays for the cheap magic
/// check without a full open. The two always describe the same file.
///
/// Returns `None` for a non-SQLite header, a locked/corrupt/partial database, or
/// a schema with no browser signature table. Never panics or propagates an error.
#[must_use]
pub fn detect_browser_artifact_with_header(
    header: &[u8],
    path: &Path,
) -> Option<BrowserArtifactKind> {
    if !starts_with_sqlite_magic(header) {
        return None;
    }
    detect_from_sqlite_master(path)
}

/// Detect a browser artifact from a file `path` by content alone.
///
/// Reads the 16-byte header, and only if it is the SQLite magic opens the file
/// read-only and matches its `sqlite_master` schema. Path- and filename-
/// independent: a renamed Chromium `History` (e.g. `evidence.dat`) is detected by
/// its `urls` table just the same.
#[must_use]
pub fn detect_browser_artifact(path: &Path) -> Option<BrowserArtifactKind> {
    let header = read_header(path);
    detect_browser_artifact_with_header(&header, path)
}

/// `true` when `header` begins with the SQLite 3 magic. Short buffers (a partial
/// read) simply do not match — no panic.
fn starts_with_sqlite_magic(header: &[u8]) -> bool {
    header.len() >= SQLITE_MAGIC.len() && &header[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

/// Read up to the first 16 bytes of `path` (empty on any error — a missing or
/// unreadable file simply fails the magic check).
fn read_header(path: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; SQLITE_MAGIC.len()];
    match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

/// Open `path` read-only and match the browser signature tables in its
/// `sqlite_master`. Read-only immutable so a live/locked database is still
/// probed; any open or query failure (corrupt, encrypted, not really SQLite)
/// yields `None`.
fn detect_from_sqlite_master(path: &Path) -> Option<BrowserArtifactKind> {
    // `SQLITE_OPEN_READ_ONLY` never mutates the evidence file; pairing it with a
    // best-effort query keeps a locked or partially-written DB from erroring out
    // to a crash — worst case we see no signature table and return None.
    let conn = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .ok()?;
    let tables = table_names(&conn)?;
    classify_tables(&tables)
}

/// The set of table names in `conn`'s `sqlite_master`, lowercased. `None` if the
/// schema cannot be read (corrupt/locked past the open).
fn table_names(conn: &rusqlite::Connection) -> Option<std::collections::HashSet<String>> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .ok()?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .ok()?
        .filter_map(Result::ok)
        .map(|n| n.to_lowercase())
        .collect();
    Some(rows)
}

/// Map a schema's table set to a browser artifact. The signature tables are
/// disjoint across kinds, so a single containment check per kind is unambiguous;
/// history is checked first because it is the kind issen parses.
fn classify_tables(tables: &std::collections::HashSet<String>) -> Option<BrowserArtifactKind> {
    let has = |t: &str| tables.contains(t);
    if has("urls") || has("visits") {
        Some(BrowserArtifactKind::ChromiumHistory)
    } else if has("moz_places") {
        Some(BrowserArtifactKind::FirefoxPlaces)
    } else if has("moz_cookies") {
        Some(BrowserArtifactKind::FirefoxCookies)
    } else if has("cookies") {
        Some(BrowserArtifactKind::ChromiumCookies)
    } else if has("logins") {
        Some(BrowserArtifactKind::ChromiumLoginData)
    } else if has("autofill") || has("web_data") {
        Some(BrowserArtifactKind::ChromiumWebData)
    } else {
        None
    }
}

/// `true` when a file at `path` is a browser artifact issen can currently parse
/// into the timeline — recognized either by the path-based classifier
/// ([`issen_core::classify::browser_history`]) OR by *content* (a history
/// database, whatever its path or filename). The content arm is what catches
/// off-path / Electron / renamed history DBs the path arm misses; it is scoped to
/// *history* so the discovery never claims a file the history-only parser cannot
/// read.
#[must_use]
pub fn is_parseable_browser_artifact(path: &Path) -> bool {
    issen_core::classify::browser_history(path)
        || detect_browser_artifact(path).is_some_and(BrowserArtifactKind::is_history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::path::PathBuf;

    /// Create a SQLite DB at `path` with the given `schema`.
    fn write_db(path: &Path, schema: &str) {
        let conn = Connection::open(path).expect("open");
        conn.execute_batch(schema).expect("schema");
    }

    fn chrome_history_schema() -> &'static str {
        // The exact schema issen-browser's own tests use.
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT NOT NULL, \
         title TEXT DEFAULT '', visit_count INTEGER DEFAULT 0 NOT NULL, \
         last_visit_time INTEGER NOT NULL);"
    }

    #[test]
    fn chromium_history_detected_at_arbitrary_path() {
        let dir = tempfile::tempdir().expect("tmp");
        // No browser vendor token anywhere in the path or filename.
        let db = dir.path().join("some_random_name");
        write_db(&db, chrome_history_schema());
        assert_eq!(
            detect_browser_artifact(&db),
            Some(BrowserArtifactKind::ChromiumHistory)
        );
    }

    #[test]
    fn chromium_cookies_detected_by_content() {
        let dir = tempfile::tempdir().expect("tmp");
        // Off-path Chromium Cookies — the Electron/Slack case (no vendor token).
        let db = dir.path().join("AppData/Roaming/Slack");
        std::fs::create_dir_all(&db).expect("mkdir");
        let db = db.join("Cookies");
        write_db(
            &db,
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT);",
        );
        assert_eq!(
            detect_browser_artifact(&db),
            Some(BrowserArtifactKind::ChromiumCookies)
        );
    }

    #[test]
    fn firefox_places_detected_by_content() {
        let dir = tempfile::tempdir().expect("tmp");
        let db = dir.path().join("renamed.bin");
        write_db(
            &db,
            "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, \
             title TEXT, visit_count INTEGER, last_visit_date INTEGER);",
        );
        assert_eq!(
            detect_browser_artifact(&db),
            Some(BrowserArtifactKind::FirefoxPlaces)
        );
    }

    #[test]
    fn renamed_history_db_detected_by_content_not_name() {
        let dir = tempfile::tempdir().expect("tmp");
        // A deliberately misleading name — anti-forensic relocation/rename.
        let db = dir.path().join("evidence.dat");
        write_db(&db, chrome_history_schema());
        assert_eq!(
            detect_browser_artifact(&db),
            Some(BrowserArtifactKind::ChromiumHistory),
            "a renamed Chromium History must be found by its `urls` table"
        );
    }

    #[test]
    fn non_sqlite_file_is_none() {
        let dir = tempfile::tempdir().expect("tmp");
        let f = dir.path().join("notes.txt");
        std::fs::write(&f, b"this is just some text, not a database").expect("write");
        assert_eq!(detect_browser_artifact(&f), None);
    }

    #[test]
    fn sqlite_without_browser_tables_is_none() {
        let dir = tempfile::tempdir().expect("tmp");
        let db = dir.path().join("app.db");
        write_db(
            &db,
            "CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);",
        );
        assert_eq!(
            detect_browser_artifact(&db),
            None,
            "a SQLite DB with no browser signature table is not a browser artifact"
        );
    }

    #[test]
    fn missing_file_is_none_not_panic() {
        // A non-existent path (the classifier-differential corpus case): the
        // header read fails, the magic check fails, no open is attempted.
        let p = PathBuf::from("/nonexistent/definitely/not/here.db");
        assert_eq!(detect_browser_artifact(&p), None);
    }

    #[test]
    fn header_variant_short_circuits_non_sqlite() {
        // The 16-byte gate rejects before any open — a bogus path is never opened
        // because the header alone disqualifies it.
        let not_sqlite = b"PK\x03\x04 zip header";
        assert_eq!(
            detect_browser_artifact_with_header(not_sqlite, Path::new("/whatever")),
            None
        );
    }

    #[test]
    fn is_history_only_true_for_history_kinds() {
        assert!(BrowserArtifactKind::ChromiumHistory.is_history());
        assert!(BrowserArtifactKind::FirefoxPlaces.is_history());
        assert!(!BrowserArtifactKind::ChromiumCookies.is_history());
        assert!(!BrowserArtifactKind::ChromiumLoginData.is_history());
    }

    #[test]
    fn is_parseable_matches_content_history_off_path() {
        let dir = tempfile::tempdir().expect("tmp");
        // Renamed Chromium History with no vendor token — path classifier misses
        // it, the content arm catches it.
        let db = dir.path().join("data.blob");
        write_db(&db, chrome_history_schema());
        assert!(
            !issen_core::classify::browser_history(&db),
            "path classifier must NOT match (no vendor token, non-canonical name)"
        );
        assert!(
            is_parseable_browser_artifact(&db),
            "content classifier must match the renamed History"
        );
    }

    #[test]
    fn is_parseable_still_matches_canonical_path() {
        // Regression guard: the existing path-based recognition still works even
        // for a file that doesn't exist on disk (path-only, no content read).
        let p = Path::new("/Users/u/AppData/Local/Google/Chrome/User Data/Default/History");
        assert!(is_parseable_browser_artifact(p));
    }

    #[test]
    fn is_parseable_rejects_non_browser_sqlite() {
        let dir = tempfile::tempdir().expect("tmp");
        let db = dir.path().join("Cookies"); // canonical NAME, but Chromium Cookies
        write_db(
            &db,
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT);",
        );
        // Cookies is a browser artifact but NOT history — issen's history-only
        // parser must not claim it (would fail to parse), so is_parseable is false.
        assert!(
            !is_parseable_browser_artifact(&db),
            "a Cookies DB is not parseable by the history-only wrapper"
        );
    }
}
