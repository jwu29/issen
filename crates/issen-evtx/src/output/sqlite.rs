//! SQLite/FTS5 output: write EvtxEvents to an in-memory or file-backed SQLite database.

use winevt_core::EvtxEvent;

/// Write events to an SQLite database at `path` with an FTS5 virtual table.
///
/// Schema:
/// - `evtx_events(event_id, channel, timestamp_ns, computer, data_json TEXT)` (regular table)
/// - `evtx_fts USING fts5(channel, computer, data_json, content=evtx_events)` (FTS5 index)
///
/// Returns the number of events written.
pub fn write_to_sqlite(events: &[EvtxEvent], path: &std::path::Path) -> anyhow::Result<usize> {
    todo!()
}

/// Write events to an in-memory SQLite database and return the connection.
///
/// Useful for testing and ephemeral analysis sessions.
pub fn write_to_memory(events: &[EvtxEvent]) -> anyhow::Result<rusqlite::Connection> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    fn make_event(event_id: u32, ts_ns: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".into(), "testuser".into());
        EvtxEvent {
            event_id,
            channel: "Security".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    #[test]
    fn write_to_sqlite_empty_events_succeeds() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let result = write_to_sqlite(&[], tmp.path());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn write_to_sqlite_returns_correct_count() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let events = vec![make_event(4624, 1_000), make_event(4688, 2_000)];
        let count = write_to_sqlite(&events, tmp.path()).expect("write");
        assert_eq!(count, 2);
    }

    #[test]
    fn write_to_sqlite_db_has_evtx_events_table() {
        let tmp = NamedTempFile::new().expect("tempfile");
        let events = vec![make_event(4624, 1_000)];
        write_to_sqlite(&events, tmp.path()).expect("write");

        let conn = rusqlite::Connection::open(tmp.path()).expect("open");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM evtx_events", [], |r| r.get(0))
            .expect("query");
        assert_eq!(count, 1);
    }

    #[test]
    fn write_to_memory_empty_succeeds() {
        let result = write_to_memory(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn write_to_memory_events_queryable() {
        let events = vec![make_event(4624, 1_000), make_event(4688, 2_000)];
        let conn = write_to_memory(&events).expect("write");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM evtx_events", [], |r| r.get(0))
            .expect("query");
        assert_eq!(count, 2);
    }

    #[test]
    fn write_to_memory_fts5_table_exists() {
        let events = vec![make_event(4624, 1_000)];
        let conn = write_to_memory(&events).expect("write");
        // If FTS5 table doesn't exist, this will error
        let result: rusqlite::Result<i64> = conn
            .query_row("SELECT COUNT(*) FROM evtx_fts", [], |r| r.get(0));
        assert!(result.is_ok(), "evtx_fts FTS5 table must exist");
    }
}
