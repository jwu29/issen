//! SQLite/FTS5 output: write EvtxEvents to SQLite.

use winevt_core::EvtxEvent;

fn init_schema(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS evtx_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    INTEGER NOT NULL,
            channel     TEXT NOT NULL,
            timestamp_ns INTEGER NOT NULL,
            computer    TEXT NOT NULL,
            data_json   TEXT NOT NULL
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS evtx_fts
            USING fts5(channel, computer, data_json, content=evtx_events, content_rowid=id);
    ")
}

fn insert_events(conn: &rusqlite::Connection, events: &[EvtxEvent]) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare(
        "INSERT INTO evtx_events (event_id, channel, timestamp_ns, computer, data_json)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )?;

    let mut count = 0;
    for ev in events {
        let data_json = serde_json::to_string(&ev.data).unwrap_or_default();
        stmt.execute(rusqlite::params![
            ev.event_id,
            &ev.channel,
            ev.timestamp_ns,
            &ev.computer,
            data_json,
        ])?;
        count += 1;
    }

    // Rebuild FTS index
    conn.execute_batch("INSERT INTO evtx_fts(evtx_fts) VALUES('rebuild');")?;
    Ok(count)
}

/// Write events to an SQLite database at `path` with an FTS5 virtual table.
pub fn write_to_sqlite(events: &[EvtxEvent], path: &std::path::Path) -> anyhow::Result<usize> {
    let conn = rusqlite::Connection::open(path)?;
    init_schema(&conn)?;
    let count = insert_events(&conn, events)?;
    Ok(count)
}

/// Write events to an in-memory SQLite database and return the connection.
pub fn write_to_memory(events: &[EvtxEvent]) -> anyhow::Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_in_memory()?;
    init_schema(&conn)?;
    insert_events(&conn, events)?;
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    fn make_event(event_id: u32, ts_ns: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".into(), "testuser".into());
        EvtxEvent { event_id, channel: "Security".into(), timestamp_ns: ts_ns, computer: "WS01".into(), user_sid: None, logon_id: None, process_id: None, thread_id: None, data }
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
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM evtx_events", [], |r| r.get(0)).expect("query");
        assert_eq!(count, 1);
    }

    #[test]
    fn write_to_memory_empty_succeeds() {
        assert!(write_to_memory(&[]).is_ok());
    }

    #[test]
    fn write_to_memory_events_queryable() {
        let events = vec![make_event(4624, 1_000), make_event(4688, 2_000)];
        let conn = write_to_memory(&events).expect("write");
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM evtx_events", [], |r| r.get(0)).expect("query");
        assert_eq!(count, 2);
    }

    #[test]
    fn write_to_memory_fts5_table_exists() {
        let events = vec![make_event(4624, 1_000)];
        let conn = write_to_memory(&events).expect("write");
        let result: rusqlite::Result<i64> = conn.query_row("SELECT COUNT(*) FROM evtx_fts", [], |r| r.get(0));
        assert!(result.is_ok(), "evtx_fts must exist: {:?}", result.err());
    }
}
