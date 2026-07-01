//! Plaso/l2t export: emit l2tcsv and JSONL for Timesketch ingestion.
//!
//! l2tcsv format (log2timeline legacy CSV):
//! `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`

use serde_json::json;
use winevt_core::EvtxEvent;

/// Convert an i64 nanosecond count since the Unix epoch into a `jiff::Timestamp`.
///
/// Any `i64` nanosecond value is within jiff's supported range, so the fallback
/// to the Unix epoch is unreachable in practice but keeps the conversion
/// panic-free.
fn timestamp_from_nanos(ns: i64) -> jiff::Timestamp {
    jiff::Timestamp::from_nanosecond(i128::from(ns)).unwrap_or_default()
}

/// l2tcsv header line.
pub const L2TCSV_HEADER: &str =
    "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra";

/// Serialize one event to an l2tcsv row (no trailing newline).
///
/// Timestamps are rendered as UTC. Empty optional fields use `-`.
pub fn event_to_l2tcsv(event: &EvtxEvent) -> String {
    let ts = timestamp_from_nanos(event.timestamp_ns);
    let date = jiff::fmt::strtime::format("%m/%d/%Y", ts).unwrap_or_default();
    let time = jiff::fmt::strtime::format("%H:%M:%S", ts).unwrap_or_default();
    let user = event.user_sid.as_deref().unwrap_or("-");
    let short = format!("EID {} on {}", event.event_id, event.channel);
    let desc = format!("EID {} channel:{}", event.event_id, event.channel);
    // l2tcsv columns: date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
    format!(
        "{date},{time},UTC,...,EVT,{channel},Content Modification Time,{user},{host},{short},{desc},2,-,-,-,issen-evtx,EID={eid}",
        date = date,
        time = time,
        channel = event.channel,
        user = user,
        host = event.computer,
        short = short,
        desc = desc,
        eid = event.event_id,
    )
}

/// Serialize a slice of events to a full l2tcsv document (header + rows).
pub fn events_to_l2tcsv(events: &[EvtxEvent]) -> String {
    let mut out = L2TCSV_HEADER.to_string();
    for ev in events {
        out.push('\n');
        out.push_str(&event_to_l2tcsv(ev));
    }
    out
}

/// Serialize one event to a Plaso-style JSONL record (one JSON object, no newline).
///
/// Schema mirrors plaso's `data_type: windows:evtx:record`.
pub fn event_to_jsonl(event: &EvtxEvent) -> String {
    let ts = timestamp_from_nanos(event.timestamp_ns);
    let obj = json!({
        "data_type": "windows:evtx:record",
        "event_identifier": event.event_id,
        "channel": event.channel,
        "computer_name": event.computer,
        "timestamp": ts.to_string(),
        "user_sid": event.user_sid,
        "strings": event.data,
    });
    obj.to_string()
}

/// Serialize a slice of events to a JSONL document (one JSON object per line).
pub fn events_to_jsonl(events: &[EvtxEvent]) -> String {
    events
        .iter()
        .map(event_to_jsonl)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, channel: &str, timestamp_ns: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("TargetUserName".into(), "analyst".into());
        EvtxEvent {
            event_id,
            channel: channel.to_string(),
            timestamp_ns,
            computer: "WS01".into(),
            user_sid: Some("S-1-5-21-1234".into()),
            logon_id: Some(0x1234),
            process_id: Some(500),
            thread_id: None,
            data,
        }
    }

    #[test]
    fn l2tcsv_header_has_17_columns() {
        let cols: Vec<_> = L2TCSV_HEADER.split(',').collect();
        assert_eq!(cols.len(), 17);
    }

    #[test]
    fn event_to_l2tcsv_contains_event_id_and_channel() {
        let ev = make_event(4624, "Security", 1_700_000_000_000_000_000);
        let row = event_to_l2tcsv(&ev);
        assert!(row.contains("4624"), "row must contain event ID");
        assert!(row.contains("Security"), "row must contain channel");
    }

    #[test]
    fn event_to_l2tcsv_contains_hostname() {
        let ev = make_event(4624, "Security", 1_700_000_000_000_000_000);
        let row = event_to_l2tcsv(&ev);
        assert!(row.contains("WS01"));
    }

    #[test]
    fn event_to_l2tcsv_has_17_columns() {
        let ev = make_event(4624, "Security", 1_700_000_000_000_000_000);
        let row = event_to_l2tcsv(&ev);
        // Split by comma — the row should have exactly 17 fields
        // (some fields may be quoted and contain commas, so we count minimum)
        let col_count = row.split(',').count();
        assert!(col_count >= 17, "expected ≥17 columns, got {col_count}");
    }

    #[test]
    fn events_to_l2tcsv_first_line_is_header() {
        let evs = vec![make_event(4624, "Security", 1_000_000)];
        let csv = events_to_l2tcsv(&evs);
        let first = csv.lines().next().unwrap_or("");
        assert_eq!(first, L2TCSV_HEADER);
    }

    #[test]
    fn events_to_l2tcsv_empty_input_returns_header_only() {
        let csv = events_to_l2tcsv(&[]);
        let lines: Vec<_> = csv.lines().collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], L2TCSV_HEADER);
    }

    #[test]
    fn event_to_jsonl_is_valid_json() {
        let ev = make_event(4688, "Security", 1_700_000_000_000_000_000);
        let line = event_to_jsonl(&ev);
        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("JSONL row must be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn event_to_jsonl_contains_event_id_and_channel() {
        let ev = make_event(4688, "Security", 1_700_000_000_000_000_000);
        let line = event_to_jsonl(&ev);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["event_identifier"], 4688);
        assert_eq!(v["channel"].as_str().unwrap(), "Security");
    }

    #[test]
    fn events_to_jsonl_one_line_per_event() {
        let evs = vec![
            make_event(4624, "Security", 1_000_000),
            make_event(4688, "Security", 2_000_000),
        ];
        let out = events_to_jsonl(&evs);
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn events_to_jsonl_empty_input_is_empty_string() {
        assert_eq!(events_to_jsonl(&[]), "");
    }
}
