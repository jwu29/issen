//! ECS (Elastic Common Schema) JSON output for EvtxEvent.

use winevt_core::EvtxEvent;

/// Serialize a slice of events to ECS-compliant JSON (newline-delimited).
///
/// Each event is serialized as one JSON object per line with:
/// - `@timestamp`: ISO-8601 UTC from `timestamp_ns`
/// - `event.id`, `event.dataset` ("windows.evtx")
/// - `log.level`, `winlog.channel`, `winlog.computer_name`
/// - `winlog.event_data.*` for all `data` fields
pub fn to_ecs_ndjson(events: &[EvtxEvent]) -> String {
    todo!()
}

/// Serialize a single event to an ECS JSON object.
pub fn event_to_ecs(event: &EvtxEvent) -> serde_json::Value {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, ts_ns: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("SubjectUserName".into(), "testuser".into());
        EvtxEvent {
            event_id,
            channel: "Security".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: Some("S-1-5-21-1234".into()),
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    #[test]
    fn to_ecs_ndjson_empty_returns_empty_string() {
        assert_eq!(to_ecs_ndjson(&[]), "");
    }

    #[test]
    fn to_ecs_ndjson_one_event_one_line() {
        let events = vec![make_event(4624, 1_000_000_000)];
        let output = to_ecs_ndjson(&events);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 1, "one event → one NDJSON line");
    }

    #[test]
    fn to_ecs_ndjson_each_line_is_valid_json() {
        let events = vec![make_event(4624, 1_000_000_000), make_event(4688, 2_000_000_000)];
        let output = to_ecs_ndjson(&events);
        for line in output.lines() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "each line must be valid JSON: {line}");
        }
    }

    #[test]
    fn event_to_ecs_has_timestamp_field() {
        let ev = make_event(4624, 1_609_459_200_000_000_000); // 2021-01-01T00:00:00Z
        let ecs = event_to_ecs(&ev);
        assert!(ecs.get("@timestamp").is_some(), "ECS object must have @timestamp");
    }

    #[test]
    fn event_to_ecs_has_winlog_channel() {
        let ev = make_event(4624, 1_000_000_000);
        let ecs = event_to_ecs(&ev);
        let channel = ecs.pointer("/winlog/channel")
            .or_else(|| ecs.get("winlog").and_then(|w| w.get("channel")));
        assert!(channel.is_some(), "ECS object must have winlog.channel");
    }

    #[test]
    fn event_to_ecs_dataset_is_windows_evtx() {
        let ev = make_event(4624, 1_000_000_000);
        let ecs = event_to_ecs(&ev);
        let dataset = ecs.pointer("/event/dataset")
            .or_else(|| ecs.get("event").and_then(|e| e.get("dataset")));
        assert_eq!(
            dataset.and_then(|v| v.as_str()),
            Some("windows.evtx"),
            "dataset must be 'windows.evtx'"
        );
    }
}
