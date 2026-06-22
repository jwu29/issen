//! ECS (Elastic Common Schema) JSON output for EvtxEvent.

use winevt_core::EvtxEvent;

/// Serialize a single event to an ECS JSON object.
pub fn event_to_ecs(event: &EvtxEvent) -> serde_json::Value {
    use serde_json::json;

    // Convert nanoseconds to ISO-8601 UTC string
    let secs = event.timestamp_ns / 1_000_000_000;
    let nanos = (event.timestamp_ns % 1_000_000_000).unsigned_abs();
    let ts = chrono::DateTime::from_timestamp(secs, nanos as u32).map_or_else(
        || event.timestamp_ns.to_string(),
        |dt| dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
    );

    let event_data: serde_json::Map<String, serde_json::Value> = event
        .data
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();

    json!({
        "@timestamp": ts,
        "event": {
            "id": event.event_id,
            "dataset": "windows.evtx",
        },
        "winlog": {
            "event_id": event.event_id,
            "channel": event.channel,
            "computer_name": event.computer,
            "event_data": event_data,
        },
        "host": {
            "name": event.computer,
        },
        "user": {
            "id": event.user_sid,
        }
    })
}

/// Serialize a slice of events to ECS-compliant NDJSON (one JSON object per line).
pub fn to_ecs_ndjson(events: &[EvtxEvent]) -> String {
    if events.is_empty() {
        return String::new();
    }
    events
        .iter()
        .map(|e| serde_json::to_string(&event_to_ecs(e)).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
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
        assert_eq!(output.lines().count(), 1);
    }

    #[test]
    fn to_ecs_ndjson_each_line_is_valid_json() {
        let events = vec![
            make_event(4624, 1_000_000_000),
            make_event(4688, 2_000_000_000),
        ];
        let output = to_ecs_ndjson(&events);
        for line in output.lines() {
            let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "invalid JSON: {line}");
        }
    }

    #[test]
    fn event_to_ecs_has_timestamp_field() {
        let ev = make_event(4624, 1_609_459_200_000_000_000);
        let ecs = event_to_ecs(&ev);
        assert!(ecs.get("@timestamp").is_some());
    }

    #[test]
    fn event_to_ecs_has_winlog_channel() {
        let ev = make_event(4624, 1_000_000_000);
        let ecs = event_to_ecs(&ev);
        let channel = ecs.get("winlog").and_then(|w| w.get("channel"));
        assert!(channel.is_some());
    }

    #[test]
    fn event_to_ecs_dataset_is_windows_evtx() {
        let ev = make_event(4624, 1_000_000_000);
        let ecs = event_to_ecs(&ev);
        let dataset = ecs
            .get("event")
            .and_then(|e| e.get("dataset"))
            .and_then(|v| v.as_str());
        assert_eq!(dataset, Some("windows.evtx"));
    }
}
