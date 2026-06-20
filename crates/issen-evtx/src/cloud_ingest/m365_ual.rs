//! M365 Unified Audit Log (UAL) ingest.

use winevt_core::EvtxEvent;

/// Map a UAL Operation string to a synthetic Windows event ID.
pub fn operation_to_event_id(operation: &str) -> u32 {
    match operation {
        "UserLoggedIn" | "UserLoginFailed" | "AzureActiveDirectoryLogin" => 4624,
        "FileAccessed" | "FileModified" | "FileRead" => 4663,
        "FileDeleted" | "FileTrashed" => 4660,
        "FileMoved" | "FileCopied" => 4663,
        "SharePointFileOperation" => 4663,
        "MailItemsAccessed" => 4663,
        "Set-Mailbox" | "Set-TransportRule" => 4657,
        _ => 4688, // fallback: synthetic process event
    }
}

/// Parse M365 Unified Audit Log JSON and normalize to EvtxEvent slice.
pub fn parse_m365_ual(json: &str) -> Vec<EvtxEvent> {
    let records: Vec<serde_json::Value> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    records.into_iter().filter_map(|rec| {
        let ts_str = rec.get("CreationTime")?.as_str()?;
        let ts_ns = parse_iso8601_ns(ts_str)?;

        let operation = rec.get("Operation").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let event_id = operation_to_event_id(operation);

        let mut data = std::collections::HashMap::new();
        data.insert("Operation".into(), operation.into());

        if let Some(uid) = rec.get("UserId").and_then(|v| v.as_str()) {
            data.insert("UserId".into(), uid.into());
            data.insert("TargetUserName".into(), uid.into());
        }
        if let Some(ip) = rec.get("ClientIP").and_then(|v| v.as_str()) {
            data.insert("IpAddress".into(), ip.into());
        }
        if let Some(obj) = rec.get("ObjectId").and_then(|v| v.as_str()) {
            data.insert("ObjectId".into(), obj.into());
        }
        if let Some(wl) = rec.get("Workload").and_then(|v| v.as_str()) {
            data.insert("Workload".into(), wl.into());
        }

        Some(EvtxEvent {
            event_id,
            channel: "M365/UnifiedAuditLog".into(),
            timestamp_ns: ts_ns,
            computer: "m365-ual".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        })
    }).collect()
}

#[allow(clippy::map_identity, clippy::unnecessary_lazy_evaluations)] // pre-existing convoluted parse chain whose `?` short-circuit is load-bearing
fn parse_iso8601_ns(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .or_else(|_| {
            let with_z = format!("{s}Z");
            chrono::DateTime::parse_from_rfc3339(&with_z)
        })
        .or_else(|_| chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S"))
        .ok()?
        .timestamp_nanos_opt()
        .map(|n| n)
        .map(|_| ())
        .and_then(|()| {
            // Re-parse to get timestamp_nanos
            None::<()>
        });

    // Simpler: parse with naive then assume UTC
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return dt.and_utc().timestamp_nanos_opt();
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return dt.timestamp_nanos_opt();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_UAL: &str = r#"[{"CreationTime":"2024-01-15T10:30:00","Id":"aaaabbbb-1234-5678-abcd-ef0123456789","Operation":"UserLoggedIn","OrganizationId":"ffffffff-ffff-ffff-ffff-ffffffffffff","RecordType":15,"ResultStatus":"Succeeded","UserKey":"user@contoso.com","UserType":0,"Version":1,"Workload":"AzureActiveDirectory","ClientIP":"203.0.113.5","ObjectId":"user@contoso.com","UserId":"user@contoso.com"}]"#;

    #[test]
    fn parse_empty_array_returns_empty() { assert!(parse_m365_ual("[]").is_empty()); }
    #[test]
    fn parse_invalid_json_returns_empty() { assert!(parse_m365_ual("not json").is_empty()); }
    #[test]
    fn parse_sets_channel_to_m365_ual() {
        let events = parse_m365_ual(SAMPLE_UAL);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].channel, "M365/UnifiedAuditLog");
    }
    #[test]
    fn parse_userloggedin_maps_to_known_event_id() {
        let events = parse_m365_ual(SAMPLE_UAL);
        assert_eq!(events[0].event_id, 4624);
    }
    #[test]
    fn parse_carries_operation_in_data() {
        let events = parse_m365_ual(SAMPLE_UAL);
        assert!(events[0].data.contains_key("Operation") || events[0].data.contains_key("operation"));
    }
    #[test]
    fn operation_to_event_id_userloggedin_is_4624() { assert_eq!(operation_to_event_id("UserLoggedIn"), 4624); }
    #[test]
    fn operation_to_event_id_fileaccessed_is_4663() { assert_eq!(operation_to_event_id("FileAccessed"), 4663); }
    #[test]
    fn operation_to_event_id_unknown_returns_nonzero() { assert_ne!(operation_to_event_id("SomeUnknownOp"), 0); }
}
