//! MDE Advanced Hunting JSON ingest.

use winevt_core::EvtxEvent;

/// Map an MDE ActionType string to a synthetic Windows event ID.
pub fn action_type_to_event_id(action_type: &str) -> u32 {
    match action_type {
        "ProcessCreated" => 4688,
        "NetworkConnectionEvents" => 5156,
        "FileCreated" | "FileModified" | "FileRenamed" | "FileDeleted" => 4663,
        "RegistryValueSet" | "RegistryKeyCreated" => 4657,
        "LogonSuccess" => 4624,
        "LogonFailed" => 4625,
        "InboundConnectionAccepted" | "ConnectionFound" => 5156,
        _ => 4688,
    }
}

/// Parse MDE Advanced Hunting JSON and normalize to EvtxEvent slice.
pub fn parse_mde_advanced_hunting(json: &str) -> Vec<EvtxEvent> {
    let records: Vec<serde_json::Value> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    records.into_iter().filter_map(|rec| {
        let ts_str = rec.get("Timestamp")?.as_str()?;
        let ts_ns = parse_iso8601_ns(ts_str)?;

        let action_type = rec.get("ActionType").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let event_id = action_type_to_event_id(action_type);
        let computer = rec.get("DeviceName").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let mut data = std::collections::HashMap::new();
        data.insert("ActionType".into(), action_type.into());

        if let Some(fname) = rec.get("FileName").and_then(|v| v.as_str()) {
            data.insert("FileName".into(), fname.into());
        }
        if let Some(folder) = rec.get("FolderPath").and_then(|v| v.as_str()) {
            data.insert("FolderPath".into(), folder.into());
            // Build full image path
            let image = format!("{folder}\\{}", rec.get("FileName").and_then(|v| v.as_str()).unwrap_or(""));
            data.insert("NewProcessName".into(), image);
        }
        if let Some(cmd) = rec.get("ProcessCommandLine").and_then(|v| v.as_str()) {
            data.insert("CommandLine".into(), cmd.into());
        }
        if let Some(acc) = rec.get("AccountName").and_then(|v| v.as_str()) {
            data.insert("SubjectUserName".into(), acc.into());
        }
        if let Some(rip) = rec.get("RemoteIP").and_then(|v| v.as_str()) {
            if !rip.is_empty() { data.insert("RemoteIP".into(), rip.into()); }
        }
        if let Some(rport) = rec.get("RemotePort").and_then(|v| v.as_u64()) {
            if rport > 0 { data.insert("RemotePort".into(), rport.to_string()); }
        }

        Some(EvtxEvent {
            event_id,
            channel: "MDE/AdvancedHunting".into(),
            timestamp_ns: ts_ns,
            computer,
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        })
    }).collect()
}

fn parse_iso8601_ns(s: &str) -> Option<i64> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_nanos_opt()?);
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
        return Some(dt.and_utc().timestamp_nanos_opt()?);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROC: &str = r#"[{"Timestamp":"2024-01-15T10:30:00Z","DeviceName":"WORKSTATION01","ActionType":"ProcessCreated","FileName":"powershell.exe","FolderPath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0","ProcessCommandLine":"powershell.exe -enc base64data","InitiatingProcessFileName":"cmd.exe","AccountName":"Administrator","AccountDomain":"CONTOSO","RemoteIP":"","RemotePort":0}]"#;
    const SAMPLE_NET: &str = r#"[{"Timestamp":"2024-01-15T10:31:00Z","DeviceName":"WORKSTATION01","ActionType":"NetworkConnectionEvents","RemoteIP":"185.220.101.5","RemotePort":443,"LocalIP":"192.168.1.100","LocalPort":54321,"Protocol":"Tcp","InitiatingProcessFileName":"powershell.exe"}]"#;

    #[test]
    fn parse_empty_array_returns_empty() { assert!(parse_mde_advanced_hunting("[]").is_empty()); }
    #[test]
    fn parse_invalid_json_returns_empty() { assert!(parse_mde_advanced_hunting("not json").is_empty()); }
    #[test]
    fn parse_process_event_sets_channel() {
        let events = parse_mde_advanced_hunting(SAMPLE_PROC);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].channel, "MDE/AdvancedHunting");
    }
    #[test]
    fn parse_processcreated_maps_to_4688() {
        let events = parse_mde_advanced_hunting(SAMPLE_PROC);
        assert_eq!(events[0].event_id, 4688);
    }
    #[test]
    fn parse_network_event_maps_to_5156() {
        let events = parse_mde_advanced_hunting(SAMPLE_NET);
        assert_eq!(events[0].event_id, 5156);
    }
    #[test]
    fn parse_carries_filename_in_data() {
        let events = parse_mde_advanced_hunting(SAMPLE_PROC);
        assert!(events[0].data.values().any(|v| v.to_lowercase().contains("powershell")));
    }
    #[test]
    fn parse_computer_set_from_device_name() {
        let events = parse_mde_advanced_hunting(SAMPLE_PROC);
        assert_eq!(events[0].computer, "WORKSTATION01");
    }
    #[test]
    fn action_type_to_event_id_processcreated_is_4688() { assert_eq!(action_type_to_event_id("ProcessCreated"), 4688); }
    #[test]
    fn action_type_to_event_id_network_is_5156() { assert_eq!(action_type_to_event_id("NetworkConnectionEvents"), 5156); }
    #[test]
    fn action_type_to_event_id_unknown_returns_nonzero() { assert_ne!(action_type_to_event_id("SomeUnknownAction"), 0); }
}
