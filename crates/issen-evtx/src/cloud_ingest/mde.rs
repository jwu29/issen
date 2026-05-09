//! Microsoft Defender for Endpoint (MDE) Advanced Hunting JSON ingest.
//!
//! MDE Advanced Hunting results are exported as JSON from the MDE portal.
//! Each record is normalized to EvtxEvent with:
//! - `event_id` mapped from `ActionType` (e.g. ProcessCreated=4688, NetworkConnectionEvents=5156)
//! - `channel = "MDE/AdvancedHunting"`
//! - `data` carries all MDE fields verbatim

use winevt_core::EvtxEvent;

/// Parse MDE Advanced Hunting JSON and normalize to EvtxEvent slice.
///
/// `json` should be the JSON array from a MDE Advanced Hunting query export.
pub fn parse_mde_advanced_hunting(json: &str) -> Vec<EvtxEvent> {
    todo!()
}

/// Map an MDE `ActionType` string to a synthetic Windows event ID.
pub fn action_type_to_event_id(action_type: &str) -> u32 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MDE_PROCESS: &str = r#"[
        {
            "Timestamp": "2024-01-15T10:30:00Z",
            "DeviceName": "WORKSTATION01",
            "ActionType": "ProcessCreated",
            "FileName": "powershell.exe",
            "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0",
            "ProcessCommandLine": "powershell.exe -enc base64data",
            "InitiatingProcessFileName": "cmd.exe",
            "AccountName": "Administrator",
            "AccountDomain": "CONTOSO",
            "RemoteIP": "",
            "RemotePort": 0
        }
    ]"#;

    const SAMPLE_MDE_NETWORK: &str = r#"[
        {
            "Timestamp": "2024-01-15T10:31:00Z",
            "DeviceName": "WORKSTATION01",
            "ActionType": "NetworkConnectionEvents",
            "RemoteIP": "185.220.101.5",
            "RemotePort": 443,
            "LocalIP": "192.168.1.100",
            "LocalPort": 54321,
            "Protocol": "Tcp",
            "InitiatingProcessFileName": "powershell.exe"
        }
    ]"#;

    #[test]
    fn parse_empty_array_returns_empty() {
        assert!(parse_mde_advanced_hunting("[]").is_empty());
    }

    #[test]
    fn parse_invalid_json_returns_empty() {
        assert!(parse_mde_advanced_hunting("not json").is_empty());
    }

    #[test]
    fn parse_process_event_sets_channel() {
        let events = parse_mde_advanced_hunting(SAMPLE_MDE_PROCESS);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].channel, "MDE/AdvancedHunting");
    }

    #[test]
    fn parse_processcreated_maps_to_4688() {
        let events = parse_mde_advanced_hunting(SAMPLE_MDE_PROCESS);
        assert_eq!(events[0].event_id, 4688, "ProcessCreated should map to EID 4688");
    }

    #[test]
    fn parse_network_event_maps_to_5156() {
        let events = parse_mde_advanced_hunting(SAMPLE_MDE_NETWORK);
        assert_eq!(events[0].event_id, 5156, "NetworkConnectionEvents should map to EID 5156");
    }

    #[test]
    fn parse_carries_filename_in_data() {
        let events = parse_mde_advanced_hunting(SAMPLE_MDE_PROCESS);
        let has_ps = events[0].data.values().any(|v| v.to_lowercase().contains("powershell"));
        assert!(has_ps, "filename should appear in event data");
    }

    #[test]
    fn parse_computer_set_from_device_name() {
        let events = parse_mde_advanced_hunting(SAMPLE_MDE_PROCESS);
        assert_eq!(events[0].computer, "WORKSTATION01");
    }

    #[test]
    fn action_type_to_event_id_processcreated_is_4688() {
        assert_eq!(action_type_to_event_id("ProcessCreated"), 4688);
    }

    #[test]
    fn action_type_to_event_id_network_is_5156() {
        assert_eq!(action_type_to_event_id("NetworkConnectionEvents"), 5156);
    }

    #[test]
    fn action_type_to_event_id_unknown_returns_nonzero() {
        assert_ne!(action_type_to_event_id("SomeUnknownAction"), 0);
    }
}
