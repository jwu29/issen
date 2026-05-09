//! M365 Unified Audit Log (UAL) ingest: parse JSON and normalize to EvtxEvent schema.
//!
//! UAL records are exported via the Compliance center or `Search-UnifiedAuditLog`.
//! Each entry is normalized to EvtxEvent with:
//! - `event_id` mapped from `Operation` (e.g. FileAccessed=4663, UserLoggedIn=4624)
//! - `channel = "M365/UnifiedAuditLog"`
//! - `data` carries all UAL fields verbatim

use winevt_core::EvtxEvent;

/// Parse M365 Unified Audit Log JSON and normalize to EvtxEvent slice.
///
/// `json` should be the JSON array from `Search-UnifiedAuditLog -ResultSize 5000 | ConvertTo-Json`.
pub fn parse_m365_ual(json: &str) -> Vec<EvtxEvent> {
    todo!()
}

/// Map a UAL `Operation` string to a synthetic Windows event ID.
pub fn operation_to_event_id(operation: &str) -> u32 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_UAL: &str = r#"[
        {
            "CreationTime": "2024-01-15T10:30:00",
            "Id": "aaaabbbb-1234-5678-abcd-ef0123456789",
            "Operation": "UserLoggedIn",
            "OrganizationId": "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "RecordType": 15,
            "ResultStatus": "Succeeded",
            "UserKey": "user@contoso.com",
            "UserType": 0,
            "Version": 1,
            "Workload": "AzureActiveDirectory",
            "ClientIP": "203.0.113.5",
            "ObjectId": "user@contoso.com",
            "UserId": "user@contoso.com"
        }
    ]"#;

    #[test]
    fn parse_empty_array_returns_empty() {
        assert!(parse_m365_ual("[]").is_empty());
    }

    #[test]
    fn parse_invalid_json_returns_empty() {
        assert!(parse_m365_ual("not json").is_empty());
    }

    #[test]
    fn parse_sets_channel_to_m365_ual() {
        let events = parse_m365_ual(SAMPLE_UAL);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].channel, "M365/UnifiedAuditLog");
    }

    #[test]
    fn parse_userloggedin_maps_to_known_event_id() {
        let events = parse_m365_ual(SAMPLE_UAL);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 4624, "UserLoggedIn should map to 4624");
    }

    #[test]
    fn parse_carries_operation_in_data() {
        let events = parse_m365_ual(SAMPLE_UAL);
        let op = events[0].data.get("Operation").or_else(|| events[0].data.get("operation"));
        assert!(op.is_some(), "Operation field should be in event data");
    }

    #[test]
    fn operation_to_event_id_userloggedin_is_4624() {
        assert_eq!(operation_to_event_id("UserLoggedIn"), 4624);
    }

    #[test]
    fn operation_to_event_id_fileaccessed_is_4663() {
        assert_eq!(operation_to_event_id("FileAccessed"), 4663);
    }

    #[test]
    fn operation_to_event_id_unknown_returns_nonzero() {
        let id = operation_to_event_id("SomeUnknownOp");
        assert_ne!(id, 0, "unknown operations should map to a non-zero fallback ID");
    }
}
