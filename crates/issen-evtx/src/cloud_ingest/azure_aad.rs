//! Azure AD Sign-In log ingest: parse JSON and normalize to EvtxEvent schema.
//!
//! Azure AD sign-in logs are exported from the Azure portal as JSON arrays.
//! Each entry is normalized to an EvtxEvent with:
//! - `event_id = 4624` (successful sign-in) or `4625` (failed)
//! - `channel = "AzureAD/SignIn"`
//! - `data` fields mapped from Azure AD field names

use winevt_core::EvtxEvent;

/// Parse Azure AD sign-in log JSON and normalize to EvtxEvent slice.
///
/// `json` should be a JSON array of Azure AD sign-in records.
/// Records that cannot be decoded are silently skipped.
pub fn parse_azure_aad_signin(json: &str) -> Vec<EvtxEvent> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SIGNIN: &str = r#"[
        {
            "createdDateTime": "2024-01-15T10:30:00Z",
            "userPrincipalName": "user@contoso.com",
            "ipAddress": "203.0.113.5",
            "status": {"errorCode": 0},
            "appDisplayName": "Microsoft Teams",
            "clientAppUsed": "Browser",
            "location": {"city": "Seattle", "countryOrRegion": "US"}
        }
    ]"#;

    const SAMPLE_FAILED_SIGNIN: &str = r#"[
        {
            "createdDateTime": "2024-01-15T10:31:00Z",
            "userPrincipalName": "attacker@external.com",
            "ipAddress": "198.51.100.10",
            "status": {"errorCode": 50126},
            "appDisplayName": "Azure Portal",
            "clientAppUsed": "Browser"
        }
    ]"#;

    #[test]
    fn parse_empty_array_returns_empty() {
        assert!(parse_azure_aad_signin("[]").is_empty());
    }

    #[test]
    fn parse_invalid_json_returns_empty() {
        assert!(parse_azure_aad_signin("not json").is_empty());
    }

    #[test]
    fn parse_successful_signin_maps_to_4624() {
        let events = parse_azure_aad_signin(SAMPLE_SIGNIN);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 4624, "successful sign-in should map to EID 4624");
    }

    #[test]
    fn parse_failed_signin_maps_to_4625() {
        let events = parse_azure_aad_signin(SAMPLE_FAILED_SIGNIN);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 4625, "failed sign-in (errorCode != 0) should map to EID 4625");
    }

    #[test]
    fn parse_sets_channel_to_azure_ad_signin() {
        let events = parse_azure_aad_signin(SAMPLE_SIGNIN);
        assert_eq!(events[0].channel, "AzureAD/SignIn");
    }

    #[test]
    fn parse_maps_user_principal_name_to_data() {
        let events = parse_azure_aad_signin(SAMPLE_SIGNIN);
        assert!(
            events[0].data.contains_key("userPrincipalName") ||
            events[0].data.contains_key("TargetUserName"),
            "user principal name should be in event data"
        );
    }

    #[test]
    fn parse_maps_ip_address() {
        let events = parse_azure_aad_signin(SAMPLE_SIGNIN);
        let has_ip = events[0].data.values().any(|v| v.contains("203.0.113.5"));
        assert!(has_ip, "IP address should appear in event data");
    }

    #[test]
    fn parse_multiple_records() {
        let json = format!("[{}, {}]",
            &SAMPLE_SIGNIN[1..SAMPLE_SIGNIN.len()-1],
            &SAMPLE_FAILED_SIGNIN[1..SAMPLE_FAILED_SIGNIN.len()-1]
        );
        let events = parse_azure_aad_signin(&json);
        assert_eq!(events.len(), 2);
    }
}
