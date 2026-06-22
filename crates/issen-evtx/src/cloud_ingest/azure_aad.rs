//! Azure AD Sign-In log ingest.

use winevt_core::EvtxEvent;

/// Parse Azure AD sign-in log JSON and normalize to EvtxEvent slice.
pub fn parse_azure_aad_signin(json: &str) -> Vec<EvtxEvent> {
    let records: Vec<serde_json::Value> = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    records
        .into_iter()
        .filter_map(|rec| {
            let ts_str = rec.get("createdDateTime")?.as_str()?;
            let ts_ns = parse_iso8601_ns(ts_str)?;

            // errorCode == 0 → success (4624), else failure (4625)
            let error_code = rec
                .get("status")
                .and_then(|s| s.get("errorCode"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let event_id: u32 = if error_code == 0 { 4624 } else { 4625 };

            let mut data = std::collections::HashMap::new();

            if let Some(upn) = rec.get("userPrincipalName").and_then(|v| v.as_str()) {
                data.insert("userPrincipalName".into(), upn.into());
                data.insert("TargetUserName".into(), upn.into());
            }
            if let Some(ip) = rec.get("ipAddress").and_then(|v| v.as_str()) {
                data.insert("IpAddress".into(), ip.into());
            }
            if let Some(app) = rec.get("appDisplayName").and_then(|v| v.as_str()) {
                data.insert("appDisplayName".into(), app.into());
            }
            if let Some(client) = rec.get("clientAppUsed").and_then(|v| v.as_str()) {
                data.insert("clientAppUsed".into(), client.into());
            }
            data.insert("errorCode".into(), error_code.to_string());

            Some(EvtxEvent {
                event_id,
                channel: "AzureAD/SignIn".into(),
                timestamp_ns: ts_ns,
                computer: "azure-ad".into(),
                user_sid: None,
                logon_id: None,
                process_id: None,
                thread_id: None,
                data,
            })
        })
        .collect()
}

fn parse_iso8601_ns(s: &str) -> Option<i64> {
    // Try chrono parse
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .or_else(|_| chrono::DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ"))
        .ok()?;
    dt.timestamp_nanos_opt()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SIGNIN: &str = r#"[{"createdDateTime":"2024-01-15T10:30:00Z","userPrincipalName":"user@contoso.com","ipAddress":"203.0.113.5","status":{"errorCode":0},"appDisplayName":"Microsoft Teams","clientAppUsed":"Browser"}]"#;
    const SAMPLE_FAILED: &str = r#"[{"createdDateTime":"2024-01-15T10:31:00Z","userPrincipalName":"attacker@external.com","ipAddress":"198.51.100.10","status":{"errorCode":50126},"appDisplayName":"Azure Portal","clientAppUsed":"Browser"}]"#;

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
        assert_eq!(events[0].event_id, 4624);
    }
    #[test]
    fn parse_failed_signin_maps_to_4625() {
        let events = parse_azure_aad_signin(SAMPLE_FAILED);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 4625);
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
            events[0].data.contains_key("userPrincipalName")
                || events[0].data.contains_key("TargetUserName")
        );
    }
    #[test]
    fn parse_maps_ip_address() {
        let events = parse_azure_aad_signin(SAMPLE_SIGNIN);
        assert!(events[0].data.values().any(|v| v.contains("203.0.113.5")));
    }
    #[test]
    fn parse_multiple_records() {
        let json = format!(
            "[{},{}]",
            &SAMPLE_SIGNIN[1..SAMPLE_SIGNIN.len() - 1],
            &SAMPLE_FAILED[1..SAMPLE_FAILED.len() - 1]
        );
        let events = parse_azure_aad_signin(&json);
        assert_eq!(events.len(), 2);
    }
}
