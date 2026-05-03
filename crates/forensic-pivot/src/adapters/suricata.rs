//! Suricata EVE JSON adapter.
//!
//! Converts Suricata EVE JSON alert events into `Evidence` objects.

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_EVE: &str = r#"{
        "event_type": "alert",
        "timestamp": "2026-01-01T00:00:00.000000+0000",
        "src_ip": "192.168.1.100",
        "src_port": 4444,
        "dest_ip": "10.0.0.1",
        "dest_port": 3333,
        "alert": {
            "action": "allowed",
            "signature_id": 12345,
            "signature": "ET MINING XMRig"
        }
    }"#;

    #[test]
    fn test_eve_alert_parses_valid_json() {
        let result = EveAlert::from_json_line(VALID_EVE).expect("should parse");
        let alert = result.expect("should be Some for alert event");
        assert_eq!(alert.src_ip, "192.168.1.100");
        assert_eq!(alert.src_port, 4444);
        assert_eq!(alert.dest_ip, "10.0.0.1");
        assert_eq!(alert.dest_port, 3333);
        assert_eq!(alert.signature, "ET MINING XMRig");
        assert_eq!(alert.signature_id, 12345);
        assert_eq!(alert.action, "allowed");
    }

    #[test]
    fn test_eve_alert_converts_to_evidence_with_suricata_source() {
        use crate::evidence::{Evidence, EvidenceSource};
        let alert = EveAlert::from_json_line(VALID_EVE)
            .expect("parse ok")
            .expect("is alert");
        let ev: Evidence = alert.into();
        assert_eq!(ev.source, EvidenceSource::Suricata);
    }

    #[test]
    fn test_eve_alert_sets_network_kind() {
        use crate::evidence::{Evidence, EvidenceKind};
        let alert = EveAlert::from_json_line(VALID_EVE)
            .expect("parse ok")
            .expect("is alert");
        let ev: Evidence = alert.into();
        assert_eq!(ev.kind, EvidenceKind::Custom("Network".to_string()));
    }

    #[test]
    fn test_eve_alert_captures_src_and_dest_ip_in_attrs() {
        use crate::evidence::Evidence;
        let alert = EveAlert::from_json_line(VALID_EVE)
            .expect("parse ok")
            .expect("is alert");
        let ev: Evidence = alert.into();
        assert_eq!(ev.attrs.get("src_ip").map(|s| s.as_str()), Some("192.168.1.100"));
        assert_eq!(ev.attrs.get("dest_ip").map(|s| s.as_str()), Some("10.0.0.1"));
        assert_eq!(ev.attrs.get("src_port").map(|s| s.as_str()), Some("4444"));
        assert_eq!(ev.attrs.get("dest_port").map(|s| s.as_str()), Some("3333"));
    }

    #[test]
    fn test_eve_non_alert_event_returns_none() {
        let dns_event = r#"{"event_type": "dns", "timestamp": "2026-01-01T00:00:00Z"}"#;
        let result = EveAlert::from_json_line(dns_event).expect("should parse");
        assert!(result.is_none(), "non-alert events should return None");
    }
}
