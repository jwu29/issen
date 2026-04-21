//! STIX 2.1 Attack Flow bundle serialisation for `RapidTriage` findings.

use std::path::Path;

use rt_correlation::model::Finding;

/// A STIX 2.1 bundle with Attack Flow SDOs.
pub struct StixBundle {
    pub id: String,
    pub objects: Vec<serde_json::Value>,
}

/// Convert correlation findings to a STIX 2.1 Attack Flow bundle.
pub fn findings_to_stix_bundle(
    _findings: &[Finding],
    _title: &str,
    _author: Option<&str>,
) -> StixBundle {
    todo!("implement findings_to_stix_bundle")
}

/// Serialize the bundle to a JSON file (pretty-printed, 2-space indent).
pub fn write_stix_bundle(_bundle: &StixBundle, _path: &Path) -> anyhow::Result<()> {
    todo!("implement write_stix_bundle")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rt_correlation::model::{AssertionLevel, Finding};

    fn make_finding(title: &str, severity: &str) -> Finding {
        Finding {
            rule_id: "test.rule".into(),
            title: title.into(),
            severity: severity.into(),
            evidence_ids: vec!["ev-1".into()],
            summary: Some("Summary text".into()),
            explanation: Some("Explanation text".into()),
            confidence: 80,
            assertion_level: AssertionLevel::Correlated,
            evidence_rendered: vec!["line one".into(), "line two".into()],
        }
    }

    #[test]
    fn empty_findings_bundle_has_spec_version() {
        let bundle = findings_to_stix_bundle(&[], "Test Flow", None);
        let json = serde_json::to_string(&serde_json::json!({
            "type": "bundle",
            "id": bundle.id,
            "objects": bundle.objects,
        }))
        .expect("serialize");
        assert!(
            json.contains("\"spec_version\""),
            "serialized bundle must contain spec_version"
        );
    }

    #[test]
    fn empty_findings_bundle_has_extension_definition() {
        let bundle = findings_to_stix_bundle(&[], "Test Flow", None);
        let has_ext_def = bundle
            .objects
            .iter()
            .any(|o| o.get("type").and_then(|t| t.as_str()) == Some("extension-definition"));
        assert!(has_ext_def, "bundle must contain an extension-definition object");
    }

    #[test]
    fn finding_becomes_attack_action() {
        let findings = vec![make_finding("Phishing Email", "high")];
        let bundle = findings_to_stix_bundle(&findings, "Test Flow", None);
        let has_action = bundle
            .objects
            .iter()
            .any(|o| o.get("type").and_then(|t| t.as_str()) == Some("attack-action"));
        assert!(has_action, "one finding must produce one attack-action object");
    }

    #[test]
    fn attack_action_name_matches_finding_title() {
        let findings = vec![make_finding("Lateral Movement via SMB", "high")];
        let bundle = findings_to_stix_bundle(&findings, "Test Flow", None);
        let action = bundle
            .objects
            .iter()
            .find(|o| o.get("type").and_then(|t| t.as_str()) == Some("attack-action"))
            .expect("attack-action must exist");
        assert_eq!(
            action.get("name").and_then(|n| n.as_str()),
            Some("Lateral Movement via SMB"),
            "action name must match finding title"
        );
    }

    #[test]
    fn severity_critical_maps_to_confidence_100() {
        let findings = vec![make_finding("Critical Finding", "critical")];
        let bundle = findings_to_stix_bundle(&findings, "Test Flow", None);
        let action = bundle
            .objects
            .iter()
            .find(|o| o.get("type").and_then(|t| t.as_str()) == Some("attack-action"))
            .expect("attack-action must exist");
        assert_eq!(
            action.get("confidence").and_then(|c| c.as_u64()),
            Some(100),
            "critical severity must map to confidence 100"
        );
    }

    #[test]
    fn write_stix_bundle_creates_file() {
        let bundle = findings_to_stix_bundle(&[], "Test Flow", None);
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("bundle.json");
        write_stix_bundle(&bundle, &path).expect("write_stix_bundle");
        assert!(path.exists(), "output file must be created");
    }
}
