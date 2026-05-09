//! ATT&CK Navigator layer.json output from Detection results.

use crate::detections::Detection;

/// A single technique entry in an ATT&CK Navigator layer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NavigatorTechnique {
    /// ATT&CK technique ID (e.g. "T1558.003").
    #[serde(rename = "techniqueID")]
    pub technique_id: String,
    /// Tactic (e.g. "credential-access").
    pub tactic: String,
    /// Color to render in Navigator (based on confidence).
    pub color: String,
    /// Comment / description.
    pub comment: String,
    /// Score (0-100, based on hit count).
    pub score: u32,
}

/// Serialize detections to an ATT&CK Navigator layer JSON string.
///
/// Groups by technique ID, accumulates hit counts, and maps confidence to color:
/// - High   → `#ff6666` (red)
/// - Medium → `#ffaa00` (orange)
/// - Low    → `#ffff66` (yellow)
pub fn to_navigator_layer(detections: &[Detection], layer_name: &str) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detections::{Confidence, Detection};
    use winevt_core::EvtxEvent;
    use std::collections::HashMap;

    fn make_detection(technique_id: &'static str, confidence: Confidence) -> Detection {
        Detection {
            technique: "Test Technique",
            mitre_technique_id: technique_id,
            tactic: "credential-access",
            confidence,
            evidence: vec![],
            description: "test".into(),
        }
    }

    #[test]
    fn to_navigator_layer_empty_detections_valid_json() {
        let output = to_navigator_layer(&[], "test-layer");
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&output);
        assert!(parsed.is_ok(), "empty detections should produce valid JSON");
    }

    #[test]
    fn to_navigator_layer_contains_layer_name() {
        let output = to_navigator_layer(&[], "my-investigation");
        assert!(
            output.contains("my-investigation"),
            "layer name should appear in output"
        );
    }

    #[test]
    fn to_navigator_layer_includes_technique_id() {
        let detections = vec![make_detection("T1558.003", Confidence::High)];
        let output = to_navigator_layer(&detections, "test");
        assert!(
            output.contains("T1558.003"),
            "technique ID should appear in layer output"
        );
    }

    #[test]
    fn to_navigator_layer_high_confidence_is_red() {
        let detections = vec![make_detection("T1558.003", Confidence::High)];
        let output = to_navigator_layer(&detections, "test");
        assert!(
            output.contains("#ff6666"),
            "High confidence should use red color"
        );
    }

    #[test]
    fn to_navigator_layer_medium_confidence_is_orange() {
        let detections = vec![make_detection("T1003.001", Confidence::Medium)];
        let output = to_navigator_layer(&detections, "test");
        assert!(
            output.contains("#ffaa00"),
            "Medium confidence should use orange color"
        );
    }

    #[test]
    fn to_navigator_layer_groups_duplicate_techniques() {
        let detections = vec![
            make_detection("T1558.003", Confidence::High),
            make_detection("T1558.003", Confidence::High),
        ];
        let output = to_navigator_layer(&detections, "test");
        let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        // Find techniques array
        let techniques = parsed.pointer("/techniques")
            .or_else(|| parsed.get("techniques"))
            .expect("techniques key");
        let arr = techniques.as_array().expect("techniques is array");
        // Should have exactly one entry for T1558.003 (grouped)
        let t1558_count = arr.iter()
            .filter(|t| t.get("techniqueID").and_then(|v| v.as_str()) == Some("T1558.003"))
            .count();
        assert_eq!(t1558_count, 1, "duplicate techniques should be grouped into one entry");
    }
}
