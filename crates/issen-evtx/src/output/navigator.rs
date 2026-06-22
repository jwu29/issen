//! ATT&CK Navigator layer.json output from Detection results.

use crate::detections::{Confidence, Detection};
use std::collections::HashMap;

/// Serialize detections to an ATT&CK Navigator layer JSON string.
pub fn to_navigator_layer(detections: &[Detection], layer_name: &str) -> String {
    // Group by technique ID, pick highest confidence
    let mut by_technique: HashMap<&str, (u32, Confidence, &str)> = HashMap::new();
    for det in detections {
        let entry =
            by_technique
                .entry(det.mitre_technique_id)
                .or_insert((0, det.confidence, det.tactic));
        entry.0 += 1;
        if det.confidence > entry.1 {
            entry.1 = det.confidence;
        }
    }

    let techniques: Vec<serde_json::Value> = by_technique
        .iter()
        .map(|(&id, &(count, confidence, tactic))| {
            let color = match confidence {
                Confidence::High => "#ff6666",
                Confidence::Medium => "#ffaa00",
                Confidence::Low => "#ffff66",
            };
            serde_json::json!({
                "techniqueID": id,
                "tactic": tactic,
                "color": color,
                "score": count.min(100),
                "comment": format!("{count} hit(s)"),
            })
        })
        .collect();

    let layer = serde_json::json!({
        "name": layer_name,
        "version": "4.4",
        "domain": "mitre-enterprise-attack",
        "techniques": techniques,
    });

    serde_json::to_string_pretty(&layer).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(serde_json::from_str::<serde_json::Value>(&output).is_ok());
    }

    #[test]
    fn to_navigator_layer_contains_layer_name() {
        let output = to_navigator_layer(&[], "my-investigation");
        assert!(output.contains("my-investigation"));
    }

    #[test]
    fn to_navigator_layer_includes_technique_id() {
        let detections = vec![make_detection("T1558.003", Confidence::High)];
        let output = to_navigator_layer(&detections, "test");
        assert!(output.contains("T1558.003"));
    }

    #[test]
    fn to_navigator_layer_high_confidence_is_red() {
        let detections = vec![make_detection("T1558.003", Confidence::High)];
        let output = to_navigator_layer(&detections, "test");
        assert!(output.contains("#ff6666"));
    }

    #[test]
    fn to_navigator_layer_medium_confidence_is_orange() {
        let detections = vec![make_detection("T1003.001", Confidence::Medium)];
        let output = to_navigator_layer(&detections, "test");
        assert!(output.contains("#ffaa00"));
    }

    #[test]
    fn to_navigator_layer_groups_duplicate_techniques() {
        let detections = vec![
            make_detection("T1558.003", Confidence::High),
            make_detection("T1558.003", Confidence::High),
        ];
        let output = to_navigator_layer(&detections, "test");
        let parsed: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");
        let arr = parsed
            .get("techniques")
            .and_then(|t| t.as_array())
            .expect("techniques array");
        let count = arr
            .iter()
            .filter(|t| t.get("techniqueID").and_then(|v| v.as_str()) == Some("T1558.003"))
            .count();
        assert_eq!(count, 1);
    }
}
