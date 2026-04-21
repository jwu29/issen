//! Attack Flow Builder `.afb` JSON file serialisation.

use std::collections::HashMap;
use std::path::Path;

use rt_correlation::model::Finding;

/// Auto-layout algorithm for DAG nodes.
///
/// Returns a `HashMap` of `instance_id -> [x, y]` coordinates.
pub fn auto_layout_dag(
    _node_ids: &[&str],
    _edges: &[(&str, &str)],
    _x_spacing: f64,
    _y_spacing: f64,
) -> HashMap<String, [f64; 2]> {
    todo!("implement auto_layout_dag")
}

/// A camera position for an `AfbDocument`.
#[derive(serde::Serialize)]
pub struct AfbCamera {
    pub x: f64,
    pub y: f64,
    pub k: f64,
}

/// A single object in an `AfbDocument`.
#[derive(serde::Serialize)]
pub struct AfbObject {
    pub id: String,
    pub instance: String,
    pub properties: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<String>>,
}

/// An Attack Flow Builder document.
#[derive(serde::Serialize)]
pub struct AfbDocument {
    pub schema: String,
    pub theme: String,
    pub objects: Vec<AfbObject>,
    pub layout: HashMap<String, [f64; 2]>,
    pub camera: AfbCamera,
}

/// Convert a slice of `Finding`s to an `AfbDocument`.
pub fn findings_to_afb(_findings: &[Finding], _title: &str) -> AfbDocument {
    todo!("implement findings_to_afb")
}

/// Write `AfbDocument` to a `.afb` file (pretty JSON, 2-space indent).
pub fn write_afb(_doc: &AfbDocument, _path: &Path) -> anyhow::Result<()> {
    todo!("implement write_afb")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rt_correlation::model::{AssertionLevel, Finding};

    fn make_finding(title: &str) -> Finding {
        Finding {
            rule_id: "test.rule".into(),
            title: title.into(),
            severity: "medium".into(),
            evidence_ids: vec![],
            summary: None,
            explanation: Some("Some explanation".into()),
            confidence: 70,
            assertion_level: AssertionLevel::Correlated,
            evidence_rendered: vec![],
        }
    }

    #[test]
    fn afb_schema_is_attack_flow_v2() {
        let doc = findings_to_afb(&[], "Test Flow");
        assert_eq!(doc.schema, "attack_flow_v2");
    }

    #[test]
    fn afb_has_dark_theme() {
        let doc = findings_to_afb(&[], "Test Flow");
        assert_eq!(doc.theme, "dark_theme");
    }

    #[test]
    fn auto_layout_single_node_at_origin() {
        let coords = auto_layout_dag(&["A"], &[], 300.0, 200.0);
        let pos = coords.get("A").expect("node A must be in layout");
        assert_eq!(*pos, [0.0, 0.0], "single node must be at origin");
    }

    #[test]
    fn auto_layout_linear_chain_increasing_x() {
        let coords = auto_layout_dag(&["A", "B", "C"], &[("A", "B"), ("B", "C")], 300.0, 200.0);
        let xa = coords.get("A").expect("node A")[0];
        let xb = coords.get("B").expect("node B")[0];
        let xc = coords.get("C").expect("node C")[0];
        assert_eq!(xa, 0.0, "root node A must have x=0");
        assert_eq!(xb, 300.0, "node B must have x=300");
        assert_eq!(xc, 600.0, "node C must have x=600");
    }

    #[test]
    fn auto_layout_parallel_nodes_different_y() {
        // A -> B and A -> C: B and C are in the same layer but different rows
        let coords =
            auto_layout_dag(&["A", "B", "C"], &[("A", "B"), ("A", "C")], 300.0, 200.0);
        let yb = coords.get("B").expect("node B")[1];
        let yc = coords.get("C").expect("node C")[1];
        let xb = coords.get("B").expect("node B")[0];
        let xc = coords.get("C").expect("node C")[0];
        assert_eq!(xb, xc, "parallel nodes B and C must have the same x");
        assert_ne!(yb, yc, "parallel nodes B and C must have different y");
    }

    #[test]
    fn write_afb_creates_file() {
        let doc = findings_to_afb(&[make_finding("Test Finding")], "Test Flow");
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("output.afb");
        write_afb(&doc, &path).expect("write_afb");
        assert!(path.exists(), "output .afb file must be created");
    }
}
