//! Attack Flow STIX 2.1 bundle ingestion for `rt-correlation`.
//!
//! Parses STIX bundles containing Attack Flow custom SDOs and converts them
//! to [`CorrelationRule`] objects for the engine, as well as [`FlowGraph`]
//! for Mermaid rendering.

use std::path::{Path, PathBuf};

use crate::model::{CorrelationRule, EvidenceSource, RuleAttrPredicate, RuleClause};

// ── Public structs ────────────────────────────────────────────────────────────

/// Parsed Attack Flow STIX custom SDO: `attack-action`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackAction {
    pub id: String,
    pub name: String,
    pub tactic_id: Option<String>,
    pub technique_id: Option<String>,
    pub description: Option<String>,
    pub confidence: Option<u8>,
    pub effect_refs: Vec<String>,
}

/// Parsed Attack Flow STIX custom SDO: `attack-operator`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackOperator {
    pub id: String,
    pub operator: String,
    pub effect_refs: Vec<String>,
}

/// Parsed Attack Flow STIX custom SDO: `attack-asset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackAsset {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

/// Parsed Attack Flow STIX custom SDO: `attack-flow` (the root object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackFlowRoot {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub start_refs: Vec<String>,
}

/// Full parsed Attack Flow STIX 2.1 bundle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttackFlowBundle {
    pub flow: Option<AttackFlowRoot>,
    pub actions: Vec<AttackAction>,
    pub operators: Vec<AttackOperator>,
    pub assets: Vec<AttackAsset>,
}

/// Simplified graph node for rendering (avoids importing `rt-report` types).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowNode {
    pub id: String,
    pub label: String,
    pub tactic_id: Option<String>,
    pub technique_id: Option<String>,
}

/// Directed edge in a [`FlowGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEdge {
    pub from: String,
    pub to: String,
}

/// Simplified directed graph for Mermaid rendering or display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowGraph {
    pub title: String,
    pub nodes: Vec<FlowNode>,
    pub edges: Vec<FlowEdge>,
}

// ── Private serde structs ─────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct RawBundle {
    #[serde(rename = "type")]
    type_: String,
    objects: Option<Vec<RawObject>>,
}

#[derive(serde::Deserialize)]
struct RawObject {
    id: Option<String>,
    #[serde(rename = "type")]
    type_: Option<String>,
    name: Option<String>,
    operator: Option<String>,
    tactic_id: Option<String>,
    technique_id: Option<String>,
    description: Option<String>,
    confidence: Option<serde_json::Value>,
    scope: Option<String>,
    #[serde(default)]
    effect_refs: Option<Vec<String>>,
    #[serde(default)]
    start_refs: Option<Vec<String>>,
}

// ── Public functions ──────────────────────────────────────────────────────────

/// Parse a STIX 2.1 bundle JSON string into an [`AttackFlowBundle`].
///
/// Returns `Ok(bundle)` with only attack-flow custom SDOs populated.
/// Ignores identity, extension-definition, relationship, malware, tool, etc.
/// Returns `Err` if the JSON is invalid or the root object is not a bundle.
pub fn parse_attack_flow_bundle(json: &str) -> anyhow::Result<AttackFlowBundle> {
    todo!("parse_attack_flow_bundle stub")
}

/// Convert an [`AttackFlowBundle`] into [`CorrelationRule`] objects.
///
/// Walks the DAG via `effect_refs` (BFS from `start_refs`).
/// Each action with a `technique_id` becomes a [`RuleClause`].
/// Returns an empty vec if no actions have a `technique_id`.
pub fn bundle_to_correlation_rules(bundle: &AttackFlowBundle) -> Vec<CorrelationRule> {
    todo!("bundle_to_correlation_rules stub")
}

/// Convert an [`AttackFlowBundle`] to a [`FlowGraph`] for rendering.
///
/// Actions become nodes. `effect_refs` become edges.
/// Node IDs are sequential short strings: A, B, C…Z, AA, AB…
/// Operators are pass-through (not represented as nodes).
pub fn bundle_to_flow_graph(bundle: &AttackFlowBundle) -> FlowGraph {
    todo!("bundle_to_flow_graph stub")
}

/// Extract and parse all STIX bundles from a corpus zip file.
///
/// Looks for `*.json` files in the zip that are STIX 2.1 bundles containing
/// `attack-flow` objects. Skips schema files and non-STIX JSON.
pub fn extract_bundles_from_zip(zip_path: &Path) -> anyhow::Result<Vec<AttackFlowBundle>> {
    todo!("extract_bundles_from_zip stub")
}

/// Download the Attack Flow v3.0.0 corpus zip from GitHub and save to
/// `cache_dir`. Returns the path to the downloaded zip.
#[cfg(feature = "remote")]
pub fn download_attack_flow_corpus_zip(cache_dir: &Path) -> anyhow::Result<PathBuf> {
    todo!("download_attack_flow_corpus_zip stub")
}

/// Generate a short node ID from an index (0→"A", 25→"Z", 26→"AA", …).
fn short_id(index: usize) -> String {
    let mut n = index;
    let mut result = String::new();
    loop {
        let remainder = n % 26;
        result.insert(0, (b'A' + remainder as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test 1 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_empty_json_returns_err() {
        // "{}" is not a bundle — type field is missing / not "bundle"
        let result = parse_attack_flow_bundle("{}");
        assert!(result.is_err(), "expected Err for non-bundle JSON, got Ok");
    }

    // ── Test 2 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_with_no_attack_objects_returns_empty_bundle() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "identity",
                    "id": "identity--00000000-0000-0000-0000-000000000002",
                    "name": "Test Org"
                },
                {
                    "type": "extension-definition",
                    "id": "extension-definition--00000000-0000-0000-0000-000000000003",
                    "name": "Attack Flow"
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        assert!(bundle.flow.is_none());
        assert!(bundle.actions.is_empty());
        assert!(bundle.operators.is_empty());
        assert!(bundle.assets.is_empty());
    }

    // ── Test 3 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_attack_action_fields() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-action",
                    "id": "attack-action--aaaaaaaa-0000-0000-0000-000000000001",
                    "name": "Phishing",
                    "tactic_id": "TA0001",
                    "technique_id": "T1566.002",
                    "effect_refs": []
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        assert_eq!(bundle.actions.len(), 1);
        let action = &bundle.actions[0];
        assert_eq!(action.name, "Phishing");
        assert_eq!(action.tactic_id, Some("TA0001".to_string()));
        assert_eq!(action.technique_id, Some("T1566.002".to_string()));
    }

    // ── Test 4 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_operator() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-operator",
                    "id": "attack-operator--bbbbbbbb-0000-0000-0000-000000000001",
                    "operator": "AND",
                    "effect_refs": ["attack-action--aaaaaaaa-0000-0000-0000-000000000001"]
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        assert_eq!(bundle.operators.len(), 1);
        assert_eq!(bundle.operators[0].operator, "AND");
    }

    // ── Test 5 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_flow_root() {
        let json = r#"{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-flow",
                    "id": "attack-flow--cccccccc-0000-0000-0000-000000000001",
                    "name": "Test Flow",
                    "scope": "incident",
                    "start_refs": ["attack-action--aaaaaaaa-0000-0000-0000-000000000001"]
                }
            ]
        }"#;
        let bundle = parse_attack_flow_bundle(json).expect("should parse bundle");
        assert!(bundle.flow.is_some());
        let flow = bundle.flow.as_ref().unwrap();
        assert_eq!(flow.name, "Test Flow");
        assert_eq!(
            flow.start_refs,
            vec!["attack-action--aaaaaaaa-0000-0000-0000-000000000001".to_string()]
        );
    }

    // ── Test 6 ────────────────────────────────────────────────────────────────

    #[test]
    fn parse_bundle_extracts_chained_actions() {
        let action_b_id = "attack-action--bbbbbbbb-0000-0000-0000-000000000002";
        let json = format!(
            r#"{{
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000001",
            "spec_version": "2.1",
            "objects": [
                {{
                    "type": "attack-action",
                    "id": "attack-action--aaaaaaaa-0000-0000-0000-000000000001",
                    "name": "Action A",
                    "effect_refs": ["{action_b_id}"]
                }},
                {{
                    "type": "attack-action",
                    "id": "{action_b_id}",
                    "name": "Action B",
                    "effect_refs": []
                }}
            ]
        }}"#
        );
        let bundle = parse_attack_flow_bundle(&json).expect("should parse bundle");
        assert_eq!(bundle.actions.len(), 2);
        let action_a = bundle
            .actions
            .iter()
            .find(|a| a.name == "Action A")
            .expect("Action A not found");
        assert_eq!(action_a.effect_refs, vec![action_b_id.to_string()]);
    }

    // ── Test 7 ────────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_rules_empty_actions_returns_empty() {
        let bundle = AttackFlowBundle::default();
        let rules = bundle_to_correlation_rules(&bundle);
        assert!(rules.is_empty());
    }

    // ── Test 8 ────────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_rules_single_technique_creates_rule() {
        let bundle = AttackFlowBundle {
            flow: None,
            actions: vec![AttackAction {
                id: "attack-action--aaaaaaaa-0000-0000-0000-000000000001".into(),
                name: "Phishing".into(),
                tactic_id: None,
                technique_id: Some("T1566.002".into()),
                description: None,
                confidence: None,
                effect_refs: vec![],
            }],
            operators: vec![],
            assets: vec![],
        };
        let rules = bundle_to_correlation_rules(&bundle);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].clauses[0].required_tag, "technique:T1566.002");
    }

    // ── Test 9 ────────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_rules_chain_creates_multi_clause_rule() {
        let action_b_id = "attack-action--bbbbbbbb-0000-0000-0000-000000000002";
        let flow_id = "attack-flow--cccccccc-0000-0000-0000-000000000001";
        let action_a_id = "attack-action--aaaaaaaa-0000-0000-0000-000000000001";

        let bundle = AttackFlowBundle {
            flow: Some(AttackFlowRoot {
                id: flow_id.into(),
                name: "Test Chain".into(),
                description: None,
                scope: "incident".into(),
                start_refs: vec![action_a_id.into()],
            }),
            actions: vec![
                AttackAction {
                    id: action_a_id.into(),
                    name: "Action A".into(),
                    tactic_id: None,
                    technique_id: Some("T1566.002".into()),
                    description: None,
                    confidence: None,
                    effect_refs: vec![action_b_id.into()],
                },
                AttackAction {
                    id: action_b_id.into(),
                    name: "Action B".into(),
                    tactic_id: None,
                    technique_id: Some("T1059.001".into()),
                    description: None,
                    confidence: None,
                    effect_refs: vec![],
                },
            ],
            operators: vec![],
            assets: vec![],
        };

        let rules = bundle_to_correlation_rules(&bundle);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].clauses.len(), 2);
        assert_eq!(rules[0].clauses[0].required_tag, "technique:T1566.002");
        assert_eq!(rules[0].clauses[1].required_tag, "technique:T1059.001");
    }

    // ── Test 10 ───────────────────────────────────────────────────────────────

    #[test]
    fn bundle_to_flow_graph_creates_nodes_and_edges() {
        let action_b_id = "attack-action--bbbbbbbb-0000-0000-0000-000000000002";
        let bundle = AttackFlowBundle {
            flow: None,
            actions: vec![
                AttackAction {
                    id: "attack-action--aaaaaaaa-0000-0000-0000-000000000001".into(),
                    name: "Action A".into(),
                    tactic_id: None,
                    technique_id: None,
                    description: None,
                    confidence: None,
                    effect_refs: vec![action_b_id.into()],
                },
                AttackAction {
                    id: action_b_id.into(),
                    name: "Action B".into(),
                    tactic_id: None,
                    technique_id: None,
                    description: None,
                    confidence: None,
                    effect_refs: vec![],
                },
            ],
            operators: vec![],
            assets: vec![],
        };
        let graph = bundle_to_flow_graph(&bundle);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
    }

    // ── Helper: short_id ──────────────────────────────────────────────────────

    #[test]
    fn short_id_generates_excel_column_names() {
        assert_eq!(short_id(0), "A");
        assert_eq!(short_id(25), "Z");
        assert_eq!(short_id(26), "AA");
        assert_eq!(short_id(27), "AB");
        assert_eq!(short_id(51), "AZ");
        assert_eq!(short_id(52), "BA");
    }
}
