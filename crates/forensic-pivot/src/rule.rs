// RED: stub — types declared but no real logic
use crate::evidence::{EvidenceKind, EvidenceSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AssertionLevel {
    Observed,
    Correlated,
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchClause {
    pub source: Option<EvidenceSource>,
    pub kind: Option<EvidenceKind>,
    pub value_contains: Option<String>,
    #[serde(default)]
    pub attr_eq: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub assertion_level: AssertionLevel,
    pub default_confidence: u8,
    pub clauses: Vec<MatchClause>,
    pub time_window_secs: Option<u64>,
}
