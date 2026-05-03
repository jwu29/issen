// RED: stub — PivotEngine::evaluate always returns empty (will make tests fail)
use serde::{Deserialize, Serialize};
use crate::evidence::Evidence;
use crate::rule::{AssertionLevel, PivotRule, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub assertion_level: AssertionLevel,
    pub confidence: u8,
    pub matched_evidence: Vec<String>,
    pub description: String,
}

pub struct PivotEngine {
    rules: Vec<PivotRule>,
}

impl PivotEngine {
    pub fn new(rules: Vec<PivotRule>) -> Self {
        Self { rules }
    }

    /// Evaluate all rules against the provided evidence slice.
    /// RED stub: always returns empty — tests will fail.
    pub fn evaluate(&self, _evidence: &[Evidence]) -> Vec<Finding> {
        vec![]
    }
}
