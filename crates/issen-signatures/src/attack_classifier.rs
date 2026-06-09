//! Native event → MITRE ATT&CK classifier (no Sigma required).
//!
//! Task D1. The scan phase is YARA/Sigma/hash/IOC only today; this module adds a
//! small, data-driven classifier that maps *native* Windows event signatures
//! (event IDs, logon types) directly to [`ScanFinding`]s carrying ATT&CK tactic
//! and technique tags. The report's attack-chain reads `attack.<tactic>` tags,
//! so a finding charted here lands in the chain without any Sigma ruleset.
//!
//! Findings are observations consistent with the named technique — never a
//! verdict. The tribunal draws the conclusion.

use crate::matching::results::{MatchSource, ScanFinding, Severity};

/// Failed-logon (4625) count at or above which a brute-force (T1110) finding
/// fires. A burst, not a single failure, is the signal.
pub const FAILED_LOGON_BURST_THRESHOLD: usize = 5;

/// A normalized native event signature the classifier keys on.
///
/// Deliberately minimal: just the fields the case-001 techniques need. Extend
/// additively as more native detections are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeEventSignature {
    /// Windows event ID (e.g. `4624`, `4625`, `7045`, `4672`).
    pub event_id: u32,
    /// Logon type for 4624/4625 (e.g. `10` = RemoteInteractive/RDP), else `None`.
    pub logon_type: Option<u32>,
}

impl NativeEventSignature {
    /// Construct a signature from an event ID, with no logon type.
    #[must_use]
    pub fn new(event_id: u32) -> Self {
        Self {
            event_id,
            logon_type: None,
        }
    }

    /// Builder: attach a logon type.
    #[must_use]
    pub fn with_logon_type(mut self, logon_type: u32) -> Self {
        self.logon_type = Some(logon_type);
        self
    }
}

/// A per-event mapping rule: one matching signature → one finding.
struct PerEventRule {
    /// Windows event ID to match.
    event_id: u32,
    /// Required logon type, or `None` to match any.
    logon_type: Option<u32>,
    /// ATT&CK technique ID, e.g. `"T1021.001"`.
    technique: &'static str,
    /// ATT&CK tactic in `attack.<tactic>` form, e.g. `"persistence"`.
    tactic: &'static str,
    /// Stable rule name.
    rule_name: &'static str,
    /// Graded severity.
    severity: Severity,
    /// Human-readable description.
    description: &'static str,
}

/// The data-driven per-event mapping table. Add a row to extend coverage.
const PER_EVENT_RULES: &[PerEventRule] = &[
    PerEventRule {
        event_id: 4624,
        logon_type: Some(10),
        technique: "T1021.001",
        tactic: "initial_access",
        rule_name: "rdp-interactive-logon",
        severity: Severity::High,
        description: "Type-10 (RemoteInteractive/RDP) successful logon",
    },
    PerEventRule {
        event_id: 7045,
        logon_type: None,
        technique: "T1543.003",
        tactic: "persistence",
        rule_name: "windows-service-install",
        severity: Severity::High,
        description: "New Windows service installed (7045)",
    },
    PerEventRule {
        event_id: 4672,
        logon_type: None,
        technique: "T1078",
        tactic: "privilege_escalation",
        rule_name: "privileged-logon",
        severity: Severity::Medium,
        description: "Privileged (admin-equivalent) logon assigned (4672)",
    },
];

/// Build the ATT&CK tag pair `["attack.<tactic>", "attack.<technique-lower>"]`.
fn attack_tags(tactic: &str, technique: &str) -> Vec<String> {
    vec![
        format!("attack.{tactic}"),
        format!("attack.{}", technique.to_ascii_lowercase()),
    ]
}

/// Classify a batch of native event signatures into ATT&CK-tagged findings.
///
/// Handles both per-event mappings (a single 4624 type-10 → T1021.001) and
/// aggregate ones (a burst of 4625 failures → T1110).
#[must_use]
pub fn classify_native_events(sigs: &[NativeEventSignature]) -> Vec<ScanFinding> {
    let mut out = Vec::new();

    // Aggregate: a burst of failed logons (4625) → brute force (T1110).
    let failed = sigs.iter().filter(|s| s.event_id == 4625).count();
    if failed >= FAILED_LOGON_BURST_THRESHOLD {
        out.push(ScanFinding {
            source: MatchSource::Native,
            severity: Severity::High,
            rule_name: "failed-logon-burst".to_string(),
            description: format!(
                "{failed} failed logons (4625) — consistent with a password brute-force attempt"
            ),
            matched_indicator: Some(format!("{failed} x EID 4625")),
            tags: attack_tags("initial_access", "T1110"),
        });
    }

    // Per-event mappings.
    for sig in sigs {
        for rule in PER_EVENT_RULES {
            let id_matches = sig.event_id == rule.event_id;
            let type_matches = rule.logon_type.map_or(true, |lt| sig.logon_type == Some(lt));
            if id_matches && type_matches {
                out.push(ScanFinding {
                    source: MatchSource::Native,
                    severity: rule.severity,
                    rule_name: rule.rule_name.to_string(),
                    description: rule.description.to_string(),
                    matched_indicator: Some(format!("EID {}", rule.event_id)),
                    tags: attack_tags(rule.tactic, rule.technique),
                });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_tag(f: &ScanFinding, tag: &str) -> bool {
        f.tags.iter().any(|t| t == tag)
    }

    #[test]
    fn failed_logon_burst_emits_t1110_initial_access() {
        let sigs: Vec<_> = (0..FAILED_LOGON_BURST_THRESHOLD)
            .map(|_| NativeEventSignature::new(4625))
            .collect();
        let findings = classify_native_events(&sigs);
        let bf = findings
            .iter()
            .find(|f| has_tag(f, "attack.t1110"))
            .expect("brute-force finding must fire at threshold");
        assert_eq!(bf.source, MatchSource::Native);
        assert!(has_tag(bf, "attack.initial_access"));
    }

    #[test]
    fn below_threshold_no_brute_force() {
        let sigs: Vec<_> = (0..FAILED_LOGON_BURST_THRESHOLD - 1)
            .map(|_| NativeEventSignature::new(4625))
            .collect();
        let findings = classify_native_events(&sigs);
        assert!(!findings.iter().any(|f| has_tag(f, "attack.t1110")));
    }

    #[test]
    fn rdp_logon_type_10_emits_t1021_001() {
        let sigs = vec![NativeEventSignature::new(4624).with_logon_type(10)];
        let findings = classify_native_events(&sigs);
        let f = findings
            .iter()
            .find(|f| has_tag(f, "attack.t1021.001"))
            .expect("RDP logon must map to T1021.001");
        assert!(has_tag(f, "attack.initial_access"));
        assert_eq!(f.source, MatchSource::Native);
    }

    #[test]
    fn interactive_logon_type_2_does_not_emit_rdp() {
        // A console (type-2) logon is not lateral movement.
        let sigs = vec![NativeEventSignature::new(4624).with_logon_type(2)];
        let findings = classify_native_events(&sigs);
        assert!(!findings.iter().any(|f| has_tag(f, "attack.t1021.001")));
    }

    #[test]
    fn service_install_7045_emits_t1543_003_persistence() {
        let sigs = vec![NativeEventSignature::new(7045)];
        let findings = classify_native_events(&sigs);
        let f = findings
            .iter()
            .find(|f| has_tag(f, "attack.t1543.003"))
            .expect("service install must map to T1543.003");
        assert!(has_tag(f, "attack.persistence"));
    }

    #[test]
    fn privileged_logon_4672_emits_finding() {
        let sigs = vec![NativeEventSignature::new(4672)];
        let findings = classify_native_events(&sigs);
        assert!(
            findings
                .iter()
                .any(|f| has_tag(f, "attack.privilege_escalation")),
            "4672 must emit a privileged-logon finding"
        );
    }

    #[test]
    fn unknown_event_id_yields_nothing() {
        let sigs = vec![NativeEventSignature::new(4634)];
        assert!(classify_native_events(&sigs).is_empty());
    }
}
