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
use forensicnomicon::attack_events::{technique_for, NativeEventTechnique, FAILED_LOGON_BURST};

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

/// Analyzer severity grade for a native technique. This is a forensic judgment
/// the classifier owns — the `forensicnomicon` knowledge table carries the
/// technique facts, not severity. New techniques default to `High`; downgrade
/// the few that are routinely benign in isolation.
fn severity_for(technique: &str) -> Severity {
    match technique {
        // A privileged logon (4672) is noisy on its own; grade it down.
        "T1078" => Severity::Medium,
        _ => Severity::High,
    }
}

/// Build the `attack.<tactic>`/`attack.<technique-lower>` tag pair the report
/// attack-chain reads, from a knowledge entry.
fn attack_tags(t: &NativeEventTechnique) -> Vec<String> {
    vec![
        format!("attack.{}", t.tactic),
        format!("attack.{}", t.technique.to_ascii_lowercase()),
    ]
}

/// Assemble a [`ScanFinding`] from a knowledge entry plus analyzer-owned
/// presentation (severity, rule name, description, indicator).
fn finding_from(t: &NativeEventTechnique, description: String, indicator: String) -> ScanFinding {
    ScanFinding {
        source: MatchSource::Native,
        severity: severity_for(t.technique),
        rule_name: format!("native-{}", t.technique.to_ascii_lowercase()),
        description,
        matched_indicator: Some(indicator),
        tags: attack_tags(t),
    }
}

/// Classify a *single* event signature into its per-event ATT&CK finding(s),
/// resolved from the [`forensicnomicon::attack_events`] knowledge table. Returns
/// empty for events with no per-event technique (e.g. a lone 4625 — its signal is
/// the aggregate burst, see [`failed_logon_burst_finding`]).
#[must_use]
pub fn classify_event(sig: &NativeEventSignature) -> Vec<ScanFinding> {
    technique_for(sig.event_id, sig.logon_type)
        .map(|t| {
            finding_from(
                t,
                t.description.to_string(),
                format!("EID {}", sig.event_id),
            )
        })
        .into_iter()
        .collect()
}

/// The aggregate brute-force (T1110) finding for `count` failed logons (4625),
/// or `None` below the analyzer's burst threshold. The *threshold* is the
/// analyzer's tuning decision; the *technique* is a fact from the knowledge table.
#[must_use]
pub fn failed_logon_burst_finding(count: usize) -> Option<ScanFinding> {
    if count >= FAILED_LOGON_BURST_THRESHOLD {
        Some(finding_from(
            &FAILED_LOGON_BURST,
            format!(
                "{count} failed logons (EID {}) — consistent with a password brute-force attempt",
                FAILED_LOGON_BURST.event_id
            ),
            format!("{count} x EID {}", FAILED_LOGON_BURST.event_id),
        ))
    } else {
        None
    }
}

/// Classify a batch of native event signatures into ATT&CK-tagged findings —
/// the aggregate burst plus every per-event mapping.
#[must_use]
pub fn classify_native_events(sigs: &[NativeEventSignature]) -> Vec<ScanFinding> {
    let failed = sigs
        .iter()
        .filter(|s| s.event_id == FAILED_LOGON_BURST.event_id)
        .count();
    let mut out: Vec<ScanFinding> = failed_logon_burst_finding(failed).into_iter().collect();
    for sig in sigs {
        out.extend(classify_event(sig));
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

    // ── Provenance-friendly split (D2 wiring needs per-event + burst separately) ──

    #[test]
    fn classify_event_maps_single_rdp_logon() {
        let f = classify_event(&NativeEventSignature::new(4624).with_logon_type(10));
        assert!(f.iter().any(|f| has_tag(f, "attack.t1021.001")));
    }

    #[test]
    fn classify_event_ignores_failed_logon_burst() {
        // A single 4625 is not a per-event technique — the burst is aggregate.
        assert!(classify_event(&NativeEventSignature::new(4625)).is_empty());
    }

    #[test]
    fn failed_logon_burst_finding_fires_at_threshold() {
        assert!(failed_logon_burst_finding(FAILED_LOGON_BURST_THRESHOLD)
            .is_some_and(|f| has_tag(&f, "attack.t1110")));
    }

    #[test]
    fn failed_logon_burst_finding_silent_below_threshold() {
        assert!(failed_logon_burst_finding(FAILED_LOGON_BURST_THRESHOLD - 1).is_none());
    }
}
