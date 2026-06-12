//! `CORR-MALWARE-PERSIST` — placeholder; implemented in its own RED/GREEN pair.

use crate::evaluator::{RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict.
pub const PERSIST_NOTE: &str =
    "An executable file create followed by a service install naming that image \
     is consistent with service-based persistence (T1543.003).";

/// 24 hours in nanoseconds — the create→service-install window (plan v4 §5.2).
pub const PERSIST_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// The ordered-window rule (placeholder body; finalized in the GREEN commit).
#[must_use]
pub fn persist_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-MALWARE-PERSIST",
        attack_technique: Some("T1543.003"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "FileCreate",
        consequent_event_type: "ServiceInstall",
        window_ns: PERSIST_WINDOW_NS,
        scope: ScopeRule::SameHost,
        note: PERSIST_NOTE,
    }
}
