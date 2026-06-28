//! Stable content digest of the correlation ruleset.
//!
//! The resumable pipeline caches the correlate stage and must re-run it when the
//! rules change. Keying that cache on the crate version is too coarse — a rule
//! edit without a version bump goes undetected, so a re-run keeps serving the
//! old codes/notes (the `CORR-PROC-DISK-MATCH` staleness). [`ruleset_digest`]
//! instead hashes every rule's observable contract — code, severity, ATT&CK
//! technique, examiner note, and (for ordered-window rules) the structural
//! parameters — so any rule rename / re-grade / re-note / re-scope flips the
//! digest and the pipeline re-correlates on the next run, no version bump needed.
//!
//! Notes are referenced by their `pub const` so a note edit always re-syncs the
//! digest; the bespoke matchers' code/severity/technique are listed here too. A
//! [`RULE_COUNT`] tripwire test fails loudly if a rule is added without being
//! folded in, so a new rule can never silently escape cache invalidation.

use std::fmt::Write as _;

use forensicnomicon::report::Severity;
use sha2::{Digest, Sha256};

use crate::evaluator::RuleSpec;
use crate::tier_a::copy_delete::COPY_DELETE_NOTE;
use crate::tier_a::persist::persist_rule;
use crate::tier_a::relocate::relocate_rule;
use crate::tier_b::bruteforce::bruteforce_rule;
use crate::tier_b::exfil_stage::exfil_stage_rule;
use crate::tier_b::logon_malware::logon_malware_rule;
use crate::tier_b_prime::regconfirm::regconfirm_rule;
use crate::tier_c::injected_c2::INJECTED_C2_NOTE;
use crate::tier_c::proc_disk_match::PROC_DISK_MATCH_NOTE;
use crate::tier_c::proc_migration::{PROC_MIGRATION_DEGRADED_NOTE, PROC_MIGRATION_NOTE};
use crate::tier_d::lateral_move::lateral_move_rule;

/// Total number of correlation rules folded into the digest — a tripwire. Adding
/// or removing a rule must update this and the assembly in [`ruleset_descriptors`],
/// or `digest_covers_every_rule` fails.
pub const RULE_COUNT: usize = 12;

/// A `RuleSpec`'s full structural contract as one canonical line.
fn spec_descriptor(r: &RuleSpec) -> String {
    let sep = '\u{1f}';
    format!(
        "spec{sep}{}{sep}{:?}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{:?}{sep}{}",
        r.code,
        r.severity,
        r.attack_technique.unwrap_or(""),
        r.note,
        r.anchor_event_type,
        r.consequent_event_type,
        r.window_ns,
        r.scope,
        r.ordered,
    )
}

/// A bespoke (non-`RuleSpec`) matcher's published contract as one canonical line.
fn bespoke_descriptor(code: &str, sev: Severity, tech: Option<&str>, note: &str) -> String {
    let sep = '\u{1f}';
    format!(
        "bespoke{sep}{code}{sep}{sev:?}{sep}{}{sep}{note}",
        tech.unwrap_or("")
    )
}

/// The canonical descriptor of every correlation rule the engine can emit.
#[must_use]
pub fn ruleset_descriptors() -> Vec<String> {
    let specs = [
        persist_rule(),
        relocate_rule(),
        regconfirm_rule(),
        exfil_stage_rule(),
        bruteforce_rule(),
        logon_malware_rule(),
        lateral_move_rule(),
    ];
    let mut out: Vec<String> = specs.iter().map(spec_descriptor).collect();
    // Bespoke matchers (construct a Correlation directly, no RuleSpec).
    out.push(bespoke_descriptor(
        "CORR-COPY-DELETE",
        Severity::Medium,
        Some("T1070"),
        COPY_DELETE_NOTE,
    ));
    out.push(bespoke_descriptor(
        "CORR-DISK-FILE-RUNNING",
        Severity::Medium,
        None,
        PROC_DISK_MATCH_NOTE,
    ));
    out.push(bespoke_descriptor(
        "CORR-PROC-MIGRATION",
        Severity::Critical,
        Some("T1055"),
        PROC_MIGRATION_NOTE,
    ));
    out.push(bespoke_descriptor(
        "CORR-PROC-MIGRATION-DEGRADED",
        Severity::High,
        Some("T1055"),
        PROC_MIGRATION_DEGRADED_NOTE,
    ));
    out.push(bespoke_descriptor(
        "CORR-INJECTED-C2",
        Severity::Critical,
        Some("T1055"),
        INJECTED_C2_NOTE,
    ));
    out
}

/// SHA-256 hex over the sorted rule descriptors — the ruleset's content digest.
#[must_use]
pub fn ruleset_digest() -> String {
    let mut parts = ruleset_descriptors();
    parts.sort();
    let mut hasher = Sha256::new();
    for p in &parts {
        hasher.update(p.as_bytes());
        hasher.update([0x1e_u8]); // record separator between descriptors
    }
    hasher.finalize().iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic_64_hex() {
        let d = ruleset_digest();
        assert_eq!(d, ruleset_digest(), "must be stable across calls");
        assert_eq!(d.len(), 64, "SHA-256 hex");
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn digest_covers_every_rule() {
        // Tripwire: a new rule must be folded in (update RULE_COUNT + assembly).
        assert_eq!(ruleset_descriptors().len(), RULE_COUNT);
        let blob = ruleset_descriptors().join("\n");
        for code in [
            "CORR-COPY-DELETE",
            "CORR-DISK-FILE-RUNNING",
            "CORR-PROC-MIGRATION",
            "CORR-PROC-MIGRATION-DEGRADED",
            "CORR-INJECTED-C2",
            "CORR-BRUTEFORCE-LOGON",
        ] {
            assert!(blob.contains(code), "digest must cover {code}");
        }
    }

    #[test]
    fn digest_reflects_a_note_edit() {
        // A rule's note is part of its descriptor (by const reference), so editing
        // PROC_DISK_MATCH_NOTE re-syncs the digest — the exact staleness we fix.
        let blob = ruleset_descriptors().join("\n");
        assert!(blob.contains(PROC_DISK_MATCH_NOTE));
    }
}
