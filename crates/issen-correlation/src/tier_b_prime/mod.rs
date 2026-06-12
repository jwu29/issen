//! Tier-B′ correlation rules (capstone task #37, plan v4 §5.2 row ★, v5 §7.2).
//!
//! The single rule that *corroborates* an EVTX persistence event with a second,
//! independent artifact source — the registry. Tier A's `CORR-MALWARE-PERSIST`
//! fires on a file-create→service-install pair entirely within the disk/EVTX
//! legs; this rule strengthens the persistence finding by joining the same 7045
//! `ServiceInstall` to a **registry** event (a `Run` key value or a
//! `...\Services\<name>` key) that names the same image/service:
//!
//! - **`CORR-PERSIST-REGCONFIRM`** — anchor a 7045 `ServiceInstall` (EVTX),
//!   consequent a `RegistryModify` (registry leg) of a Run key or
//!   `Services\<name>` key naming the same image/service. Joined on the
//!   image/service *stem* (the same [`stem_entity`] normalization Tier-A PERSIST
//!   uses), same host, within ≤ 24 h. ATT&CK: T1543.003 (Windows service) /
//!   T1547.001 (Run key). This is a cross-artifact-source corroboration
//!   (EVTX ↔ registry), the defining Tier-B′ trait.
//!
//! Findings are observations: every note says "consistent with", never a
//! verdict. The [`tests::no_tier_b_prime_note_asserts_a_verdict`] test enforces
//! this.
//!
//! [`stem_entity`]: crate::tier_a::stem_entity

use crate::evaluator::RuleSpec;

pub mod regconfirm;

/// The bundled Tier-B′ ordered-window rules.
///
/// `CORR-PERSIST-REGCONFIRM` joins on the image/service stem (the Tier-A PERSIST
/// normalization) and runs over the generic engine under `SameHost`; its
/// `evaluate_*` wrapper attaches the stem join entities both sides carry.
#[must_use]
pub fn tier_b_prime_rules() -> Vec<RuleSpec> {
    vec![regconfirm::regconfirm_rule()]
}

#[cfg(test)]
pub(crate) mod testkit {
    use issen_core::timeline::event::EntityRef;

    use crate::evaluator::{EventSource, EventView};

    /// A synthetic event for Tier-B′ rule unit tests. Carries entity refs (the
    /// image/service stem) plus the full `artifact_path` (the registry key path
    /// or service `ImagePath`), modeling the documented registry/EVTX event
    /// shape.
    #[derive(Debug, Clone)]
    pub struct TestEvent {
        pub id: u64,
        pub ts: i64,
        pub event_type: String,
        pub entity_refs: Vec<EntityRef>,
        pub host: Option<String>,
        pub source: EventSource,
        pub path: String,
    }

    impl TestEvent {
        pub fn new(id: u64, ts: i64, event_type: &str, host: &str, source: EventSource) -> Self {
            Self {
                id,
                ts,
                event_type: event_type.to_string(),
                entity_refs: Vec::new(),
                host: Some(host.to_string()),
                source,
                path: String::new(),
            }
        }

        #[must_use]
        pub fn with_entity(mut self, e: EntityRef) -> Self {
            self.entity_refs.push(e);
            self
        }

        #[must_use]
        pub fn with_path(mut self, p: &str) -> Self {
            self.path = p.to_string();
            self
        }
    }

    impl EventView for TestEvent {
        fn id(&self) -> u64 {
            self.id
        }
        fn timestamp_ns(&self) -> i64 {
            self.ts
        }
        fn event_type(&self) -> &str {
            &self.event_type
        }
        fn entity_refs(&self) -> &[EntityRef] {
            &self.entity_refs
        }
        fn hostname(&self) -> Option<&str> {
            self.host.as_deref()
        }
        fn source(&self) -> EventSource {
            self.source
        }
        fn artifact_path(&self) -> &str {
            &self.path
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_carries_the_tier_b_prime_rules() {
        let codes: Vec<&str> = tier_b_prime_rules().iter().map(|r| r.code).collect();
        assert!(codes.contains(&"CORR-PERSIST-REGCONFIRM"));
    }

    /// Epistemics gate (plan v5 §7.5): every Tier-B′ note is an observation, not
    /// a verdict. It must say "consistent with" and never assert proof.
    #[test]
    fn no_tier_b_prime_note_asserts_a_verdict() {
        let forbidden = ["confirm", "prove", "proof", "exceed", "undoubtedly", "certainly"];
        let notes: Vec<&str> = tier_b_prime_rules().iter().map(|r| r.note).collect();
        for note in notes {
            let lower = note.to_ascii_lowercase();
            assert!(
                lower.contains("consistent with"),
                "note must hedge with 'consistent with': {note:?}"
            );
            for needle in forbidden {
                assert!(
                    !lower.contains(needle),
                    "note must not assert a verdict ({needle:?}): {note:?}"
                );
            }
        }
    }
}
