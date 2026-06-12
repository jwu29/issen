//! Tier-D correlation rules (capstone task #37, plan v4 §5.2 / §5.3, v5 §7.2).
//!
//! The single cross-host rule that models the adversary's *lateral movement*
//! phase — a remote-interactive (RDP, logon type 10) session established into one
//! host, then a second type-10 session established into a *different* host using
//! the *same compromised account*, sourced from the first host's own address.
//! It is the only [`ScopeRule::CrossHost`](crate::evaluator::ScopeRule::CrossHost)
//! rule in the fleet:
//!
//! - **`CORR-LATERAL-MOVE`** — anchor a type-10 `RdpLogon` into host A from an
//!   internal IP; consequent a type-10 `RdpLogon` into host B (a different host)
//!   under the same account, sourced from host A's IP, within ≤ 24 h. Joined on
//!   the account ([`EntityRef::User`]); the five plan §5.3 precision guards are
//!   realised as: (1+4) the host-B logon's source IP ∈ host-A's address
//!   inventory — a Part-A [`guard`]; (2) ordered timing; (3) same account — the
//!   engine entity join; (5) the [`CrossHost`] scope (different target hosts).
//!   ATT&CK: T1021.001 (RDP) → T1078 (valid accounts).
//!
//! Findings are observations: every note says "consistent with", never a
//! verdict. The [`tests::no_tier_d_note_asserts_a_verdict`] test enforces this.
//!
//! [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User
//! [`guard`]: crate::evaluator::RuleSpec::guard
//! [`CrossHost`]: crate::evaluator::ScopeRule::CrossHost

use crate::evaluator::RuleSpec;

pub mod lateral_move;

/// The bundled Tier-D ordered-window rules.
///
/// `CORR-LATERAL-MOVE` carries a Part-A guard for its source-IP-inventory
/// precision and runs over the generic engine under the `CrossHost` scope; only
/// its `evaluate_*` wrapper attaches the IP entities the guard reads.
#[must_use]
pub fn tier_d_rules() -> Vec<RuleSpec> {
    vec![lateral_move::lateral_move_rule()]
}

#[cfg(test)]
pub(crate) mod testkit {
    use issen_core::timeline::event::EntityRef;

    use crate::evaluator::{EventSource, EventView};

    /// A synthetic event for Tier-D rule unit tests. Like the Tier-A testkit it
    /// carries only entity refs (the source IP and the account); the lateral-move
    /// guard reads the IP entities rather than a path.
    #[derive(Debug, Clone)]
    pub struct TestEvent {
        pub id: u64,
        pub ts: i64,
        pub event_type: String,
        pub entity_refs: Vec<EntityRef>,
        pub host: Option<String>,
        pub source: EventSource,
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
            }
        }

        #[must_use]
        pub fn with_entity(mut self, e: EntityRef) -> Self {
            self.entity_refs.push(e);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_carries_the_tier_d_rules() {
        let codes: Vec<&str> = tier_d_rules().iter().map(|r| r.code).collect();
        assert!(codes.contains(&"CORR-LATERAL-MOVE"));
    }

    /// Epistemics gate (plan v5 §7.5): every Tier-D note is an observation, not a
    /// verdict. It must say "consistent with" and never assert proof.
    #[test]
    fn no_tier_d_note_asserts_a_verdict() {
        let forbidden = ["confirm", "prove", "proof", "exceed", "undoubtedly", "certainly"];
        let notes: Vec<&str> = tier_d_rules().iter().map(|r| r.note).collect();
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
