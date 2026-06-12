//! `CORR-LATERAL-MOVE` (plan v4 §5.2 / §5.3, v5 §7.2).
//!
//! A remote-interactive logon (4624 **type 10 / RDP**) into host A from an
//! internal IP, then a 4624 **type 10** logon into a *different* host B using the
//! **same account**, sourced from host A's IP, within ≤ 24 h — a DC→Desktop
//! pivot on a single reused credential. The two events are joined on the account
//! ([`EntityRef::User`]); the host-A-IP-inventory precision lives in a Part-A
//! [`guard`](crate::evaluator::RuleSpec::guard) that checks the host-B logon's
//! source IP against host A's own address inventory. This is the fleet's only
//! [`CrossHost`](crate::evaluator::ScopeRule::CrossHost) rule.
//!
//! The §5.3 five guards map to the engine as follows:
//! 1. host-A address inventory ⊇ host-B source IP — the [`guard`];
//! 2. ordered timing (host-A logon strictly before host-B logon, ≤ 24 h) — the
//!    `ordered`/`window_ns` fields;
//! 3. same account as the host-A chain — the engine's [`EntityRef::User`] join,
//!    re-asserted inside the [`guard`] (the engine's any-shared-entity join is
//!    structurally satisfied by the shared host-A source IP of guard 4, so the
//!    account-equality must be enforced explicitly rather than relied on);
//! 4. host-B 4624 source IP ∈ host-A inventory — the same [`guard`] as (1);
//! 5. different target hosts — the [`CrossHost`](crate::evaluator::ScopeRule::CrossHost)
//!    scope.
//!
//! ATT&CK: T1021.001 (Remote Desktop Protocol) → T1078 (valid accounts).
//!
//! [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User
//! [`guard`]: crate::evaluator::RuleSpec::guard

use issen_core::timeline::event::EntityRef;

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict.
pub const LATERAL_MOVE_NOTE: &str =
    "A remote-interactive (RDP) logon into one host followed by a second \
     remote-interactive logon into a different host under the same account, \
     sourced from the first host's address, is consistent with lateral movement \
     on a reused credential (T1021.001 / T1078).";

/// 24 hours in nanoseconds — the host-A→host-B pivot window (plan v4 §5.3).
pub const LATERAL_MOVE_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// The IP-address values an event carries as [`EntityRef::Ip`] join entities.
fn ip_entities(event: &dyn EventView) -> impl Iterator<Item = &str> {
    event.entity_refs().iter().filter_map(|e| match e {
        EntityRef::Ip(ip) => Some(ip.as_str()),
        _ => None,
    })
}

/// The account ([`EntityRef::User`]) values an event carries.
fn user_entities(event: &dyn EventView) -> impl Iterator<Item = &str> {
    event.entity_refs().iter().filter_map(|e| match e {
        EntityRef::User(u) => Some(u.as_str()),
        _ => None,
    })
}

/// The Part-A per-pair guard (plan §5.3 guards 1, 3 and 4). The engine's
/// any-shared-entity join is structurally satisfied by the shared host-A source
/// IP (guard 4), so the *account-equality* (guard 3) and *IP-in-inventory*
/// (guards 1+4) constraints both live in the guard — the IP join alone would let
/// a different-account pair through. Both must hold:
///
/// - the host-B logon and the host-A logon name the **same account**; and
/// - the host-B logon's source IP is present in host A's address inventory (the
///   anchor's [`EntityRef::Ip`] entities), i.e. host B was reached *from* host A.
fn same_account_from_host_a_ip(anchor: &dyn EventView, consequent: &dyn EventView) -> bool {
    let accounts: Vec<&str> = user_entities(anchor).collect();
    let same_account = user_entities(consequent).any(|u| accounts.contains(&u));

    let inventory: Vec<&str> = ip_entities(anchor).collect();
    let from_host_a = ip_entities(consequent).any(|src| inventory.contains(&src));

    same_account && from_host_a
}

/// The ordered-window cross-host rule. Anchor `RdpLogon` (4624 type 10) into host
/// A, consequent `RdpLogon` (4624 type 10) into host B, joined on the shared
/// [`EntityRef::User`]; the guard enforces the host-A-source-IP condition and the
/// [`CrossHost`](crate::evaluator::ScopeRule::CrossHost) scope enforces the
/// distinct-target-hosts condition.
///
/// [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User
#[must_use]
pub fn lateral_move_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-LATERAL-MOVE",
        attack_technique: Some("T1021.001"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "__unimplemented__",
        consequent_event_type: "__unimplemented__",
        window_ns: LATERAL_MOVE_WINDOW_NS,
        scope: ScopeRule::CrossHost,
        note: LATERAL_MOVE_NOTE,
        ordered: true,
        guard: Some(same_account_from_host_a_ip),
    }
}

/// Evaluate the lateral-move rule: a type-10 logon into host A against type-10
/// logon candidates into other hosts. Thin wrapper over the generic engine; both
/// sides must carry the account ([`EntityRef::User`]) join entity, the anchor
/// host A's IP inventory, and each consequent its own source IP — all as
/// [`EntityRef::Ip`] entities.
///
/// [`EntityRef::User`]: issen_core::timeline::event::EntityRef::User
#[must_use]
pub fn evaluate_lateral_move<A, C>(host_a_logon: &A, host_b_logons: &[C]) -> Option<Correlation>
where
    A: EventView,
    C: EventView,
{
    evaluate(&lateral_move_rule(), host_a_logon, host_b_logons)
}

#[cfg(test)]
mod tests {
    use super::super::testkit::TestEvent;
    use super::*;
    use crate::correlation::{CorrelationRole, CorrelationScope};
    use crate::evaluator::EventSource;
    use forensicnomicon::report::Severity;

    /// The type-10 logon *into* host A: carries the account, host A's interface
    /// address inventory (one or more IPs), and the source IP it came from.
    fn host_a_logon(id: u64, ts: i64, user: &str, host_a_ips: &[&str]) -> TestEvent {
        let mut ev = TestEvent::new(id, ts, "RdpLogon", "DC01", EventSource::Evtx)
            .with_entity(EntityRef::User(user.to_string()));
        for ip in host_a_ips {
            ev = ev.with_entity(EntityRef::Ip((*ip).to_string()));
        }
        ev
    }

    /// The type-10 logon *into* host B: carries the same account and its own
    /// source IP (the address the session originated from).
    fn host_b_logon(id: u64, ts: i64, user: &str, src_ip: &str, host_b: &str) -> TestEvent {
        TestEvent::new(id, ts, "RdpLogon", host_b, EventSource::Evtx)
            .with_entity(EntityRef::User(user.to_string()))
            .with_entity(EntityRef::Ip(src_ip.to_string()))
    }

    #[test]
    fn fires_for_rdp_pivot_same_account_from_host_a_ip_into_a_different_host() {
        // Host A (DC01) interface address is 10.0.0.10; the host-B (WS01) logon's
        // source IP is exactly that — the pivot used the same compromised account
        // and originated from the DC. All five §5.3 guards hold.
        let anchor = host_a_logon(1, 1_000, "Administrator", &["10.0.0.10"]);
        let cands = vec![host_b_logon(2, 2_000, "Administrator", "10.0.0.10", "WS01")];

        let corr = evaluate_lateral_move(&anchor, &cands).expect("a correlation");
        assert_eq!(corr.code, "CORR-LATERAL-MOVE");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1021.001"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.scope, CorrelationScope::CrossHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert_eq!(corr.members[1].role, CorrelationRole::Consequent);
        assert!(corr.note.contains("consistent with"));
    }

    // ── Negative controls (plan §5.3) ────────────────────────────────────────

    #[test]
    fn does_not_fire_for_a_type_2_console_logon() {
        // Guard #2 (both type 10 / RDP): a console interactive logon (type 2,
        // modeled as a distinct event type) into host B is not a remote pivot —
        // the anchor/consequent event-type match keeps the rule silent.
        let anchor = host_a_logon(1, 1_000, "Administrator", &["10.0.0.10"]);
        let mut console = host_b_logon(2, 2_000, "Administrator", "10.0.0.10", "WS01");
        console.event_type = "ConsoleLogon".to_string(); // 4624 type 2, not type 10
        let cands = vec![console];
        assert!(evaluate_lateral_move(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_for_a_different_account() {
        // Guard #3 (same account): the host-B logon uses a different account than
        // the host-A chain — the User join must keep the rule silent.
        let anchor = host_a_logon(1, 1_000, "Administrator", &["10.0.0.10"]);
        let cands = vec![host_b_logon(2, 2_000, "beth", "10.0.0.10", "WS01")];
        assert!(evaluate_lateral_move(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_on_the_same_host() {
        // Guard #5 (different target hosts): a second type-10 logon back into the
        // *same* host A is not lateral movement — CrossHost rejects it.
        let anchor = host_a_logon(1, 1_000, "Administrator", &["10.0.0.10"]);
        let cands = vec![host_b_logon(2, 2_000, "Administrator", "10.0.0.10", "DC01")];
        assert!(evaluate_lateral_move(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_host_b_source_ip_is_not_in_host_a_inventory() {
        // Guards #1/#4 (host-B source IP ∈ host-A inventory): the host-B logon
        // came from a third address, not from host A — the guard rejects it.
        let anchor = host_a_logon(1, 1_000, "Administrator", &["10.0.0.10"]);
        let cands = vec![host_b_logon(2, 2_000, "Administrator", "192.0.2.99", "WS01")];
        assert!(evaluate_lateral_move(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_host_b_logon_precedes_host_a_logon() {
        // Guard #2 (ordered timing): the host-B logon happened first.
        let anchor = host_a_logon(1, 5_000, "Administrator", &["10.0.0.10"]);
        let cands = vec![host_b_logon(2, 1_000, "Administrator", "10.0.0.10", "WS01")];
        assert!(evaluate_lateral_move(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_outside_the_24h_window() {
        let anchor = host_a_logon(1, 1_000, "Administrator", &["10.0.0.10"]);
        let late = 1_000 + LATERAL_MOVE_WINDOW_NS + 1;
        let cands = vec![host_b_logon(2, late, "Administrator", "10.0.0.10", "WS01")];
        assert!(evaluate_lateral_move(&anchor, &cands).is_none());
    }
}
