//! Ordered-window correlation evaluator (DuckDB-free).
//!
//! Given an *anchor* event and a slice of candidate *consequent* events
//! (already fetched from the store), a [`RuleSpec`] decides whether they form a
//! [`Correlation`]: the anchor must satisfy the anchor predicate, a consequent
//! must satisfy the consequent predicate, the two must share a join entity, and
//! the consequent must fall strictly *after* the anchor within the rule's time
//! window. Ordering is point-in-time: a missing or non-positive timestamp never
//! satisfies the window, and an anchor never matches a consequent at the same
//! instant.
//!
//! The evaluator is generic over [`EventView`] so it stays free of any storage
//! type — `issen-timeline::events::StoredEvent` implements it; the unit tests
//! use a synthetic event. This is the seam that keeps `issen-correlation`
//! DuckDB-free while still consuming events read back from DuckDB.

use issen_core::timeline::event::EntityRef;

use crate::correlation::{Correlation, CorrelationMember, CorrelationRole, CorrelationScope};

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::Severity;

    /// A synthetic event for evaluator unit tests — proves the evaluator needs
    /// no storage type.
    #[derive(Debug, Clone)]
    struct TestEvent {
        id: u64,
        ts: i64,
        event_type: String,
        entity_refs: Vec<EntityRef>,
        host: Option<String>,
        source: EventSource,
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

    fn ev(id: u64, ts: i64, et: &str, ip: &str, host: &str, src: EventSource) -> TestEvent {
        TestEvent {
            id,
            ts,
            event_type: et.to_string(),
            entity_refs: vec![EntityRef::Ip(ip.to_string())],
            host: Some(host.to_string()),
            source: src,
        }
    }

    /// The example rule: a failed-logon burst (anchor) followed by a success
    /// from the same IP (consequent), within a window.
    fn brute_force_rule() -> RuleSpec {
        RuleSpec {
            code: "CORR-BRUTEFORCE-LOGON",
            attack_technique: Some("T1110"),
            severity: Severity::High,
            anchor_event_type: "LogonFailure",
            consequent_event_type: "LogonSuccess",
            window_ns: 60_000_000_000, // 60s
            scope: ScopeRule::SameHost,
            note: "Failed-logon burst then success from the same IP is consistent with brute force.",
        }
    }

    #[test]
    fn matches_an_ordered_same_entity_pair() {
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2,
            2_000,
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        let result = evaluate(&brute_force_rule(), &anchor, &consequents);
        let corr = result.expect("a correlation");
        assert_eq!(corr.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.first_ts, 1_000);
        assert_eq!(corr.last_ts, 2_000);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert_eq!(corr.members[1].role, CorrelationRole::Consequent);
    }

    #[test]
    fn rejects_a_reversed_pair() {
        // Consequent BEFORE the anchor — ordering must reject it.
        let anchor = ev(1, 5_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2, 1_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_a_simultaneous_pair() {
        // Same instant — strictly-after means no match.
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2, 1_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_out_of_window_consequent() {
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2,
            999_000_000_000, // way past the 60s window
            "LogonSuccess",
            "203.0.113.5",
            "DC01",
            EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_different_entity() {
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2, 2_000, "LogonSuccess", "10.0.0.9", "DC01", EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn rejects_wrong_anchor_type() {
        let anchor = ev(1, 1_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2, 2_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn same_host_scope_rejects_cross_host_pair() {
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2, 2_000, "LogonSuccess", "203.0.113.5", "WS01", EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn non_positive_anchor_timestamp_never_matches() {
        let anchor = ev(1, 0, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![ev(
            2, 2_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx,
        )];
        assert!(evaluate(&brute_force_rule(), &anchor, &consequents).is_none());
    }

    #[test]
    fn same_dump_scope_requires_same_evidence_leg() {
        // Point-in-time semantics seam: a SameDump rule must reject members from
        // different memory dumps even when entity + ordering align. Modeled here
        // via the EventSource leg + the SameDump scope rule's same-host proxy.
        let rule = RuleSpec {
            scope: ScopeRule::SameDump,
            ..brute_force_rule()
        };
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DUMP-A", EventSource::Memory);
        // Different host label stands in for a different dump identity.
        let consequents = vec![ev(
            2, 2_000, "LogonSuccess", "203.0.113.5", "DUMP-B", EventSource::Memory,
        )];
        assert!(evaluate(&rule, &anchor, &consequents).is_none());

        let same_dump = vec![ev(
            2, 2_000, "LogonSuccess", "203.0.113.5", "DUMP-A", EventSource::Memory,
        )];
        assert!(evaluate(&rule, &anchor, &same_dump).is_some());
    }

    #[test]
    fn first_matching_consequent_wins() {
        let anchor = ev(1, 1_000, "LogonFailure", "203.0.113.5", "DC01", EventSource::Evtx);
        let consequents = vec![
            ev(2, 2_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx),
            ev(3, 3_000, "LogonSuccess", "203.0.113.5", "DC01", EventSource::Evtx),
        ];
        let corr = evaluate(&brute_force_rule(), &anchor, &consequents).expect("match");
        assert_eq!(corr.members[1].timeline_id, 2, "earliest consequent");
        assert_eq!(corr.last_ts, 2_000);
    }

    #[test]
    fn event_source_round_trips_its_token() {
        for src in [
            EventSource::Disk,
            EventSource::Evtx,
            EventSource::Registry,
            EventSource::Memory,
            EventSource::Other,
        ] {
            assert_eq!(EventSource::from_str(src.as_str()), Some(src));
        }
        assert_eq!(EventSource::from_str("nope"), None);
    }

    #[test]
    fn unused_member_ctor_guard() {
        let m = CorrelationMember::new(1, CorrelationRole::Supporting);
        assert_eq!(m.timeline_id, 1);
    }
}
