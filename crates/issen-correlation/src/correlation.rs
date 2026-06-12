//! Correlation findings — the DuckDB-free model for a cross-artifact match.
//!
//! A [`Correlation`] is an *observation*: a set of timeline events that, taken
//! together, are *consistent with* a named behavior (an ATT&CK technique, a
//! lateral-move, a brute-force-then-success). It is never a verdict — the
//! analyst and the tribunal conclude; the engine only reports what it observed.
//!
//! These types are pure data with no storage dependency, so the ordered
//! evaluator (and its unit tests) can produce them without touching DuckDB.
//! The `issen-timeline` crate persists them into the `correlations` and
//! `correlation_members` tables, keyed on `timeline.id`.

use forensicnomicon::report::Severity;

#[cfg(test)]
mod tests {
    use super::*;
    use forensicnomicon::report::Severity;

    #[test]
    fn correlation_carries_code_and_window() {
        let c = Correlation::new("CORR-BRUTEFORCE-LOGON", Severity::High)
            .with_attack_technique("T1110")
            .with_scope(CorrelationScope::SameHost)
            .with_window(1_000, 2_000)
            .with_note("Failed-logon burst is consistent with a brute-force attempt.");

        assert_eq!(c.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(c.severity, Severity::High);
        assert_eq!(c.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(c.scope, CorrelationScope::SameHost);
        assert_eq!(c.first_ts, 1_000);
        assert_eq!(c.last_ts, 2_000);
        assert!(c.note.contains("consistent with"));
    }

    #[test]
    fn correlation_defaults_are_empty() {
        let c = Correlation::new("CORR-X", Severity::Low);
        assert!(c.attack_technique.is_none());
        assert_eq!(c.scope, CorrelationScope::SameHost);
        assert_eq!(c.first_ts, 0);
        assert_eq!(c.last_ts, 0);
        assert!(c.note.is_empty());
        assert!(c.members.is_empty());
    }

    #[test]
    fn members_record_their_timeline_id_and_role() {
        let c = Correlation::new("CORR-X", Severity::Medium)
            .with_member(CorrelationMember::new(7, CorrelationRole::Anchor))
            .with_member(CorrelationMember::new(9, CorrelationRole::Consequent));

        assert_eq!(c.members.len(), 2);
        assert_eq!(c.members[0].timeline_id, 7);
        assert_eq!(c.members[0].role, CorrelationRole::Anchor);
        assert_eq!(c.members[1].timeline_id, 9);
        assert_eq!(c.members[1].role, CorrelationRole::Consequent);
    }

    #[test]
    fn role_str_is_a_stable_lowercase_token() {
        assert_eq!(CorrelationRole::Anchor.as_str(), "anchor");
        assert_eq!(CorrelationRole::Consequent.as_str(), "consequent");
        assert_eq!(CorrelationRole::Supporting.as_str(), "supporting");
    }

    #[test]
    fn scope_str_round_trips() {
        for scope in [
            CorrelationScope::SameHost,
            CorrelationScope::CrossHost,
            CorrelationScope::SameDump,
        ] {
            let s = scope.as_str();
            assert_eq!(CorrelationScope::from_str(s), Some(scope));
        }
        assert_eq!(CorrelationScope::from_str("nonsense"), None);
    }

    #[test]
    fn severity_str_maps_to_canonical_token() {
        let c = Correlation::new("CORR-X", Severity::Critical);
        assert_eq!(c.severity_str(), "critical");
    }
}
