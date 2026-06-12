//! Persistence for cross-artifact [`Correlation`] findings.
//!
//! Two tables join the correlation engine's output back to the timeline:
//!
//! - `correlations` — one row per finding (code, technique, severity, window,
//!   scope, note).
//! - `correlation_members` — the events that make up a finding, keyed on
//!   `timeline.id` and tagged with the member's role (anchor / consequent /
//!   supporting). `timeline.id` is chosen over `record_hash` because dedup is
//!   within-epoch only, so an id is the only stable per-row key.
//!
//! The DDL is created additively (`ADD COLUMN IF NOT EXISTS`-style safety like
//! PRE-4) so opening an older case DB is non-destructive.

use issen_correlation::correlation::Correlation;

use crate::store::{TimelineStore, TimelineStoreError};

#[cfg(test)]
mod tests {
    use forensicnomicon::report::Severity;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};
    use issen_correlation::correlation::{
        Correlation, CorrelationMember, CorrelationRole, CorrelationScope,
    };

    use crate::store::TimelineStore;

    fn sample_event(ts: i64, desc: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2023-11-14T22:13:20.{ts:09}Z"),
            EventType::LogonFailure,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            desc.to_string(),
            "evidence-001".to_string(),
        )
    }

    #[test]
    fn persist_correlation_returns_an_id_and_reads_back() {
        let store = TimelineStore::in_memory().expect("store");
        // Two real timeline rows so the members can key on their ids.
        let anchor = sample_event(1_000, "failed logon burst");
        let consequent = sample_event(2_000, "successful logon");
        store
            .inseissen_batch(&[anchor.clone(), consequent.clone()])
            .expect("ingest");
        let anchor_id = store
            .timeline_id_for_hash(&anchor.record_hash)
            .expect("anchor id");
        let consequent_id = store
            .timeline_id_for_hash(&consequent.record_hash)
            .expect("consequent id");

        let corr = Correlation::new("CORR-BRUTEFORCE-LOGON", Severity::High)
            .with_attack_technique("T1110")
            .with_scope(CorrelationScope::SameHost)
            .with_window(1_000, 2_000)
            .with_note("Failed-logon burst followed by success is consistent with brute force.");

        let id = store
            .persist_correlation(
                &corr,
                &[
                    (anchor_id, CorrelationRole::Anchor.as_str()),
                    (consequent_id, CorrelationRole::Consequent.as_str()),
                ],
            )
            .expect("persist");

        let stored = store.correlation(id).expect("read back").expect("present");
        assert_eq!(stored.code, "CORR-BRUTEFORCE-LOGON");
        assert_eq!(stored.attack_technique.as_deref(), Some("T1110"));
        assert_eq!(stored.severity, Severity::High);
        assert_eq!(stored.scope, CorrelationScope::SameHost);
        assert_eq!(stored.first_ts, 1_000);
        assert_eq!(stored.last_ts, 2_000);
        assert!(stored.note.contains("consistent with"));

        assert_eq!(stored.members.len(), 2);
        let anchor_member = stored
            .members
            .iter()
            .find(|m| m.role == CorrelationRole::Anchor)
            .expect("anchor member");
        assert_eq!(anchor_member.timeline_id, anchor_id);
        let consequent_member = stored
            .members
            .iter()
            .find(|m| m.role == CorrelationRole::Consequent)
            .expect("consequent member");
        assert_eq!(consequent_member.timeline_id, consequent_id);
    }

    #[test]
    fn correlation_read_back_absent_id_is_none() {
        let store = TimelineStore::in_memory().expect("store");
        assert!(store.correlation(999).expect("query").is_none());
    }

    #[test]
    fn persist_correlation_schema_is_idempotent_for_old_dbs() {
        // Re-initializing the schema (as on re-open of an existing case DB) must
        // not drop or error on the correlation tables.
        let store = TimelineStore::in_memory().expect("store");
        let corr = Correlation::new("CORR-X", Severity::Low).with_window(5, 9);
        let id = store.persist_correlation(&corr, &[]).expect("persist");
        store.initialize_schema_public().expect("re-init");
        assert!(store.correlation(id).expect("read back").is_some());
    }

    #[test]
    fn member_unused_import_guard() {
        // Touch CorrelationMember so the import is exercised in this module.
        let m = CorrelationMember::new(1, CorrelationRole::Supporting);
        assert_eq!(m.timeline_id, 1);
    }
}
