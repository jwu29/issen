//! Bounded event retrieval for the correlation engine.
//!
//! [`StoredEvent`] is a timeline row read back with its `entity_refs` parsed —
//! the input the DuckDB-free evaluator consumes. [`EventQuery`] is a query
//! builder that is **bounded by construction**: it cannot express an unbounded
//! full-table scan, because every constructor requires at least a time window
//! or an entity filter. [`burst_windows`] groups same-type events into bursts
//! (the 4625 failed-logon burst that anchors `CORR-BRUTEFORCE-LOGON`).

use std::time::Duration;

use issen_core::timeline::event::EntityRef;

use crate::store::{TimelineStore, TimelineStoreError};

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

    use crate::store::TimelineStore;

    fn logon_failure(ts: i64, ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::LogonFailure,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "An account failed to log on".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
        .with_entity_ref(EntityRef::Ip(ip.to_string()))
    }

    fn store_with(events: &[TimelineEvent]) -> TimelineStore {
        let store = TimelineStore::in_memory().expect("store");
        store.inseissen_batch(events).expect("ingest");
        store
    }

    // ── EventQuery is bounded by construction ────────────────────────────────

    #[test]
    fn query_within_window_requires_no_extra_filter() {
        // A time window alone is a valid bound.
        let q = EventQuery::within(1_000, 2_000);
        assert_eq!(q.from_ns(), Some(1_000));
        assert_eq!(q.to_ns(), Some(2_000));
    }

    #[test]
    fn query_for_entity_is_bounded_without_a_time_window() {
        // An entity filter alone is a valid bound (no time window needed).
        let q = EventQuery::for_entity(EntityRef::Ip("203.0.113.5".to_string()));
        assert_eq!(q.from_ns(), None);
        assert!(q.entity_filter().is_some());
    }

    #[test]
    fn query_builders_add_optional_filters() {
        let q = EventQuery::within(0, 10_000)
            .event_types(["LogonFailure", "LogonSuccess"])
            .host("DC01")
            .with_entity(EntityRef::Ip("203.0.113.5".to_string()))
            .limit(500);
        assert_eq!(q.host(), Some("DC01"));
        assert_eq!(q.limit(), 500);
        assert!(q.entity_filter().is_some());
    }

    // ── fetch_events round-trips, including entity_refs ──────────────────────

    #[test]
    fn fetch_events_within_window_reconstructs_entity_refs() {
        let store = store_with(&[
            logon_failure(1_000, "203.0.113.5"),
            logon_failure(2_000, "203.0.113.5"),
            logon_failure(9_999_999, "10.0.0.1"), // outside window
        ]);
        let q = EventQuery::within(0, 5_000);
        let events = store.fetch_events(&q).expect("fetch");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].timestamp_ns, 1_000);
        assert_eq!(events[0].event_type, "LogonFailure");
        assert_eq!(events[0].source, "EventLog");
        assert_eq!(events[0].hostname.as_deref(), Some("DC01"));
        assert_eq!(events[0].evidence_source, "DC01");
        assert!(events[0].id > 0);
        assert_eq!(
            events[0].entity_refs,
            vec![EntityRef::Ip("203.0.113.5".to_string())]
        );
    }

    #[test]
    fn fetch_events_for_entity_filters_to_matching_rows() {
        let store = store_with(&[
            logon_failure(1_000, "203.0.113.5"),
            logon_failure(2_000, "10.0.0.1"),
        ]);
        let q = EventQuery::for_entity(EntityRef::Ip("203.0.113.5".to_string()));
        let events = store.fetch_events(&q).expect("fetch");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 1_000);
    }

    #[test]
    fn fetch_events_filters_by_event_type_and_host() {
        let mut success = logon_failure(3_000, "203.0.113.5");
        success.event_type = EventType::LogonSuccess;
        let store = store_with(&[logon_failure(1_000, "203.0.113.5"), success]);
        let q = EventQuery::within(0, 10_000).event_types(["LogonSuccess"]);
        let events = store.fetch_events(&q).expect("fetch");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "LogonSuccess");
    }

    // ── burst_windows groups same-type events ────────────────────────────────

    #[test]
    fn burst_windows_groups_a_dense_run_into_one_burst() {
        // Five failed logons within 1s windows → a single burst of >= threshold.
        let store = store_with(&[
            logon_failure(1_000_000_000, "203.0.113.5"),
            logon_failure(1_100_000_000, "203.0.113.5"),
            logon_failure(1_200_000_000, "203.0.113.5"),
            logon_failure(1_300_000_000, "203.0.113.5"),
            logon_failure(1_400_000_000, "203.0.113.5"),
        ]);
        let q = EventQuery::within(0, 5_000_000_000);
        let events = store.fetch_events(&q).expect("fetch");
        let bursts = burst_windows(&events, 4, Duration::from_secs(2));
        assert_eq!(bursts.len(), 1, "one dense burst");
        assert_eq!(bursts[0].len(), 5);
    }

    #[test]
    fn burst_windows_splits_on_a_gap_and_drops_below_threshold() {
        // Two events, then a long gap, then two events. With threshold 3,
        // neither cluster reaches the threshold → no burst.
        let store = store_with(&[
            logon_failure(1_000_000_000, "203.0.113.5"),
            logon_failure(1_100_000_000, "203.0.113.5"),
            logon_failure(9_000_000_000, "203.0.113.5"),
            logon_failure(9_100_000_000, "203.0.113.5"),
        ]);
        let q = EventQuery::within(0, 20_000_000_000);
        let events = store.fetch_events(&q).expect("fetch");
        let bursts = burst_windows(&events, 3, Duration::from_secs(2));
        assert!(bursts.is_empty(), "no cluster reaches the threshold");
    }

    #[test]
    fn burst_windows_separates_distinct_event_types() {
        // Same timestamps but different event types must not merge into a burst.
        let mut a = logon_failure(1_000_000_000, "203.0.113.5");
        a.event_type = EventType::LogonFailure;
        let mut b = logon_failure(1_050_000_000, "203.0.113.5");
        b.event_type = EventType::LogonSuccess;
        let mut c = logon_failure(1_100_000_000, "203.0.113.5");
        c.event_type = EventType::LogonFailure;
        let store = store_with(&[a, b, c]);
        let q = EventQuery::within(0, 5_000_000_000);
        let events = store.fetch_events(&q).expect("fetch");
        // Only two LogonFailure events → below threshold 3.
        let bursts = burst_windows(&events, 3, Duration::from_secs(2));
        assert!(bursts.is_empty());
    }
}
