//! Store-facing driver for the disk-leg correlation runner (capstone task #37,
//! plan v5 §7.1 phase 5).
//!
//! [`TimelineStore::run_and_persist`] fetches the timeline's events, identifies
//! the 4625 failed-logon bursts that anchor `CORR-BRUTEFORCE-LOGON`
//! ([`burst_windows`]), runs every disk-leg rule
//! ([`issen_correlation::runner::run_correlations`]), and persists each firing
//! back into the `correlations` tables — returning the firings so a caller can
//! render them without a second read.
//!
//! The pure rule logic lives in `issen-correlation`; this module is the thin
//! storage adapter (fetch → synthesize burst anchors → run → persist).

use std::time::Duration;

use issen_correlation::correlation::Correlation;
use issen_correlation::evaluator::{EventSource, EventView};
use issen_correlation::runner::run_correlations;
use issen_core::timeline::event::EntityRef;

use crate::events::{burst_windows, EventQuery, StoredEvent};
use crate::store::{TimelineStore, TimelineStoreError};

/// The failed-logon burst threshold and window that seed a `LogonFailureBurst`
/// anchor (plan v4 §5.2: a 4625 burst preceding a 4624 success).
const BURST_THRESHOLD: usize = 4;
const BURST_WINDOW: Duration = Duration::from_secs(60);

/// A synthetic `LogonFailureBurst` anchor event, owned by the runner.
///
/// `burst_windows` groups raw `LogonFailure` rows into bursts; the brute-force
/// rule anchors on a single `LogonFailureBurst` event carrying the shared source
/// IP. We synthesize one per burst, keyed on the burst's *latest* member id (a
/// real `timeline.id`, so the persisted correlation member resolves to a row),
/// timestamped at the latest failure, carrying that group's source IP.
#[derive(Debug, Clone)]
struct BurstAnchor {
    id: u64,
    timestamp_ns: i64,
    entity_refs: Vec<EntityRef>,
    hostname: Option<String>,
}

impl EventView for BurstAnchor {
    fn id(&self) -> u64 {
        self.id
    }
    fn timestamp_ns(&self) -> i64 {
        self.timestamp_ns
    }
    fn event_type(&self) -> &str {
        "LogonFailureBurst"
    }
    fn entity_refs(&self) -> &[EntityRef] {
        &self.entity_refs
    }
    fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }
    fn source(&self) -> EventSource {
        EventSource::Evtx
    }
}

/// Adapter so a `StoredEvent` and a synthesized `BurstAnchor` can sit in one
/// homogeneous slice that the generic runner consumes.
#[derive(Debug, Clone)]
enum RunInput {
    Stored(StoredEvent),
    Burst(BurstAnchor),
}

impl EventView for RunInput {
    fn id(&self) -> u64 {
        match self {
            Self::Stored(e) => e.id(),
            Self::Burst(e) => e.id(),
        }
    }
    fn timestamp_ns(&self) -> i64 {
        match self {
            Self::Stored(e) => e.timestamp_ns(),
            Self::Burst(e) => e.timestamp_ns(),
        }
    }
    fn event_type(&self) -> &str {
        match self {
            Self::Stored(e) => e.event_type(),
            Self::Burst(e) => e.event_type(),
        }
    }
    fn entity_refs(&self) -> &[EntityRef] {
        match self {
            Self::Stored(e) => e.entity_refs(),
            Self::Burst(e) => e.entity_refs(),
        }
    }
    fn hostname(&self) -> Option<&str> {
        match self {
            Self::Stored(e) => e.hostname(),
            Self::Burst(e) => e.hostname(),
        }
    }
    fn source(&self) -> EventSource {
        match self {
            Self::Stored(e) => e.source(),
            Self::Burst(e) => e.source(),
        }
    }
    fn artifact_path(&self) -> &str {
        match self {
            Self::Stored(e) => e.artifact_path(),
            Self::Burst(e) => e.artifact_path(),
        }
    }
}

/// The IP a `LogonFailure` event carries, if any (the brute-force join key).
fn ip_of(event: &StoredEvent) -> Option<EntityRef> {
    event
        .entity_refs
        .iter()
        .find(|e| matches!(e, EntityRef::Ip(_)))
        .cloned()
}

/// Synthesize a `LogonFailureBurst` anchor for each identified burst whose
/// members share one source IP.
fn burst_anchors(events: &[StoredEvent]) -> Vec<BurstAnchor> {
    let mut anchors = Vec::new();
    for group in burst_windows(events, BURST_THRESHOLD, BURST_WINDOW) {
        // The latest member fronts the burst (its id keys the persisted member).
        let Some(last) = group.iter().max_by_key(|e| e.timestamp_ns) else {
            continue; // cov:unreachable: burst_windows never emits an empty group
        };
        let Some(ip) = ip_of(last) else {
            continue;
        };
        anchors.push(BurstAnchor {
            id: last.id,
            timestamp_ns: last.timestamp_ns,
            entity_refs: vec![ip],
            hostname: last.hostname.clone(),
        });
    }
    anchors
}

impl TimelineStore {
    /// Fetch the timeline, run every disk-leg correlation rule, and persist each
    /// firing; returns the firings (each carrying its members).
    ///
    /// The fetch is bounded by the full positive-timestamp window. Memory-leg
    /// (Tier C) rules are not run here — the runner leaves an additive seam for
    /// them (see [`run_correlations`]).
    pub fn run_and_persist(&self) -> Result<Vec<Correlation>, TimelineStoreError> {
        // RED stub — implementation follows in the GREEN commit.
        let _ = (
            burst_anchors,
            run_correlations::<RunInput>,
            EventQuery::within(1, i64::MAX),
        );
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

    use crate::store::TimelineStore;

    fn file_create(ts: i64, path: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            path.to_string(),
            "file create".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
    }

    fn service_install(ts: i64, image: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::ServiceInstall,
            ArtifactType::EventLog,
            image.to_string(),
            "service install".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
    }

    fn logon_failure(ts: i64, ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::LogonFailure,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "failed logon".to_string(),
            "DC01".to_string(),
        )
        .with_hostname("DC01")
        .with_entity_ref(EntityRef::Ip(ip.to_string()))
    }

    fn logon_success(ts: i64, ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            ts,
            format!("2026-01-01T00:00:00.{ts:09}Z"),
            EventType::LogonSuccess,
            ArtifactType::EventLog,
            "Security.evtx".to_string(),
            "successful logon".to_string(),
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

    #[test]
    fn run_and_persist_fires_two_distinct_rules_and_reads_back() {
        // A persistence pair (FileCreate -> ServiceInstall on the same stem) AND
        // a brute-force pattern (a 4625 burst -> 4624 success from one IP).
        let secs = 1_000_000_000i64;
        let mut events = vec![
            file_create(1 * secs, "C:\\Windows\\System32\\coreupdater.exe"),
            service_install(2 * secs, "C:\\Windows\\System32\\coreupdater.exe"),
        ];
        // Five failed logons within 60s from one IP -> a burst.
        for k in 0..5 {
            events.push(logon_failure(10 * secs + k * secs, "194.61.24.102"));
        }
        // A success from the same IP shortly after the burst.
        events.push(logon_success(16 * secs, "194.61.24.102"));

        let store = store_with(&events);
        let fired = store.run_and_persist().expect("run");

        let codes: std::collections::BTreeSet<&str> =
            fired.iter().map(|c| c.code.as_str()).collect();
        assert!(codes.contains("CORR-MALWARE-PERSIST"), "codes: {codes:?}");
        assert!(codes.contains("CORR-BRUTEFORCE-LOGON"), "codes: {codes:?}");
        assert!(codes.len() >= 2, "at least two distinct rule codes: {codes:?}");

        // Persisted firings read back with their members.
        for corr in &fired {
            assert!(!corr.members.is_empty(), "{} has members", corr.code);
        }
    }

    #[test]
    fn run_and_persist_on_empty_timeline_is_clean() {
        let store = TimelineStore::in_memory().expect("store");
        assert!(store.run_and_persist().expect("run").is_empty());
    }
}
