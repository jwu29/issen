//! Tier-C / C′ memory-leg correlation rules (capstone task #37, plan v5 §7.2 /
//! v4 §5.2).
//!
//! The disk/EVTX rules (Tiers A, B, B′, D) join *flat* timeline events on an
//! exact [`EntityRef`] through the ordered-window engine. The memory rules need
//! more than `EventView` exposes: a process's `thread_count` and `ppid`, and an
//! injection's class string — fields that live in the event's `metadata` JSON,
//! which the shared [`EventView`](crate::evaluator::EventView) trait deliberately
//! does **not** surface (a metadata accessor on the shared trait once silently
//! broke a downstream crate). So, exactly like Tier-A's
//! [`copy_delete_pairs`](crate::tier_a::copy_delete::copy_delete_pairs), the
//! memory rules are matched by dedicated, tested functions that read a richer
//! input than a `RuleSpec` can — a [`MemEvent`], the small typed projection of a
//! memory `TimelineEvent` whose `pid` / `ppid` / `thread_count` / `injection`
//! have already been parsed out of the metadata JSON once.
//!
//! Three rules live here:
//!
//! - **`CORR-INJECTED-C2`** (Tier C) — a `MemoryInjection` on a PID and an
//!   ESTABLISHED `NetworkConnect` to an external [`EntityRef::Ip`] from the
//!   *same* process: an injected process beaconing to C2
//!   ([`injected_c2::injected_c2_pairs`]). ATT&CK T1055 + T1071.
//! - **`CORR-PROC-DISK-MATCH`** (Tier C) — a memory `ProcessExec` and a *disk*
//!   `FileCreate` for the *same image name*: the on-disk artifact is the running
//!   process ([`proc_disk_match::proc_disk_matches`]). ATT&CK T1055 / T1105.
//! - **★`CORR-PROC-MIGRATION`** (Tier C′) — a dead-and-orphaned process plus a
//!   `MemoryInjection` on a different, live PID plus `NetworkConnect` rows tying
//!   both PIDs to the same remote endpoint: process migration
//!   ([`proc_migration::proc_migration_chains`]). ATT&CK T1055.
//!
//! Findings are observations: every note says "consistent with", never a
//! verdict. The [`tests::no_tier_c_note_asserts_a_verdict`] test enforces this.

use issen_core::timeline::event::EntityRef;

use crate::correlation::Correlation;
use crate::evaluator::EventSource;

pub mod injected_c2;
pub mod proc_disk_match;
pub mod proc_migration;

/// The event-type token a memory injection (malfind) row carries, as the
/// timeline persists it: `format!("{:?}", EventType::Other("MemoryInjection"))`,
/// i.e. with the inner quotes. Matched literally so a real persisted row joins.
pub const MEMORY_INJECTION_EVENT_TYPE: &str = "Other(\"MemoryInjection\")";

/// The `ProcessExec` event-type token (memory ps row and disk process events).
pub const PROCESS_EXEC_EVENT_TYPE: &str = "ProcessExec";

/// The `NetworkConnect` event-type token (memory netstat row).
pub const NETWORK_CONNECT_EVENT_TYPE: &str = "NetworkConnect";

/// The `FileCreate` event-type token (disk file events).
pub const FILE_CREATE_EVENT_TYPE: &str = "FileCreate";

/// The ESTABLISHED connection-state string a beaconing netstat row carries.
pub const ESTABLISHED_STATE: &str = "ESTABLISHED";

/// A memory-leg timeline event projected for the Tier-C matchers.
///
/// This is the richer input the memory rules need: it carries the same
/// identity/ordering fields an [`EventView`](crate::evaluator::EventView) exposes
/// **plus** the memory-specific fields (`pid`, `ppid`, `thread_count`,
/// `injection`, `state`) that have been parsed out of the event's `metadata`
/// JSON. The store-facing wrapper (in `issen-timeline`, which owns `StoredEvent`
/// and its metadata) builds these; the unit tests build them directly. Keeping
/// the field-parse on the *consumer* side of the dependency edge avoids putting a
/// metadata accessor on the shared `EventView` trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemEvent {
    /// The persisted `timeline.id` (the correlation-member key).
    pub id: u64,
    /// Event time in nanoseconds (the dump acquisition instant for memory rows).
    pub timestamp_ns: i64,
    /// The persisted event-type token (e.g. `"ProcessExec"`,
    /// `"NetworkConnect"`, or [`MEMORY_INJECTION_EVENT_TYPE`]).
    pub event_type: String,
    /// The entity references this event carries (the `Process` subject and, for
    /// a netstat row with a real peer, the remote `Ip`).
    pub entity_refs: Vec<EntityRef>,
    /// Host / dump attribution (the dump stem).
    pub hostname: Option<String>,
    /// Which artifact leg this event came from (memory rows are
    /// [`EventSource::Memory`]).
    pub source: EventSource,
    /// `pid` metadata (process / netstat / malfind rows carry it).
    pub pid: Option<u32>,
    /// `ppid` metadata (process rows carry it; the dead-orphan check needs it).
    pub ppid: Option<u32>,
    /// `thread_count` metadata (process rows; `0` means dead/terminated).
    pub thread_count: Option<u32>,
    /// `injection` class metadata (malfind rows, e.g. `injected-PE`).
    pub injection: Option<String>,
    /// `state` metadata (netstat rows, e.g. `ESTABLISHED`).
    pub state: Option<String>,
}

impl MemEvent {
    /// A bare memory event carrying only identity/ordering fields, with all
    /// memory-specific metadata absent. Builder methods add the rest.
    #[must_use]
    pub fn new(id: u64, timestamp_ns: i64, event_type: &str, hostname: &str) -> Self {
        Self {
            id,
            timestamp_ns,
            event_type: event_type.to_string(),
            entity_refs: Vec::new(),
            hostname: Some(hostname.to_string()),
            source: EventSource::Memory,
            pid: None,
            ppid: None,
            thread_count: None,
            injection: None,
            state: None,
        }
    }

    /// Attach an entity reference.
    #[must_use]
    pub fn with_entity(mut self, e: EntityRef) -> Self {
        self.entity_refs.push(e);
        self
    }

    /// Set the `pid` metadata.
    #[must_use]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set the `ppid` metadata.
    #[must_use]
    pub fn with_ppid(mut self, ppid: u32) -> Self {
        self.ppid = Some(ppid);
        self
    }

    /// Set the `thread_count` metadata.
    #[must_use]
    pub fn with_thread_count(mut self, thread_count: u32) -> Self {
        self.thread_count = Some(thread_count);
        self
    }

    /// Set the `injection` class metadata.
    #[must_use]
    pub fn with_injection(mut self, injection: &str) -> Self {
        self.injection = Some(injection.to_string());
        self
    }

    /// Set the connection-`state` metadata.
    #[must_use]
    pub fn with_state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    /// The process [`EntityRef::Process`] subject values this event carries.
    fn process_subjects(&self) -> impl Iterator<Item = &str> {
        self.entity_refs.iter().filter_map(|e| match e {
            EntityRef::Process(p) => Some(p.as_str()),
            _ => None,
        })
    }

    /// The remote [`EntityRef::Ip`] values this event carries.
    fn ip_subjects(&self) -> impl Iterator<Item = &str> {
        self.entity_refs.iter().filter_map(|e| match e {
            EntityRef::Ip(ip) => Some(ip.as_str()),
            _ => None,
        })
    }

    /// `true` when this event shares a `Process` subject with `other`.
    fn shares_process(&self, other: &MemEvent) -> bool {
        let mine: Vec<&str> = self.process_subjects().collect();
        other.process_subjects().any(|p| mine.contains(&p))
    }
}

/// The bundled Tier-C / C′ matcher entry points run over a memory-event slice.
///
/// `run_correlations` (the disk-leg runner) cannot feed these because it is
/// generic over [`EventView`](crate::evaluator::EventView) and never sees the
/// metadata these rules need; the store-facing wrapper passes the projected
/// [`MemEvent`] slice here and appends the result to the same `Vec<Correlation>`.
#[must_use]
pub fn run_memory_rules(events: &[MemEvent]) -> Vec<Correlation> {
    let mut out = Vec::new();
    out.extend(injected_c2::injected_c2_pairs(events));
    out.extend(proc_disk_match::proc_disk_matches(events));
    out.extend(proc_migration::proc_migration_chains(events));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_tier_c_note_asserts_a_verdict() {
        let forbidden = ["confirm", "prove", "proof", "exceed", "undoubtedly", "certainly"];
        let notes = [
            injected_c2::INJECTED_C2_NOTE,
            proc_disk_match::PROC_DISK_MATCH_NOTE,
            proc_migration::PROC_MIGRATION_NOTE,
        ];
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

    #[test]
    fn mem_event_builder_carries_metadata_and_entities() {
        let e = MemEvent::new(7, 1_000, PROCESS_EXEC_EVENT_TYPE, "DUMP-A")
            .with_entity(EntityRef::Process("coreupdater.exe".to_string()))
            .with_pid(3644)
            .with_ppid(4)
            .with_thread_count(0);
        assert_eq!(e.id, 7);
        assert_eq!(e.source, EventSource::Memory);
        assert_eq!(e.pid, Some(3644));
        assert_eq!(e.ppid, Some(4));
        assert_eq!(e.thread_count, Some(0));
        assert!(e
            .process_subjects()
            .any(|p| p == "coreupdater.exe"));
    }
}
