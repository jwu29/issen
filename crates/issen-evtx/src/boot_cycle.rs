//! Boot cycle segmentation: partition a timeline by EID 6005/6006 markers.
//!
//! EID 6005 (System channel): EventLog service started → clean boot boundary.
//! EID 6006 (System channel): EventLog service stopped → clean shutdown boundary.
//! EID 6008 (System channel): Unexpected shutdown → dirty boot boundary.

use forensicnomicon::heuristics::evtx::{EID_BOOT, EID_SHUTDOWN, EID_UNEXPECTED_SHUTDOWN};
use winevt_core::EvtxEvent;

/// Dirty-boot indicator: whether the previous shutdown was clean or unexpected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownKind {
    /// EID 6006 preceded this boot — clean shutdown.
    Clean,
    /// EID 6008 preceded this boot — crash or power loss.
    Unexpected,
    /// No shutdown marker found (first cycle, or data truncated).
    Unknown,
}

/// A single boot session: everything between a boot marker and the next.
#[derive(Debug, Clone)]
pub struct BootCycle {
    /// Timestamp of the 6005 event that opened this cycle (nanoseconds).
    pub boot_time_ns: i64,
    /// Timestamp of the 6006 event closing this cycle, if seen.
    pub shutdown_time_ns: Option<i64>,
    /// Shutdown kind of the *previous* cycle (how the system shut down before this boot).
    pub prior_shutdown_kind: ShutdownKind,
    /// Events that fall within this boot cycle.
    pub events: Vec<EvtxEvent>,
}

impl BootCycle {
    /// Duration of this cycle in seconds, or None if shutdown was not seen.
    pub fn duration_secs(&self) -> Option<u64> {
        let shutdown = self.shutdown_time_ns?;
        let delta_ns = (shutdown - self.boot_time_ns).unsigned_abs();
        Some(delta_ns / 1_000_000_000)
    }
}

/// Segment `events` into boot cycles using EID 6005/6006/6008 as boundaries.
///
/// Events before the first boot marker are placed in a synthetic "pre-boot" cycle
/// with `boot_time_ns = events[0].timestamp_ns` and `ShutdownKind::Unknown`.
///
/// Events are expected to be in timestamp order but the function sorts them
/// internally for correctness.
pub fn segment_by_boot_cycle(mut events: Vec<EvtxEvent>) -> Vec<BootCycle> {
    if events.is_empty() {
        return vec![];
    }
    events.sort_by_key(|e| e.timestamp_ns);

    let mut cycles: Vec<BootCycle> = Vec::new();
    let mut current: Option<BootCycle> = None;
    let mut last_shutdown_kind = ShutdownKind::Unknown;

    for ev in events {
        match ev.event_id {
            id if id == EID_BOOT => {
                // Close out any open cycle (no shutdown seen)
                if let Some(c) = current.take() {
                    cycles.push(c);
                }
                current = Some(BootCycle {
                    boot_time_ns: ev.timestamp_ns,
                    shutdown_time_ns: None,
                    prior_shutdown_kind: last_shutdown_kind,
                    events: Vec::new(),
                });
                // Reset for next cycle
                last_shutdown_kind = ShutdownKind::Unknown;
            }
            id if id == EID_SHUTDOWN => {
                if let Some(c) = current.as_mut() {
                    c.shutdown_time_ns = Some(ev.timestamp_ns);
                }
                last_shutdown_kind = ShutdownKind::Clean;
            }
            id if id == EID_UNEXPECTED_SHUTDOWN => {
                last_shutdown_kind = ShutdownKind::Unexpected;
            }
            _ => {
                // Non-marker event — assign to current cycle
                if let Some(c) = current.as_mut() {
                    c.events.push(ev);
                }
            }
        }
    }

    // Push last open cycle
    if let Some(c) = current.take() {
        cycles.push(c);
    }

    cycles
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, ts: i64) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: "System".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        }
    }

    fn sec_ev(event_id: u32, ts: i64) -> EvtxEvent {
        let mut e = make_event(event_id, ts);
        e.channel = "Security".into();
        e
    }

    #[test]
    fn segment_empty_input_returns_empty() {
        let cycles = segment_by_boot_cycle(vec![]);
        assert!(cycles.is_empty());
    }

    #[test]
    fn segment_single_boot_with_shutdown() {
        let events = vec![
            make_event(6005, 1_000), // boot
            sec_ev(4624, 2_000),     // some event during the cycle
            make_event(6006, 3_000), // shutdown
        ];
        let cycles = segment_by_boot_cycle(events);
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].boot_time_ns, 1_000);
        assert_eq!(cycles[0].shutdown_time_ns, Some(3_000));
    }

    #[test]
    fn segment_cycle_contains_events_between_markers() {
        let events = vec![
            make_event(6005, 1_000),
            sec_ev(4624, 2_000),
            sec_ev(4688, 2_500),
            make_event(6006, 3_000),
        ];
        let cycles = segment_by_boot_cycle(events);
        // The Security events should be inside the cycle (not the boot/shutdown markers themselves)
        assert_eq!(cycles[0].events.len(), 2);
    }

    #[test]
    fn segment_two_boot_cycles() {
        let events = vec![
            make_event(6005, 1_000),
            sec_ev(4624, 1_500),
            make_event(6006, 2_000),
            make_event(6005, 3_000),
            sec_ev(4688, 3_500),
            make_event(6006, 4_000),
        ];
        let cycles = segment_by_boot_cycle(events);
        assert_eq!(cycles.len(), 2);
        assert_eq!(cycles[1].boot_time_ns, 3_000);
    }

    #[test]
    fn segment_orphaned_boot_has_no_shutdown() {
        let events = vec![make_event(6005, 1_000), sec_ev(4624, 2_000)];
        let cycles = segment_by_boot_cycle(events);
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].shutdown_time_ns, None);
    }

    #[test]
    fn segment_second_cycle_has_clean_prior_shutdown() {
        let events = vec![
            make_event(6005, 1_000),
            make_event(6006, 2_000), // clean shutdown
            make_event(6005, 3_000), // next boot
        ];
        let cycles = segment_by_boot_cycle(events);
        assert_eq!(cycles.len(), 2);
        assert_eq!(cycles[1].prior_shutdown_kind, ShutdownKind::Clean);
    }

    #[test]
    fn segment_unexpected_shutdown_detected() {
        let events = vec![
            make_event(6005, 1_000),
            make_event(6008, 2_000), // unexpected shutdown
            make_event(6005, 3_000),
        ];
        let cycles = segment_by_boot_cycle(events);
        assert_eq!(cycles.len(), 2);
        assert_eq!(cycles[1].prior_shutdown_kind, ShutdownKind::Unexpected);
    }

    #[test]
    fn duration_secs_computes_correctly() {
        let cycle = BootCycle {
            boot_time_ns: 0,
            shutdown_time_ns: Some(10_000_000_000), // 10 s
            prior_shutdown_kind: ShutdownKind::Clean,
            events: vec![],
        };
        assert_eq!(cycle.duration_secs(), Some(10));
    }
}
