//! Multi-channel super-timeline: merge Security/System/Sysmon/PowerShell/TaskScheduler
//! events into one chronologically ordered stream.

use forensicnomicon::heuristics::evtx::SUPER_TIMELINE_CHANNELS;
use winevt_core::EvtxEvent;

/// A merged, time-ordered stream of EVTX events from multiple channels.
#[derive(Debug, Default)]
pub struct SuperTimeline {
    events: Vec<EvtxEvent>,
}

impl SuperTimeline {
    /// Merge and sort events from any number of channels by `timestamp_ns`.
    pub fn from_events(mut events: Vec<EvtxEvent>) -> Self {
        events.sort_by_key(|e| e.timestamp_ns);
        Self { events }
    }

    /// All events in chronological order.
    pub fn events(&self) -> &[EvtxEvent] {
        &self.events
    }

    /// Events from a specific channel in chronological order.
    pub fn filter_channel<'a>(&'a self, channel: &str) -> Vec<&'a EvtxEvent> {
        self.events
            .iter()
            .filter(|e| e.channel == channel)
            .collect()
    }

    /// Events whose `event_id` is in `ids`.
    pub fn filter_event_ids<'a>(&'a self, ids: &[u32]) -> Vec<&'a EvtxEvent> {
        self.events
            .iter()
            .filter(|e| ids.contains(&e.event_id))
            .collect()
    }

    /// Number of events in the timeline.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// True when the timeline contains no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Returns true if `channel` is one of the five super-timeline channels.
pub fn is_super_timeline_channel(channel: &str) -> bool {
    SUPER_TIMELINE_CHANNELS.contains(&channel)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, channel: &str, timestamp_ns: i64) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: channel.to_string(),
            timestamp_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        }
    }

    #[test]
    fn super_timeline_empty_from_no_events() {
        let tl = SuperTimeline::from_events(vec![]);
        assert!(tl.is_empty());
        assert_eq!(tl.len(), 0);
    }

    #[test]
    fn super_timeline_sorts_events_by_timestamp() {
        let events = vec![
            make_event(4624, "Security", 3_000_000_000),
            make_event(6005, "System", 1_000_000_000),
            make_event(1, "Microsoft-Windows-Sysmon/Operational", 2_000_000_000),
        ];
        let tl = SuperTimeline::from_events(events);
        let ev = tl.events();
        assert_eq!(ev.len(), 3);
        assert_eq!(ev[0].timestamp_ns, 1_000_000_000);
        assert_eq!(ev[1].timestamp_ns, 2_000_000_000);
        assert_eq!(ev[2].timestamp_ns, 3_000_000_000);
    }

    #[test]
    fn super_timeline_filter_channel_returns_only_that_channel() {
        let events = vec![
            make_event(4624, "Security", 1_000),
            make_event(6005, "System", 2_000),
            make_event(4624, "Security", 3_000),
        ];
        let tl = SuperTimeline::from_events(events);
        let sec = tl.filter_channel("Security");
        assert_eq!(sec.len(), 2);
        assert!(sec.iter().all(|e| e.channel == "Security"));
    }

    #[test]
    fn super_timeline_filter_event_ids() {
        let events = vec![
            make_event(4624, "Security", 1_000),
            make_event(4688, "Security", 2_000),
            make_event(6005, "System", 3_000),
        ];
        let tl = SuperTimeline::from_events(events);
        let proc = tl.filter_event_ids(&[4688, 4689]);
        assert_eq!(proc.len(), 1);
        assert_eq!(proc[0].event_id, 4688);
    }

    #[test]
    fn is_super_timeline_channel_returns_true_for_security() {
        assert!(is_super_timeline_channel("Security"));
    }

    #[test]
    fn is_super_timeline_channel_returns_true_for_sysmon() {
        assert!(is_super_timeline_channel(
            "Microsoft-Windows-Sysmon/Operational"
        ));
    }

    #[test]
    fn is_super_timeline_channel_returns_false_for_application() {
        assert!(!is_super_timeline_channel("Application"));
    }
}
