//! Rare-event analysis and EVTX diff: histogram-based rarity, Z-score anomaly scoring, set diff.

use winevt_core::EvtxEvent;

/// A rare process or event detected by frequency analysis.
#[derive(Debug, Clone)]
pub struct RareEvent {
    /// The event that appeared rarely.
    pub event: EvtxEvent,
    /// The key value that was counted (e.g., process image basename).
    pub key: String,
    /// Count of occurrences.
    pub count: usize,
}

/// A frequency anomaly scored by Z-score within time windows.
#[derive(Debug, Clone)]
pub struct FrequencyAnomaly {
    /// Event ID of the anomalous bucket.
    pub event_id: u32,
    /// Time window start (nanoseconds).
    pub window_start_ns: i64,
    /// Event count in this window.
    pub count: usize,
    /// Z-score relative to other windows.
    pub z_score: f64,
}

/// An event present in one set but not the other.
#[derive(Debug, Clone)]
pub struct DiffEntry {
    /// The event that differs.
    pub event: EvtxEvent,
    /// Which side it came from.
    pub side: DiffSide,
}

/// Which side of the diff the entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    Left,
    Right,
}

/// Find processes that appear fewer than `threshold` times (rare-process detection).
///
/// Groups by executable basename (case-insensitive) from EID 4688 / Sysmon EID 1.
pub fn detect_rare_processes(events: &[EvtxEvent], threshold: usize) -> Vec<RareEvent> {
    todo!()
}

/// Sort histogram entries ascending by count (least-frequency-first ordering, LFO).
///
/// Returns (key, count) pairs sorted by count ascending, then key alphabetically.
pub fn stack_count_lfo(events: &[EvtxEvent]) -> Vec<(String, usize)> {
    todo!()
}

/// Detect frequency anomalies using Z-score over EID rate in fixed-size time windows.
///
/// Splits the event stream into `window_ns`-wide buckets, computes counts per EID per bucket,
/// then Z-scores each bucket count against the global mean/stddev for that EID.
/// Returns buckets where |z_score| >= `z_threshold`.
pub fn frequency_anomaly_score(
    events: &[EvtxEvent],
    window_ns: i64,
    z_threshold: f64,
) -> Vec<FrequencyAnomaly> {
    todo!()
}

/// Diff two EVTX event sets by canonical hash (event_id + channel + sorted data).
///
/// Returns entries present in `left` but not `right` (side=Left) and
/// entries present in `right` but not `left` (side=Right).
pub fn evtx_diff(left: &[EvtxEvent], right: &[EvtxEvent]) -> Vec<DiffEntry> {
    todo!()
}

/// Compute a canonical hash for an event (event_id + channel + sorted data kv pairs).
/// Used by `evtx_diff` for set membership.
pub fn event_canonical_hash(event: &EvtxEvent) -> u64 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_proc_event(image: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("NewProcessName".into(), format!("C:\\Windows\\{image}"));
        EvtxEvent {
            event_id: 4688,
            channel: "Security".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn make_event(event_id: u32, ts: i64) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: "Security".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        }
    }

    // ── Rare process detection ────────────────────────────────────────────────

    #[test]
    fn detect_rare_processes_empty_returns_empty() {
        assert!(detect_rare_processes(&[], 5).is_empty());
    }

    #[test]
    fn detect_rare_processes_flags_single_occurrence() {
        let events = vec![
            make_proc_event("cmd.exe", 1000),
            make_proc_event("cmd.exe", 2000),
            make_proc_event("cmd.exe", 3000),
            make_proc_event("mimikatz.exe", 4000), // only once
        ];
        let rare = detect_rare_processes(&events, 2);
        assert_eq!(rare.len(), 1, "mimikatz.exe appears once, below threshold 2");
        assert_eq!(rare[0].key, "mimikatz.exe");
        assert_eq!(rare[0].count, 1);
    }

    #[test]
    fn detect_rare_processes_case_insensitive() {
        let events = vec![
            make_proc_event("CMD.EXE", 1000),
            make_proc_event("cmd.exe", 2000),
            make_proc_event("Cmd.Exe", 3000),
        ];
        // All three are the same basename — count=3, above threshold=5
        let rare = detect_rare_processes(&events, 5);
        assert!(rare.is_empty(), "case-normalized group should not be rare");
    }

    // ── LFO stack count ───────────────────────────────────────────────────────

    #[test]
    fn stack_count_lfo_empty_returns_empty() {
        assert!(stack_count_lfo(&[]).is_empty());
    }

    #[test]
    fn stack_count_lfo_sorted_ascending() {
        let events = vec![
            make_proc_event("cmd.exe", 1000),
            make_proc_event("cmd.exe", 2000),
            make_proc_event("cmd.exe", 3000),
            make_proc_event("evil.exe", 4000), // count=1
        ];
        let lfo = stack_count_lfo(&events);
        assert!(!lfo.is_empty());
        // First entry should have the lowest count
        let counts: Vec<usize> = lfo.iter().map(|(_, c)| *c).collect();
        for w in counts.windows(2) {
            assert!(w[0] <= w[1], "LFO should be sorted ascending by count");
        }
    }

    // ── Frequency anomaly scoring ─────────────────────────────────────────────

    #[test]
    fn frequency_anomaly_empty_returns_empty() {
        assert!(frequency_anomaly_score(&[], 60_000_000_000, 2.0).is_empty());
    }

    #[test]
    fn frequency_anomaly_spike_detected() {
        let ns = 1_000_000_000_i64;
        let window = 60 * ns;
        // 10 windows with ~1 event each, then one window with 50 events
        let mut events: Vec<_> = (0..10).map(|i| make_event(4624, i * window)).collect();
        // Spike window
        events.extend((0..50).map(|i| make_event(4624, 10 * window + i * ns)));
        let anomalies = frequency_anomaly_score(&events, window as i64, 2.0);
        assert!(!anomalies.is_empty(), "spike window should be detected as anomaly");
        let max_z = anomalies.iter().map(|a| a.z_score).fold(0.0_f64, f64::max);
        assert!(max_z > 2.0, "spike z-score should exceed threshold");
    }

    // ── EVTX diff ─────────────────────────────────────────────────────────────

    #[test]
    fn evtx_diff_identical_sets_returns_empty() {
        let events = vec![make_event(4624, 1000), make_event(4688, 2000)];
        let diff = evtx_diff(&events, &events);
        assert!(diff.is_empty(), "identical sets should produce empty diff");
    }

    #[test]
    fn evtx_diff_finds_left_only_entry() {
        let left = vec![make_event(4624, 1000), make_event(4688, 2000)];
        let right = vec![make_event(4624, 1000)];
        let diff = evtx_diff(&left, &right);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].side, DiffSide::Left);
        assert_eq!(diff[0].event.event_id, 4688);
    }

    #[test]
    fn evtx_diff_finds_right_only_entry() {
        let left = vec![make_event(4624, 1000)];
        let right = vec![make_event(4624, 1000), make_event(4697, 3000)];
        let diff = evtx_diff(&left, &right);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].side, DiffSide::Right);
        assert_eq!(diff[0].event.event_id, 4697);
    }

    #[test]
    fn evtx_diff_empty_both_returns_empty() {
        assert!(evtx_diff(&[], &[]).is_empty());
    }

    // ── Canonical hash ────────────────────────────────────────────────────────

    #[test]
    fn canonical_hash_same_event_same_hash() {
        let e = make_event(4624, 1000);
        assert_eq!(event_canonical_hash(&e), event_canonical_hash(&e));
    }

    #[test]
    fn canonical_hash_different_event_id_different_hash() {
        let e1 = make_event(4624, 1000);
        let e2 = make_event(4688, 1000);
        assert_ne!(event_canonical_hash(&e1), event_canonical_hash(&e2));
    }
}
