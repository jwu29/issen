//! Rare-event analysis and EVTX diff.

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SYSMON_CHANNEL,
};
use winevt_core::EvtxEvent;

#[derive(Debug, Clone)]
pub struct RareEvent {
    pub event: EvtxEvent,
    pub key: String,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct FrequencyAnomaly {
    pub event_id: u32,
    pub window_start_ns: i64,
    pub count: usize,
    pub z_score: f64,
}

#[derive(Debug, Clone)]
pub struct DiffEntry {
    pub event: EvtxEvent,
    pub side: DiffSide,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffSide {
    Left,
    Right,
}

fn image_basename(ev: &EvtxEvent) -> Option<String> {
    let path = if ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL {
        ev.data.get("Image")?.as_str()
    } else if ev.event_id == EID_PROCESS_CREATE {
        ev.data.get("NewProcessName")?.as_str()
    } else {
        return None;
    };
    Some(
        path.rsplit(['\\', '/'])
            .next()
            .unwrap_or(path)
            .to_lowercase(),
    )
}

/// Find processes that appear fewer than `threshold` times.
pub fn detect_rare_processes(events: &[EvtxEvent], threshold: usize) -> Vec<RareEvent> {
    use std::collections::HashMap;

    let mut counts: HashMap<String, Vec<&EvtxEvent>> = HashMap::new();
    for ev in events {
        if let Some(basename) = image_basename(ev) {
            counts.entry(basename).or_default().push(ev);
        }
    }

    // Only flag rare processes when a common baseline exists (some process meets threshold).
    let has_baseline = counts.values().any(|evs| evs.len() >= threshold);
    if !has_baseline {
        return vec![];
    }

    counts
        .into_iter()
        .filter(|(_, evs)| evs.len() < threshold)
        .flat_map(|(key, evs)| {
            let count = evs.len();
            evs.into_iter().map(move |e| RareEvent {
                event: e.clone(),
                key: key.clone(),
                count,
            })
        })
        .collect()
}

/// Sort histogram entries ascending by count (LFO).
pub fn stack_count_lfo(events: &[EvtxEvent]) -> Vec<(String, usize)> {
    use std::collections::HashMap;

    let mut counts: HashMap<String, usize> = HashMap::new();
    for ev in events {
        if let Some(basename) = image_basename(ev) {
            *counts.entry(basename).or_default() += 1;
        }
    }

    let mut lfo: Vec<(String, usize)> = counts.into_iter().collect();
    lfo.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
    lfo
}

/// Detect frequency anomalies using Z-score over EID rate in fixed-size time windows.
pub fn frequency_anomaly_score(
    events: &[EvtxEvent],
    window_ns: i64,
    z_threshold: f64,
) -> Vec<FrequencyAnomaly> {
    use std::collections::HashMap;

    if events.is_empty() || window_ns <= 0 {
        return vec![];
    }

    let min_ts = events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);

    // Count events per (event_id, window_bucket)
    let mut buckets: HashMap<(u32, i64), usize> = HashMap::new();
    for ev in events {
        let bucket = ((ev.timestamp_ns - min_ts) / window_ns) * window_ns + min_ts;
        *buckets.entry((ev.event_id, bucket)).or_default() += 1;
    }

    // Group by event_id to compute mean/stddev
    let mut by_eid: HashMap<u32, Vec<(i64, usize)>> = HashMap::new();
    for ((eid, bucket), count) in &buckets {
        by_eid.entry(*eid).or_default().push((*bucket, *count));
    }

    let mut anomalies = Vec::new();
    for (eid, windows) in &by_eid {
        if windows.len() < 2 {
            continue;
        }
        let counts: Vec<f64> = windows.iter().map(|(_, c)| *c as f64).collect();
        let mean = counts.iter().sum::<f64>() / counts.len() as f64;
        let variance = counts.iter().map(|c| (c - mean).powi(2)).sum::<f64>() / counts.len() as f64;
        let stddev = variance.sqrt();
        if stddev < 1e-9 {
            continue;
        }

        for (bucket, count) in windows {
            let z = (*count as f64 - mean) / stddev;
            if z.abs() >= z_threshold {
                anomalies.push(FrequencyAnomaly {
                    event_id: *eid,
                    window_start_ns: *bucket,
                    count: *count,
                    z_score: z,
                });
            }
        }
    }
    anomalies
}

/// Compute a canonical hash for an event.
pub fn event_canonical_hash(event: &EvtxEvent) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    event.event_id.hash(&mut hasher);
    event.channel.hash(&mut hasher);
    event.computer.hash(&mut hasher);
    // Sort data keys for determinism
    let mut kv: Vec<(&String, &String)> = event.data.iter().collect();
    kv.sort_by_key(|(k, _)| *k);
    for (k, v) in kv {
        k.hash(&mut hasher);
        v.hash(&mut hasher);
    }
    hasher.finish()
}

/// Diff two EVTX event sets by canonical hash.
pub fn evtx_diff(left: &[EvtxEvent], right: &[EvtxEvent]) -> Vec<DiffEntry> {
    use std::collections::HashSet;

    let left_hashes: HashSet<u64> = left.iter().map(event_canonical_hash).collect();
    let right_hashes: HashSet<u64> = right.iter().map(event_canonical_hash).collect();

    let mut result = Vec::new();

    // Events in left but not right
    for ev in left {
        let h = event_canonical_hash(ev);
        if !right_hashes.contains(&h) {
            result.push(DiffEntry {
                event: ev.clone(),
                side: DiffSide::Left,
            });
        }
    }

    // Events in right but not left
    for ev in right {
        let h = event_canonical_hash(ev);
        if !left_hashes.contains(&h) {
            result.push(DiffEntry {
                event: ev.clone(),
                side: DiffSide::Right,
            });
        }
    }

    result
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
            make_proc_event("mimikatz.exe", 4000),
        ];
        let rare = detect_rare_processes(&events, 2);
        assert_eq!(rare.len(), 1);
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
        let rare = detect_rare_processes(&events, 5);
        assert!(rare.is_empty());
    }

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
            make_proc_event("evil.exe", 4000),
        ];
        let lfo = stack_count_lfo(&events);
        assert!(!lfo.is_empty());
        let counts: Vec<usize> = lfo.iter().map(|(_, c)| *c).collect();
        for w in counts.windows(2) {
            assert!(w[0] <= w[1]);
        }
    }

    #[test]
    fn frequency_anomaly_empty_returns_empty() {
        assert!(frequency_anomaly_score(&[], 60_000_000_000, 2.0).is_empty());
    }

    #[test]
    fn frequency_anomaly_spike_detected() {
        let ns = 1_000_000_000_i64;
        let window = 60 * ns;
        let mut events: Vec<_> = (0..10).map(|i| make_event(4624, i * window)).collect();
        events.extend((0..50).map(|i| make_event(4624, 10 * window + i * ns)));
        let anomalies = frequency_anomaly_score(&events, window, 2.0);
        assert!(!anomalies.is_empty());
        let max_z = anomalies.iter().map(|a| a.z_score).fold(0.0_f64, f64::max);
        assert!(max_z > 2.0);
    }

    #[test]
    fn evtx_diff_identical_sets_returns_empty() {
        let events = vec![make_event(4624, 1000), make_event(4688, 2000)];
        assert!(evtx_diff(&events, &events).is_empty());
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
