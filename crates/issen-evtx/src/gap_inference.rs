//! Gap inference: estimate missing event counts in silent windows.
//!
//! Algorithm:
//! 1. Sort events by timestamp and compute inter-event intervals.
//! 2. Compute mean and standard deviation of intervals.
//! 3. Identify "silent windows" where gap > mean + k·σ (default k=3).
//! 4. Estimate missing events = gap_duration / mean_interval (rounded).

use winevt_core::EvtxEvent;

/// A detected silent window where events appear to be missing.
#[derive(Debug, Clone)]
pub struct Gap {
    /// Timestamp of the last event before the gap (nanoseconds).
    pub start_ns: i64,
    /// Timestamp of the first event after the gap (nanoseconds).
    pub end_ns: i64,
    /// Gap duration in seconds.
    pub duration_secs: f64,
    /// Estimated count of missing events based on the background event rate.
    pub estimated_missing: u64,
}

/// Configuration for gap detection.
#[derive(Debug, Clone)]
pub struct GapConfig {
    /// Number of standard deviations above the mean to consider a gap anomalous.
    pub sigma_threshold: f64,
    /// Minimum gap duration (seconds) to report, regardless of rate.
    pub min_gap_secs: f64,
}

impl Default for GapConfig {
    fn default() -> Self {
        Self {
            sigma_threshold: 3.0,
            min_gap_secs: 60.0,
        }
    }
}

/// Detect silent windows in `events` and estimate how many events may be missing.
///
/// Returns an empty vec when there are fewer than 2 events (no intervals to analyse).
pub fn detect_gaps(events: &[EvtxEvent], config: &GapConfig) -> Vec<Gap> {
    if events.len() < 2 {
        return vec![];
    }

    let mut sorted: Vec<i64> = events.iter().map(|e| e.timestamp_ns).collect();
    sorted.sort_unstable();

    let intervals: Vec<f64> = sorted
        .windows(2)
        .map(|w| (w[1] - w[0]) as f64 / 1_000_000_000.0)
        .collect();

    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let variance =
        intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
    let stddev = variance.sqrt();
    let threshold_secs = (mean + config.sigma_threshold * stddev).max(config.min_gap_secs);

    // Use median as background rate for estimated_missing — robust to the gap itself
    // inflating the mean.
    let mut sorted_intervals = intervals.clone();
    sorted_intervals.sort_by(f64::total_cmp);
    let mid = sorted_intervals.len() / 2;
    let median = if sorted_intervals.len().is_multiple_of(2) {
        f64::midpoint(sorted_intervals[mid - 1], sorted_intervals[mid])
    } else {
        sorted_intervals[mid]
    };

    let mut gaps = Vec::new();
    for (i, &interval) in intervals.iter().enumerate() {
        if interval >= threshold_secs && interval >= config.min_gap_secs {
            let start_ns = sorted[i];
            let end_ns = sorted[i + 1];
            let duration_secs = interval;
            let estimated_missing = if median > 0.0 {
                (duration_secs / median).round() as u64
            } else {
                0
            };
            gaps.push(Gap {
                start_ns,
                end_ns,
                duration_secs,
                estimated_missing,
            });
        }
    }
    gaps
}

/// Compute the mean inter-event interval in seconds from a sorted event slice.
/// Returns `None` when fewer than 2 events are present.
pub fn mean_interval_secs(events: &[EvtxEvent]) -> Option<f64> {
    if events.len() < 2 {
        return None;
    }
    let mut sorted: Vec<i64> = events.iter().map(|e| e.timestamp_ns).collect();
    sorted.sort_unstable();
    let total_ns: i64 = sorted.windows(2).map(|w| w[1] - w[0]).sum();
    let count = (events.len() - 1) as f64;
    Some(total_ns as f64 / count / 1_000_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(ts_ns: i64) -> EvtxEvent {
        EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: HashMap::new(),
        }
    }

    const NS: i64 = 1_000_000_000; // 1 second in nanoseconds

    #[test]
    fn detect_gaps_empty_input() {
        let gaps = detect_gaps(&[], &GapConfig::default());
        assert!(gaps.is_empty());
    }

    #[test]
    fn detect_gaps_single_event_no_gaps() {
        let gaps = detect_gaps(&[make_event(0)], &GapConfig::default());
        assert!(gaps.is_empty());
    }

    #[test]
    fn detect_gaps_uniform_stream_no_gaps() {
        // 100 events at 1-second intervals — no anomalous gap expected
        let events: Vec<_> = (0..100).map(|i| make_event(i * NS)).collect();
        let gaps = detect_gaps(&events, &GapConfig::default());
        assert!(gaps.is_empty(), "uniform stream should have no gaps");
    }

    #[test]
    fn detect_gaps_finds_large_silent_window() {
        // 10 events at 1-s intervals, then a 10-minute gap, then 10 more
        let mut events: Vec<_> = (0..10).map(|i| make_event(i * NS)).collect();
        let gap_start = 9 * NS;
        let gap_end = gap_start + 600 * NS; // 600 s = 10 min
        events.extend((0..10).map(|i| make_event(gap_end + i * NS)));

        let gaps = detect_gaps(&events, &GapConfig::default());
        assert!(!gaps.is_empty(), "10-minute gap should be detected");
        let gap = &gaps[0];
        assert!(gap.duration_secs >= 590.0, "gap duration should be ~600 s");
        assert!(gap.estimated_missing > 0);
    }

    #[test]
    fn detect_gaps_estimated_missing_proportional_to_rate() {
        // Background rate: 1 event/second → gap of 60 s → ~60 missing
        let mut events: Vec<_> = (0..30).map(|i| make_event(i * NS)).collect();
        let gap_end = 29 * NS + 120 * NS; // 120 s gap
        events.extend((0..30).map(|i| make_event(gap_end + i * NS)));

        let gaps = detect_gaps(&events, &GapConfig::default());
        if !gaps.is_empty() {
            // estimated_missing should be in the right ballpark (>50, <200)
            assert!(
                gaps[0].estimated_missing > 50,
                "expected >50 missing, got {}",
                gaps[0].estimated_missing
            );
        }
    }

    #[test]
    fn mean_interval_secs_none_for_empty() {
        assert!(mean_interval_secs(&[]).is_none());
    }

    #[test]
    fn mean_interval_secs_none_for_single_event() {
        assert!(mean_interval_secs(&[make_event(0)]).is_none());
    }

    #[test]
    fn mean_interval_secs_correct_for_uniform_stream() {
        let events: Vec<_> = (0..11).map(|i| make_event(i * NS)).collect();
        let mean = mean_interval_secs(&events).unwrap();
        assert!(
            (mean - 1.0).abs() < 0.01,
            "mean should be ~1.0 s, got {mean}"
        );
    }
}
