//! Anti-forensics detection: log clearing, service tampering, time skew, Sysmon tampering.

use forensicnomicon::heuristics::evtx::{
    EID_LOG_CLEARED, EID_LOG_CLEARED_SYSTEM, EID_CHANNEL_LOG_CLEARED,
    EID_SYSMON_DRIVER_UNLOAD, EID_SYSMON_CONFIG_CHANGE, SYSMON_CHANNEL,
    EID_W32TIME_NTP_FAILED,
};
use winevt_core::EvtxEvent;

use crate::gap_inference::{detect_gaps, GapConfig};

/// An anti-forensics alert.
#[derive(Debug, Clone)]
pub struct AntiForensicsAlert {
    pub kind: AlertKind,
    pub description: String,
    pub evidence: Vec<EvtxEvent>,
}

/// Category of anti-forensics alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    LogClearing,
    ServiceStopAroundGap,
    TimeSkew,
    SysmonTampering,
    ChannelDisabled,
    PsHistoryWipe,
}

/// Detect log clearing: EID 1102 or EID 104.
pub fn detect_log_clearing(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    events
        .iter()
        .filter(|e| e.event_id == EID_LOG_CLEARED || e.event_id == EID_LOG_CLEARED_SYSTEM)
        .map(|e| AntiForensicsAlert {
            kind: AlertKind::LogClearing,
            description: format!(
                "Event log cleared (EID {}) by '{}'",
                e.event_id,
                e.data.get("SubjectUserName").map(String::as_str).unwrap_or("?")
            ),
            evidence: vec![e.clone()],
        })
        .collect()
}

/// Detect service stop around event-log gaps using gap_inference.
///
/// Looks for boot/shutdown events (6005/6006/6008) that are suspiciously close to
/// gap_inference silent windows, hinting that the system was stopped to allow log tampering.
pub fn detect_service_stop_around_gaps(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    let gaps = detect_gaps(events, &GapConfig::default());
    if gaps.is_empty() {
        return vec![];
    }

    // Find shutdown/restart events near gap boundaries (within 60 s)
    const SHUTDOWN_EIDS: &[u32] = &[6005, 6006, 6008];
    const PROXIMITY_NS: i64 = 60 * 1_000_000_000;

    let mut alerts = Vec::new();
    for gap in &gaps {
        for ev in events {
            if !SHUTDOWN_EIDS.contains(&ev.event_id) { continue; }
            let near_start = (ev.timestamp_ns - gap.start_ns).abs() < PROXIMITY_NS;
            let near_end = (ev.timestamp_ns - gap.end_ns).abs() < PROXIMITY_NS;
            if near_start || near_end {
                alerts.push(AntiForensicsAlert {
                    kind: AlertKind::ServiceStopAroundGap,
                    description: format!(
                        "Boot/shutdown EID {} within 60s of a {:.0}s silent window",
                        ev.event_id, gap.duration_secs
                    ),
                    evidence: vec![ev.clone()],
                });
            }
        }
    }
    alerts
}

/// Detect time skew: non-monotonic timestamps or W32Time sync failure (EID 37).
pub fn detect_time_skew(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    let mut alerts = Vec::new();

    // W32Time sync failures
    for ev in events {
        if ev.event_id == EID_W32TIME_NTP_FAILED {
            alerts.push(AntiForensicsAlert {
                kind: AlertKind::TimeSkew,
                description: format!(
                    "W32Time sync failure (EID {}): error {:?}",
                    ev.event_id,
                    ev.data.get("ErrorCode")
                ),
                evidence: vec![ev.clone()],
            });
        }
    }

    // Non-monotonic timestamp sequence
    let mut sorted_ts: Vec<(i64, usize)> = events.iter()
        .enumerate()
        .map(|(i, e)| (e.timestamp_ns, i))
        .collect();
    sorted_ts.sort_unstable_by_key(|(ts, _)| *ts);

    // Find backward jumps: original sequence position goes out of order
    let mut prev_ts = i64::MIN;
    for ev in events {
        if ev.timestamp_ns < prev_ts {
            alerts.push(AntiForensicsAlert {
                kind: AlertKind::TimeSkew,
                description: format!(
                    "Non-monotonic timestamp: {} < previous {}",
                    ev.timestamp_ns, prev_ts
                ),
                evidence: vec![ev.clone()],
            });
        }
        prev_ts = ev.timestamp_ns;
    }

    alerts
}

/// Detect Sysmon tampering: EID 255 (driver unload) or EID 16 (config change).
pub fn detect_sysmon_tampering(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    events
        .iter()
        .filter(|e| e.channel == SYSMON_CHANNEL)
        .filter(|e| e.event_id == EID_SYSMON_DRIVER_UNLOAD || e.event_id == EID_SYSMON_CONFIG_CHANGE)
        .map(|e| AntiForensicsAlert {
            kind: AlertKind::SysmonTampering,
            description: format!(
                "Sysmon tampered: EID {} ({})",
                e.event_id,
                if e.event_id == EID_SYSMON_DRIVER_UNLOAD { "driver unload" } else { "config change" }
            ),
            evidence: vec![e.clone()],
        })
        .collect()
}

/// Detect channel disable: EID 104 (log cleared/disabled) or EID 105.
pub fn detect_channel_disable(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    events
        .iter()
        .filter(|e| e.event_id == EID_CHANNEL_LOG_CLEARED || e.event_id == 105)
        .map(|e| AntiForensicsAlert {
            kind: AlertKind::ChannelDisabled,
            description: format!(
                "Channel disable event (EID {}): channel {:?}",
                e.event_id,
                e.data.get("Channel")
            ),
            evidence: vec![e.clone()],
        })
        .collect()
}

/// Run all anti-forensics detectors.
pub fn run_all_antiforensics(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    let mut results = Vec::new();
    results.extend(detect_log_clearing(events));
    results.extend(detect_service_stop_around_gaps(events));
    results.extend(detect_time_skew(events));
    results.extend(detect_sysmon_tampering(events));
    results.extend(detect_channel_disable(events));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_id: u32, channel: &str, data: Vec<(&str, &str)>, ts: i64) -> EvtxEvent {
        EvtxEvent {
            event_id, channel: channel.into(), timestamp_ns: ts, computer: "WS01".into(),
            user_sid: None, logon_id: None, process_id: None, thread_id: None,
            data: data.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        }
    }

    #[test]
    fn log_clearing_detected_on_eid_1102() {
        let events = vec![make_event(1102, "Security", vec![("SubjectUserName", "attacker")], 1_000_000_000)];
        let alerts = detect_log_clearing(&events);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].kind, AlertKind::LogClearing);
    }

    #[test]
    fn log_clearing_detected_on_eid_104() {
        let events = vec![make_event(104, "System", vec![], 1_000_000_000)];
        let alerts = detect_log_clearing(&events);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].kind, AlertKind::LogClearing);
    }

    #[test]
    fn log_clearing_empty_events() {
        assert!(detect_log_clearing(&[]).is_empty());
    }

    #[test]
    fn service_stop_around_gaps_empty_returns_empty() {
        assert!(detect_service_stop_around_gaps(&[]).is_empty());
    }

    #[test]
    fn service_stop_around_gaps_uniform_stream_no_alert() {
        let ns = 1_000_000_000_i64;
        let events: Vec<_> = (0..50).map(|i| make_event(4624, "Security", vec![], i * ns)).collect();
        assert!(detect_service_stop_around_gaps(&events).is_empty());
    }

    #[test]
    fn time_skew_detected_on_backward_jump() {
        let ns = 1_000_000_000_i64;
        let events = vec![
            make_event(4624, "Security", vec![], 100 * ns),
            make_event(4624, "Security", vec![], 50 * ns),
        ];
        let alerts = detect_time_skew(&events);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].kind, AlertKind::TimeSkew);
    }

    #[test]
    fn time_skew_w32time_sync_failure_detected() {
        let events = vec![make_event(37, "System", vec![("ErrorCode", "0x800705B4")], 1_000_000_000)];
        let alerts = detect_time_skew(&events);
        assert!(!alerts.is_empty());
    }

    #[test]
    fn time_skew_empty_events() {
        assert!(detect_time_skew(&[]).is_empty());
    }

    #[test]
    fn sysmon_tampering_detected_on_eid_255() {
        let events = vec![make_event(255, "Microsoft-Windows-Sysmon/Operational", vec![], 1_000_000_000)];
        let alerts = detect_sysmon_tampering(&events);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].kind, AlertKind::SysmonTampering);
    }

    #[test]
    fn sysmon_tampering_detected_on_eid_16() {
        let events = vec![make_event(16, "Microsoft-Windows-Sysmon/Operational", vec![("Configuration","C:\\Temp\\custom.xml")], 1_000_000_000)];
        let alerts = detect_sysmon_tampering(&events);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].kind, AlertKind::SysmonTampering);
    }

    #[test]
    fn channel_disable_detected_on_eid_105() {
        let events = vec![make_event(105, "System", vec![("Channel","Microsoft-Windows-Sysmon/Operational")], 1_000_000_000)];
        let alerts = detect_channel_disable(&events);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].kind, AlertKind::ChannelDisabled);
    }

    #[test]
    fn run_all_antiforensics_empty_returns_empty() {
        assert!(run_all_antiforensics(&[]).is_empty());
    }

    #[test]
    fn run_all_antiforensics_aggregates_multiple() {
        let events = vec![
            make_event(1102, "Security", vec![("SubjectUserName", "attacker")], 1_000),
            make_event(255, "Microsoft-Windows-Sysmon/Operational", vec![], 2_000),
        ];
        let alerts = run_all_antiforensics(&events);
        assert!(alerts.len() >= 2);
    }

    // ── PS history wipe tests (RED) ──────────────────────────────────────────

    #[test]
    fn ps_history_wipe_detected_on_sysmon_eid23() {
        let events = vec![make_event(23, "Microsoft-Windows-Sysmon/Operational",
            vec![("TargetFilename",
                  "C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"),
                 ("Image","C:\\Windows\\System32\\cmd.exe")],
            1_000_000_000)];
        let alerts = detect_ps_history_wipe(&events);
        assert!(!alerts.is_empty(), "Sysmon EID 23 on ConsoleHost_history.txt must be detected");
        assert_eq!(alerts[0].kind, AlertKind::PsHistoryWipe);
    }

    #[test]
    fn ps_history_wipe_other_file_not_detected() {
        let events = vec![make_event(23, "Microsoft-Windows-Sysmon/Operational",
            vec![("TargetFilename","C:\\Users\\victim\\Desktop\\legit.txt"),
                 ("Image","C:\\Windows\\System32\\cmd.exe")],
            1_000)];
        assert!(detect_ps_history_wipe(&events).is_empty());
    }

    #[test]
    fn ps_history_wipe_wrong_eid_not_detected() {
        let events = vec![make_event(11, "Microsoft-Windows-Sysmon/Operational",
            vec![("TargetFilename","C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt")],
            1_000)];
        assert!(detect_ps_history_wipe(&events).is_empty());
    }

    #[test]
    fn ps_history_wipe_empty() { assert!(detect_ps_history_wipe(&[]).is_empty()); }
}
