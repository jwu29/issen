//! Anti-forensics detection: log clearing, service tampering, time skew, Sysmon tampering.

use winevt_core::EvtxEvent;

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
}

/// Detect log clearing: EID 1102 (Security audit log cleared) or EID 104 (System log cleared).
/// Cross-references gap_inference to flag clearings that correlate with silent windows.
pub fn detect_log_clearing(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    todo!()
}

/// Detect services stopped around event-log gaps: correlates boot_cycle boundaries with
/// gap_inference silent windows.
pub fn detect_service_stop_around_gaps(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    todo!()
}

/// Detect time skew: non-monotonic timestamp sequences and W32Time EID 1/158 sync failures.
pub fn detect_time_skew(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    todo!()
}

/// Detect Sysmon tampering: EID 255 (driver unload error) or EID 16 (config change).
pub fn detect_sysmon_tampering(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    todo!()
}

/// Detect channel disable: EID 104 (log cleared/disabled) or EID 105 (channel enabled/disabled).
pub fn detect_channel_disable(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    todo!()
}

/// Run all anti-forensics detectors.
pub fn run_all_antiforensics(events: &[EvtxEvent]) -> Vec<AntiForensicsAlert> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, channel: &str, data: Vec<(&str, &str)>, ts: i64) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: channel.into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data: data.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        }
    }

    // ── Log Clearing ──────────────────────────────────────────────────────────

    #[test]
    fn log_clearing_detected_on_eid_1102() {
        let events = vec![make_event(1102, "Security", vec![("SubjectUserName", "attacker")], 1_000_000_000)];
        let alerts = detect_log_clearing(&events);
        assert!(!alerts.is_empty(), "EID 1102 should trigger log clearing alert");
        assert_eq!(alerts[0].kind, AlertKind::LogClearing);
    }

    #[test]
    fn log_clearing_detected_on_eid_104() {
        let events = vec![make_event(104, "System", vec![], 1_000_000_000)];
        let alerts = detect_log_clearing(&events);
        assert!(!alerts.is_empty(), "EID 104 should trigger log clearing alert");
        assert_eq!(alerts[0].kind, AlertKind::LogClearing);
    }

    #[test]
    fn log_clearing_empty_events() {
        assert!(detect_log_clearing(&[]).is_empty());
    }

    // ── Service Stop Around Gaps ──────────────────────────────────────────────

    #[test]
    fn service_stop_around_gaps_empty_returns_empty() {
        assert!(detect_service_stop_around_gaps(&[]).is_empty());
    }

    #[test]
    fn service_stop_around_gaps_uniform_stream_no_alert() {
        // Dense uniform event stream — no gaps → no alert
        let ns = 1_000_000_000_i64;
        let events: Vec<_> = (0..50).map(|i| make_event(4624, "Security", vec![], i * ns)).collect();
        let alerts = detect_service_stop_around_gaps(&events);
        assert!(alerts.is_empty(), "uniform stream should produce no alerts");
    }

    // ── Time Skew ─────────────────────────────────────────────────────────────

    #[test]
    fn time_skew_detected_on_backward_jump() {
        let ns = 1_000_000_000_i64;
        let events = vec![
            make_event(4624, "Security", vec![], 100 * ns),
            make_event(4624, "Security", vec![], 50 * ns),  // backwards
        ];
        let alerts = detect_time_skew(&events);
        assert!(!alerts.is_empty(), "backward timestamp jump should trigger time skew");
        assert_eq!(alerts[0].kind, AlertKind::TimeSkew);
    }

    #[test]
    fn time_skew_w32time_sync_failure_detected() {
        // W32Time EID 158 = time sync
        let events = vec![make_event(37, "System", vec![("ErrorCode", "0x800705B4")], 1_000_000_000)];
        let alerts = detect_time_skew(&events);
        assert!(!alerts.is_empty(), "W32Time sync failure should flag time skew");
    }

    #[test]
    fn time_skew_empty_events() {
        assert!(detect_time_skew(&[]).is_empty());
    }

    // ── Sysmon Tampering ─────────────────────────────────────────────────────

    #[test]
    fn sysmon_tampering_detected_on_eid_255() {
        let events = vec![make_event(255, "Microsoft-Windows-Sysmon/Operational", vec![("Description", "Sysmon driver unload")], 1_000_000_000)];
        let alerts = detect_sysmon_tampering(&events);
        assert!(!alerts.is_empty(), "EID 255 should flag Sysmon tampering");
        assert_eq!(alerts[0].kind, AlertKind::SysmonTampering);
    }

    #[test]
    fn sysmon_tampering_detected_on_eid_16() {
        let events = vec![make_event(16, "Microsoft-Windows-Sysmon/Operational", vec![("Configuration", "C:\\Temp\\custom.xml")], 1_000_000_000)];
        let alerts = detect_sysmon_tampering(&events);
        assert!(!alerts.is_empty(), "EID 16 should flag Sysmon config change");
        assert_eq!(alerts[0].kind, AlertKind::SysmonTampering);
    }

    // ── Channel Disable ───────────────────────────────────────────────────────

    #[test]
    fn channel_disable_detected_on_eid_105() {
        let events = vec![make_event(105, "System", vec![("Channel", "Microsoft-Windows-Sysmon/Operational")], 1_000_000_000)];
        let alerts = detect_channel_disable(&events);
        assert!(!alerts.is_empty(), "EID 105 should flag channel disable");
        assert_eq!(alerts[0].kind, AlertKind::ChannelDisabled);
    }

    // ── run_all ───────────────────────────────────────────────────────────────

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
        assert!(alerts.len() >= 2, "expected at least 2 anti-forensics alerts");
    }
}
