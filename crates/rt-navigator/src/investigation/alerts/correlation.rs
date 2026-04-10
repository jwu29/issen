//! Cross-artifact correlation heuristics.
//!
//! Correlates data across multiple forensic artifact types to surface
//! compound indicators of compromise that individual artifact checks miss.

use super::types::{Alert, AlertInput, AlertSeverity};

/// Cross-correlate memory process list with MFT entries.
///
/// For each running process whose executable path appears as a *deleted* MFT
/// entry, emit a Critical alert — a process running from a deleted binary is a
/// strong anti-forensics / malware indicator.
///
/// Returns an empty `Vec` when `input.processes` or `input.mft_entries` are
/// empty.
#[must_use]
pub fn correlate_memory_process_mft(input: &AlertInput<'_>) -> Vec<Alert> {
    let _ = input;
    vec![]
}

/// Cross-correlate active network connections with EventLog failed-logon events.
///
/// For each active connection whose remote IP appears as the source in 3 or
/// more failed logon events (Windows Event ID 4625), emit a Warning alert —
/// the host is brute-forcing and still has an open connection.
///
/// Returns an empty `Vec` when `input.network` or `input.windows_events` are
/// empty.
#[must_use]
pub fn correlate_network_eventlog(input: &AlertInput<'_>) -> Vec<Alert> {
    let _ = input;
    vec![]
}

/// Detect C2 beacon timing patterns in timestamped connection logs.
///
/// Groups connections in `input.connection_log` by remote IP. For each IP
/// with 3 or more recorded connections, computes inter-arrival time deltas.
/// If the standard deviation is less than 10% of the mean and the mean
/// interval falls between 30 and 3600 seconds, emits a Warning alert.
///
/// Returns an empty `Vec` when `input.connection_log` has fewer than 3
/// entries for any IP.
#[must_use]
pub fn correlate_c2_beacon(input: &AlertInput<'_>) -> Vec<Alert> {
    let _ = input;
    vec![]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::types::{
        AlertInput, AlertSeverity, MftFileEntry, TimestampedConnection, WindowsEvent,
    };
    use super::*;
    use rt_parser_uac::parsers::bodyfile::BodyfileEntry;
    use rt_parser_uac::parsers::network::NetworkConnection;
    use rt_parser_uac::parsers::process::ProcessInfo;

    fn empty_input() -> AlertInput<'static> {
        AlertInput {
            bodyfile: &[],
            network: &[],
            processes: &[],
            crontabs: &[],
            chkrootkit: &[],
            rootkit_findings: &[],
            configs: &[],
            hashes: &[],
            packages: &[],
            logins: &[],
            windows_events: &[],
            mft_entries: &[],
            connection_log: &[],
        }
    }

    // -----------------------------------------------------------------------
    // Test 1 — process running from deleted executable triggers Critical
    // -----------------------------------------------------------------------

    #[test]
    fn memory_process_deleted_exe_triggers_critical() {
        let mft = vec![
            MftFileEntry {
                path: "C:\\Windows\\Temp\\evil.exe".into(),
                is_deleted: true,
            },
            MftFileEntry {
                path: "C:\\Windows\\System32\\svchost.exe".into(),
                is_deleted: false,
            },
        ];
        let procs = vec![
            ProcessInfo {
                pid: 1234,
                ppid: 1,
                user: "SYSTEM".into(),
                command: "C:\\Windows\\Temp\\evil.exe".into(),
                cpu_pct: None,
                mem_pct: None,
                start_time: None,
            },
            ProcessInfo {
                pid: 556,
                ppid: 1,
                user: "SYSTEM".into(),
                command: "C:\\Windows\\System32\\svchost.exe -k NetworkService".into(),
                cpu_pct: None,
                mem_pct: None,
                start_time: None,
            },
        ];
        let input = AlertInput {
            processes: &procs,
            mft_entries: &mft,
            ..empty_input()
        };
        let alerts = correlate_memory_process_mft(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "process"
                && a.message.contains("deleted executable")
                && a.message.contains("evil.exe")),
            "expected Critical alert for process running from deleted exe, got: {alerts:?}"
        );
        // svchost (not deleted) must NOT be flagged
        assert!(
            !alerts.iter().any(|a| a.message.contains("svchost")),
            "svchost should not be flagged, got: {alerts:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2 — brute-force source IP with active connection triggers Warning
    // -----------------------------------------------------------------------

    #[test]
    fn brute_force_ip_connection_triggers_high() {
        let brute_ip = "10.0.0.99";

        // 4 failed logon events from the brute-force IP
        let events: Vec<WindowsEvent> = (0..4)
            .map(|i| WindowsEvent {
                event_id: 4625,
                channel: "Security".into(),
                provider: "Microsoft-Windows-Security-Auditing".into(),
                computer: "WORKSTATION01".into(),
                timestamp: 1_700_000_000 + i * 60,
                description: format!(
                    "An account failed to log on. IpAddress: {brute_ip} LogonType: 3"
                ),
            })
            .collect();

        // Active connection to that IP
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:54321".into(),
            remote_addr: format!("{brute_ip}:22"),
            state: "ESTAB".into(),
            pid: Some(9876),
            program: Some("ssh".into()),
        }];

        let input = AlertInput {
            network: &conns,
            windows_events: &events,
            ..empty_input()
        };
        let alerts = correlate_network_eventlog(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "network"
                && a.message.contains("brute-force source")
                && a.message.contains(brute_ip)),
            "expected Warning for active connection to brute-force source, got: {alerts:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Test 3 — regular beacon intervals trigger Warning
    // -----------------------------------------------------------------------

    #[test]
    fn c2_beacon_regular_intervals_triggers_high() {
        let beacon_ip = "198.51.100.1".to_string();
        // 5 connections at exactly 60s intervals
        let connection_log: Vec<TimestampedConnection> = (0..5)
            .map(|i| TimestampedConnection {
                remote_ip: beacon_ip.clone(),
                timestamp: 1_700_000_000_i64 + i * 60,
            })
            .collect();

        let input = AlertInput {
            connection_log: &connection_log,
            ..empty_input()
        };
        let alerts = correlate_c2_beacon(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Warning
                && a.category == "network"
                && a.message.contains("C2 beacon")
                && a.message.contains(&beacon_ip)),
            "expected Warning for regular beacon intervals, got: {alerts:?}"
        );
    }
}
