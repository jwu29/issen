//! Logon session correlation and process linking for Windows Event Logs.
//!
//! Correlates 4624 logon events with 4634/4647 logoff events by LogonId,
//! then links 4688 process creation events to their owning sessions.
//! This is the innovation that Events Ripper's sec4688.pl explicitly does NOT do.

use std::collections::HashMap;
use std::path::Path;

use winevt_core::{EvtxEvent, LogonSession, ProcessEvent};

/// Summary of session correlation results.
#[derive(Debug, Default)]
pub struct EvtxSessionSummary {
    pub session_count: usize,
    pub lateral_movement_count: usize,
    pub sessions: Vec<LogonSession>,
    pub lateral_movements: Vec<LateralMovementFinding>,
}

/// Lateral movement finding from session analysis.
#[derive(Debug, Clone)]
pub struct LateralMovementFinding {
    pub src_ip: String,
    pub sessions: Vec<u64>,
    pub reason: String,
}

/// Build a map of `LogonId` -> `LogonSession` from a slice of `EvtxEvent`s.
///
/// Matches 4624 (logon) with 4634/4647 (logoff) by `logon_id`.
/// Sessions without a matching logoff are marked `is_orphaned = true`.
pub fn correlate_sessions(events: &[EvtxEvent]) -> HashMap<u64, LogonSession> {
    let mut sessions: HashMap<u64, LogonSession> = HashMap::new();

    // First pass: create sessions from 4624 logon events
    for ev in events {
        if ev.event_id == 4624 {
            let Some(logon_id) = ev.logon_id else {
                continue;
            };
            let logon_type = ev
                .data
                .get("LogonType")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);
            let username = ev
                .data
                .get("TargetUserName")
                .cloned()
                .unwrap_or_default();
            let domain = ev
                .data
                .get("TargetDomainName")
                .cloned()
                .unwrap_or_default();
            let src_ip = ev.data.get("IpAddress").cloned().filter(|ip| ip != "-");

            sessions.insert(
                logon_id,
                LogonSession {
                    logon_id,
                    logon_type,
                    username,
                    domain,
                    src_ip,
                    logon_time_ns: ev.timestamp_ns,
                    logoff_time_ns: None,
                    duration_secs: None,
                    processes: Vec::new(),
                    is_orphaned: true,
                },
            );
        }
    }

    // Second pass: match 4634/4647 logoff events
    for ev in events {
        if ev.event_id == 4634 || ev.event_id == 4647 {
            let Some(logon_id) = ev.logon_id else {
                continue;
            };
            if let Some(session) = sessions.get_mut(&logon_id) {
                session.logoff_time_ns = Some(ev.timestamp_ns);
                session.is_orphaned = false;
                // Duration in seconds = (logoff - logon) / 1_000_000_000
                let delta_ns = ev.timestamp_ns.saturating_sub(session.logon_time_ns);
                #[allow(clippy::cast_sign_loss)]
                let secs = (delta_ns / 1_000_000_000) as u64;
                session.duration_secs = Some(secs);
            }
        }
    }

    sessions
}

/// Link process events (4688) to sessions via `logon_id`.
///
/// Mutates sessions in-place: adds PIDs to `LogonSession::processes`.
/// THIS IS OUR INNOVATION -- Events Ripper's sec4688.pl explicitly does NOT do this.
pub fn link_processes_to_sessions<S: std::hash::BuildHasher>(
    sessions: &mut HashMap<u64, LogonSession, S>,
    process_events: &[ProcessEvent],
) {
    for proc in process_events {
        if let Some(lid) = proc.logon_id {
            if let Some(session) = sessions.get_mut(&lid) {
                session.processes.push(proc.process_id);
            }
        }
    }
}

/// Extract process-creation events from an EVTX file at `path`.
///
/// Delegates to `winevt_extract::process_cmdlines`, which handles EID 4688
/// (Security audit) and Sysmon EID 1. Returns an empty vec on I/O or parse
/// error so callers can treat missing/corrupt files as no-ops.
///
/// **Note:** `winevt_extract::ProcessExecution` does not carry `LogonId`, so
/// the returned `ProcessEvent` structs will have `logon_id = None`.
/// `link_processes_to_sessions` will therefore be a no-op after this migration;
/// the trade-off is documented in PLAN-winevt-extract-migration.md.
pub fn extract_process_events(path: &Path) -> Vec<ProcessEvent> {
    todo!("implement using winevt_extract::process_cmdlines — RED commit")
}

/// Find sessions that had lateral movement indicators:
/// - Type 3 (Network) logons from remote IPs
/// - Multiple sessions from same source with short gaps
pub fn find_lateral_movement(sessions: &[LogonSession]) -> Vec<LateralMovementFinding> {
    // Group type-3 sessions by source IP
    let mut by_ip: HashMap<String, Vec<u64>> = HashMap::new();
    for s in sessions {
        if s.logon_type == 3 {
            if let Some(ref ip) = s.src_ip {
                by_ip.entry(ip.clone()).or_default().push(s.logon_id);
            }
        }
    }

    by_ip
        .into_iter()
        .map(|(ip, session_ids)| {
            let reason = if session_ids.len() > 1 {
                format!(
                    "Multiple Network logons ({}) from {}",
                    session_ids.len(),
                    ip
                )
            } else {
                format!("Network logon (type 3) from {ip}")
            };
            LateralMovementFinding {
                src_ip: ip,
                sessions: session_ids,
                reason,
            }
        })
        .collect()
}

/// Detect orphaned sessions (logon without matching logoff).
pub fn find_orphaned_sessions(sessions: &[LogonSession]) -> Vec<&LogonSession> {
    sessions.iter().filter(|s| s.is_orphaned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_security_evtx() -> std::path::PathBuf {
        // Sibling winevt-forensic corpus; available on dev machines, skipped in CI.
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../winevt-forensic/tests/data/DFIRArtifactMuseum/BelkasoftCTF-InsiderThreat/Security.evtx")
    }

    #[test]
    fn extract_process_events_nonexistent_path_returns_empty() {
        let result = extract_process_events(Path::new("/nonexistent/Security.evtx"));
        assert!(
            result.is_empty(),
            "non-existent path should return empty vec, got {}",
            result.len()
        );
    }

    #[test]
    fn extract_process_events_non_evtx_path_returns_empty() {
        let result = extract_process_events(Path::new("/tmp/not_an_evtx_file.txt"));
        assert!(
            result.is_empty(),
            "non-EVTX path should return empty vec gracefully"
        );
    }

    #[test]
    fn extract_process_events_returns_process_events_with_image_path() {
        let corpus = corpus_security_evtx();
        if !corpus.exists() {
            eprintln!("skip: corpus not found at {:?}", corpus);
            return;
        }
        let procs = extract_process_events(&corpus);
        // Security.evtx from an enterprise system must have EID 4688 events.
        assert!(
            !procs.is_empty(),
            "expected ≥1 ProcessEvent from {:?}, got 0",
            corpus
        );
        // Every returned event must have a non-empty image_path.
        for p in &procs {
            assert!(
                !p.image_path.is_empty(),
                "image_path must not be empty: {:?}",
                p
            );
        }
    }

    #[test]
    fn extract_process_events_result_has_no_logon_id() {
        let corpus = corpus_security_evtx();
        if !corpus.exists() {
            eprintln!("skip: corpus not found at {:?}", corpus);
            return;
        }
        let procs = extract_process_events(&corpus);
        if procs.is_empty() {
            return;
        }
        // ProcessExecution does not carry LogonId; linkage is acknowledged trade-off.
        for p in &procs {
            assert!(
                p.logon_id.is_none(),
                "expected logon_id=None after winevt_extract migration, got {:?}",
                p.logon_id
            );
        }
    }
}
