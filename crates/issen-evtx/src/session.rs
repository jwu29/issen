//! Logon session correlation and process linking for Windows Event Logs.
//!
//! Correlates 4624 logon events with 4634/4647 logoff events by LogonId,
//! then links 4688 process creation events to their owning sessions.
//! This is the innovation that Events Ripper's sec4688.pl explicitly does NOT do.

use std::collections::HashMap;
use std::path::Path;

use issen_core::timeline::event::{EntityRef, TimelineEvent};
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
            let username = ev.data.get("TargetUserName").cloned().unwrap_or_default();
            let domain = ev.data.get("TargetDomainName").cloned().unwrap_or_default();
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
    match winevt_extract::process_cmdlines(path) {
        Ok(execs) => execs.into_iter().map(execution_to_process_event).collect(),
        Err(_) => Vec::new(),
    }
}

/// Convert a `winevt_extract::ProcessExecution` into a `winevt_core::ProcessEvent`.
///
/// `ProcessExecution` does not carry `LogonId`; the field is set to `None`.
fn execution_to_process_event(pe: winevt_extract::ProcessExecution) -> ProcessEvent {
    let timestamp_ns = pe
        .timestamp
        .parse::<jiff::Timestamp>()
        .ok()
        .and_then(|ts| i64::try_from(ts.as_nanosecond()).ok())
        .unwrap_or(0);
    ProcessEvent {
        timestamp_ns,
        process_id: pe.pid as u32,
        parent_pid: if pe.parent_pid == 0 {
            None
        } else {
            Some(pe.parent_pid as u32)
        },
        image_path: pe.image,
        command_line: if pe.command_line.is_empty() {
            None
        } else {
            Some(pe.command_line)
        },
        logon_id: None,
        user: None,
    }
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

/// Enrich timeline events by joining on `metadata["logon_id"]` against the session map.
///
/// For each event that carries a `logon_id` metadata key matching a known session:
/// - Pushes `EntityRef::Session(logon_id)` onto `event.entity_refs`
/// - Populates `session_username`, `session_domain`, `session_logon_type`, and
///   `session_src_ip` (if present) into `event.metadata`
/// - Adds a `session:<logon_type_name>` tag (e.g. `session:network` for type 3)
/// - Adds `session:orphaned` tag if the session has no matching logoff
///
/// Events without a `logon_id` metadata field, or with an id not present in the map,
/// are left untouched.
pub fn enrich_timeline_events(events: &mut [TimelineEvent], sessions: &HashMap<u64, LogonSession>) {
    for event in events {
        let Some(logon_id) = event
            .metadata
            .get("logon_id")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let Some(session) = sessions.get(&logon_id) else {
            continue;
        };
        event.entity_refs.push(EntityRef::Session(logon_id));
        event
            .metadata
            .insert("session_username".into(), session.username.clone().into());
        event
            .metadata
            .insert("session_domain".into(), session.domain.clone().into());
        event
            .metadata
            .insert("session_logon_type".into(), session.logon_type.into());
        if let Some(ip) = &session.src_ip {
            event
                .metadata
                .insert("session_src_ip".into(), ip.clone().into());
        }
        if session.is_orphaned {
            event.tags.push("session:orphaned".into());
        }
        let logon_type_name = winevt_core::logon_type_name(session.logon_type);
        event
            .tags
            .push(format!("session:{}", logon_type_name.to_lowercase()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

    // ── enrich_timeline_events tests (Step 3 RED) ───────────────────────────

    fn make_event_with_logon_id(logon_id: u64) -> TimelineEvent {
        TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::LogonSuccess,
            ArtifactType::EventLog,
            "/test/Security.evtx".to_string(),
            "Logon success".to_string(),
            "evidence-001".to_string(),
        )
        .with_metadata("logon_id", serde_json::json!(logon_id))
    }

    fn make_event_no_logon_id() -> TimelineEvent {
        TimelineEvent::new(
            1_700_000_000_000_000_001,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::FileCreate,
            ArtifactType::EventLog,
            "/test/System.evtx".to_string(),
            "File created".to_string(),
            "evidence-001".to_string(),
        )
    }

    fn make_session(
        logon_id: u64,
        username: &str,
        domain: &str,
        logon_type: u8,
        src_ip: Option<&str>,
        is_orphaned: bool,
    ) -> LogonSession {
        LogonSession {
            logon_id,
            logon_type,
            username: username.to_string(),
            domain: domain.to_string(),
            src_ip: src_ip.map(std::string::ToString::to_string),
            logon_time_ns: 1_700_000_000_000_000_000,
            logoff_time_ns: None,
            duration_secs: None,
            processes: Vec::new(),
            is_orphaned,
        }
    }

    #[test]
    fn enrich_pushes_session_entity_ref_on_matching_event() {
        let mut events = vec![make_event_with_logon_id(0x59b61)];
        let mut sessions = HashMap::new();
        sessions.insert(
            0x59b61,
            make_session(0x59b61, "alice", "CORP", 3, Some("10.0.0.5"), false),
        );

        enrich_timeline_events(&mut events, &sessions);

        assert!(
            events[0].entity_refs.contains(&EntityRef::Session(0x59b61)),
            "Session entity ref must be pushed for matching logon_id"
        );
    }

    #[test]
    fn enrich_populates_session_metadata() {
        let mut events = vec![make_event_with_logon_id(0x59b61)];
        let mut sessions = HashMap::new();
        sessions.insert(
            0x59b61,
            make_session(0x59b61, "alice", "CORP", 3, Some("10.0.0.5"), false),
        );

        enrich_timeline_events(&mut events, &sessions);

        let meta = &events[0].metadata;
        assert_eq!(
            meta.get("session_username").and_then(|v| v.as_str()),
            Some("alice")
        );
        assert_eq!(
            meta.get("session_domain").and_then(|v| v.as_str()),
            Some("CORP")
        );
        assert_eq!(
            meta.get("session_logon_type")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            meta.get("session_src_ip").and_then(|v| v.as_str()),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn enrich_adds_logon_type_tag() {
        let mut events = vec![make_event_with_logon_id(0x59b61)];
        let mut sessions = HashMap::new();
        sessions.insert(
            0x59b61,
            make_session(0x59b61, "alice", "CORP", 3, None, false),
        );

        enrich_timeline_events(&mut events, &sessions);

        assert!(
            events[0].tags.iter().any(|t| t == "session:network"),
            "tag 'session:network' must be added for logon_type=3, got {:?}",
            events[0].tags
        );
    }

    #[test]
    fn enrich_adds_orphaned_tag_for_orphaned_session() {
        let mut events = vec![make_event_with_logon_id(0xABCD)];
        let mut sessions = HashMap::new();
        sessions.insert(
            0xABCD,
            make_session(0xABCD, "bob", "WORKGROUP", 2, None, true),
        );

        enrich_timeline_events(&mut events, &sessions);

        assert!(
            events[0].tags.iter().any(|t| t == "session:orphaned"),
            "tag 'session:orphaned' must be added for orphaned session, got {:?}",
            events[0].tags
        );
    }

    #[test]
    fn enrich_leaves_events_without_logon_id_unchanged() {
        let mut events = vec![make_event_no_logon_id()];
        let original_refs = events[0].entity_refs.clone();
        let original_tags = events[0].tags.clone();
        let mut sessions = HashMap::new();
        sessions.insert(
            0x59b61,
            make_session(0x59b61, "alice", "CORP", 3, None, false),
        );

        enrich_timeline_events(&mut events, &sessions);

        assert_eq!(
            events[0].entity_refs, original_refs,
            "entity_refs must not change for events with no logon_id"
        );
        assert_eq!(
            events[0].tags, original_tags,
            "tags must not change for events with no logon_id"
        );
    }

    #[test]
    fn enrich_skips_events_with_unknown_session_id() {
        let mut events = vec![make_event_with_logon_id(0xDEAD)];
        let mut sessions = HashMap::new();
        // 0xDEAD not in sessions map
        sessions.insert(
            0x1111,
            make_session(0x1111, "charlie", "DOM", 3, None, false),
        );

        enrich_timeline_events(&mut events, &sessions);

        assert!(
            events[0].entity_refs.is_empty(),
            "no entity ref must be added when session not in map"
        );
    }

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
            eprintln!("skip: corpus not found at {corpus:?}");
            return;
        }
        let procs = extract_process_events(&corpus);
        // Security.evtx from an enterprise system must have EID 4688 events.
        assert!(
            !procs.is_empty(),
            "expected ≥1 ProcessEvent from {corpus:?}, got 0"
        );
        // Every returned event must have a non-empty image_path.
        for p in &procs {
            assert!(
                !p.image_path.is_empty(),
                "image_path must not be empty: {p:?}"
            );
        }
    }

    #[test]
    fn extract_process_events_result_has_no_logon_id() {
        let corpus = corpus_security_evtx();
        if !corpus.exists() {
            eprintln!("skip: corpus not found at {corpus:?}");
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
