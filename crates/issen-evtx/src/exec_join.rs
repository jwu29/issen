//! Prefetch/Amcache join: confirm process executions in EVTX against execution artifacts.
//!
//! Security EID 4688 and Sysmon EID 1 record process creation.
//! Prefetch (.pf) and Amcache.hve independently track execution evidence.
//! Joining on executable basename confirms or refutes EVTX process events and
//! surfaces executions present in one source but not the other.

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SYSMON_CHANNEL, SYSMON_FIELD_IMAGE,
};
use winevt_core::EvtxEvent;

/// An execution artifact record from Prefetch or Amcache.
#[derive(Debug, Clone)]
pub struct ExecutionArtifact {
    /// Executable name as it appears in the artifact (may include path or just basename).
    pub image_name: String,
    /// Last-run timestamp from the artifact (nanoseconds), if available.
    pub last_run_ns: Option<i64>,
    /// Originating artifact type.
    pub source: ArtifactSource,
}

/// Which artifact produced the execution evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactSource {
    Prefetch,
    Amcache,
    Shimcache,
}

/// Result of joining one EVTX process event against execution artifacts.
#[derive(Debug, Clone)]
pub struct ExecConfirmation {
    /// Executable basename (lowercase).
    pub image_name: String,
    /// Timestamp of the EVTX process-creation event (nanoseconds).
    pub evtx_timestamp_ns: i64,
    /// Matching artifact timestamp, if any.
    pub artifact_timestamp_ns: Option<i64>,
    /// True when at least one artifact confirmed this execution.
    pub confirmed: bool,
    /// Which artifact provided the confirmation.
    pub artifact_source: Option<ArtifactSource>,
}

/// Join EVTX process-creation events (EID 4688 or Sysmon EID 1) against
/// execution artifacts, matching by case-insensitive executable basename.
///
/// When multiple artifacts match, the one with the closest timestamp is chosen.
/// When no artifact matches, `confirmed = false`.
pub fn join_with_execution_artifacts(
    events: &[EvtxEvent],
    artifacts: &[ExecutionArtifact],
) -> Vec<ExecConfirmation> {
    let mut results = Vec::new();

    for ev in events {
        let Some(raw_image) = extract_image(ev) else {
            continue;
        };
        let ev_basename = image_basename(&raw_image);

        // Find best-matching artifact by case-insensitive basename
        let best = artifacts
            .iter()
            .filter(|a| image_basename(&a.image_name) == ev_basename)
            .min_by_key(|a| {
                a.last_run_ns
                    .map_or(u64::MAX, |t| (t - ev.timestamp_ns).unsigned_abs())
            });

        if let Some(artifact) = best {
            results.push(ExecConfirmation {
                image_name: ev_basename,
                evtx_timestamp_ns: ev.timestamp_ns,
                artifact_timestamp_ns: artifact.last_run_ns,
                confirmed: true,
                artifact_source: Some(artifact.source),
            });
        } else {
            results.push(ExecConfirmation {
                image_name: ev_basename,
                evtx_timestamp_ns: ev.timestamp_ns,
                artifact_timestamp_ns: None,
                confirmed: false,
                artifact_source: None,
            });
        }
    }

    results
}

/// Extract the executable basename from a full image path (case-insensitive).
///
/// `C:\Windows\System32\cmd.exe` → `cmd.exe`
pub fn image_basename(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}

fn extract_image(ev: &EvtxEvent) -> Option<String> {
    if ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL {
        return ev.data.get(SYSMON_FIELD_IMAGE).cloned();
    }
    if ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security" {
        return ev.data.get("NewProcessName").cloned();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sec_4688(image: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("NewProcessName".into(), image.into());
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

    fn sysmon_1(image: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("Image".into(), image.into());
        data.insert("ProcessGuid".into(), "{GUID}".into());
        EvtxEvent {
            event_id: 1,
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn pf(name: &str, last_run: Option<i64>) -> ExecutionArtifact {
        ExecutionArtifact {
            image_name: name.into(),
            last_run_ns: last_run,
            source: ArtifactSource::Prefetch,
        }
    }

    const NS: i64 = 1_000_000_000;

    #[test]
    fn join_empty_events_returns_empty() {
        let result = join_with_execution_artifacts(&[], &[pf("cmd.exe", None)]);
        assert!(result.is_empty());
    }

    #[test]
    fn join_confirmed_when_artifact_matches() {
        let events = vec![sec_4688(r"C:\Windows\System32\cmd.exe", 100 * NS)];
        let artifacts = vec![pf("CMD.EXE", Some(100 * NS))];
        let result = join_with_execution_artifacts(&events, &artifacts);
        assert_eq!(result.len(), 1);
        assert!(result[0].confirmed);
        assert_eq!(result[0].image_name, "cmd.exe");
    }

    #[test]
    fn join_not_confirmed_when_no_artifact_matches() {
        let events = vec![sec_4688(r"C:\evil.exe", 100 * NS)];
        let artifacts = vec![pf("benign.exe", Some(100 * NS))];
        let result = join_with_execution_artifacts(&events, &artifacts);
        assert_eq!(result.len(), 1);
        assert!(!result[0].confirmed);
        assert!(result[0].artifact_source.is_none());
    }

    #[test]
    fn join_works_for_sysmon_eid1() {
        let events = vec![sysmon_1(r"C:\Windows\System32\powershell.exe", 100 * NS)];
        let artifacts = vec![pf("powershell.exe", Some(100 * NS))];
        let result = join_with_execution_artifacts(&events, &artifacts);
        assert_eq!(result.len(), 1);
        assert!(result[0].confirmed);
    }

    #[test]
    fn join_ignores_non_process_events() {
        let mut data = HashMap::new();
        data.insert("TargetUserName".into(), "user".into());
        let events = vec![EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: 100 * NS,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }];
        let result = join_with_execution_artifacts(&events, &[pf("cmd.exe", None)]);
        assert!(result.is_empty());
    }

    #[test]
    fn join_all_events_no_artifacts() {
        let events = vec![sec_4688(r"C:\cmd.exe", 100 * NS)];
        let result = join_with_execution_artifacts(&events, &[]);
        assert_eq!(result.len(), 1);
        assert!(!result[0].confirmed);
    }

    #[test]
    fn image_basename_strips_path() {
        assert_eq!(image_basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
    }

    #[test]
    fn image_basename_lowercases() {
        assert_eq!(image_basename(r"C:\CMD.EXE"), "cmd.exe");
    }

    #[test]
    fn image_basename_handles_forward_slash() {
        assert_eq!(image_basename("C:/Windows/notepad.exe"), "notepad.exe");
    }
}
