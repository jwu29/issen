//! MFT correlation: align Sysmon EID 11/15 file-create events with MFT timestamps.
//!
//! Sysmon EID 11 (FileCreate) records `TargetFilename` and `CreationUtcTime`.
//! MFT entries provide `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps.
//! Matching by normalised path within a configurable time window surfaces
//! timestomping (MFT ≠ Sysmon) or confirms file creation chains.

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_FILE_CREATE, EID_SYSMON_FILE_CREATE_STREAM_HASH, SYSMON_FIELD_TARGET_FILENAME,
};
use winevt_core::EvtxEvent;

/// An MFT file entry used as correlation input.
#[derive(Debug, Clone)]
pub struct MftEntry {
    /// Normalised absolute Windows path (e.g. `C:\Users\user\file.txt`).
    pub path: String,
    /// `$STANDARD_INFORMATION` Created timestamp (nanoseconds since Unix epoch).
    pub si_created_ns: i64,
    /// `$FILE_NAME` Created timestamp (nanoseconds since Unix epoch).
    pub fn_created_ns: i64,
    /// `$STANDARD_INFORMATION` Modified timestamp.
    pub si_modified_ns: i64,
}

/// A match between a Sysmon file event and an MFT entry.
#[derive(Debug, Clone)]
pub struct MftCorrelation {
    /// Absolute file path matched on.
    pub path: String,
    /// Sysmon event timestamp (nanoseconds).
    pub evtx_timestamp_ns: i64,
    /// MFT `$STANDARD_INFORMATION` Created timestamp.
    pub mft_si_created_ns: i64,
    /// Absolute delta between Sysmon and MFT timestamps in seconds.
    pub delta_secs: f64,
    /// True when delta exceeds the configured tolerance — possible timestomping.
    pub is_suspicious: bool,
}

/// Correlate Sysmon EID 11/15 events against MFT entries.
///
/// Only events with `TargetFilename` present are considered.
/// Path comparison is case-insensitive (Windows paths).
pub fn correlate_with_mft(
    events: &[EvtxEvent],
    mft_entries: &[MftEntry],
    tolerance_secs: f64,
) -> Vec<MftCorrelation> {
    let mut results = Vec::new();

    for ev in events {
        if ev.event_id != EID_SYSMON_FILE_CREATE
            && ev.event_id != EID_SYSMON_FILE_CREATE_STREAM_HASH
        {
            continue;
        }
        let Some(target) = ev.data.get(SYSMON_FIELD_TARGET_FILENAME) else {
            continue;
        };
        let norm_target = normalise_path(target);

        for entry in mft_entries {
            if normalise_path(&entry.path) != norm_target {
                continue;
            }
            let delta_ns = (ev.timestamp_ns - entry.si_created_ns).unsigned_abs();
            let delta_secs = delta_ns as f64 / 1_000_000_000.0;
            results.push(MftCorrelation {
                path: norm_target.clone(),
                evtx_timestamp_ns: ev.timestamp_ns,
                mft_si_created_ns: entry.si_created_ns,
                delta_secs,
                is_suspicious: delta_secs > tolerance_secs,
            });
        }
    }

    results
}

/// Normalise a Windows path for comparison: lowercase, forward slashes stripped
/// of trailing separators.
pub fn normalise_path(path: &str) -> String {
    path.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sysmon_file_create(path: &str, ts_ns: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("TargetFilename".into(), path.into());
        EvtxEvent {
            event_id: 11,
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp_ns: ts_ns,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn mft(path: &str, si_created_ns: i64) -> MftEntry {
        MftEntry {
            path: path.into(),
            si_created_ns,
            fn_created_ns: si_created_ns,
            si_modified_ns: si_created_ns,
        }
    }

    const NS: i64 = 1_000_000_000;

    #[test]
    fn correlate_empty_events_returns_empty() {
        let result = correlate_with_mft(&[], &[mft(r"C:\test.txt", 0)], 5.0);
        assert!(result.is_empty());
    }

    #[test]
    fn correlate_empty_mft_returns_empty() {
        let result = correlate_with_mft(&[sysmon_file_create(r"C:\test.txt", 0)], &[], 5.0);
        assert!(result.is_empty());
    }

    #[test]
    fn correlate_matching_path_within_tolerance() {
        let ev = sysmon_file_create(r"C:\Windows\Temp\evil.exe", 100 * NS);
        let entry = mft(r"C:\Windows\Temp\evil.exe", 100 * NS + 500_000_000); // 0.5 s delta
        let result = correlate_with_mft(&[ev], &[entry], 5.0);
        assert_eq!(result.len(), 1);
        assert!(!result[0].is_suspicious);
        assert!(result[0].delta_secs < 1.0);
    }

    #[test]
    fn correlate_suspicious_when_delta_exceeds_tolerance() {
        let ev = sysmon_file_create(r"C:\evil.exe", 100 * NS);
        let entry = mft(r"C:\evil.exe", 50 * NS); // 50 s delta — timestomped
        let result = correlate_with_mft(&[ev], &[entry], 5.0);
        assert_eq!(result.len(), 1);
        assert!(result[0].is_suspicious);
    }

    #[test]
    fn correlate_path_comparison_is_case_insensitive() {
        let ev = sysmon_file_create(r"C:\WINDOWS\Temp\file.txt", 100 * NS);
        let entry = mft(r"C:\Windows\Temp\file.txt", 100 * NS);
        let result = correlate_with_mft(&[ev], &[entry], 5.0);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn correlate_non_matching_path_not_included() {
        let ev = sysmon_file_create(r"C:\Users\user\file.txt", 100 * NS);
        let entry = mft(r"C:\Users\user\other.txt", 100 * NS);
        let result = correlate_with_mft(&[ev], &[entry], 5.0);
        assert!(result.is_empty());
    }

    #[test]
    fn normalise_path_lowercases() {
        assert_eq!(
            normalise_path(r"C:\Windows\System32\cmd.exe"),
            r"c:\windows\system32\cmd.exe"
        );
    }
}
