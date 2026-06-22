//! USNJrnl correlation: cross-reference $UsnJrnl:$J records with Sysmon EID 11 events.
//!
//! Sysmon EID 11 (FileCreate) captures `TargetFilename` at the moment of creation.
//! USN journal records the same file activity with fine-grained reason flags.
//! Correlating by filename (last path component) + timestamp window confirms
//! activity and surfaces cases where USN records exist without EVTX (log cleared)
//! or vice versa.

use forensicnomicon::heuristics::evtx::{
    EID_SYSMON_FILE_CREATE, EID_SYSMON_FILE_CREATE_STREAM_HASH, SYSMON_FIELD_TARGET_FILENAME,
};
use winevt_core::EvtxEvent;

/// A parsed USN journal record, consumed from ntfs_core::usn output.
#[derive(Debug, Clone)]
pub struct UsnEntry {
    /// File name (not full path — USN provides FRN-based paths).
    pub file_name: String,
    /// Timestamp in nanoseconds since Unix epoch.
    pub timestamp_ns: i64,
    /// USN reason flags as a human-readable string (e.g. `"FILE_CREATE|CLOSE"`).
    pub reason: String,
    /// File reference number (NTFS inode-equivalent).
    pub file_ref: u64,
}

/// A match between a Sysmon file event and a USN journal entry.
#[derive(Debug, Clone)]
pub struct UsnCorrelation {
    /// File name matched on (basename of Sysmon `TargetFilename`).
    pub file_name: String,
    /// Full path from Sysmon (if available).
    pub full_path: Option<String>,
    /// Sysmon event timestamp (nanoseconds).
    pub evtx_timestamp_ns: i64,
    /// USN journal entry timestamp (nanoseconds).
    pub usn_timestamp_ns: i64,
    /// Delta between the two timestamps in milliseconds.
    pub delta_ms: i64,
    /// USN reason flags.
    pub usn_reason: String,
}

/// Correlate Sysmon EID 11/15 events with USN journal entries.
///
/// Matching criteria: case-insensitive filename equality + timestamp within
/// `tolerance_secs`. When multiple USN entries match, the closest in time is
/// chosen.
pub fn correlate_with_usn(
    events: &[EvtxEvent],
    usn_entries: &[UsnEntry],
    tolerance_secs: f64,
) -> Vec<UsnCorrelation> {
    let tolerance_ns = (tolerance_secs * 1_000_000_000.0) as i64;
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
        let ev_basename = basename(target).to_lowercase();

        // Find all USN entries matching basename + within tolerance
        let candidates: Vec<_> = usn_entries
            .iter()
            .filter(|u| u.file_name.to_lowercase() == ev_basename)
            .filter(|u| (u.timestamp_ns - ev.timestamp_ns).unsigned_abs() <= tolerance_ns as u64)
            .collect();

        if let Some(best) = candidates
            .into_iter()
            .min_by_key(|u| (u.timestamp_ns - ev.timestamp_ns).unsigned_abs())
        {
            let delta_ms = (best.timestamp_ns - ev.timestamp_ns) / 1_000_000;
            results.push(UsnCorrelation {
                file_name: best.file_name.clone(),
                full_path: Some(target.clone()),
                evtx_timestamp_ns: ev.timestamp_ns,
                usn_timestamp_ns: best.timestamp_ns,
                delta_ms,
                usn_reason: best.reason.clone(),
            });
        }
    }

    results
}

/// Extract the filename component from a Windows path.
///
/// Returns the original string if no separator is found.
pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sysmon_file(path: &str, ts_ns: i64) -> EvtxEvent {
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

    fn usn(file_name: &str, ts_ns: i64, reason: &str) -> UsnEntry {
        UsnEntry {
            file_name: file_name.into(),
            timestamp_ns: ts_ns,
            reason: reason.into(),
            file_ref: 0x0001_0000_0000_0001,
        }
    }

    const NS: i64 = 1_000_000_000;

    #[test]
    fn correlate_empty_events_returns_empty() {
        let result = correlate_with_usn(&[], &[usn("file.txt", 0, "FILE_CREATE")], 5.0);
        assert!(result.is_empty());
    }

    #[test]
    fn correlate_empty_usn_returns_empty() {
        let result = correlate_with_usn(&[sysmon_file(r"C:\file.txt", 0)], &[], 5.0);
        assert!(result.is_empty());
    }

    #[test]
    fn correlate_matching_filename_within_tolerance() {
        let ev = sysmon_file(r"C:\Windows\Temp\evil.exe", 100 * NS);
        let entry = usn("evil.exe", 100 * NS + 200_000_000, "FILE_CREATE|CLOSE"); // 200 ms delta
        let result = correlate_with_usn(&[ev], &[entry], 5.0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file_name, "evil.exe");
        assert!(result[0].delta_ms.abs() <= 500);
    }

    #[test]
    fn correlate_picks_closest_usn_entry_when_multiple_match() {
        let ev = sysmon_file(r"C:\file.txt", 100 * NS);
        let entries = vec![
            usn("file.txt", 100 * NS + 100_000_000, "FILE_CREATE"), // 100 ms
            usn("file.txt", 100 * NS + 2_000_000_000, "DATA_EXTEND"), // 2 s
        ];
        let result = correlate_with_usn(&[ev], &entries, 5.0);
        assert_eq!(result.len(), 1);
        assert!(result[0].delta_ms.abs() < 500);
    }

    #[test]
    fn correlate_no_match_when_outside_tolerance() {
        let ev = sysmon_file(r"C:\file.txt", 100 * NS);
        let entry = usn("file.txt", 200 * NS, "FILE_CREATE"); // 100 s delta — too far
        let result = correlate_with_usn(&[ev], &[entry], 5.0);
        assert!(result.is_empty());
    }

    #[test]
    fn correlate_filename_matching_is_case_insensitive() {
        let ev = sysmon_file(r"C:\EVIL.EXE", 100 * NS);
        let entry = usn("evil.exe", 100 * NS, "FILE_CREATE");
        let result = correlate_with_usn(&[ev], &[entry], 5.0);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn basename_extracts_filename_from_windows_path() {
        assert_eq!(basename(r"C:\Windows\System32\cmd.exe"), "cmd.exe");
    }

    #[test]
    fn basename_handles_forward_slash() {
        assert_eq!(basename("C:/Windows/cmd.exe"), "cmd.exe");
    }

    #[test]
    fn basename_returns_whole_string_if_no_separator() {
        assert_eq!(basename("file.txt"), "file.txt");
    }
}
