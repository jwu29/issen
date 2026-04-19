//! Core registry hive parsing logic using `notatin`.

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a Windows registry hive file and emit [`TimelineEvent`]s.
///
/// For each key with a `LastWrite` timestamp, one event is emitted with:
/// - `event_type = RegistryModify`
/// - `source = Registry`
/// - `timestamp` from the key's LastWrite time
/// - `path` = full key path
/// - `description` = "Registry key modified: <key_name>"
/// - `attributes` = JSON `{"hive": "<filename>", "key": "<path>", "value_count": N}`
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures.  `notatin` parse errors
/// on a zero-byte or malformed hive are caught and surfaced as `Ok(vec![])`.
pub fn parse_hive(path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // Stub — GREEN implementation goes here.
    let _ = path;
    Ok(vec![])
}
