//! Prefetch header parsing — stub (RED).

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a Windows Prefetch file and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures. Parse errors (short file,
/// bad signature) are returned as `Ok(vec![])`.
pub fn parse_prefetch(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // RED stub — implementation pending.
    unimplemented!("parse_prefetch not yet implemented")
}
