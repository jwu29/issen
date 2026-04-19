//! LNK header parsing stub (RED phase — not yet implemented).

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a Windows LNK file and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures.
pub fn parse_lnk(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    // RED: stub — always returns empty.
    Ok(vec![])
}
