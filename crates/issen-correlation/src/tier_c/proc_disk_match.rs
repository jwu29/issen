//! `CORR-PROC-DISK-MATCH` (Tier C, plan v4 §5.2 / v5 §7.2).
//!
//! Placeholder — implemented in its own RED→GREEN cycle.

use crate::correlation::Correlation;

use super::MemEvent;

/// Examiner-facing note — an observation, never a verdict.
pub const PROC_DISK_MATCH_NOTE: &str =
    "A process resident in a memory dump whose image name matches an on-disk file \
     create is consistent with the on-disk artifact being the running process \
     (T1055 / T1105).";

/// Placeholder matcher — returns nothing until implemented.
#[must_use]
pub fn proc_disk_matches(_memory: &[MemEvent]) -> Vec<Correlation> {
    Vec::new()
}
