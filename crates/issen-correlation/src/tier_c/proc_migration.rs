//! `CORR-PROC-MIGRATION` (Tier C′, plan v5 §7.2).
//!
//! Placeholder — implemented in its own RED→GREEN cycle.

use crate::correlation::Correlation;

use super::MemEvent;

/// Examiner-facing note — an observation, never a verdict.
pub const PROC_MIGRATION_NOTE: &str =
    "A dead, orphaned process and an injected live process tied to the same remote \
     endpoint within one dump are consistent with process migration (T1055).";

/// Placeholder matcher — returns nothing until implemented.
#[must_use]
pub fn proc_migration_chains(_memory: &[MemEvent]) -> Vec<Correlation> {
    Vec::new()
}
