//! `CORR-COPY-DELETE` — placeholder; implemented in its own RED/GREEN pair.

/// Examiner-facing note — an observation, never a verdict.
pub const COPY_DELETE_NOTE: &str =
    "A file delete paired with a near-identical copy within a short window is \
     consistent with covering tracks after duplication (T1070).";
