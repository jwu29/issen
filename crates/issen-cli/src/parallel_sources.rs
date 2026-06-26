//! Inter-image parallelism: parse multiple evidence sources concurrently.
//!
//! Each evidence source (an E01, a folder, …) parses independently and is
//! CPU-bound, so the per-source parse is the unit of parallelism. This module
//! owns only the *orchestration* — a capped, order-preserving parallel map —
//! so it is unit-testable with an injected parse fn, with no real disk images
//! (Humble Object: the decision lives here; the real parser is injected by the
//! caller). The serial commit phase that follows relies on the output being in
//! input order, so it assigns timeline ids deterministically regardless of the
//! order parses actually finish.

use rayon::prelude::*;

/// Run `parse` over every source concurrently, capped at `max_par` in-flight
/// parses, returning the results in **input order** (not completion order).
///
/// `max_par` is clamped to at least 1. The parse closure receives the source
/// index and a reference to the source; it must be `Sync` (shared across the
/// worker threads).
pub fn parse_sources_parallel<S, R, F>(sources: &[S], max_par: usize, parse: F) -> Vec<R>
where
    F: Fn(usize, &S) -> R + Sync,
    S: Sync,
    R: Send,
{
    let _ = (sources, max_par, parse);
    todo!("implement capped, order-preserving parallel map")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::parse_sources_parallel;

    /// Output order must match input order even though parses run concurrently
    /// (the serial commit phase depends on this for deterministic ids).
    #[test]
    fn preserves_input_order_and_covers_every_source() {
        let sources = vec!["a", "b", "c", "d", "e"];
        let out = parse_sources_parallel(&sources, 3, |i, s| format!("{i}:{s}"));
        assert_eq!(out, vec!["0:a", "1:b", "2:c", "3:d", "4:e"]);
    }

    /// Proves the map is genuinely concurrent: two tasks rendezvous on a
    /// `Barrier(2)`. If the orchestration serialized them, the first `wait()`
    /// would block forever and this test would hang — so passing IS the proof
    /// that `max_par >= 2` tasks run at once.
    #[test]
    fn runs_at_least_max_par_tasks_concurrently() {
        let barrier = Arc::new(Barrier::new(2));
        let sources = vec![10u32, 20u32];
        let out = parse_sources_parallel(&sources, 2, |_, &n| {
            barrier.wait();
            n * 2
        });
        assert_eq!(out, vec![20u32, 40u32]);
    }

    /// `max_par` of 0 is clamped to 1 (never a zero-thread pool that deadlocks).
    #[test]
    fn zero_max_par_is_clamped_to_one() {
        let sources = vec![1, 2, 3];
        let out = parse_sources_parallel(&sources, 0, |_, &n| n + 100);
        assert_eq!(out, vec![101, 102, 103]);
    }
}
