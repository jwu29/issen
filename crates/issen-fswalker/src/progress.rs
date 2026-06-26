use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

/// The pipeline phase a source is currently in, for the live display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Not started yet (another source is active).
    Queued = 0,
    /// Pulling artifacts off the disk image into a temp tree.
    Extracting = 1,
    /// Walking the extracted tree and classifying artifacts.
    Discovering = 2,
    /// Parsing artifacts into timeline events (the bulk phase).
    Parsing = 3,
    /// This source is finished.
    Done = 4,
}

impl Phase {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Extracting,
            2 => Self::Discovering,
            3 => Self::Parsing,
            4 => Self::Done,
            _ => Self::Queued,
        }
    }
}

/// A consistent point-in-time read of a [`ProgressReporter`], for the render
/// loop to map to a display without racing on individual counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressSnapshot {
    /// Current pipeline phase.
    pub phase: Phase,
    /// Total artifacts to parse (`0` = not yet known — still discovering).
    pub artifacts_total: u64,
    /// Artifacts parsed so far.
    pub artifacts_completed: u64,
    /// Timeline events emitted so far.
    pub events_emitted: u64,
    /// Bytes processed so far.
    pub bytes_processed: u64,
    /// Parse errors so far.
    pub errors_encountered: u64,
}

/// Thread-safe progress tracking for pipeline operations.
#[derive(Debug, Clone)]
pub struct ProgressReporter {
    events_emitted: Arc<AtomicU64>,
    bytes_processed: Arc<AtomicU64>,
    artifacts_completed: Arc<AtomicU64>,
    errors_encountered: Arc<AtomicU64>,
    artifacts_total: Arc<AtomicU64>,
    phase: Arc<AtomicU8>,
    /// One entry per worker bar; `Some(label)` = that slot is parsing `label`,
    /// `None` = idle. Empty when the reporter has no worker bars.
    worker_slots: Arc<Mutex<Vec<Option<String>>>>,
}

impl ProgressReporter {
    #[must_use]
    pub fn new() -> Self {
        Self::with_workers(0)
    }

    /// Create a reporter with `n` worker slots backing the per-source worker
    /// bars. `new()` (`n == 0`) shows no worker bars.
    #[must_use]
    pub fn with_workers(n: usize) -> Self {
        Self {
            events_emitted: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            artifacts_completed: Arc::new(AtomicU64::new(0)),
            errors_encountered: Arc::new(AtomicU64::new(0)),
            artifacts_total: Arc::new(AtomicU64::new(0)),
            phase: Arc::new(AtomicU8::new(Phase::Queued as u8)),
            worker_slots: Arc::new(Mutex::new(vec![None; n])),
        }
    }

    /// Claim a worker slot for the artifact `label` currently being parsed; the
    /// returned guard frees the slot on drop. When every slot is busy the guard
    /// owns no slot (the artifact simply isn't shown until one frees) — this
    /// never panics and never displaces a live slot.
    pub fn claim_worker(&self, label: impl Into<String>) -> WorkerGuard {
        let label = label.into();
        let mut slots = self
            .worker_slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let idx = slots.iter().position(Option::is_none);
        if let Some(i) = idx {
            slots[i] = Some(label);
        }
        WorkerGuard {
            slots: Arc::clone(&self.worker_slots),
            idx,
        }
    }

    /// A snapshot of every worker slot's current artifact label (`None` = idle),
    /// for the render loop. Empty when the reporter has no worker slots.
    #[must_use]
    pub fn worker_labels(&self) -> Vec<Option<String>> {
        self.worker_slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Set the current pipeline phase (for the live display).
    pub fn set_phase(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    /// The current pipeline phase.
    #[must_use]
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    /// Record the total artifact count once discovery knows it (enables a
    /// determinate parse bar; `0` until then).
    pub fn set_artifacts_total(&self, total: u64) {
        self.artifacts_total.store(total, Ordering::Relaxed);
    }

    /// Total artifacts to parse (`0` = not yet known).
    #[must_use]
    pub fn artifacts_total(&self) -> u64 {
        self.artifacts_total.load(Ordering::Relaxed)
    }

    /// A consistent point-in-time read of every counter.
    #[must_use]
    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            phase: self.phase(),
            artifacts_total: self.artifacts_total(),
            artifacts_completed: self.artifacts_completed(),
            events_emitted: self.events_emitted(),
            bytes_processed: self.bytes_processed(),
            errors_encountered: self.errors_encountered(),
        }
    }

    pub fn add_events(&self, count: u64) {
        self.events_emitted.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_bytes(&self, count: u64) {
        self.bytes_processed.fetch_add(count, Ordering::Relaxed);
    }

    pub fn complete_artifact(&self) {
        self.artifacts_completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors_encountered.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn events_emitted(&self) -> u64 {
        self.events_emitted.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn artifacts_completed(&self) -> u64 {
        self.artifacts_completed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn errors_encountered(&self) -> u64 {
        self.errors_encountered.load(Ordering::Relaxed)
    }
}

impl Default for ProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

/// Holds a [`ProgressReporter`] worker slot for the lifetime of one artifact's
/// parse; the slot returns to idle when this guard drops.
#[must_use = "the worker slot is held only while this guard is alive"]
pub struct WorkerGuard {
    slots: Arc<Mutex<Vec<Option<String>>>>,
    idx: Option<usize>,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if let Some(i) = self.idx {
            let mut slots = self
                .slots
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(slot) = slots.get_mut(i) {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_reporter_initial_state() {
        let progress = ProgressReporter::new();
        assert_eq!(progress.events_emitted(), 0);
        assert_eq!(progress.bytes_processed(), 0);
        assert_eq!(progress.artifacts_completed(), 0);
        assert_eq!(progress.errors_encountered(), 0);
    }

    #[test]
    fn test_progress_reporter_tracking() {
        let progress = ProgressReporter::new();
        progress.add_events(100);
        progress.add_events(50);
        progress.add_bytes(1024);
        progress.complete_artifact();
        progress.complete_artifact();
        progress.record_error();

        assert_eq!(progress.events_emitted(), 150);
        assert_eq!(progress.bytes_processed(), 1024);
        assert_eq!(progress.artifacts_completed(), 2);
        assert_eq!(progress.errors_encountered(), 1);
    }

    #[test]
    fn test_progress_reporter_clone_shares_state() {
        let progress1 = ProgressReporter::new();
        let progress2 = progress1.clone();

        progress1.add_events(10);
        assert_eq!(progress2.events_emitted(), 10, "Clone shares Arc state");

        progress2.add_events(5);
        assert_eq!(progress1.events_emitted(), 15);
    }

    #[test]
    fn phase_defaults_to_queued_and_tracks() {
        let p = ProgressReporter::new();
        assert_eq!(p.phase(), Phase::Queued, "a fresh source is queued");
        p.set_phase(Phase::Extracting);
        assert_eq!(p.phase(), Phase::Extracting);
        p.set_phase(Phase::Parsing);
        assert_eq!(p.phase(), Phase::Parsing);
    }

    #[test]
    fn artifacts_total_defaults_zero_and_is_settable() {
        let p = ProgressReporter::new();
        assert_eq!(
            p.artifacts_total(),
            0,
            "0 = total not yet known (discovery)"
        );
        p.set_artifacts_total(417);
        assert_eq!(p.artifacts_total(), 417);
    }

    #[test]
    fn snapshot_is_a_consistent_view_of_all_counters() {
        let p = ProgressReporter::new();
        p.set_phase(Phase::Parsing);
        p.set_artifacts_total(417);
        p.add_events(120);
        p.add_bytes(2048);
        p.complete_artifact();
        p.complete_artifact();
        p.record_error();

        let s = p.snapshot();
        assert_eq!(s.phase, Phase::Parsing);
        assert_eq!(s.artifacts_total, 417);
        assert_eq!(s.artifacts_completed, 2);
        assert_eq!(s.events_emitted, 120);
        assert_eq!(s.bytes_processed, 2048);
        assert_eq!(s.errors_encountered, 1);
    }

    #[test]
    fn phase_and_total_share_arc_state_across_clones() {
        let a = ProgressReporter::new();
        let b = a.clone();
        a.set_phase(Phase::Discovering);
        a.set_artifacts_total(9);
        assert_eq!(b.phase(), Phase::Discovering);
        assert_eq!(b.artifacts_total(), 9);
    }

    #[test]
    fn worker_slots_claim_release_and_overflow() {
        // Worker bars: each in-flight artifact claims a slot naming what it's
        // parsing; the slot frees when the guard drops. Slots are shared across
        // clones (the render thread reads from its own clone).
        let r = ProgressReporter::with_workers(2);
        let render_side = r.clone();
        assert_eq!(render_side.worker_labels(), vec![None, None]);

        let g1 = r.claim_worker("$MFT");
        assert_eq!(
            render_side.worker_labels(),
            vec![Some("$MFT".to_string()), None]
        );
        let g2 = r.claim_worker("Registry");
        assert_eq!(
            render_side.worker_labels(),
            vec![Some("$MFT".to_string()), Some("Registry".to_string())]
        );

        // All slots busy → overflow claim shows nowhere, but never panics and
        // never displaces a live slot.
        let g3 = r.claim_worker("EVTX");
        assert_eq!(
            render_side.worker_labels(),
            vec![Some("$MFT".to_string()), Some("Registry".to_string())]
        );

        drop(g1); // frees slot 0
        assert_eq!(
            render_side.worker_labels(),
            vec![None, Some("Registry".to_string())]
        );
        drop(g2);
        drop(g3);
        assert_eq!(render_side.worker_labels(), vec![None, None]);

        // new() has no worker slots.
        assert!(ProgressReporter::new().worker_labels().is_empty());
    }
}
