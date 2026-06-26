//! Resumable pipeline planning for the unified front door.
//!
//! `issen <evidence…>` is a re-entrant target: re-running it must continue from
//! wherever it stopped and re-run only the stages whose inputs changed. The
//! decision of *which stages to run* is pure logic — given the stage-state
//! persisted in the case DB and the current input fingerprints — and lives here
//! as a Humble Object so it can be unit-tested without any I/O.
//!
//! See `docs/cli-unified-frontdoor-spec.md`.

use std::collections::{HashMap, HashSet};

use issen_timeline::store::TimelineStore;
use sha2::{Digest, Sha256};

/// A pipeline stage. `Ingest`/`Correlate`/`Scan` form the disk chain; `Memory`
/// is independent (it consumes memory dumps, not the disk timeline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Ingest,
    Correlate,
    Scan,
    Memory,
}

impl Stage {
    /// Canonical evaluation order. Both ingest legs (disk, then memory) populate
    /// the timeline before correlate/scan consume it.
    pub const ORDER: [Stage; 4] = [Stage::Ingest, Stage::Memory, Stage::Correlate, Stage::Scan];

    /// Upstream stages whose re-run forces this stage to re-run, because this
    /// stage consumes their output. Correlate and scan run over the *combined*
    /// disk+memory timeline, so a re-run of either ingest leg invalidates them;
    /// the two ingest legs depend on nothing.
    #[must_use]
    pub fn deps(self) -> &'static [Stage] {
        match self {
            Stage::Ingest | Stage::Memory => &[],
            Stage::Correlate | Stage::Scan => &[Stage::Ingest, Stage::Memory],
        }
    }
}

/// Persisted completion status of a stage from a prior run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The stage finished cleanly.
    Done,
    /// The stage started but did not finish (e.g. the process was killed).
    Incomplete,
}

/// A stage-state row recovered from the case DB.
#[derive(Debug, Clone)]
pub struct StageRecord {
    pub stage: Stage,
    pub status: Status,
    /// Fingerprint of the stage's inputs at the time it last ran.
    pub fingerprint: String,
}

/// Why a stage needs to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No prior record — never run for this case.
    Missing,
    /// Prior run did not finish.
    Incomplete,
    /// Inputs changed since the last successful run (fingerprint mismatch).
    Stale,
    /// An upstream dependency is re-running, so this stage's input will change.
    UpstreamRerun,
}

/// What to do with a stage this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Run(Reason),
    Skip,
}

impl Action {
    #[must_use]
    pub fn is_run(self) -> bool {
        matches!(self, Action::Run(_))
    }
}

/// Decide, for each *applicable* stage (one with a current fingerprint — e.g. the
/// memory stage is absent when the case has no dumps), whether to run it and why,
/// or to skip it. Stages are returned in [`Stage::ORDER`].
///
/// Rules, per stage:
/// - no prior record → `Run(Missing)`
/// - prior `Incomplete` → `Run(Incomplete)`
/// - prior `Done` but fingerprint changed → `Run(Stale)`
/// - prior `Done` and fingerprint matches → `Skip` …
/// - …unless an upstream dependency is itself running → `Run(UpstreamRerun)`.
#[must_use]
pub fn plan<S: std::hash::BuildHasher>(
    prior: &[StageRecord],
    current_fp: &HashMap<Stage, String, S>,
) -> Vec<(Stage, Action)> {
    let prior_by: HashMap<Stage, &StageRecord> = prior.iter().map(|r| (r.stage, r)).collect();
    let mut running: HashSet<Stage> = HashSet::new();
    let mut out: Vec<(Stage, Action)> = Vec::new();
    for stage in Stage::ORDER {
        // A stage with no current fingerprint is not applicable to this case
        // (e.g. the memory stage when there are no dumps) — leave it out entirely.
        let Some(cur) = current_fp.get(&stage) else {
            continue;
        };
        let base = match prior_by.get(&stage) {
            None => Action::Run(Reason::Missing),
            Some(r) if r.status == Status::Incomplete => Action::Run(Reason::Incomplete),
            Some(r) if &r.fingerprint != cur => Action::Run(Reason::Stale),
            Some(_) => Action::Skip,
        };
        // Cascade: a stage that would otherwise skip must re-run when one of its
        // upstream dependencies is re-running, because its input will change.
        let action = if base == Action::Skip && stage.deps().iter().any(|d| running.contains(d)) {
            Action::Run(Reason::UpstreamRerun)
        } else {
            base
        };
        if action.is_run() {
            running.insert(stage);
        }
        out.push((stage, action));
    }
    out
}

/// Stable, order-independent fingerprint of a set of self-describing input
/// parts. Same inputs (any order) → same string; any change → different string.
/// SHA-256 hex over the sorted, separator-delimited parts.
#[must_use]
pub fn fingerprint(parts: &[String]) -> String {
    use std::fmt::Write as _;
    let mut sorted: Vec<&str> = parts.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    for p in sorted {
        hasher.update(p.as_bytes());
        hasher.update([0x1f_u8]); // unit separator: unambiguous part boundary
    }
    hasher.finalize().iter().fold(String::new(), |mut acc, b| {
        // write! to a String is infallible; the Result is intentionally ignored.
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Ingest-stage fingerprint from the evidence set (path, byte-size).
#[must_use]
pub fn ingest_fingerprint(evidence: &[(String, u64)]) -> String {
    let parts: Vec<String> = evidence
        .iter()
        .map(|(p, n)| format!("ev:{p}:{n}"))
        .collect();
    fingerprint(&parts)
}

/// Correlate-stage fingerprint from the correlation ruleset version.
#[must_use]
pub fn correlate_fingerprint(ruleset_version: &str) -> String {
    fingerprint(&[format!("rules:{ruleset_version}")])
}

/// Scan-stage fingerprint from the ruleset version and the feed snapshot.
#[must_use]
pub fn scan_fingerprint(ruleset_version: &str, feed_snapshot: &str) -> String {
    fingerprint(&[
        format!("rules:{ruleset_version}"),
        format!("feeds:{feed_snapshot}"),
    ])
}

/// Memory-stage fingerprint from the dump set (path, byte-size).
#[must_use]
pub fn memory_fingerprint(dumps: &[(String, u64)]) -> String {
    let parts: Vec<String> = dumps.iter().map(|(p, n)| format!("dump:{p}:{n}")).collect();
    fingerprint(&parts)
}

/// What kind of evidence a path holds, for routing to the disk chain vs the
/// memory leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    Disk,
    Memory,
}

/// Opt-out / control flags on the bare front door.
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub no_scan: bool,
    pub no_correlate: bool,
    /// Ignore saved stage-state and redo everything.
    pub rerun: bool,
    /// Force exactly one stage (debug/power-user escape hatch).
    pub only: Option<Stage>,
}

/// Classify an evidence path by extension. `None` = unrecognized (the caller
/// warns and skips). Directories/collections are classified as disk by the
/// shell, not here. `.raw`/`.dd` are treated as disk (dd images); evidence
/// archives (`.zip`/`.7z`/`.tar.gz`/…) route to the disk leg, where
/// `issen-unpack` cracks the image/collection out of them; memory dumps must
/// use `.mem`/`.vmem`/`.lime`/`.dmp`/`.core`.
#[must_use]
pub fn classify(path: &str) -> Option<EvidenceKind> {
    const DISK: &[&str] = &[
        // Container / raw disk images.
        "e01", "ex01", "s01", "vmdk", "vhd", "vhdx", "qcow2", "raw", "dd", "img", "001", "iso",
        "aff4",
        // Evidence archives — issen-unpack cracks a zipped E01 (or a
        // loose-artifact collection) out of these onto the disk leg, so no
        // manual extract is needed.
        "zip", "7z", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst",
    ];
    const MEMORY: &[&str] = &["mem", "vmem", "lime", "dmp", "core"];
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)?;
    if DISK.contains(&ext.as_str()) {
        Some(EvidenceKind::Disk)
    } else if MEMORY.contains(&ext.as_str()) {
        Some(EvidenceKind::Memory)
    } else {
        None
    }
}

/// The stages applicable to this case given what evidence is present and the
/// flags, in [`Stage::ORDER`]. STUB (RED).
#[must_use]
pub fn applicable_stages(has_disk: bool, has_memory: bool, flags: &Flags) -> Vec<Stage> {
    Stage::ORDER
        .into_iter()
        .filter(|s| match s {
            Stage::Ingest => has_disk,
            Stage::Correlate => has_disk && !flags.no_correlate,
            Stage::Scan => has_disk && !flags.no_scan,
            Stage::Memory => has_memory,
        })
        .collect()
}

/// Resolve the per-stage actions for a run: restrict to applicable stages (and
/// `--only`), honor `--rerun` (ignore prior state), then delegate to [`plan`].
/// STUB (RED).
#[must_use]
pub fn resolve_actions<S: std::hash::BuildHasher>(
    applicable: &[Stage],
    flags: &Flags,
    current_fp: &HashMap<Stage, String, S>,
    prior: &[StageRecord],
) -> Vec<(Stage, Action)> {
    let allowed: HashSet<Stage> = match flags.only {
        Some(s) if applicable.contains(&s) => std::iter::once(s).collect(),
        Some(_) => HashSet::new(), // --only a non-applicable stage → nothing runs
        None => applicable.iter().copied().collect(),
    };
    let fp: HashMap<Stage, String> = current_fp
        .iter()
        .filter(|(s, _)| allowed.contains(s))
        .map(|(s, v)| (*s, v.clone()))
        .collect();
    // --rerun ignores prior state: every applicable stage reads as Missing → runs.
    if flags.rerun {
        plan(&[], &fp)
    } else {
        plan(prior, &fp)
    }
}

impl Stage {
    /// Stable persistence token (matches the `pipeline_state.stage` column).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Ingest => "ingest",
            Stage::Correlate => "correlate",
            Stage::Scan => "scan",
            Stage::Memory => "memory",
        }
    }

    /// Parse a persistence token back into a stage (`None` if unrecognized).
    #[must_use]
    pub fn from_token(s: &str) -> Option<Stage> {
        match s {
            "ingest" => Some(Stage::Ingest),
            "correlate" => Some(Stage::Correlate),
            "scan" => Some(Stage::Scan),
            "memory" => Some(Stage::Memory),
            _ => None,
        }
    }
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Done => "done",
            Status::Incomplete => "incomplete",
        }
    }

    #[must_use]
    pub fn from_token(s: &str) -> Option<Status> {
        match s {
            "done" => Some(Status::Done),
            "incomplete" => Some(Status::Incomplete),
            _ => None,
        }
    }
}

/// Executes a single pipeline stage end-to-end. The real implementation calls
/// the ingest/correlate/scan/memory commands and streams their output; tests
/// inject a recording mock. This is the seam that keeps [`run_bare`]'s
/// orchestration testable without real evidence.
pub trait StageExecutor {
    /// # Errors
    /// Propagates any failure from the underlying stage command.
    fn execute(&self, stage: Stage) -> anyhow::Result<()>;
}

/// Outcome of a bare-path run: which stages ran (and why) and which were skipped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RunReport {
    pub ran: Vec<(Stage, Reason)>,
    pub skipped: Vec<Stage>,
}

/// Read persisted stage-state into planner records, dropping rows with
/// unrecognized tokens (forward-compatible). STUB (RED).
///
/// # Errors
/// Propagates store read errors.
pub fn load_prior(store: &TimelineStore) -> anyhow::Result<Vec<StageRecord>> {
    let rows = store
        .load_stage_states()
        .map_err(|e| anyhow::anyhow!("load stage state: {e}"))?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(StageRecord {
                stage: Stage::from_token(&r.stage)?,
                status: Status::from_token(&r.status)?,
                fingerprint: r.fingerprint,
            })
        })
        .collect())
}

/// Persists and reloads per-stage state. The real impl writes the case DB's
/// `pipeline_state` table, opening it *briefly* per call so it never holds the
/// DB open while a stage executor opens it (DuckDB allows one handle per file);
/// tests use an in-memory recorder. This seam keeps [`run_bare`] testable and
/// free of the file-lock / WAL hazards of holding a connection across stages.
pub trait StateRecorder {
    /// # Errors
    /// Propagates state read errors.
    fn load(&self) -> anyhow::Result<Vec<StageRecord>>;
    /// # Errors
    /// Propagates state write errors.
    fn record(&self, stage: Stage, status: Status, fingerprint: &str) -> anyhow::Result<()>;
}

/// Run the resumable pipeline: load prior state, resolve actions, then for each
/// stage to run, mark it incomplete, execute it, and mark it done — so a crash
/// mid-stage leaves it resumable. Up-to-date stages are skipped.
///
/// # Errors
/// Propagates recorder and executor errors; a failed stage stays `incomplete`.
pub fn run_bare<S: std::hash::BuildHasher>(
    applicable: &[Stage],
    flags: &Flags,
    current_fp: &HashMap<Stage, String, S>,
    recorder: &dyn StateRecorder,
    executor: &dyn StageExecutor,
) -> anyhow::Result<RunReport> {
    let prior = recorder.load()?;
    let actions = resolve_actions(applicable, flags, current_fp, &prior);
    let mut report = RunReport::default();
    for (stage, action) in actions {
        match action {
            Action::Skip => report.skipped.push(stage),
            Action::Run(reason) => {
                let Some(fp) = current_fp.get(&stage) else {
                    continue; // cov:unreachable: actions are derived from current_fp keys
                };
                // Mark incomplete BEFORE running so a crash mid-stage is resumable.
                recorder.record(stage, Status::Incomplete, fp)?;
                executor.execute(stage)?;
                recorder.record(stage, Status::Done, fp)?;
                report.ran.push((stage, reason));
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExecutor {
        ran: std::cell::RefCell<Vec<Stage>>,
        fail_on: Option<Stage>,
    }
    impl MockExecutor {
        fn new() -> Self {
            Self {
                ran: std::cell::RefCell::new(Vec::new()),
                fail_on: None,
            }
        }
        fn failing(stage: Stage) -> Self {
            Self {
                ran: std::cell::RefCell::new(Vec::new()),
                fail_on: Some(stage),
            }
        }
    }
    impl StageExecutor for MockExecutor {
        fn execute(&self, stage: Stage) -> anyhow::Result<()> {
            self.ran.borrow_mut().push(stage);
            if self.fail_on == Some(stage) {
                anyhow::bail!("simulated stage failure");
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemRecorder {
        rows: std::cell::RefCell<Vec<StageRecord>>,
    }
    impl StateRecorder for MemRecorder {
        fn load(&self) -> anyhow::Result<Vec<StageRecord>> {
            Ok(self.rows.borrow().clone())
        }
        fn record(&self, stage: Stage, status: Status, fingerprint: &str) -> anyhow::Result<()> {
            let mut rows = self.rows.borrow_mut();
            rows.retain(|r| r.stage != stage);
            rows.push(StageRecord {
                stage,
                status,
                fingerprint: fingerprint.to_string(),
            });
            Ok(())
        }
    }

    #[test]
    fn stage_and_status_tokens_roundtrip() {
        for s in Stage::ORDER {
            assert_eq!(Stage::from_token(s.as_str()), Some(s));
        }
        assert_eq!(
            Status::from_token(Status::Done.as_str()),
            Some(Status::Done)
        );
        assert_eq!(
            Status::from_token(Status::Incomplete.as_str()),
            Some(Status::Incomplete)
        );
        assert_eq!(Stage::from_token("bogus"), None);
    }

    #[test]
    fn cold_run_executes_all_then_resume_skips_all() {
        let rec = MemRecorder::default();
        let applicable = vec![Stage::Ingest, Stage::Correlate, Stage::Scan];
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);

        let exec = MockExecutor::new();
        let r1 = run_bare(&applicable, &Flags::default(), &cur, &rec, &exec).expect("run1");
        assert_eq!(
            *exec.ran.borrow(),
            vec![Stage::Ingest, Stage::Correlate, Stage::Scan]
        );
        assert!(r1.skipped.is_empty());

        // Same inputs again: everything is up to date → nothing executes.
        let exec2 = MockExecutor::new();
        let r2 = run_bare(&applicable, &Flags::default(), &cur, &rec, &exec2).expect("run2");
        assert!(
            exec2.ran.borrow().is_empty(),
            "resume must skip completed stages"
        );
        assert_eq!(
            r2.skipped,
            vec![Stage::Ingest, Stage::Correlate, Stage::Scan]
        );
    }

    #[test]
    fn failed_stage_stays_incomplete_and_only_it_resumes() {
        let rec = MemRecorder::default();
        let applicable = vec![Stage::Ingest, Stage::Correlate];
        let cur = fp(&[(Stage::Ingest, "e1"), (Stage::Correlate, "r1")]);

        let exec = MockExecutor::failing(Stage::Correlate);
        let err = run_bare(&applicable, &Flags::default(), &cur, &rec, &exec);
        assert!(err.is_err(), "a stage failure propagates");

        // Ingest committed 'done'; correlate left 'incomplete' → re-run runs ONLY correlate.
        let exec2 = MockExecutor::new();
        let r2 = run_bare(&applicable, &Flags::default(), &cur, &rec, &exec2).expect("resume");
        assert_eq!(*exec2.ran.borrow(), vec![Stage::Correlate]);
        assert_eq!(r2.skipped, vec![Stage::Ingest]);
    }

    #[test]
    fn classify_routes_by_extension_case_insensitively() {
        assert_eq!(classify("DC01.E01"), Some(EvidenceKind::Disk));
        assert_eq!(classify("img.vmdk"), Some(EvidenceKind::Disk));
        assert_eq!(classify("disk.raw"), Some(EvidenceKind::Disk));
        assert_eq!(classify("citadeldc01.mem"), Some(EvidenceKind::Memory));
        assert_eq!(classify("dump.LiME"), Some(EvidenceKind::Memory));
        assert_eq!(classify("notes.txt"), None);
    }

    #[test]
    fn classify_routes_evidence_archives_to_the_disk_leg() {
        // issen-unpack cracks a zipped E01 (and loose-artifact collections) out
        // of an archive, so an evidence archive must route to the disk leg —
        // `issen DC01-E01.zip` should work without a manual extract.
        assert_eq!(classify("DC01-E01.zip"), Some(EvidenceKind::Disk));
        assert_eq!(classify("collection.7z"), Some(EvidenceKind::Disk));
        assert_eq!(classify("evidence.tar.gz"), Some(EvidenceKind::Disk));
        assert_eq!(classify("evidence.tgz"), Some(EvidenceKind::Disk));
        assert_eq!(classify("UAC-host.tar.bz2"), Some(EvidenceKind::Disk));
    }

    #[test]
    fn applicable_stages_follow_present_evidence_and_order() {
        let f = Flags::default();
        assert_eq!(
            applicable_stages(true, true, &f),
            vec![Stage::Ingest, Stage::Memory, Stage::Correlate, Stage::Scan]
        );
        assert_eq!(
            applicable_stages(true, false, &f),
            vec![Stage::Ingest, Stage::Correlate, Stage::Scan]
        );
        assert_eq!(applicable_stages(false, true, &f), vec![Stage::Memory]);
    }

    #[test]
    fn applicable_stages_respect_no_scan_no_correlate() {
        let f = Flags {
            no_scan: true,
            no_correlate: true,
            ..Flags::default()
        };
        assert_eq!(
            applicable_stages(true, true, &f),
            vec![Stage::Ingest, Stage::Memory]
        );
    }

    #[test]
    fn rerun_forces_every_applicable_stage_even_when_unchanged() {
        let applicable = vec![Stage::Ingest, Stage::Correlate, Stage::Scan];
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let flags = Flags {
            rerun: true,
            ..Flags::default()
        };
        let out = resolve_actions(&applicable, &flags, &cur, &prior);
        for s in applicable {
            assert_eq!(
                action_for(&out, s),
                Some(Action::Run(Reason::Missing)),
                "{s:?}"
            );
        }
    }

    #[test]
    fn only_restricts_to_one_stage() {
        let applicable = vec![Stage::Ingest, Stage::Correlate, Stage::Scan];
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f2"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let flags = Flags {
            only: Some(Stage::Scan),
            ..Flags::default()
        };
        let out = resolve_actions(&applicable, &flags, &cur, &prior);
        assert_eq!(out.len(), 1);
        assert_eq!(
            action_for(&out, Stage::Scan),
            Some(Action::Run(Reason::Stale))
        );
    }

    #[test]
    fn default_run_delegates_to_plan() {
        // Updated feeds only → scan re-runs, ingest+correlate skip.
        let applicable = vec![Stage::Ingest, Stage::Correlate, Stage::Scan];
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f2"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let out = resolve_actions(&applicable, &Flags::default(), &cur, &prior);
        assert_eq!(action_for(&out, Stage::Ingest), Some(Action::Skip));
        assert_eq!(action_for(&out, Stage::Correlate), Some(Action::Skip));
        assert_eq!(
            action_for(&out, Stage::Scan),
            Some(Action::Run(Reason::Stale))
        );
    }

    #[test]
    fn fingerprint_is_deterministic_and_order_independent() {
        let a = fingerprint(&["x".into(), "y".into()]);
        let b = fingerprint(&["y".into(), "x".into()]);
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn fingerprint_changes_when_a_part_changes() {
        let a = fingerprint(&["x".into(), "y".into()]);
        let b = fingerprint(&["x".into(), "z".into()]);
        assert_ne!(a, b);
    }

    #[test]
    fn ingest_fingerprint_is_set_based() {
        let a = ingest_fingerprint(&[("a.E01".into(), 10), ("b.E01".into(), 20)]);
        let b = ingest_fingerprint(&[("b.E01".into(), 20), ("a.E01".into(), 10)]);
        assert_eq!(a, b, "evidence is a set — order independent");
        let c = ingest_fingerprint(&[("a.E01".into(), 11), ("b.E01".into(), 20)]);
        assert_ne!(a, c, "a size change re-fingerprints");
    }

    #[test]
    fn scan_fingerprint_separates_rules_and_feeds() {
        let base = scan_fingerprint("r1", "f1");
        assert_ne!(base, scan_fingerprint("r2", "f1"), "rule change");
        assert_ne!(base, scan_fingerprint("r1", "f2"), "feed change");
    }

    #[test]
    fn stage_fingerprints_do_not_collide_across_stages() {
        let same = [("x".to_string(), 1u64)];
        assert_ne!(ingest_fingerprint(&same), memory_fingerprint(&same));
    }

    fn fp(pairs: &[(Stage, &str)]) -> HashMap<Stage, String> {
        pairs.iter().map(|(s, f)| (*s, (*f).to_string())).collect()
    }

    fn rec(stage: Stage, status: Status, f: &str) -> StageRecord {
        StageRecord {
            stage,
            status,
            fingerprint: f.to_string(),
        }
    }

    fn action_for(plan: &[(Stage, Action)], stage: Stage) -> Option<Action> {
        plan.iter().find(|(s, _)| *s == stage).map(|(_, a)| *a)
    }

    #[test]
    fn cold_run_runs_every_applicable_stage_as_missing() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
            (Stage::Memory, "m1"),
        ]);
        let p = plan(&[], &cur);
        for s in Stage::ORDER {
            assert_eq!(
                action_for(&p, s),
                Some(Action::Run(Reason::Missing)),
                "{s:?}"
            );
        }
    }

    #[test]
    fn all_done_and_unchanged_skips_everything() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        for s in [Stage::Ingest, Stage::Correlate, Stage::Scan] {
            assert_eq!(action_for(&p, s), Some(Action::Skip), "{s:?}");
        }
    }

    #[test]
    fn changed_evidence_reingests_and_cascades_to_disk_chain_only() {
        // Ingest fingerprint changed (new evidence); correlate/scan rule+feed
        // fingerprints unchanged; memory dump unchanged.
        let cur = fp(&[
            (Stage::Ingest, "e2"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
            (Stage::Memory, "m1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
            rec(Stage::Memory, Status::Done, "m1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(
            action_for(&p, Stage::Ingest),
            Some(Action::Run(Reason::Stale))
        );
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::UpstreamRerun))
        );
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::UpstreamRerun))
        );
        // Memory is independent of the disk chain — unchanged, so it skips.
        assert_eq!(action_for(&p, Stage::Memory), Some(Action::Skip));
    }

    #[test]
    fn changed_memory_cascades_to_correlate_and_scan() {
        // A new/changed memory dump (disk unchanged): memory re-runs, and because
        // correlate+scan consume the combined disk+memory timeline, they cascade.
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Memory, "m2"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Memory, Status::Done, "m1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Memory),
            Some(Action::Run(Reason::Stale))
        );
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::UpstreamRerun))
        );
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::UpstreamRerun))
        );
    }

    #[test]
    fn updated_feeds_rerun_scan_only() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f2"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(action_for(&p, Stage::Correlate), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::Stale))
        );
    }

    #[test]
    fn edited_rule_reruns_correlate_only() {
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r2"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Done, "r1"),
            rec(Stage::Scan, Status::Done, "f1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::Stale))
        );
        // Scan does not depend on correlate's output, so it is unaffected.
        assert_eq!(action_for(&p, Stage::Scan), Some(Action::Skip));
    }

    #[test]
    fn incomplete_stage_resumes_without_rerunning_completed_upstream() {
        // Killed mid-correlate: ingest done, correlate incomplete.
        let cur = fp(&[
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
            (Stage::Scan, "f1"),
        ]);
        let prior = vec![
            rec(Stage::Ingest, Status::Done, "e1"),
            rec(Stage::Correlate, Status::Incomplete, "r1"),
        ];
        let p = plan(&prior, &cur);
        assert_eq!(action_for(&p, Stage::Ingest), Some(Action::Skip));
        assert_eq!(
            action_for(&p, Stage::Correlate),
            Some(Action::Run(Reason::Incomplete))
        );
        // Scan was never run (no record) → Missing; ingest (its dep) is not running.
        assert_eq!(
            action_for(&p, Stage::Scan),
            Some(Action::Run(Reason::Missing))
        );
    }

    #[test]
    fn stage_with_no_current_fingerprint_is_not_planned() {
        // No memory dumps in this case → no Memory fingerprint → Memory absent.
        let cur = fp(&[(Stage::Ingest, "e1")]);
        let p = plan(&[], &cur);
        assert_eq!(action_for(&p, Stage::Memory), None);
        assert_eq!(
            action_for(&p, Stage::Ingest),
            Some(Action::Run(Reason::Missing))
        );
    }

    #[test]
    fn plan_is_returned_in_canonical_order() {
        let cur = fp(&[
            (Stage::Memory, "m1"),
            (Stage::Scan, "f1"),
            (Stage::Ingest, "e1"),
            (Stage::Correlate, "r1"),
        ]);
        let p = plan(&[], &cur);
        let order: Vec<Stage> = p.iter().map(|(s, _)| *s).collect();
        assert_eq!(order, Stage::ORDER.to_vec());
    }

    #[test]
    fn action_is_run_predicate() {
        let _: HashSet<Stage> = HashSet::new();
        assert!(Action::Run(Reason::Missing).is_run());
        assert!(!Action::Skip.is_run());
    }
}
