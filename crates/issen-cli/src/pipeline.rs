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
    /// Canonical evaluation order. Disk chain first, then the independent memory leg.
    pub const ORDER: [Stage; 4] = [Stage::Ingest, Stage::Correlate, Stage::Scan, Stage::Memory];

    /// Upstream stages whose re-run forces this stage to re-run, because this
    /// stage consumes their output. Re-ingesting the disk timeline invalidates
    /// correlation and scanning; the memory leg depends on neither.
    #[must_use]
    pub fn deps(self) -> &'static [Stage] {
        match self {
            Stage::Ingest | Stage::Memory => &[],
            Stage::Correlate | Stage::Scan => &[Stage::Ingest],
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
/// shell, not here. `.raw`/`.dd` are treated as disk (dd images); memory dumps
/// must use `.mem`/`.vmem`/`.lime`/`.dmp`/`.core`. STUB (RED).
#[must_use]
pub fn classify(path: &str) -> Option<EvidenceKind> {
    let _ = path;
    None
}

/// The stages applicable to this case given what evidence is present and the
/// flags, in [`Stage::ORDER`]. STUB (RED).
#[must_use]
pub fn applicable_stages(has_disk: bool, has_memory: bool, flags: &Flags) -> Vec<Stage> {
    let _ = (has_disk, has_memory, flags);
    Vec::new()
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
    let _ = (applicable, flags, current_fp, prior);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn applicable_stages_follow_present_evidence_and_order() {
        let f = Flags::default();
        assert_eq!(
            applicable_stages(true, true, &f),
            vec![Stage::Ingest, Stage::Correlate, Stage::Scan, Stage::Memory]
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
