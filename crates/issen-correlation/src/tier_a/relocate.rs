//! `CORR-MALWARE-RELOCATE` (plan v4 §5.2).
//!
//! A malicious file is written into a user-writable / temp directory and then
//! moved or renamed into a system directory (System32). The two file events are
//! joined on the file *basename*; the move target must be a system path and the
//! create source must be user-writable, with the create strictly before the
//! move. ATT&CK: T1036.005 (masquerading: match legitimate name/location).

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict.
pub const RELOCATE_NOTE: &str =
    "A file created in a user-writable directory then moved into a system \
     directory under the same name is consistent with masquerading (T1036.005).";

/// 24 hours in nanoseconds — the create→relocate window (plan v4 §5.2).
pub const RELOCATE_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// The ordered-window rule. The basename join is supplied by normalizing each
/// event's join entity with [`basename_entity`](super::basename_entity); the
/// system-path / user-path guards are applied by [`relocate_candidates`] before
/// evaluation.
#[must_use]
pub fn relocate_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-MALWARE-RELOCATE",
        attack_technique: Some("T1036.005"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "FileCreate",
        consequent_event_type: "FileRename",
        window_ns: RELOCATE_WINDOW_NS,
        scope: ScopeRule::SameHost,
        note: RELOCATE_NOTE,
    }
}

/// `true` when `path` is a user-writable / temp location an initial drop lands
/// in (Downloads, Temp, a user profile, `%APPDATA%`, `/tmp`).
#[must_use]
pub fn is_user_writable_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('\\', "/");
    p.contains("/users/")
        || p.contains("/downloads/")
        || p.contains("/temp/")
        || p.contains("/tmp/")
        || p.contains("/appdata/")
        || p.starts_with("/tmp/")
        || p.contains("/documents and settings/")
}

/// `true` when `path` is a protected system directory a relocation hides in
/// (`System32`, `SysWOW64`, `/usr`, `/sbin`, `/bin`).
#[must_use]
pub fn is_system_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase().replace('\\', "/");
    p.contains("/windows/system32/")
        || p.contains("/windows/syswow64/")
        || p.starts_with("/usr/")
        || p.starts_with("/sbin/")
        || p.starts_with("/bin/")
}

/// Evaluate the relocate rule against a create anchor and rename candidates,
/// returning a [`Correlation`] only when the guards hold:
///
/// 1. the anchor (create) path is user-writable;
/// 2. the consequent (rename) target path is a system path;
/// 3. they share the same basename, are ordered (create before move), within
///    the 24 h window, on the same host.
///
/// `anchor_path` / `candidate_paths[i]` are the full paths used by the guards;
/// the events' own join entities (basename) drive the engine join. The guard is
/// applied by pre-filtering candidates so only system-path targets reach the
/// engine — no parallel evaluation path.
#[must_use]
pub fn evaluate_relocate<A, C>(
    anchor: &A,
    anchor_path: &str,
    candidates: &[(C, String)],
) -> Option<Correlation>
where
    A: EventView,
    C: EventView + Clone,
{
    if !is_user_writable_path(anchor_path) {
        return None;
    }
    let system_targets: Vec<C> = candidates
        .iter()
        .filter(|(_, path)| is_system_path(path))
        .map(|(ev, _)| ev.clone())
        .collect::<Vec<_>>();
    evaluate(&relocate_rule(), anchor, &system_targets)
}

#[cfg(test)]
mod tests {
    use super::super::{basename_entity, testkit::TestEvent};
    use super::*;
    use crate::correlation::{CorrelationRole, CorrelationScope};
    use crate::evaluator::EventSource;
    use forensicnomicon::report::Severity;

    fn create(id: u64, ts: i64, full_path: &str) -> TestEvent {
        TestEvent::new(id, ts, "FileCreate", "DC01", EventSource::Disk)
            .with_entity(basename_entity(full_path))
    }

    fn rename(id: u64, ts: i64, full_path: &str) -> TestEvent {
        TestEvent::new(id, ts, "FileRename", "DC01", EventSource::Disk)
            .with_entity(basename_entity(full_path))
    }

    #[test]
    fn fires_for_create_in_user_dir_then_rename_into_system32() {
        let src = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let dst = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, src);
        let cands = vec![(rename(2, 2_000, dst), dst.to_string())];

        let corr = evaluate_relocate(&anchor, src, &cands).expect("a correlation");
        assert_eq!(corr.code, "CORR-MALWARE-RELOCATE");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1036.005"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert!(corr.note.contains("consistent with"));
    }

    // ── Negative controls ────────────────────────────────────────────────────

    #[test]
    fn does_not_fire_for_unrelated_file_moved_within_user_space() {
        // A file moved from one user dir to another user dir: no system target,
        // so the rule must stay silent.
        let src = "C:\\Users\\beth\\Downloads\\report.docx";
        let dst = "C:\\Users\\beth\\Documents\\report.docx";
        let anchor = create(1, 1_000, src);
        let cands = vec![(rename(2, 2_000, dst), dst.to_string())];
        assert!(evaluate_relocate(&anchor, src, &cands).is_none());
    }

    #[test]
    fn does_not_fire_for_a_different_basename() {
        // Move into System32 but of a *different* file — basenames differ.
        let src = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let dst = "C:\\Windows\\System32\\svchost.exe";
        let anchor = create(1, 1_000, src);
        let cands = vec![(rename(2, 2_000, dst), dst.to_string())];
        assert!(evaluate_relocate(&anchor, src, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_the_create_is_already_in_system32() {
        // Create already inside a system dir is not a relocation out of user
        // space — the anchor-path guard rejects it.
        let src = "C:\\Windows\\System32\\coreupdater.exe";
        let dst = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, src);
        let cands = vec![(rename(2, 2_000, dst), dst.to_string())];
        assert!(evaluate_relocate(&anchor, src, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_the_move_precedes_the_create() {
        // Reversed ordering: the rename happens before the create.
        let src = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let dst = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 5_000, src);
        let cands = vec![(rename(2, 1_000, dst), dst.to_string())];
        assert!(evaluate_relocate(&anchor, src, &cands).is_none());
    }

    #[test]
    fn does_not_fire_outside_the_24h_window() {
        let src = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let dst = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, src);
        let late = 1_000 + RELOCATE_WINDOW_NS + 1;
        let cands = vec![(rename(2, late, dst), dst.to_string())];
        assert!(evaluate_relocate(&anchor, src, &cands).is_none());
    }

    #[test]
    fn does_not_fire_across_hosts() {
        let src = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let dst = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, src);
        let mut other = rename(2, 2_000, dst);
        other.host = Some("WS01".to_string());
        let cands = vec![(other, dst.to_string())];
        assert!(evaluate_relocate(&anchor, src, &cands).is_none());
    }
}
