//! `CORR-MALWARE-PERSIST` (plan v4 §5.2).
//!
//! An executable file create is followed by a 7045 `ServiceInstall` whose
//! image names that same binary — service-based persistence. The two events are
//! joined on the image *stem* (extension dropped, lowercased), so a file event
//! and the service `ImagePath` correlate on the binary identity rather than an
//! exact full-path match. Ordered: the create strictly before the install,
//! within 24 h, same host. ATT&CK: T1543.003 (Windows service).

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict.
pub const PERSIST_NOTE: &str =
    "An executable file create followed by a service install naming that image \
     is consistent with service-based persistence (T1543.003).";

/// 24 hours in nanoseconds — the create→service-install window (plan v4 §5.2).
pub const PERSIST_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// The ordered-window rule. The image-stem join is supplied by normalizing each
/// event's join entity with [`stem_entity`](super::stem_entity): the file event
/// carries `stem_entity(file_path)` and the 7045 event carries
/// `stem_entity(image_path)`, so the existing exact-equality engine join fires
/// on the shared binary stem.
#[must_use]
pub fn persist_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-MALWARE-PERSIST",
        attack_technique: Some("T1543.003"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "FileCreate",
        consequent_event_type: "ServiceInstall",
        window_ns: PERSIST_WINDOW_NS,
        scope: ScopeRule::SameHost,
        note: PERSIST_NOTE,
    }
}

/// Evaluate the persistence rule: an executable create anchor against
/// `ServiceInstall` candidates, firing when one names the same image stem within
/// the window on the same host. Thin wrapper over the existing
/// [`evaluate`](crate::evaluator::evaluate); both sides must already carry their
/// `stem_entity` join key.
#[must_use]
pub fn evaluate_persist<A, C>(anchor: &A, candidates: &[C]) -> Option<Correlation>
where
    A: EventView,
    C: EventView,
{
    evaluate(&persist_rule(), anchor, candidates)
}

#[cfg(test)]
mod tests {
    use super::super::{stem_entity, testkit::TestEvent};
    use super::*;
    use crate::correlation::{CorrelationRole, CorrelationScope};
    use crate::evaluator::EventSource;
    use forensicnomicon::report::Severity;

    fn create(id: u64, ts: i64, file_path: &str) -> TestEvent {
        TestEvent::new(id, ts, "FileCreate", "DC01", EventSource::Disk)
            .with_entity(stem_entity(file_path))
    }

    fn service_install(id: u64, ts: i64, image_path: &str) -> TestEvent {
        TestEvent::new(id, ts, "ServiceInstall", "DC01", EventSource::Evtx)
            .with_entity(stem_entity(image_path))
    }

    #[test]
    fn fires_when_a_service_names_the_created_image() {
        let file = "C:\\Windows\\System32\\coreupdater.exe";
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, file);
        let cands = vec![service_install(2, 2_000, image)];

        let corr = evaluate_persist(&anchor, &cands).expect("a correlation");
        assert_eq!(corr.code, "CORR-MALWARE-PERSIST");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1543.003"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert!(corr.note.contains("consistent with"));
    }

    #[test]
    fn matches_on_stem_across_differing_full_paths() {
        // Dropped to System32, service references the same stem from a temp dir
        // — the stem join still fires.
        let file = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, file);
        let cands = vec![service_install(2, 2_000, image)];
        assert!(evaluate_persist(&anchor, &cands).is_some());
    }

    // ── Negative controls ────────────────────────────────────────────────────

    #[test]
    fn does_not_fire_when_the_service_names_a_different_image() {
        // The 7045 references svchost.exe, not the created coreupdater.exe.
        let file = "C:\\Users\\beth\\Downloads\\coreupdater.exe";
        let image = "C:\\Windows\\System32\\svchost.exe";
        let anchor = create(1, 1_000, file);
        let cands = vec![service_install(2, 2_000, image)];
        assert!(evaluate_persist(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_the_install_precedes_the_create() {
        let file = "C:\\Windows\\System32\\coreupdater.exe";
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 5_000, file);
        let cands = vec![service_install(2, 1_000, image)];
        assert!(evaluate_persist(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_outside_the_24h_window() {
        let file = "C:\\Windows\\System32\\coreupdater.exe";
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, file);
        let late = 1_000 + PERSIST_WINDOW_NS + 1;
        let cands = vec![service_install(2, late, image)];
        assert!(evaluate_persist(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_across_hosts() {
        let file = "C:\\Windows\\System32\\coreupdater.exe";
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = create(1, 1_000, file);
        let mut other = service_install(2, 2_000, image);
        other.host = Some("WS01".to_string());
        let cands = vec![other];
        assert!(evaluate_persist(&anchor, &cands).is_none());
    }
}
