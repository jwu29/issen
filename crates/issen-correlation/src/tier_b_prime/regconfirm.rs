//! `CORR-PERSIST-REGCONFIRM` (plan v4 §5.2 row ★, v5 §7.2).
//!
//! A 7045 `ServiceInstall` (EVTX) for an image, corroborated by a **registry**
//! event — a `Run` key value or a `...\Services\<name>` key — naming the same
//! image/service. Where Tier-A `CORR-MALWARE-PERSIST` joins a file create to the
//! service install entirely within the disk/EVTX legs, this rule joins the
//! service install to an independent *registry* artifact, so the persistence is
//! observed across two artifact sources. The two events are joined on the
//! image/service *stem* — the same [`stem_entity`](crate::tier_a::stem_entity)
//! normalization (extension dropped, lowercased) Tier-A PERSIST uses — so the
//! 7045 `ImagePath` and the registry key tail / `Run*` value correlate on the
//! binary identity rather than an exact full-path match. Ordered: the service
//! install strictly before (or co-incident in either-order terms — here strict)
//! the registry write, within ≤ 24 h, same host. ATT&CK: T1543.003 (Windows
//! service) / T1547.001 (registry Run key).
//!
//! Modeling note (registry event shape): registry events flow as
//! [`EventSource::Registry`](crate::evaluator::EventSource::Registry) rows whose
//! key path is in [`artifact_path`](crate::evaluator::EventView::artifact_path)
//! and whose join entity is the orchestration-attached
//! [`stem_entity`](crate::tier_a::stem_entity) of the named image/service — the
//! identical mechanism Tier-A PERSIST's wrapper uses for the 7045 side. No parser
//! is modified; the rule consumes the documented row shape.

use crate::correlation::Correlation;
use crate::evaluator::{evaluate, EventView, RuleSpec, ScopeRule};

/// Examiner-facing note — an observation, never a verdict. (Deliberately avoids
/// the word "confirm" despite the rule code, so the epistemics gate over notes
/// passes: a corroborating registry artifact is an observation, not proof.)
pub const REGCONFIRM_NOTE: &str =
    "A service install corroborated by a registry Run-key or Services-key value \
     naming the same image is consistent with service/registry persistence \
     observed across two artifact sources (T1543.003 / T1547.001).";

/// 24 hours in nanoseconds — the service-install→registry-write window
/// (plan v4 §5.2, bounded by the registry key `LastWrite`).
pub const REGCONFIRM_WINDOW_NS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// The ordered-window rule. Anchor `ServiceInstall` (7045, EVTX), consequent
/// `RegistryModify` (registry leg). The image/service-stem join is supplied by
/// normalizing each event's join entity with
/// [`stem_entity`](crate::tier_a::stem_entity): the 7045 event carries
/// `stem_entity(image_path)` and the registry event carries `stem_entity` of the
/// image/service it names, so the existing exact-equality engine join fires on
/// the shared binary/service stem.
#[must_use]
pub fn regconfirm_rule() -> RuleSpec {
    RuleSpec {
        code: "CORR-PERSIST-REGCONFIRM",
        attack_technique: Some("T1543.003"),
        severity: forensicnomicon::report::Severity::High,
        anchor_event_type: "ServiceInstall",
        consequent_event_type: "RegistryModify",
        window_ns: REGCONFIRM_WINDOW_NS,
        scope: ScopeRule::SameHost,
        note: REGCONFIRM_NOTE,
        ordered: true,
        guard: None,
    }
}

/// Evaluate the registry-corroboration rule: a 7045 `ServiceInstall` anchor
/// against `RegistryModify` candidates, firing when one names the same image/
/// service stem within the window on the same host. Thin wrapper over the
/// existing [`evaluate`](crate::evaluator::evaluate); both sides must already
/// carry their `stem_entity` join key.
#[must_use]
pub fn evaluate_regconfirm<A, C>(service_install: &A, registry_writes: &[C]) -> Option<Correlation>
where
    A: EventView,
    C: EventView,
{
    evaluate(&regconfirm_rule(), service_install, registry_writes)
}

#[cfg(test)]
mod tests {
    use super::super::testkit::TestEvent;
    use super::*;
    use crate::correlation::{CorrelationRole, CorrelationScope};
    use crate::evaluator::EventSource;
    use crate::tier_a::stem_entity;
    use forensicnomicon::report::Severity;

    /// A 7045 service install (EVTX leg) carrying the image stem and the
    /// `ImagePath` in `artifact_path`.
    fn service_install(id: u64, ts: i64, image_path: &str) -> TestEvent {
        TestEvent::new(id, ts, "ServiceInstall", "DC01", EventSource::Evtx)
            .with_entity(stem_entity(image_path))
            .with_path(image_path)
    }

    /// A registry write (registry leg) of a Run key / Services key naming the
    /// same image; carries the image stem (orchestration-attached) and the key
    /// path in `artifact_path`.
    fn registry_modify(id: u64, ts: i64, image_named: &str, key_path: &str) -> TestEvent {
        TestEvent::new(id, ts, "RegistryModify", "DC01", EventSource::Registry)
            .with_entity(stem_entity(image_named))
            .with_path(key_path)
    }

    #[test]
    fn fires_when_a_run_key_names_the_installed_service_image() {
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = service_install(1, 1_000, image);
        let cands = vec![registry_modify(
            2,
            2_000,
            image,
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\coreupdater",
        )];

        let corr = evaluate_regconfirm(&anchor, &cands).expect("a correlation");
        assert_eq!(corr.code, "CORR-PERSIST-REGCONFIRM");
        assert_eq!(corr.attack_technique.as_deref(), Some("T1543.003"));
        assert_eq!(corr.severity, Severity::High);
        assert_eq!(corr.scope, CorrelationScope::SameHost);
        assert_eq!(corr.members.len(), 2);
        assert_eq!(corr.members[0].timeline_id, 1);
        assert_eq!(corr.members[0].role, CorrelationRole::Anchor);
        assert_eq!(corr.members[1].timeline_id, 2);
        assert_eq!(corr.members[1].role, CorrelationRole::Consequent);
        assert!(corr.note.contains("consistent with"));
        // Corroboration is genuinely cross-source: EVTX anchor, registry
        // consequent.
        assert_eq!(anchor.source, EventSource::Evtx);
        assert_eq!(cands[0].source, EventSource::Registry);
    }

    #[test]
    fn fires_when_a_services_subkey_names_the_image() {
        // The `...\Services\<name>` key tail joins on the same stem even though
        // the key path differs from a Run value.
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = service_install(1, 1_000, image);
        let cands = vec![registry_modify(
            2,
            2_000,
            image,
            "HKLM\\System\\CurrentControlSet\\Services\\coreupdater\\ImagePath",
        )];
        assert!(evaluate_regconfirm(&anchor, &cands).is_some());
    }

    // ── Negative controls (plan v4 §5.2 row ★) ───────────────────────────────

    #[test]
    fn does_not_fire_for_a_service_install_with_no_matching_registry_key() {
        // The registry write names an unrelated image — the stem join must keep
        // the rule silent (a 7045 with NO corroborating registry key).
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = service_install(1, 1_000, image);
        let cands = vec![registry_modify(
            2,
            2_000,
            "C:\\Windows\\System32\\svchost.exe",
            "HKLM\\System\\CurrentControlSet\\Services\\svchost\\ImagePath",
        )];
        assert!(evaluate_regconfirm(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_the_registry_key_names_a_different_image() {
        // A Run key naming a different binary than the installed service.
        let anchor = service_install(1, 1_000, "C:\\Windows\\System32\\coreupdater.exe");
        let cands = vec![registry_modify(
            2,
            2_000,
            "C:\\Users\\beth\\AppData\\Roaming\\beacon.exe",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\beacon",
        )];
        assert!(evaluate_regconfirm(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_when_the_registry_write_precedes_the_service_install() {
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = service_install(1, 5_000, image);
        let cands = vec![registry_modify(
            2,
            1_000,
            image,
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\coreupdater",
        )];
        assert!(evaluate_regconfirm(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_outside_the_24h_window() {
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = service_install(1, 1_000, image);
        let late = 1_000 + REGCONFIRM_WINDOW_NS + 1;
        let cands = vec![registry_modify(
            2,
            late,
            image,
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\coreupdater",
        )];
        assert!(evaluate_regconfirm(&anchor, &cands).is_none());
    }

    #[test]
    fn does_not_fire_across_hosts() {
        let image = "C:\\Windows\\System32\\coreupdater.exe";
        let anchor = service_install(1, 1_000, image);
        let mut other = registry_modify(
            2,
            2_000,
            image,
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\coreupdater",
        );
        other.host = Some("WS01".to_string());
        let cands = vec![other];
        assert!(evaluate_regconfirm(&anchor, &cands).is_none());
    }
}
