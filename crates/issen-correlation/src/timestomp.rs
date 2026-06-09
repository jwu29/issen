//! Single-event `$SI`/`$FN` timestomp detector (MITRE T1070.006).
//!
//! Task C2. Consumes the `$FILE_NAME` timestamps that the MFT converter
//! surfaces onto each `FileCreate` event's metadata (task C1:
//! `fn_created` / `fn_modified` / `fn_accessed` / `fn_mft_modified`) and
//! compares them against the event's own `$STANDARD_INFORMATION`-driven
//! timestamp.
//!
//! `$STANDARD_INFORMATION` is user-writable (the Win32 `SetFileTime` API, and
//! every timestomping tool, touches it); `$FILE_NAME` is set by the kernel on
//! creation / rename / move and is *not* reachable through that API. So an
//! `$SI` birth time that **predates** the `$FN` birth time is the canonical
//! tell of a backdated creation timestamp. The finding is graded `High` and
//! carries T1070.006 as *consistent-with*, never a verdict — a legitimate file
//! copy that preserves the source `$SI` can produce the same ordering, so the
//! tribunal draws the conclusion.

use forensicnomicon::report::{Category, Finding, Severity};
use issen_core::timeline::event::TimelineEvent;

/// Stable, scheme-prefixed finding code (published contract — never change).
pub const TIMESTOMP_CODE: &str = "MFT-SI-FN-TIMESTOMP";

/// Detect `$SI`/`$FN` birth-time inconsistency on a single `FileCreate` event.
///
/// Fires when the `$STANDARD_INFORMATION` birth time (`event.timestamp_ns`)
/// precedes the `$FILE_NAME` birth time (`fn_created` metadata) by more than
/// `tolerance_ns`. Returns `None` when the event is not a `FileCreate`, carries
/// no parseable `fn_created`, or the two times are within tolerance.
#[must_use]
pub fn detect_timestomp(_event: &TimelineEvent, _tolerance_ns: i64) -> Option<Finding> {
    // C2 RED stub — implementation lands in the GREEN commit.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::EventType;

    const DAY_NS: i64 = 86_400_000_000_000;
    // 2020-01-01T00:00:00Z in ns since Unix epoch.
    const FN_2020_NS: i64 = 1_577_836_800_000_000_000;
    // 2010-01-01T00:00:00Z in ns since Unix epoch.
    const SI_2010_NS: i64 = 1_262_304_000_000_000_000;
    const FN_2020_DISPLAY: &str = "2020-01-01T00:00:00.000000000Z";

    fn file_create(si_ns: i64) -> TimelineEvent {
        TimelineEvent::new(
            si_ns,
            format!("{si_ns}"),
            EventType::FileCreate,
            ArtifactType::Mft,
            "C:\\Windows\\System32\\evil.dll".to_string(),
            "FileCreate: evil.dll".to_string(),
            "evidence-001".to_string(),
        )
    }

    #[test]
    fn fires_when_si_birth_predates_fn_birth() {
        // $SI says 2010, $FN says 2020 — SI was backdated by ~10 years.
        let event =
            file_create(SI_2010_NS).with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));

        let finding = detect_timestomp(&event, DAY_NS).expect("timestomp must fire");
        assert_eq!(finding.code, TIMESTOMP_CODE);
        assert_eq!(finding.severity, Some(Severity::High));
        assert_eq!(finding.category, Category::Concealment);
        assert!(
            finding
                .context
                .external_refs
                .iter()
                .any(|r| r.id.contains("T1070.006")),
            "finding must reference MITRE T1070.006"
        );
    }

    #[test]
    fn no_finding_when_si_after_fn() {
        // $SI birth later than $FN birth — normal (or a later modify), not timestomp.
        let event = file_create(FN_2020_NS + 30 * DAY_NS)
            .with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_within_tolerance() {
        // $SI one hour before $FN, tolerance one day — clock skew, not timestomp.
        let event = file_create(FN_2020_NS - 3_600_000_000_000)
            .with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_not_file_create() {
        // The detector only inspects FileCreate events.
        let mut event =
            file_create(SI_2010_NS).with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));
        event.event_type = EventType::FileModify;
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_fn_metadata_absent() {
        // Single-attribute MFT entry: no $FN to compare against.
        let event = file_create(SI_2010_NS);
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }

    #[test]
    fn no_finding_when_fn_unparseable() {
        let event = file_create(SI_2010_NS)
            .with_metadata("fn_created", serde_json::json!("not-a-timestamp"));
        assert!(detect_timestomp(&event, DAY_NS).is_none());
    }
}
