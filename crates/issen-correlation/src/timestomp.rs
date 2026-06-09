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

use chrono::{DateTime, Utc};
use forensicnomicon::report::{Category, Finding, Severity, Source};
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Stable, scheme-prefixed finding code (published contract — never change).
/// Matches the Case 001 capability-gaps sub-plan (Workstream C2).
pub const TIMESTOMP_CODE: &str = "NTFS-TIMESTOMP-SI-FN-MISMATCH";

/// Detect `$SI`/`$FN` birth-time inconsistency on a single `FileCreate` event.
///
/// Fires when the `$STANDARD_INFORMATION` birth time (`event.timestamp_ns`)
/// precedes the `$FILE_NAME` birth time (`fn_created` metadata) by more than
/// `tolerance_ns`. Returns `None` when the event is not a `FileCreate`, carries
/// no parseable `fn_created`, or the two times are within tolerance.
#[must_use]
pub fn detect_timestomp(event: &TimelineEvent, tolerance_ns: i64) -> Option<Finding> {
    if !matches!(event.event_type, EventType::FileCreate) {
        return None;
    }

    let fn_created_display = event.metadata.get("fn_created")?.as_str()?;
    let fn_created_ns = display_to_ns(fn_created_display)?;
    let si_created_ns = event.timestamp_ns;

    // The tell: $SI birth strictly earlier than $FN birth, beyond tolerance.
    if si_created_ns >= fn_created_ns.saturating_sub(tolerance_ns) {
        return None;
    }

    let delta_ns = fn_created_ns.saturating_sub(si_created_ns);
    Some(
        Finding::observation(Severity::High, Category::Concealment, TIMESTOMP_CODE)
            .source(Source {
                analyzer: "issen-correlation".to_string(),
                scope: "mft.timestomp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            })
            .note(format!(
                "$STANDARD_INFORMATION birth time precedes $FILE_NAME birth time by {} — \
                 consistent with a backdated $SI created via SetFileTime (timestomping). \
                 A file copy that preserves the source $SI can present the same ordering.",
                humanize_delta_ns(delta_ns)
            ))
            .evidence("si_created", event.timestamp_display.clone())
            .evidence("fn_created", fn_created_display)
            .evidence("path", event.artifact_path.clone())
            .mitre("T1070.006")
            .build(),
    )
}

/// Parse a `datetime_to_display`-formatted string (`%Y-%m-%dT%H:%M:%S%.9fZ`,
/// RFC3339) back to nanoseconds since the Unix epoch.
fn display_to_ns(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(s)
        .ok()?
        .with_timezone(&Utc)
        .timestamp_nanos_opt()
}

/// Render a nanosecond delta as a coarse human string for the finding note.
fn humanize_delta_ns(delta_ns: i64) -> String {
    let secs = delta_ns / 1_000_000_000;
    if secs >= 86_400 {
        format!("{} day(s)", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{} hour(s)", secs / 3_600)
    } else if secs >= 60 {
        format!("{} minute(s)", secs / 60)
    } else {
        format!("{secs} second(s)")
    }
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
    fn emits_info_lead_when_si_birth_predates_fn_birth() {
        // $SI says 2010, $FN says 2020. On its own this is the *weakest* timestomp
        // signal — file copy, archive extraction, and NTFS tunnelling all reproduce
        // it benignly (see docs/research/2026-06-09-timestomp-detection-...). So a
        // single-event SI<FN ordering must be an Info LEAD, never a High finding.
        let event =
            file_create(SI_2010_NS).with_metadata("fn_created", serde_json::json!(FN_2020_DISPLAY));

        let finding = detect_timestomp(&event, DAY_NS).expect("must emit a lead");
        assert_eq!(finding.code, TIMESTOMP_CODE);
        assert_eq!(
            finding.severity,
            Some(Severity::Info),
            "single-event SI<FN ordering is a weak lead, not a graded finding"
        );
        assert_eq!(finding.category, Category::Concealment);
        assert!(
            finding.note.to_lowercase().contains("corroborat")
                && finding.note.to_lowercase().contains("not excluded"),
            "note must state corroboration is required and benign causes are not excluded"
        );
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
