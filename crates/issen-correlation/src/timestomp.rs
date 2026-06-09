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
//! `$SI` birth time that **predates** the `$FN` birth time *can* indicate a
//! backdated creation timestamp.
//!
//! **But on its own this is the weakest signal in the literature** — a file
//! copy (which preserves the source `$SI`), archive/installer extraction, and
//! NTFS file-system tunnelling all reproduce `$SI < $FN` with no tampering. So
//! this single-event check emits only a low-confidence **`Info` lead**, never a
//! graded finding; it carries T1070.006 as *consistent-with*, and the note
//! states plainly that corroboration is required. The precision-first redesign
//! (copy/tunnelling modifiers, sub-second zeroing, USN/`$LogFile` correlation)
//! is tracked in `docs/research/2026-06-09-timestomp-detection-false-positives.md`.

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
        // Info, not graded: a single-event $SI<$FN ordering is the weakest timestomp
        // signal in the literature. File copy, archive/installer extraction, and NTFS
        // file-system tunnelling all reproduce it with no tampering, so on its own it
        // is a LEAD requiring corroboration — never a High finding. See
        // docs/research/2026-06-09-timestomp-detection-false-positives.md (§6).
        Finding::observation(Severity::Info, Category::Concealment, TIMESTOMP_CODE)
            .source(Source {
                analyzer: "issen-correlation".to_string(),
                scope: "mft.timestomp".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            })
            .note(format!(
                "$STANDARD_INFORMATION birth time precedes $FILE_NAME birth time by {} — \
                 a weak single-attribute ordering anomaly. Benign causes (file copy, \
                 archive/installer extraction, NTFS file-system tunnelling) are not \
                 excluded; corroboration ($SI.modified vs $FN, sub-second 100ns zeroing, \
                 or a USN/$LogFile contradiction) is required before this is more than a \
                 lead. Consistent with MITRE T1070.006.",
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

    // ── Layered scorer (Step 3) ────────────────────────────────────────────────
    // Builds a FileCreate event carrying the four $SI MACE + fn_created (as C3
    // surfaces them) so the scorer's signals + modifiers can run from one event.

    const SUB: i64 = 123_456_789; // a non-zero sub-second so a value is NOT whole-second
    const T: i64 = FN_2020_NS; // 2020-01-01T00:00:00Z — a whole second

    fn disp(ns: i64) -> String {
        use chrono::TimeZone;
        Utc.timestamp_nanos(ns)
            .format("%Y-%m-%dT%H:%M:%S%.9fZ")
            .to_string()
    }

    fn fc(si_c: i64, si_m: i64, si_a: i64, fn_c: i64, path: &str) -> TimelineEvent {
        TimelineEvent::new(
            si_c,
            disp(si_c),
            EventType::FileCreate,
            ArtifactType::Mft,
            path.to_string(),
            "FileCreate".to_string(),
            "evidence-001".to_string(),
        )
        .with_metadata("si_created", serde_json::json!(disp(si_c)))
        .with_metadata("si_modified", serde_json::json!(disp(si_m)))
        .with_metadata("si_accessed", serde_json::json!(disp(si_a)))
        .with_metadata("fn_created", serde_json::json!(disp(fn_c)))
    }

    #[test]
    fn s1_only_is_info_lead() {
        // si_created<fn (S1), si_modified>fn (no S2), sub-seconds (no S3), no modifier.
        let e = fc(
            T - 10 * DAY_NS + SUB,
            T + DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("must emit a lead");
        assert_eq!(f.code, TIMESTOMP_CODE);
        assert_eq!(f.severity, Some(Severity::Info));
        assert_eq!(f.category, Category::Concealment);
        assert!(
            f.note.to_lowercase().contains("corroborat")
                && f.note.to_lowercase().contains("not excluded"),
            "note must state corroboration required + benign causes not excluded"
        );
        assert!(f.context.external_refs.iter().any(|r| r.id.contains("T1070.006")));
    }

    #[test]
    fn s1_and_s2_without_subsecond_is_low() {
        // si_created<si_modified<fn (S1+S2), sub-seconds (no S3), no modifier → Low.
        let e = fc(
            T - 10 * DAY_NS + SUB,
            T - 5 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        assert_eq!(
            detect_timestomp(&e, DAY_NS).expect("emit").severity,
            Some(Severity::Low)
        );
    }

    #[test]
    fn ordering_plus_subsecond_zero_is_medium() {
        // si_created on a whole second (S3) and before fn (S1), no modifier → Medium.
        let e = fc(
            T - 10 * DAY_NS,
            T - 5 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        assert_eq!(
            detect_timestomp(&e, DAY_NS).expect("emit").severity,
            Some(Severity::Medium)
        );
    }

    #[test]
    fn copy_pattern_caps_at_info_and_is_still_emitted() {
        // si_created>si_modified ⇒ copy/restore. Even with ordering, cap at Info; never drop.
        let e = fc(
            T - 5 * DAY_NS + SUB,
            T - 10 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("must still emit a lead, not discard");
        assert_eq!(f.severity, Some(Severity::Info));
        assert!(f.note.to_lowercase().contains("copy"));
    }

    #[test]
    fn volume_move_pattern_caps_at_info() {
        // si_accessed newest ⇒ volume move. Cap at Info.
        let e = fc(
            T - 10 * DAY_NS + SUB,
            T - 8 * DAY_NS + SUB,
            T + 5 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("emit");
        assert_eq!(f.severity, Some(Severity::Info));
        assert!(f.note.to_lowercase().contains("volume"));
    }

    #[test]
    fn high_fp_path_caps_at_info() {
        // Whole-second ordering (would be Medium) but under WinSxS ⇒ cap at Info.
        let e = fc(
            T - 10 * DAY_NS,
            T - 5 * DAY_NS + SUB,
            T - 9 * DAY_NS + SUB,
            T,
            "C:\\Windows\\WinSxS\\amd64_x\\foo.dll",
        );
        let f = detect_timestomp(&e, DAY_NS).expect("emit");
        assert_eq!(f.severity, Some(Severity::Info));
        assert!(f.note.to_lowercase().contains("path"));
    }

    #[test]
    fn no_ordering_anomaly_returns_none() {
        // si_created and si_modified both after fn → nothing to flag.
        let e = fc(
            T + 2 * DAY_NS + SUB,
            T + 3 * DAY_NS + SUB,
            T + 4 * DAY_NS + SUB,
            T,
            "Users/a/x.txt",
        );
        assert!(detect_timestomp(&e, DAY_NS).is_none());
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
