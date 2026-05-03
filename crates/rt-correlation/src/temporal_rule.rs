//! Temporal rule evaluation for the supertimeline engine.
//!
//! `TemporalRule` operates on [`TimelineEvent`] slices and detects forensic
//! patterns that require temporal reasoning:
//!
//! - **sequence** — anchor event followed by expected events within a window
//! - **absent**   — anchor event with NO matching event in the window
//! - **discrepancy** — two artifact sources disagree about *when* the same
//!   entity (file, process) was created or first seen

use serde::{Deserialize, Serialize};

#[cfg(test)]
use rt_core::artifacts::ArtifactType;
#[cfg(test)]
use rt_core::timeline::event::{EntityRef, EventType, TimelineEvent};

// ── Public types ──────────────────────────────────────────────────────────────

/// Matches a [`TimelineEvent`] by event type, optional artifact source, and
/// optional description substring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTypeFilter {
    /// `EventType` display name, e.g. `"ProcessExec"`, `"FileCreate"`.
    pub event_type: String,
    /// Optional `ArtifactType` display name to restrict the source,
    /// e.g. `"Prefetch"`, `"MFT"`, `"Event Log"`.
    #[serde(default)]
    pub source: Option<String>,
    /// Optional substring that must appear in `event.description`.
    #[serde(default)]
    pub description_contains: Option<String>,
}

impl EventTypeFilter {
    /// Convenience constructor: event_type only.
    #[must_use]
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            source: None,
            description_contains: None,
        }
    }

    /// Builder: restrict to a specific artifact source.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Builder: require a substring in the event description.
    #[must_use]
    pub fn with_description(mut self, contains: impl Into<String>) -> Self {
        self.description_contains = Some(contains.into());
        self
    }
}

/// Detects a timestamp contradiction between two artifact sources for the same
/// file/process entity.
///
/// The discrepancy fires when the anchor event references entity `E` at time
/// `T_anchor`, and a `compare` event from `compare_source` references the same
/// entity `E` at time `T_compare`, such that the relationship between
/// `T_anchor` and `T_compare` violates the expected temporal order.
///
/// **direction `"before"`** — fires when `T_anchor < T_compare`
///   (the anchor saw the entity before the compare source claims it was created).
///   Example: boot log references `/lib/libymv.so.3` at 23:16, but its
///   `$MFT` born time is 23:24 → anchor predates the MFT creation claim.
///
/// **direction `"after"`** — fires when `T_anchor > T_compare`
///   (the anchor was recorded after the compare source's earlier event).
///   Example: `FileCreate` born time is later than `FileModify` for the same
///   file → classic timestomping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscrepancyClause {
    /// EntityRef role to join on: `"path"`, `"process"`, `"user"`, `"ip"`.
    pub entity_role: String,
    /// Event type in the compare source to look for.
    pub compare_event_type: String,
    /// Artifact source of the compare event (e.g. `"MFT"`, `"Prefetch"`).
    pub compare_source: String,
    /// Minimum gap in seconds for the discrepancy to fire. Default 0.
    #[serde(default)]
    pub min_delta_seconds: i64,
    /// `"before"` or `"after"` — see struct docs.
    #[serde(default = "default_direction")]
    pub direction: String,
}

fn default_direction() -> String {
    "before".to_string()
}

fn default_window() -> i64 {
    300
}

/// A temporal rule that operates on [`TimelineEvent`] slices.
///
/// Unlike [`CorrelationRule`](crate::model::CorrelationRule) (which works on
/// enriched [`Evidence`](crate::model::Evidence)), a `TemporalRule` works
/// directly on raw parsed events and detects patterns based on timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalRule {
    /// Unique rule identifier, e.g. `"temporal.hollow-process"`.
    pub id: String,
    /// Short human title shown in findings.
    pub title: String,
    /// `"critical"`, `"high"`, `"medium"`, or `"low"`.
    pub severity: String,
    /// Optional prose description.
    #[serde(default)]
    pub description: Option<String>,
    /// Time window in seconds (default 300 = 5 minutes).
    #[serde(default = "default_window")]
    pub within_seconds: i64,
    /// The anchor event that triggers rule evaluation.
    pub anchor: EventTypeFilter,
    /// Events that **must** be present in the window for the rule to fire.
    #[serde(default)]
    pub sequence: Vec<EventTypeFilter>,
    /// Event types that **must be absent** from the window for the rule to fire.
    #[serde(default)]
    pub absent: Vec<EventTypeFilter>,
    /// Timestamp contradictions between artifact sources.
    #[serde(default)]
    pub discrepancy: Vec<DiscrepancyClause>,
}

/// Detail about a detected timestamp discrepancy.
#[derive(Debug, Clone)]
pub struct DiscrepancyDetail {
    /// Canonical entity key, e.g. `"path:/lib/libymv.so.3"`.
    pub entity_key: String,
    pub anchor_source: String,
    pub anchor_timestamp_ns: i64,
    pub compare_source: String,
    pub compare_timestamp_ns: i64,
    /// |compare_timestamp_ns - anchor_timestamp_ns|
    pub delta_ns: i64,
}

/// A finding produced by [`evaluate_temporal`].
#[derive(Debug, Clone)]
pub struct TemporalFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    /// `record_hash` of the anchor event that triggered the rule.
    pub anchor_record_hash: String,
    /// `record_hash`es of the matched sequence/absent/discrepancy events.
    pub matched_record_hashes: Vec<String>,
    /// Discrepancy details when the rule fired via a discrepancy clause.
    pub discrepancy: Option<DiscrepancyDetail>,
}

// ── Evaluation ────────────────────────────────────────────────────────────────

/// Evaluate a `TemporalRule` against a slice of timeline events.
///
/// Returns one [`TemporalFinding`] per anchor event that satisfies all clauses.
///
/// - Sequence clauses: all must be present in the window.
/// - Absent clauses: all must be absent from the window.
/// - Discrepancy clauses: at least one must detect a contradiction.
#[must_use]
pub fn evaluate_temporal(
    _rule: &TemporalRule,
    _events: &[rt_core::timeline::event::TimelineEvent],
) -> Vec<TemporalFinding> {
    todo!("WS-10 Phase 2: implement temporal rule evaluation")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NS: i64 = 1_000_000_000; // 1 second in nanoseconds

    fn ev(
        ts_ns: i64,
        event_type: EventType,
        source: ArtifactType,
        description: &str,
    ) -> TimelineEvent {
        TimelineEvent::new(
            ts_ns,
            format!("{ts_ns}"),
            event_type,
            source,
            "/test/artifact".to_string(),
            description.to_string(),
            "evidence-001".to_string(),
        )
    }

    fn ev_path(
        ts_ns: i64,
        event_type: EventType,
        source: ArtifactType,
        description: &str,
        path: &str,
    ) -> TimelineEvent {
        ev(ts_ns, event_type, source, description)
            .with_entity_ref(EntityRef::FilePath(path.to_string()))
    }

    // ── Phase 2 RED tests ─────────────────────────────────────────────────────

    #[test]
    fn temporal_rule_within_60s_matches_sequence() {
        let rule = TemporalRule {
            id: "test.sequence".into(),
            title: "Process exec followed by file create".into(),
            severity: "medium".into(),
            description: None,
            within_seconds: 60,
            anchor: EventTypeFilter::new("ProcessExec"),
            sequence: vec![EventTypeFilter::new("FileCreate")],
            absent: vec![],
            discrepancy: vec![],
        };

        let anchor = ev(100 * NS, EventType::ProcessExec, ArtifactType::EventLog, "cmd.exe");
        // FileCreate at T+30s — within 60s window
        let create = ev(130 * NS, EventType::FileCreate, ArtifactType::UsnJournal, "output.exe");
        // Far event outside window
        let far = ev(300 * NS, EventType::FileCreate, ArtifactType::UsnJournal, "other.exe");

        let events = vec![anchor, create, far];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(findings.len(), 1, "one anchor event should produce one finding");
        assert_eq!(findings[0].rule_id, "test.sequence");
        assert!(!findings[0].matched_record_hashes.is_empty());
    }

    #[test]
    fn temporal_rule_outside_window_no_match() {
        let rule = TemporalRule {
            id: "test.sequence.window".into(),
            title: "Sequence with tight window".into(),
            severity: "low".into(),
            description: None,
            within_seconds: 60,
            anchor: EventTypeFilter::new("ProcessExec"),
            sequence: vec![EventTypeFilter::new("FileCreate")],
            absent: vec![],
            discrepancy: vec![],
        };

        let anchor = ev(100 * NS, EventType::ProcessExec, ArtifactType::EventLog, "cmd.exe");
        // FileCreate at T+200s — OUTSIDE 60s window
        let too_late = ev(300 * NS, EventType::FileCreate, ArtifactType::UsnJournal, "late.exe");

        let events = vec![anchor, too_late];
        let findings = evaluate_temporal(&rule, &events);

        assert!(findings.is_empty(), "event outside window must not produce a finding");
    }

    #[test]
    fn absent_clause_fires_when_prefetch_missing_after_4688() {
        // 4688 process-creation with NO Prefetch update within 5s → hollow process signal
        let rule = TemporalRule {
            id: "temporal.hollow-process".into(),
            title: "Process creation without Prefetch update".into(),
            severity: "high".into(),
            description: Some(
                "A 4688 event with no corresponding Prefetch FileModify within 5s \
                 suggests process hollowing or injection."
                    .into(),
            ),
            within_seconds: 5,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Event Log"),
            sequence: vec![],
            absent: vec![EventTypeFilter::new("FileModify").with_source("Prefetch")],
            discrepancy: vec![],
        };

        let exec = ev(
            100 * NS,
            EventType::ProcessExec,
            ArtifactType::EventLog,
            "4688: svchost.exe",
        );
        // Only a FileCreate in the window, not a FileModify from Prefetch
        let other_create = ev(
            101 * NS,
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "temp file",
        );

        let events = vec![exec, other_create];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "absent Prefetch FileModify should produce a finding"
        );
        assert_eq!(findings[0].rule_id, "temporal.hollow-process");
    }

    #[test]
    fn discrepancy_clause_fires_when_log_timestamp_before_mft_born_time() {
        // An EventLog event references a file at T1.
        // The file's $MFT born time (FileCreate) is T2 > T1.
        // This means the log proves the file existed before MFT claims it was created.
        let rule = TemporalRule {
            id: "temporal.log-predates-mft-create".into(),
            title: "Log references file before MFT creation timestamp".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("FileCreate").with_source("Event Log"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 60,
                direction: "before".into(),
            }],
        };

        let path = "/lib/x86_64-linux-gnu/libsuspect.so.1";
        // EventLog references the file at T=100s (anchor)
        let log_event = ev_path(
            100 * NS,
            EventType::FileCreate,
            ArtifactType::EventLog,
            "libsuspect.so.1 loaded",
            path,
        );
        // MFT says the file was born at T=300s (200s later)
        let mft_born = ev_path(
            300 * NS,
            EventType::FileCreate,
            ArtifactType::Mft,
            "file created: libsuspect.so.1",
            path,
        );

        let events = vec![log_event, mft_born];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "log timestamp before MFT born time should produce a discrepancy finding"
        );
        assert!(findings[0].discrepancy.is_some());
        let detail = findings[0].discrepancy.as_ref().unwrap();
        assert!(detail.delta_ns >= 200 * NS, "delta should be at least 200s");
    }

    #[test]
    fn boot_log_anchor_contradicts_file_mtime() {
        // CTF pattern: boot log at 23:16 mentions libymv.so.3 as "file too short",
        // but $MFT born time for the same file is 23:24 — 8 minutes later.
        // The boot log proves the rootkit existed BEFORE the MFT says it was created.
        let rule = TemporalRule {
            id: "temporal.boot-log-predates-mft".into(),
            title: "Boot log predates MFT file creation — possible timestomping or rootkit".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("SystemBoot").with_source("Event Log"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 60,
                direction: "before".into(),
            }],
        };

        let path = "/lib/x86_64-linux-gnu/libymv.so.3";
        let t_boot: i64 = 1_711_228_560 * NS; // 2024-03-24 23:16:00 UTC
        let t_mft: i64 = 1_711_229_040 * NS;  // 2024-03-24 23:24:00 UTC (+8min)

        let boot_log = ev_path(
            t_boot,
            EventType::SystemBoot,
            ArtifactType::EventLog,
            "/lib/x86_64-linux-gnu/libymv.so.3: file too short",
            path,
        );
        let mft_create = ev_path(
            t_mft,
            EventType::FileCreate,
            ArtifactType::Mft,
            "file created: libymv.so.3",
            path,
        );

        let events = vec![boot_log, mft_create];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(findings.len(), 1, "boot log predating MFT born time is a critical finding");
        assert_eq!(findings[0].severity, "critical");
        let detail = findings[0].discrepancy.as_ref().expect("discrepancy detail must be set");
        assert!(
            detail.delta_ns >= 8 * 60 * NS,
            "delta must be at least 8 minutes"
        );
    }

    #[test]
    fn father_rootkit_gid_7823_anomaly_detected() {
        // Father rootkit creates files owned by GID 7823 (unusual system GID).
        // Rule: FileCreate within 300s of SystemBoot that mentions gid:7823.
        let rule = TemporalRule {
            id: "temporal.father-rootkit-gid".into(),
            title: "File with unusual GID 7823 created near boot".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 300,
            anchor: EventTypeFilter::new("SystemBoot"),
            sequence: vec![
                EventTypeFilter::new("FileCreate")
                    .with_description("gid:7823"),
            ],
            absent: vec![],
            discrepancy: vec![],
        };

        let boot = ev(0, EventType::SystemBoot, ArtifactType::EventLog, "system boot");
        let rootkit_file = ev(
            60 * NS,
            EventType::FileCreate,
            ArtifactType::Mft,
            "created /proc/.hidden/entry gid:7823",
        );

        let events = vec![boot, rootkit_file];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "FileCreate with gid:7823 near boot should fire Father rootkit rule"
        );
    }

    #[test]
    fn pam_hook_artifact_tmp_silly_txt_detected() {
        // PAM hook persistence: a malicious PAM module creates /tmp/silly.txt
        // on each successful authentication as proof-of-execution.
        let rule = TemporalRule {
            id: "temporal.pam-hook-artifact".into(),
            title: "/tmp/silly.txt created on logon — PAM hook indicator".into(),
            severity: "critical".into(),
            description: None,
            within_seconds: 10,
            anchor: EventTypeFilter::new("LogonSuccess"),
            sequence: vec![
                EventTypeFilter::new("FileCreate").with_description("/tmp/silly.txt"),
            ],
            absent: vec![],
            discrepancy: vec![],
        };

        let logon = ev(100 * NS, EventType::LogonSuccess, ArtifactType::EventLog, "user root");
        let silly = ev(
            103 * NS,
            EventType::FileCreate,
            ArtifactType::UsnJournal,
            "created /tmp/silly.txt",
        );

        let events = vec![logon, silly];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "/tmp/silly.txt after LogonSuccess should fire PAM hook rule"
        );
    }

    #[test]
    fn deleted_execution_recovery_usnjrnl_plus_prefetch() {
        // Binary ran (Prefetch entry exists) then was deleted (UsnJrnl CLOSE+DELETE).
        // Pattern: ProcessExec (Prefetch) followed by FileDelete (UsnJrnl) for same entity.
        let rule = TemporalRule {
            id: "temporal.ran-then-deleted".into(),
            title: "Executable ran then deleted — anti-forensic or dropper".into(),
            severity: "high".into(),
            description: None,
            within_seconds: 3600,
            anchor: EventTypeFilter::new("ProcessExec").with_source("Prefetch"),
            sequence: vec![
                EventTypeFilter::new("FileDelete").with_source("USN Journal"),
            ],
            absent: vec![],
            discrepancy: vec![],
        };

        let path = "C:\\Users\\user\\AppData\\Local\\Temp\\payload.exe";
        let exec = ev_path(
            100 * NS,
            EventType::ProcessExec,
            ArtifactType::Prefetch,
            "payload.exe first run",
            path,
        );
        let delete = ev_path(
            500 * NS,
            EventType::FileDelete,
            ArtifactType::UsnJournal,
            "payload.exe deleted",
            path,
        );

        let events = vec![exec, delete];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "Prefetch exec followed by UsnJrnl delete on same path is a ran-then-deleted finding"
        );
    }

    #[test]
    fn timestomping_mft_born_after_modify() {
        // Classic timestomping: attacker zeroed the $STANDARD_INFORMATION born time
        // but forgot to also zero the $FILE_NAME born time, OR the modify time
        // predates the born time (logically impossible without manipulation).
        // Rule: FileCreate (born) timestamp > FileModify timestamp for same file entity.
        let rule = TemporalRule {
            id: "temporal.timestomping-born-after-modify".into(),
            title: "File born time later than modify time — timestomping indicator".into(),
            severity: "high".into(),
            description: None,
            within_seconds: i64::MAX / NS, // effectively unlimited window
            anchor: EventTypeFilter::new("FileModify").with_source("MFT"),
            sequence: vec![],
            absent: vec![],
            discrepancy: vec![DiscrepancyClause {
                entity_role: "path".into(),
                compare_event_type: "FileCreate".into(),
                compare_source: "MFT".into(),
                min_delta_seconds: 1,
                direction: "after".into(), // anchor(modify) should be AFTER compare(create),
                                           // but we're detecting when it's BEFORE — contradiction
            }],
        };

        let path = "C:\\Windows\\System32\\legit.dll";
        let modify = ev_path(
            100 * NS,
            EventType::FileModify,
            ArtifactType::Mft,
            "legit.dll modified",
            path,
        );
        // Born time is LATER than modify time — logically impossible without timestomping
        let born = ev_path(
            500 * NS,
            EventType::FileCreate,
            ArtifactType::Mft,
            "legit.dll created (born time)",
            path,
        );

        let events = vec![modify, born];
        let findings = evaluate_temporal(&rule, &events);

        assert_eq!(
            findings.len(),
            1,
            "born time later than modify time is a timestomping finding"
        );
    }
}
