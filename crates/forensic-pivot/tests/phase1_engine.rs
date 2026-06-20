use std::collections::HashMap;
use forensic_pivot::{
    AssertionLevel, Evidence, EvidenceKind, EvidenceSource, Finding, MatchClause, PivotEngine,
    PivotRule, Severity, SubjectRef,
};

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

fn make_evidence(
    id: &str,
    source: EvidenceSource,
    kind: EvidenceKind,
    value: &str,
    timestamp_ns: Option<i64>,
) -> Evidence {
    Evidence {
        id: id.to_string(),
        source,
        kind,
        value: value.to_string(),
        subject: None,
        timestamp_ns,
        confidence: 80,
        attrs: HashMap::new(),
    }
}

fn simple_rule(
    id: &str,
    clauses: Vec<MatchClause>,
    time_window_secs: Option<u64>,
) -> PivotRule {
    PivotRule {
        id: id.to_string(),
        name: format!("Rule {id}"),
        description: "test rule".to_string(),
        severity: Severity::High,
        assertion_level: AssertionLevel::Correlated,
        default_confidence: 75,
        clauses,
        time_window_secs,
    }
}

fn clause_source_kind(source: EvidenceSource, kind: EvidenceKind) -> MatchClause {
    MatchClause {
        source: Some(source),
        kind: Some(kind),
        value_contains: None,
        attr_eq: HashMap::new(),
    }
}

fn clause_kind(kind: EvidenceKind) -> MatchClause {
    MatchClause {
        source: None,
        kind: Some(kind),
        value_contains: None,
        attr_eq: HashMap::new(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Phase 1 tests
// ──────────────────────────────────────────────────────────────────────────────

/// 1. Evidence constructed with source and kind — assert fields accessible.
#[test]
fn evidence_constructed_with_source_and_kind() {
    let ev = Evidence {
        id: "ev-001".to_string(),
        source: EvidenceSource::Sigma,
        kind: EvidenceKind::ProcessName,
        value: "mimikatz.exe".to_string(),
        subject: Some(SubjectRef::Process {
            pid: Some(1234),
            name: "mimikatz.exe".to_string(),
        }),
        timestamp_ns: Some(1_700_000_000_000_000_000),
        confidence: 95,
        attrs: HashMap::new(),
    };

    assert_eq!(ev.id, "ev-001");
    assert_eq!(ev.source, EvidenceSource::Sigma);
    assert_eq!(ev.kind, EvidenceKind::ProcessName);
    assert_eq!(ev.value, "mimikatz.exe");
    assert_eq!(ev.confidence, 95);
}

/// 2. Evidence from Sigma has Sigma source variant.
#[test]
fn evidence_from_sigma_has_sigma_source() {
    let ev = make_evidence("ev-002", EvidenceSource::Sigma, EvidenceKind::Tag, "lsass", None);
    assert_eq!(ev.source, EvidenceSource::Sigma);
}

/// 3. PivotEngine::evaluate returns empty when no evidence is supplied.
#[test]
fn pivot_rule_no_match_when_evidence_empty() {
    let rule = simple_rule("R1", vec![clause_kind(EvidenceKind::ProcessName)], None);
    let engine = PivotEngine::new(vec![rule]);
    let findings = engine.evaluate(&[]);
    assert!(findings.is_empty(), "expected no findings for empty evidence");
}

/// 4. Single-clause rule fires when matching evidence is present.
#[test]
fn pivot_rule_matches_when_single_clause_satisfied() {
    let clause = clause_kind(EvidenceKind::ProcessName);
    let rule = simple_rule("R2", vec![clause], None);
    let engine = PivotEngine::new(vec![rule]);

    let ev = make_evidence("ev-003", EvidenceSource::Sigma, EvidenceKind::ProcessName, "evil.exe", None);
    let findings = engine.evaluate(&[ev]);

    assert_eq!(findings.len(), 1, "expected exactly one finding");
}

/// 5. Rule does NOT fire when clause specifies a different kind than the evidence.
#[test]
fn pivot_rule_no_match_when_clause_not_satisfied() {
    let clause = clause_kind(EvidenceKind::IpAddress); // wants IP, gets process name
    let rule = simple_rule("R3", vec![clause], None);
    let engine = PivotEngine::new(vec![rule]);

    let ev = make_evidence("ev-004", EvidenceSource::Sigma, EvidenceKind::ProcessName, "evil.exe", None);
    let findings = engine.evaluate(&[ev]);

    assert!(findings.is_empty(), "rule should not fire on wrong kind");
}

/// 6. Finding carries the correct rule_id and severity from the matched rule.
#[test]
fn finding_carries_correct_rule_id_and_severity() {
    let clause = clause_kind(EvidenceKind::Hash);
    let mut rule = simple_rule("R4", vec![clause], None);
    rule.severity = Severity::Critical;

    let engine = PivotEngine::new(vec![rule]);
    let ev = make_evidence("ev-005", EvidenceSource::Yara, EvidenceKind::Hash, "deadbeef", None);
    let findings = engine.evaluate(&[ev]);

    assert_eq!(findings.len(), 1);
    let f: &Finding = &findings[0];
    assert_eq!(f.rule_id, "R4");
    assert_eq!(f.severity, Severity::Critical);
}

/// 7. Cross-source rule requires evidence from BOTH sources (Sigma AND Zeek).
#[test]
fn cross_source_finding_requires_evidence_from_multiple_sources() {
    let clauses = vec![
        clause_source_kind(EvidenceSource::Sigma, EvidenceKind::ProcessName),
        clause_source_kind(EvidenceSource::Zeek, EvidenceKind::IpAddress),
    ];
    let rule = simple_rule("R5", clauses, None);
    let engine = PivotEngine::new(vec![rule]);

    // Only Sigma evidence — rule must NOT fire
    let sigma_ev = make_evidence("ev-006", EvidenceSource::Sigma, EvidenceKind::ProcessName, "evil.exe", None);
    let findings = engine.evaluate(std::slice::from_ref(&sigma_ev));
    assert!(findings.is_empty(), "rule should not fire with only Sigma evidence");

    // Both sources — rule MUST fire
    let zeek_ev = make_evidence("ev-007", EvidenceSource::Zeek, EvidenceKind::IpAddress, "10.0.0.1", None);
    let findings2 = engine.evaluate(&[sigma_ev, zeek_ev]);
    assert_eq!(findings2.len(), 1, "rule should fire when both sources present");
}

/// 8. Time window excludes evidence outside the window; rule must NOT fire.
#[test]
fn time_window_excludes_old_evidence() {
    // Window: 60 seconds (60_000_000_000 ns)
    let clauses = vec![
        clause_source_kind(EvidenceSource::Sigma, EvidenceKind::ProcessName),
        clause_source_kind(EvidenceSource::Zeek, EvidenceKind::IpAddress),
    ];
    let rule = simple_rule("R6", clauses, Some(60));

    let engine = PivotEngine::new(vec![rule]);

    let base_ns: i64 = 1_700_000_000_000_000_000;
    let old_ns: i64 = base_ns - 120_000_000_000; // 120 s before base — outside 60 s window

    let recent = make_evidence("ev-008", EvidenceSource::Sigma, EvidenceKind::ProcessName, "evil.exe", Some(base_ns));
    let old = make_evidence("ev-009", EvidenceSource::Zeek, EvidenceKind::IpAddress, "10.0.0.1", Some(old_ns));

    let findings = engine.evaluate(&[recent, old]);
    assert!(findings.is_empty(), "rule should not fire when one evidence is outside the time window");
}
