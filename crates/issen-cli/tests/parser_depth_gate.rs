//! Parser DEPTH gate (the third axis, after reachability + collection).
//!
//! `selector_gate` / `disk_collection_gate` / `classifier_differential` prove a
//! parser is *reached* — classified, collected, and its trait fires. None of
//! them check WHAT it surfaces. A parser can pass every reachability gate while
//! dropping the single most important field on the disk (the registry wrapper
//! emitted the `...\Run` key's write timestamp for years while discarding the
//! `coreupdate` persistence command under it — present-looking, hollow).
//!
//! This gate closes that axis: each parser declares the forensic fields it MUST
//! surface (its depth manifest), and a real-data fixture is driven through the
//! parser to assert those keys actually appear in emitted `TimelineEvent`
//! metadata — plus, for high-signal cases, that a known real IOC reaches the
//! description. The declared set is the *current* depth; deepening a parser adds
//! to it (ratchet), and a refactor that silently drops a field fails here.
//!
//! Teeth vs fixtures: cases backed by a committed fixture always run (real CI
//! teeth); cases backed by the gitignored real-corpus skip-loud when it is
//! absent, so the gate is as strong as the data present in the running
//! environment. The decision logic ([`missing_keys`]) is unit-tested
//! independently of any fixture, so the gate's failure-detection is proven even
//! where the corpus is absent (Humble Object).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use issen_core::timeline::event::TimelineEvent;

/// The pure decision core: which of `required` metadata keys appear in NO event.
/// Returns them in the order declared (deterministic) so a failure names exactly
/// what regressed. This is the Humble Object — fixture-free and unit-tested.
fn missing_keys(events: &[TimelineEvent], required: &[&str]) -> Vec<String> {
    // STUB — replaced in GREEN.
    let _ = events;
    let _ = required;
    Vec::new()
}

#[test]
fn flags_dropped_metadata_key() {
    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::EventType;

    let mk = |k: &str, v: &str| {
        TimelineEvent::new(
            0,
            String::new(),
            EventType::RegistryModify,
            ArtifactType::Registry,
            "p".into(),
            "d".into(),
            "s".into(),
        )
        .with_metadata(k, serde_json::json!(v))
    };
    // Events collectively carry {a, b}; requiring {a, b, c} must flag exactly c.
    let events = vec![mk("a", "1"), mk("b", "2")];
    assert_eq!(
        missing_keys(&events, &["a", "b", "c"]),
        vec!["c".to_string()],
        "the gate must flag a required key that appears in no event"
    );
    assert!(
        missing_keys(&events, &["a", "b"]).is_empty(),
        "a fully-surfaced manifest must pass"
    );
}
