//! Real-data category test (CADET): drive `registry` over the Case-001 DC01
//! `SOFTWARE` hive and assert each emitted event carries the correct activity
//! category — generic key writes / system-info are `SystemState`, while autorun
//! (Run-key) persistence entries are `Persistence`.
//!
//! Fixture (gitignored): extract `DC01-ProtectedFiles.zip` → `tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives/`
//! (see `docs/corpus-catalog.md`). The test skips cleanly when the hive is absent
//! (e.g. CI without the corpus), so it only asserts where real data exists.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_closure_for_method_calls
)]

use std::path::PathBuf;

fn hive(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/data/dfirmadness-szechuan-sauce/extracted/szechuan-sauce-hives")
        .join(name)
}

#[test]
fn registry_real_software_hive_tagged_system_state() {
    let path = hive("SOFTWARE");
    if !path.exists() {
        eprintln!(
            "SKIP: {} absent — extract DC01-ProtectedFiles.zip (see docs/corpus-catalog.md)",
            path.display()
        );
        return;
    }
    let events = issen_parser_registry::parser::parse_hive(&path, "szechuan-sauce-DC01-SOFTWARE")
        .expect("parse_hive must decode a real SOFTWARE hive");
    assert!(
        !events.is_empty(),
        "Case-001 SOFTWARE hive has registry keys"
    );
    // Each event must carry the category matching its meaning: autorun
    // (persistence-tagged) → `Persistence`, everything else → `SystemState`.
    for e in &events {
        let expected = if e.tags.iter().any(|t| t == "persistence") {
            "persistence"
        } else {
            "system-state"
        };
        assert_eq!(
            e.activity_category.map(|c| c.code()),
            Some(expected),
            "wrong CADET category for {}: {}",
            e.artifact_path,
            e.description
        );
    }
    // The decoder must actually surface the implant's autorun persistence — proof
    // the Persistence branch is exercised, not vacuously true.
    assert!(
        events
            .iter()
            .any(|e| e.activity_category.map(|c| c.code()) == Some("persistence")),
        "the Run-key decoder must surface at least one Persistence event"
    );
}
