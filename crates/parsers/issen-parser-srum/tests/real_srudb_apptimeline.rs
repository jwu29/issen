//! Real-data regression: SRUM's AppTimeline table records foreground application
//! usage — focus time + user-input time per app, the highest-value SRUM execution
//! signal — which the wrapper dropped. `chainsaw_SRUDB.dat` has 26 AppTimeline
//! rows. Skips cleanly when the corpus is absent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_closure_for_method_calls
)]

use std::path::{Path, PathBuf};

use issen_parser_srum::SrumParser;

fn chainsaw_srudb() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../srum-forensic/tests/data/srudb/chainsaw_SRUDB.dat");
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — real SRUDB fixture not present: {}", p.display());
        None
    }
}

#[test]
fn surfaces_app_timeline_foreground_usage() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let at = events
        .iter()
        .find(|e| e.description.starts_with("SRUM AppTimeline"))
        .expect("an AppTimeline event");
    assert_eq!(
        at.activity_category.map(|c| c.code()),
        Some("execution"),
        "AppTimeline (foreground usage) → Execution"
    );
    assert!(
        at.metadata.iter().any(|(k, _)| k == "focus_time_ms"),
        "must surface the foreground focus time"
    );
}
