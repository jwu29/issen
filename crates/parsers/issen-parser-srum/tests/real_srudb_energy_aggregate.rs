//! Real-data regression: SRUM's EnergyUsage table (per-app power consumption — an
//! app drawing power ⇒ it ran) must be aggregated per-app like PushNotifications,
//! not emitted per-row. `museum_rathbunvm_win11_SRUDB.dat` has 13 energy rows
//! (chainsaw has none). Skips when that corpus DB is absent.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::redundant_closure_for_method_calls
)]

use std::path::{Path, PathBuf};

use issen_parser_srum::SrumParser;

fn rathbun_win11_srudb() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../srum-forensic/tests/data/srudb/museum_rathbunvm_win11_SRUDB.dat");
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "SKIP — energy-bearing SRUDB fixture not present: {}",
            p.display()
        );
        None
    }
}

#[test]
fn energy_usage_is_aggregated_per_app() {
    let Some(path) = rathbun_win11_srudb() else {
        return;
    };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let energy: Vec<_> = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM EnergyUsage"))
        .collect();
    assert!(!energy.is_empty(), "energy usage must surface");
    assert_eq!(
        energy[0].activity_category.map(|c| c.code()),
        Some("execution"),
        "energy usage (an app drew power ⇒ it ran) → Execution"
    );
    let total_rows: u64 = energy
        .iter()
        .filter_map(|e| {
            e.metadata
                .iter()
                .find(|(k, _)| k.as_str() == "occurrences")
                .and_then(|(_, v)| v.as_u64())
        })
        .sum();
    assert!(
        total_rows > energy.len() as u64,
        "EnergyUsage must be aggregated per-app: {total_rows} rows collapsed into \
         {} events",
        energy.len()
    );
}
