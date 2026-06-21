//! Real-data regression: SRUM's EnergyUsageLT (long-term energy estimation) is the
//! same record shape as EnergyUsage and gets the same aggregate-per-app treatment.
//! `museum_rathbunvm_win11_SRUDB.dat` has 2 EnergyUsageLT rows. Skips when absent.
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
fn energy_lt_is_aggregated_per_app() {
    let Some(path) = rathbun_win11_srudb() else {
        return;
    };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let elt: Vec<_> = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM EnergyUsageLT"))
        .collect();
    assert!(!elt.is_empty(), "EnergyUsageLT must surface");
    assert_eq!(
        elt[0].activity_category.map(|c| c.code()),
        Some("execution"),
        "EnergyUsageLT → Execution"
    );
    let total_rows: u64 = elt
        .iter()
        .filter_map(|e| {
            e.metadata
                .iter()
                .find(|(k, _)| k.as_str() == "occurrences")
                .and_then(|(_, v)| v.as_u64())
        })
        .sum();
    assert!(
        total_rows > elt.len() as u64,
        "EnergyUsageLT must be aggregated per-app: {total_rows} rows collapsed \
         into {} events",
        elt.len()
    );
}
