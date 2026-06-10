//! RED→GREEN: the `rt srum` command must surface real SRUM rows into Issen
//! [`TimelineEvent`]s through the `issen-parser-srum` wrapper — not via a
//! direct `srum-parser` call, and never with the old "not yet implemented"
//! placeholder.
//!
//! Ground truth (real third-party fixture, see
//! `srum-forensic/tests/data/srudb/SOURCES.md`):
//!   chainsaw_SRUDB.dat — WithSecure Labs / Chainsaw (MD5 c946eb4a2c6a3da2e62f98486de5e1b0)
//!   96 network-usage rows; 94 with non-zero BytesSent; largest = 8_507_778 bytes.
//!
//! The fixture lives in the sibling `srum-forensic` repo; the test skips
//! gracefully when that checkout is absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

/// Path to the real chainsaw SRUDB.dat in the sibling srum-forensic repo.
fn chainsaw_srudb() -> Option<PathBuf> {
    // From issen/crates/issen-cli/, the sibling repo is ../../../srum-forensic.
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../srum-forensic/tests/data/srudb/chainsaw_SRUDB.dat");
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — real SRUDB fixture not present: {}", p.display());
        None
    }
}

/// `collect_events` is the CLI's single seam into the Issen timeline; it must
/// route through the wrapper and surface the real network rows with their
/// bytes_sent metadata intact (the exfil-window value).
#[test]
fn srum_command_surfaces_real_network_events_via_wrapper() {
    let Some(path) = chainsaw_srudb() else { return };

    let events = issen_cli::commands::srum::collect_events(&path)
        .expect("collect_events must succeed on a valid SRUDB.dat");

    let net: Vec<_> = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM NetworkUsage"))
        .collect();
    assert_eq!(
        net.len(),
        96,
        "rt srum must surface exactly 96 network-usage events from chainsaw SRUDB, got {}",
        net.len()
    );

    let max_sent = events
        .iter()
        .filter_map(|e| e.metadata.get("bytes_sent"))
        .filter_map(serde_json::Value::as_u64)
        .max()
        .unwrap_or(0);
    assert_eq!(
        max_sent, 8_507_778,
        "largest bytes_sent (exfil window) surfaced by rt srum must equal 8_507_778, got {max_sent}"
    );
}
