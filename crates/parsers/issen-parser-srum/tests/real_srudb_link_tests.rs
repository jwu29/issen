//! Integration tests proving the `issen-parser-srum` wrapper surfaces REAL
//! SRUM rows — decoded by the sibling `srum-parser`/`ese-core` ESE B-tree
//! traversal — into Issen [`TimelineEvent`]s.
//!
//! These exercise the full wiring path that the CLI now depends on:
//! `SrumParser::parse_path` → `srum_parser::parse_network_usage` →
//! `ese_core` leaf-page walk → `TimelineEvent` with `bytes_sent` metadata.
//!
//! Ground truth (verified against the real third-party fixture, not a
//! self-built synthetic — see `srum-forensic/tests/data/srudb/SOURCES.md`):
//!   chainsaw_SRUDB.dat — WithSecure Labs / Chainsaw test suite
//!     MD5 c946eb4a2c6a3da2e62f98486de5e1b0
//!     96 network-usage records, 94 with non-zero BytesSent,
//!     single largest BytesSent = 8_507_778 bytes (the "exfil window").
//!
//! The fixture lives in the sibling `srum-forensic` repo (the fleet's single
//! SRUDB corpus home); the test skips gracefully when that checkout is absent
//! so a stand-alone Issen build still passes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use issen_parser_srum::SrumParser;

/// Path to the real chainsaw SRUDB.dat in the sibling srum-forensic repo.
fn chainsaw_srudb() -> Option<PathBuf> {
    // From issen/crates/parsers/issen-parser-srum/, the sibling repo is
    // ../../../../srum-forensic relative to CARGO_MANIFEST_DIR.
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../srum-forensic/tests/data/srudb/chainsaw_SRUDB.dat");
    if p.exists() {
        Some(p)
    } else {
        eprintln!("SKIP — real SRUDB fixture not present: {}", p.display());
        eprintln!(
            "       (sibling srum-forensic checkout required; see its tests/data/srudb/SOURCES.md)"
        );
        None
    }
}

/// The wrapper must surface at least one network-usage event from the real DB.
#[test]
fn chainsaw_srudb_yields_network_events() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let net_events: Vec<_> = events
        .iter()
        .filter(|e| e.description.starts_with("SRUM NetworkUsage"))
        .collect();
    assert_eq!(
        net_events.len(),
        96,
        "chainsaw SRUDB must surface exactly 96 network-usage events, got {}",
        net_events.len()
    );
}

/// The "exfil window" assertion: the wrapper must carry the real per-record
/// `bytes_sent` through to TimelineEvent metadata, with the largest transfer
/// matching the ground-truth value byte-for-byte.
#[test]
fn chainsaw_srudb_surfaces_nonzero_bytes_sent_in_exfil_window() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser.parse_path(&path).expect("parse_path ok");

    let bytes_sent: Vec<u64> = events
        .iter()
        .filter_map(|e| e.metadata.get("bytes_sent"))
        .filter_map(serde_json::Value::as_u64)
        .collect();

    assert!(
        !bytes_sent.is_empty(),
        "no event carried bytes_sent metadata — wrapper is not surfacing real SRUM rows"
    );
    let nonzero = bytes_sent.iter().filter(|&&b| b > 0).count();
    assert_eq!(
        nonzero, 94,
        "chainsaw SRUDB must have 94 records with non-zero bytes_sent, got {nonzero}"
    );
    let max = bytes_sent.iter().copied().max().unwrap_or(0);
    assert_eq!(
        max, 8_507_778,
        "largest bytes_sent (exfil window) must equal the ground-truth 8_507_778, got {max}"
    );
}
