//! Real-data enrichment regression: SRUM stores `app_id` as a numeric index into
//! `SruDbIdMapTable`; an event showing `app_id=285` is useless to an analyst. The
//! wrapper must resolve it (the id-map join) to the application path/name.
//!
//! In `chainsaw_SRUDB.dat`'s id map, `app_id=285` →
//! `…\microsoft\edgeupdate\microsoftedgeupdate.exe` and `286` → `taskhostw.exe`,
//! and ALL 96 network rows resolve. Those strings can only appear if the wrapper
//! performs the resolution. Skips cleanly when the corpus is absent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

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
fn events_resolve_app_id_to_application_name() {
    let Some(path) = chainsaw_srudb() else { return };
    let events = SrumParser
        .parse_path(&path)
        .expect("parse_path must succeed on a valid SRUDB.dat");
    let blob: String = events
        .iter()
        .flat_map(|e| {
            std::iter::once(e.description.clone())
                .chain(e.metadata.iter().map(|(k, v)| format!("{k}={v}")))
        })
        .collect::<Vec<_>>()
        .join("  ")
        .to_lowercase();
    assert!(
        blob.contains("microsoftedgeupdate.exe") || blob.contains("taskhostw.exe"),
        "SRUM events must resolve app_id to the application path/name (the \
         SruDbIdMapTable join), not just the raw numeric index"
    );
}
