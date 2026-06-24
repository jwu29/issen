//! Real-dump validation for the memf-windows `shellbags` BagMRU walker, against
//! `citadeldc01.mem`. The walker navigates the in-memory HMAP cell map to
//! `Shell\BagMRU` and reconstructs the folder tree from the shell items.
//!
//! Oracle (tier-2): extract the resident hive from memory and parse it on disk
//! with an independent tool (regipy 6.2.1, MIT — no shared dependency with memf).
//! The Administrator `UsrClass.dat` is fully resident at VA 0xc001f1e94000 (107
//! BagMRU rows, 27 shell items); the recovered tree includes `FileShare\Secret`
//! and `FTK Imager`, which independently match the documented Szechuan Sauce
//! attack narrative. Full provenance + answer key:
//! memory-forensic/docs/plans/2026-06-24-shellbags-rewrite.md.
//!
//! ```bash
//! SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
//!   cargo test -p issen-mem --test szechuan_shellbags -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use issen_mem::dispatch::build_reader;

fn citadel_dc_mem() -> Option<PathBuf> {
    if let Some(p) = std::env::var("SZECHUAN_DC_MEM").ok().map(PathBuf::from) {
        if p.exists() {
            return Some(p);
        }
    }
    let local = Path::new("../../tests/data/dfirmadness-szechuan-sauce/extracted/citadeldc01.mem");
    if local.exists() {
        Some(local.to_path_buf())
    } else {
        None
    }
}

#[test]
#[ignore = "needs the 2 GB DFIR Madness citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn szechuan_shellbags_recovers_bagmru_from_resident_usrclass() {
    // The Administrator UsrClass.dat with a fully-resident, populated BagMRU
    // (the other UsrClass copies are paged out). UsrClass hives carry no useful
    // file name, so match by VA (low 48 bits), as lsadump does for SYSTEM.
    const USRCLASS_HIVE_VA: u64 = 0xc001_f1e9_4000;
    const VA_MASK: u64 = 0xFFFF_FFFF_FFFF;

    let Some(dump) = citadel_dc_mem() else {
        eprintln!("citadeldc01.mem not found; skipping (set SZECHUAN_DC_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let hives = memf_windows::registry::walk_hive_list(&reader).expect("walk_hive_list");
    let usrclass = hives
        .iter()
        .find(|h| h.base_addr & VA_MASK == USRCLASS_HIVE_VA)
        .map(|h| h.base_addr)
        .expect("Administrator UsrClass hive present at the documented VA");

    let entries =
        memf_windows::shellbags::walk_shellbags(&reader, usrclass).expect("walk_shellbags");
    eprintln!("shellbags recovered {} BagMRU folder(s):", entries.len());
    for e in &entries {
        eprintln!("  {}  (suspicious={})", e.path, e.is_suspicious);
    }

    // Answer key (regipy on the extracted resident hive): the recovered tree must
    // contain these folders. `Secret` and `FTK Imager` match the attack narrative.
    let all = entries
        .iter()
        .map(|e| e.path.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for needle in ["FileShare", "Secret", "FTK Imager", "Administrator"] {
        assert!(
            all.contains(needle),
            "BagMRU missing expected folder {needle:?}; recovered:\n{all}"
        );
    }

    // 27 shell items in the resident hive; require a healthy lower bound (a broken
    // walk silent-empties, so any real recovery clears this).
    assert!(
        entries.len() >= 20,
        "expected ~27 shell items from the resident BagMRU, got {}",
        entries.len()
    );
}
