//! Real-dump validation for the rewritten memf-windows `shimcache` walker
//! (ahcache.sys .data scan, replacing the fabricated g_ShimCache symbol),
//! against `DESKTOP-SDN1RPT.mem` (Windows 10 build 19041).
//!
//! Oracle: Volatility 3 `windows.shimcachemem.ShimcacheMem` recovers 10 entries
//! on this image (e.g. `C:\Windows\SysWOW64\DllHost.exe`, FTK Imager paths).
//! The pre-rewrite walker returned 0.
//!
//! ```bash
//! SDN1RPT_MEM=/tmp/sdn1rpt-extracted/DESKTOP-SDN1RPT.mem \
//!   cargo test -p issen-mem --test szechuan_shimcache -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use issen_mem::dispatch::build_reader;

fn sdn1rpt_mem() -> Option<PathBuf> {
    if let Some(p) = std::env::var("SDN1RPT_MEM").ok().map(PathBuf::from) {
        if p.exists() {
            return Some(p);
        }
    }
    let local =
        Path::new("../../tests/data/dfirmadness-szechuan-sauce/extracted/DESKTOP-SDN1RPT.mem");
    if local.exists() {
        Some(local.to_path_buf())
    } else {
        None
    }
}

#[test]
#[ignore = "needs the 2 GB DFIR Madness DESKTOP-SDN1RPT.mem; set SDN1RPT_MEM"]
fn szechuan_shimcache_recovers_entries() {
    let Some(dump) = sdn1rpt_mem() else {
        eprintln!("DESKTOP-SDN1RPT.mem not found; skipping (set SDN1RPT_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let entries = memf_windows::shimcache::walk_shimcache(&reader).expect("walk_shimcache");
    eprintln!("walk_shimcache returned {} entries", entries.len());
    for e in entries.iter().take(15) {
        eprintln!("  [{}] exec={} {}", e.position, e.exec_flag, e.path);
    }

    // Volatility recovers 10 entries (some with empty / "-" / mojibake paths, so
    // an exact count is fragile). The robust tier-2 check: every confirmed real
    // execution artifact the oracle reported is recovered, and the count is in a
    // comparable range. memf observed 11 here: our path-aware per-entry filter is
    // a strict superset of Volatility's is_valid() — it keeps a link-inconsistent
    // node that still carries a readable path (recovered evidence), dropping a
    // node only when it is BOTH link-inconsistent AND pathless. So memf may
    // exceed the oracle by the path-bearing borderline nodes it would discard,
    // and never drops a path-bearing entry the oracle keeps.
    let lower: Vec<String> = entries
        .iter()
        .map(|e| e.path.to_ascii_lowercase())
        .collect();
    for needle in ["dllhost.exe", "ftk imager.exe", "autorunsc64.exe"] {
        assert!(
            lower.iter().any(|p| p.contains(needle)),
            "expected Volatility-confirmed artifact {needle:?} in {:?}",
            entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
    }
    assert!(
        (8..=16).contains(&entries.len()),
        "expected ~10 shimcache entries (Volatility oracle), got {}",
        entries.len()
    );
}
