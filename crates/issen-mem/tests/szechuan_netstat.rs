//! Real-dump integration test for the memf `netstat` Windows path against the
//! DFIR Madness "Stolen Szechuan Sauce" domain-controller memory image
//! (`citadeldc01.mem`, Windows Server 2012 R2, kernel build 9600).
//!
//! Ground truth from the DFIR Madness case answers: the Cobalt Strike C2 beacon
//! `coreupdater.exe` (PID 3644) holds an ESTABLISHED TCP connection to
//! `203.78.103.109:443`. This is the independently-published answer key
//! (<https://dfirmadness.com/the-stolen-szechuan-sauce/>), not a self-authored
//! fixture.
//!
//! `#[ignore]`d by default because it needs the 2 GB `citadeldc01.mem` extract,
//! which is gitignored (see `tests/data/README.md` / `docs/corpus-catalog.md`):
//!
//! ```bash
//! cargo test -p issen-mem --test szechuan_netstat -- --ignored --nocapture
//! ```
//!
//! Override the dump location with `SZECHUAN_DC_MEM` if it lives elsewhere.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use issen_mem::dispatch::{build_reader, dispatch_windows_netstat};

/// Locate `citadeldc01.mem` via `SZECHUAN_DC_MEM`, falling back to the in-repo
/// corpus path (relative to this crate's `tests/` directory).
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

/// `windows.netstat` on the real DC dump recovers the verified Cobalt Strike
/// C2 session: `coreupdater.exe` -> `203.78.103.109:443`, ESTABLISHED.
#[test]
#[ignore = "needs the 2 GB DFIR Madness citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn szechuan_netstat_recovers_coreupdater_c2() {
    let Some(dump) = citadel_dc_mem() else {
        eprintln!("citadeldc01.mem not found; skipping (set SZECHUAN_DC_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let (headers, rows) = dispatch_windows_netstat(&reader).expect("windows netstat walk");
    let col = |name: &str| headers.iter().position(|h| *h == name);
    let remote_col = col("Remote").expect("netstat has Remote column");
    let proc_col = col("Process").expect("netstat has Process column");
    eprintln!("netstat produced {} rows", rows.len());

    // The published answer key: 203.78.103.109:443 owned by coreupdater.exe.
    let c2 = rows.iter().any(|r| {
        let remote = r.get(remote_col).map_or("", String::as_str);
        let proc = r.get(proc_col).map_or("", String::as_str);
        remote.contains("203.78.103.109")
            && remote.contains(":443")
            && proc.to_ascii_lowercase().contains("coreupdater")
    });
    let remotes: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get(remote_col).cloned())
        .collect();
    assert!(
        c2,
        "expected coreupdater.exe -> 203.78.103.109:443 (DFIR Madness answer key); \
         got remotes: {remotes:?}"
    );
}
