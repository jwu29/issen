//! Real-dump validation for the memf-windows `amcache` walker after its
//! flat→HMAP migration, against the DFIR Madness "Stolen Szechuan Sauce"
//! workstation image (`DESKTOP-SDN1RPT.mem`, Windows 10 build 19041).
//!
//! Independent oracle: Volatility 3 (`windows.registry.hivelist` and
//! `windows.registry.amcache.Amcache`). On this image the `Amcache.hve`
//! `Root\InventoryApplicationFile` is empty/paged — Volatility's own amcache
//! plugin recovers 0 entries:
//!
//! ```text
//! $ vol.py -f DESKTOP-SDN1RPT.mem windows.registry.hivelist
//!   0xcf047b8d6000  \??\C:\Windows\AppCompat\Programs\Amcache.hve
//! $ vol.py -f DESKTOP-SDN1RPT.mem windows.registry.amcache.Amcache
//!   -> 0 entries
//! ```
//!
//! So this is a tier-2 *true-negative*: `walk_amcache` must enumerate a real
//! in-memory `Amcache.hve` via the shared HMAP cell-map walker without crashing
//! and without fabricating entries the oracle does not see. (A positive
//! end-to-end check is corpus-blocked — none of the available Szechuan images
//! has a populated Amcache; Volatility recovers 0 from all of them. The HMAP
//! navigation amcache delegates to is independently tier-2-validated by
//! `szechuan_com_hijacking`'s exact 4612-subkey `SOFTWARE\Classes\CLSID`
//! enumeration, which uses the same shared primitives.)
//!
//! `#[ignore]`d by default (needs the 2 GB extract; set `SDN1RPT_MEM`):
//!
//! ```bash
//! cargo test -p issen-mem --test szechuan_amcache -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use issen_mem::dispatch::build_reader;

/// Volatility-reported `_CMHIVE` VA of the `Amcache.hve` hive (low 48 bits).
const AMCACHE_HIVE_VA: u64 = 0xcf04_7b8d_6000;
/// Low-48-bit mask for canonical x86-64 VA comparison across the two tools.
const CANONICAL_VA_MASK: u64 = 0xFFFF_FFFF_FFFF;

/// Locate the DESKTOP-SDN1RPT workstation image via `SDN1RPT_MEM`, falling back
/// to the in-repo corpus path.
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

/// `walk_amcache` on the real `Amcache.hve` agrees with Volatility (0 entries)
/// and the hive VA matches `hivelist` — confirming the HMAP walker enumerates a
/// real hive without fabricating.
#[test]
#[ignore = "needs the 2 GB DFIR Madness DESKTOP-SDN1RPT.mem; set SDN1RPT_MEM"]
fn szechuan_amcache_matches_volatility() {
    let Some(dump) = sdn1rpt_mem() else {
        eprintln!("DESKTOP-SDN1RPT.mem not found; skipping (set SDN1RPT_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let hives = memf_windows::registry::walk_hive_list(&reader).expect("walk_hive_list");
    let amcache = hives
        .iter()
        .find(|h| {
            h.file_user_name
                .to_ascii_uppercase()
                .trim_end_matches('\0')
                .ends_with("AMCACHE.HVE")
        })
        .expect("Amcache.hve present in hive list");
    eprintln!(
        "Amcache.hve base_addr = {:#x} (oracle {:#x})",
        amcache.base_addr, AMCACHE_HIVE_VA
    );
    assert_eq!(
        amcache.base_addr & CANONICAL_VA_MASK,
        AMCACHE_HIVE_VA,
        "memf _CMHIVE VA for Amcache.hve must match Volatility hivelist (low 48 bits)"
    );

    let entries =
        memf_windows::amcache::walk_amcache(&reader, amcache.base_addr).expect("walk_amcache");
    eprintln!("walk_amcache returned {} entries", entries.len());
    for e in entries.iter().take(5) {
        eprintln!("  {} (suspicious={})", e.file_path, e.is_suspicious);
    }
    assert!(
        entries.is_empty(),
        "Volatility's amcache plugin recovers 0 entries on this image; \
         walk_amcache must not fabricate, got: {entries:?}"
    );
}
