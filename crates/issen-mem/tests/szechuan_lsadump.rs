//! Real-dump validation for the memf-windows `lsadump` LSA-secret decryption,
//! against `citadeldc01.mem`. Oracle: Volatility 3 `windows.registry.lsadump`
//! decrypts 5 secrets there — notably `DefaultPassword` → UTF-16LE "ROOT#123"
//! (a recovered auto-logon password). This validates the full chain: SYSTEM
//! boot key → Vista+ LSA key (PolEKList) → per-secret AES decrypt.
//!
//! ```bash
//! SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
//!   cargo test -p issen-mem --test szechuan_lsadump -- --ignored --nocapture
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

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

#[test]
#[ignore = "needs the 2 GB DFIR Madness citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn szechuan_lsadump_decrypts_default_password() {
    // Volatility-reported _CMHIVE VA of the SYSTEM hive (memf does not populate a
    // name for it; matched by VA, low 48 bits).
    const SYSTEM_HIVE_VA: u64 = 0xc001_f0c2_8000;
    const VA_MASK: u64 = 0xFFFF_FFFF_FFFF;

    let Some(dump) = citadel_dc_mem() else {
        eprintln!("citadeldc01.mem not found; skipping (set SZECHUAN_DC_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    let hives = memf_windows::registry::walk_hive_list(&reader).expect("walk_hive_list");
    let system = hives
        .iter()
        .find(|h| h.base_addr & VA_MASK == SYSTEM_HIVE_VA)
        .map(|h| h.base_addr)
        .expect("SYSTEM hive present");
    let security = hives
        .iter()
        .find(|h| {
            h.file_user_name
                .to_ascii_uppercase()
                .trim_end_matches('\0')
                .ends_with("SECURITY")
        })
        .map(|h| h.base_addr)
        .expect("SECURITY hive present");

    let secrets = memf_windows::lsadump::walk_lsa_secrets(&reader, system, security)
        .expect("walk_lsa_secrets");
    eprintln!("lsadump recovered {} secrets:", secrets.len());
    for s in &secrets {
        eprintln!("  {} decrypted={} len={}", s.name, s.decrypted, s.length);
    }

    let dp = secrets
        .iter()
        .find(|s| s.name == "DefaultPassword")
        .expect("DefaultPassword secret present");
    assert!(dp.decrypted, "DefaultPassword must be decrypted");
    let data = dp.data.as_ref().expect("decrypted DefaultPassword data");
    // Decrypted LSA secret blob: u32 length @0, 16-byte header, then the value.
    let val_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let pw = utf16le(&data[16..(16 + val_len).min(data.len())]);
    eprintln!("DefaultPassword decrypts to: {pw:?}");
    assert_eq!(
        pw, "ROOT#123",
        "Volatility lsadump recovers DefaultPassword = ROOT#123"
    );
}
