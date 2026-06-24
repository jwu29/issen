//! Real-dump validation for the memf-windows `hashdump` SAM NTLM extraction,
//! against `citadeldc01.mem` (DFIR Madness "Szechuan Sauce" domain controller).
//!
//! This exercises the full SAM hashdump chain end-to-end on a real image after
//! the registry-dedup migration (navigation moved onto winreg-core/MemfHiveReader,
//! all crypto kept byte-for-byte): SYSTEM boot key → hashed-boot-key (`Account\F`,
//! RC4 rev-2 / AES rev-3) → per-RID `V`-value NT/LM hash decrypt.
//!
//! Forensic caveat (why a DC is a deliberately conservative target): on a domain
//! controller the *domain* account hashes live in NTDS.dit, NOT in the SAM hive.
//! SAM hashdump on a DC therefore recovers only the machine's **local** SAM
//! accounts (built-in Administrator/Guest/DefaultAccount/WDAGUtilityAccount). The
//! count is small and that is correct — this test validates that memf recovers
//! exactly the local-SAM set an independent oracle reports, not a full domain dump.
//!
//! Oracle (independent third party, same input — Doer-Checker tier 1/2):
//!   Volatility 3 `windows.hashdump` on the SAME citadeldc01.mem:
//!     vol -f citadeldc01.mem windows.hashdump.Hashdump
//!   It prints `User rid lmhash:nthash`. Provide its output (or impacket
//!   `secretsdump.py -sam <SAM> -system <SYSTEM> LOCAL`, lines
//!   `user:rid:lmhash:nthash:::`) via SZECHUAN_HASHDUMP_ORACLE pointing at a file;
//!   the test then reconciles memf's (rid → nthash) map against it exactly.
//!
//! ```bash
//! SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
//! SZECHUAN_HASHDUMP_ORACLE=/tmp/vol3-hashdump.txt \
//!   cargo test -p issen-mem --test szechuan_hashdump -- --ignored --nocapture
//! ```
//!
//! With the dump but WITHOUT an oracle file, the test still runs memf, asserts the
//! structural invariants every real NTLM record must satisfy (32-hex NT hash, a
//! plausible RID), and prints the recovered set for manual reconciliation — it
//! does NOT invent expected values.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::collections::BTreeMap;
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

/// `true` for a 32-char lowercase-hex NTLM hash.
fn is_ntlm_hex(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse an oracle file into `rid → nt_hash` (lowercase hex). Accepts both
/// Volatility 3 `windows.hashdump` rows (`User  rid  lmhash  nthash`, whitespace
/// columns) and impacket secretsdump LOCAL lines (`user:rid:lmhash:nthash:::`).
fn parse_oracle(text: &str) -> BTreeMap<u32, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // impacket: user:rid:lm:nt:::
        if line.matches(':').count() >= 3 {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4 {
                if let (Ok(rid), nt) = (f[1].parse::<u32>(), f[3].to_ascii_lowercase()) {
                    if is_ntlm_hex(&nt) {
                        map.insert(rid, nt);
                        continue;
                    }
                }
            }
        }
        // vol3: columns separated by whitespace; last token is the NT hash, the
        // numeric token is the RID.
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 {
            let nt = cols[cols.len() - 1].to_ascii_lowercase();
            if let Some(rid) = cols.iter().find_map(|c| c.parse::<u32>().ok()) {
                if is_ntlm_hex(&nt) {
                    map.insert(rid, nt);
                }
            }
        }
    }
    map
}

#[test]
#[ignore = "needs the 2 GB DFIR Madness citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn szechuan_hashdump_recovers_local_sam_hashes() {
    let Some(dump) = citadel_dc_mem() else {
        eprintln!("citadeldc01.mem not found; skipping (set SZECHUAN_DC_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    // Locate the SAM hive (named via file_user_name) and try each candidate hive
    // as the unnamed SYSTEM hive until one yields a valid boot key + hashes —
    // exactly the resolution issen-mem's dispatch uses.
    let hives = memf_windows::registry::walk_hive_list(&reader).expect("walk_hive_list");
    let sam_base = hives
        .iter()
        .find(|h| {
            h.file_user_name
                .to_ascii_uppercase()
                .trim_end_matches('\0')
                .trim_end_matches('\\')
                .ends_with("SAM")
        })
        .map(|h| h.base_addr)
        .expect("SAM hive present");

    let entries = hives
        .iter()
        .filter(|h| h.base_addr != 0 && h.base_addr != sam_base)
        .find_map(|cand| {
            match memf_windows::hashdump::walk_hashdump(&reader, sam_base, cand.base_addr) {
                Ok(e) if !e.is_empty() => Some(e),
                _ => None,
            }
        })
        .expect("hashdump recovered at least one local SAM account (boot key derived)");

    eprintln!(
        "memf hashdump recovered {} local SAM account(s):",
        entries.len()
    );
    let mut memf: BTreeMap<u32, String> = BTreeMap::new();
    for e in &entries {
        eprintln!("  rid={} user={:?} nt={}", e.rid, e.username, e.nt_hash);
        // Every recovered record must be a well-formed NTLM hash for a plausible
        // RID — this catches a navigation/decrypt regression (garbage bytes) even
        // without an oracle.
        assert!(
            is_ntlm_hex(&e.nt_hash),
            "rid {} NT hash is not 32-hex: {:?}",
            e.rid,
            e.nt_hash
        );
        assert!(e.rid >= 500, "implausible RID {}", e.rid);
        memf.insert(e.rid, e.nt_hash.to_ascii_lowercase());
    }

    // Independent-oracle reconciliation (the part that earns hashdump's ✅).
    match std::env::var("SZECHUAN_HASHDUMP_ORACLE")
        .ok()
        .map(PathBuf::from)
    {
        Some(oracle_path) if oracle_path.exists() => {
            let text = std::fs::read_to_string(&oracle_path).expect("read oracle file");
            let oracle = parse_oracle(&text);
            assert!(
                !oracle.is_empty(),
                "oracle file {oracle_path:?} parsed to zero (rid,nt) rows — check format"
            );
            eprintln!("oracle reports {} account(s):", oracle.len());
            for (rid, nt) in &oracle {
                eprintln!("  rid={rid} nt={nt}");
            }
            // Every account the oracle recovers, memf must recover with the SAME
            // NT hash. (memf may legitimately surface the same set; a divergence
            // here is a real regression.)
            for (rid, want) in &oracle {
                match memf.get(rid) {
                    Some(got) => assert_eq!(
                        got, want,
                        "rid {rid} NT hash diverges: memf={got} oracle={want}"
                    ),
                    None => panic!("oracle rid {rid} ({want}) missing from memf output"),
                }
            }
            eprintln!(
                "RECONCILED: all {} oracle account(s) match memf NT hashes",
                oracle.len()
            );
        }
        _ => {
            eprintln!(
                "SZECHUAN_HASHDUMP_ORACLE not set — structural checks passed; \
                 supply a Volatility 3 / impacket oracle file to reconcile NT hashes \
                 (hashdump stays unverified-against-oracle until then)."
            );
        }
    }
}
