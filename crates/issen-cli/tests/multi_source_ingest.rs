//! Multi-source unified-timeline ingest (issen #114 follow-up).
//!
//! Two hosts can hold byte-identical artifacts (same `$J`, same registry hive,
//! same EVTX). A unified timeline must keep them DISTINCT and attributable — a
//! lateral-movement investigation depends on knowing which host an event came
//! from. The risk is a silent cross-host dedup collision: `record_hash` folds in
//! `evidence_source_id`, so the two hosts only stay distinct if every event is
//! re-stamped with its resolved per-source id before commit. This test locks
//! that end to end through the real `issen ingest` binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::path::Path;

use assert_cmd::Command;
use issen_timeline::query::TimelineQuery;
use issen_timeline::store::TimelineStore;
use tempfile::TempDir;

/// Minimal USNv2 record (mirrors the full-pipeline integration fixture).
fn build_usn_v2_record(
    filename: &str,
    reason: u32,
    file_ref: u64,
    parent_ref: u64,
    usn: i64,
) -> Vec<u8> {
    let name_utf16: Vec<u8> = filename.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let file_name_offset: u16 = 60;
    let file_name_length = name_utf16.len() as u16;
    let record_length = file_name_offset as usize + name_utf16.len();
    let padded_length = (record_length + 7) & !7;

    let mut buf = vec![0u8; padded_length];
    buf[0..4].copy_from_slice(&(padded_length as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&2u16.to_le_bytes());
    buf[8..16].copy_from_slice(&file_ref.to_le_bytes());
    buf[16..24].copy_from_slice(&parent_ref.to_le_bytes());
    buf[24..32].copy_from_slice(&usn.to_le_bytes());
    let filetime: i64 = 133_444_736_000_000_000;
    buf[32..40].copy_from_slice(&filetime.to_le_bytes());
    buf[40..44].copy_from_slice(&reason.to_le_bytes());
    buf[52..56].copy_from_slice(&0x20u32.to_le_bytes());
    buf[56..58].copy_from_slice(&file_name_length.to_le_bytes());
    buf[58..60].copy_from_slice(&file_name_offset.to_le_bytes());
    buf[60..60 + name_utf16.len()].copy_from_slice(&name_utf16);
    buf
}

/// Write an identical 3-record USN journal under `dir` (a loose-artifact source).
fn write_journal(dir: &Path) {
    let mut data = Vec::new();
    data.extend(build_usn_v2_record("malware.exe", 0x100, 1001, 500, 100));
    data.extend(build_usn_v2_record("malware.exe", 0x200, 1001, 500, 200));
    data.extend(build_usn_v2_record(
        "evidence.docx",
        0x8000_0000,
        2002,
        600,
        300,
    ));
    std::fs::write(dir.join("$J"), &data).unwrap();
}

#[test]
fn multi_source_ingest_keeps_two_hosts_distinct() {
    let root = TempDir::new().unwrap();
    let host_a = root.path().join("hostA");
    let host_b = root.path().join("hostB");
    std::fs::create_dir(&host_a).unwrap();
    std::fs::create_dir(&host_b).unwrap();
    write_journal(&host_a);
    write_journal(&host_b); // byte-identical artifact on a second host

    let db = root.path().join("unified.duckdb");

    // One `issen ingest` over BOTH hosts → one unified timeline DB.
    Command::cargo_bin("issen")
        .unwrap()
        .arg("ingest")
        .arg(&host_a)
        .arg(&host_b)
        .arg("-o")
        .arg(&db)
        .assert()
        .success();

    let store = TimelineStore::open(&db).expect("open unified db");
    let rows = store.query(&TimelineQuery::new()).expect("query all");

    // Both hosts' identical journals must survive: a cross-host collision would
    // dedup one host away (6 → 3). This is the Codex-flagged P1 attribution loss.
    assert_eq!(
        rows.len(),
        6,
        "two hosts x 3 USN records = 6 events; a record_hash collision would drop a host to 3"
    );

    // Each host carries a distinct evidence_source id, and each owns exactly 3 events.
    let sources: HashSet<&str> = rows.iter().map(|r| r.evidence_source.as_str()).collect();
    assert_eq!(
        sources.len(),
        2,
        "each host must carry a distinct evidence_source id"
    );
    for src in &sources {
        let n = rows
            .iter()
            .filter(|r| &r.evidence_source.as_str() == src)
            .count();
        assert_eq!(n, 3, "source {src} should own exactly its own 3 records");
    }
}
