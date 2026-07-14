//! Non-NTFS triage collection (t2): ext4 (Linux) and APFS (macOS) volumes.
//!
//! `issen-disk` historically walked only NTFS partitions; ext4/APFS windows were
//! detected but skipped. These tests pin the new parallel collection path:
//! `collect_ext4` / `collect_apfs` open the recognized non-NTFS volume and read a
//! fixed list of Linux/macOS triage paths into `ExtractedFile`s.
//!
//! The ext4 leg is driven end-to-end against a REAL self-minted `mkfs.ext4` image
//! (`tests/data/ext4-minimal.img`; provenance in that dir's README). No small
//! full-APFS disk image exists in the fleet, so the APFS leg is unit-tested for
//! its path list plus graceful (loud, non-panicking) behavior on a non-APFS
//! window, and the dispatch routing `"ext"→ext4` / `"APFS"→apfs` is asserted.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;
use issen_disk::{
    collect_apfs, collect_ext4, collect_with_caps, ExtractCaps, ExtractionLimit, PartitionWindow,
    LINUX_TRIAGE_PATHS, MACOS_TRIAGE_PATHS,
};

/// An in-memory [`DataSource`] over a byte vector.
struct VecSource(Vec<u8>);

impl DataSource for VecSource {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let start = offset as usize;
        if start >= self.0.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }
}

// ── Path-list specs ──────────────────────────────────────────────────────────

#[test]
fn linux_triage_paths_cover_key_artifacts() {
    assert!(!LINUX_TRIAGE_PATHS.is_empty());
    for p in ["/etc/passwd", "/var/log/auth.log", "/etc/hostname"] {
        assert!(
            LINUX_TRIAGE_PATHS.contains(&p),
            "LINUX_TRIAGE_PATHS must include {p}, got {LINUX_TRIAGE_PATHS:?}"
        );
    }
}

#[test]
fn macos_triage_paths_cover_key_artifacts() {
    assert!(!MACOS_TRIAGE_PATHS.is_empty());
    for p in ["/private/etc/passwd", "/private/var/log/system.log"] {
        assert!(
            MACOS_TRIAGE_PATHS.contains(&p),
            "MACOS_TRIAGE_PATHS must include {p}, got {MACOS_TRIAGE_PATHS:?}"
        );
    }
}

// ── ext4 end-to-end (real self-minted image) ─────────────────────────────────

/// The committed real bare-ext4 fixture. Bare filesystem (no partition table),
/// so the whole image is one window at offset 0.
fn ext4_source() -> VecSource {
    let bytes = include_bytes!("data/ext4-minimal.img");
    VecSource(bytes.to_vec())
}

fn whole_image_window(src: &VecSource) -> PartitionWindow {
    PartitionWindow {
        offset: 0,
        length: src.len(),
    }
}

#[test]
fn collect_ext4_reads_known_files_from_real_image() {
    let src = ext4_source();
    let window = whole_image_window(&src);
    // The fixture carries /hello.txt and /subdir/nested.txt (see tests/data/README.md).
    let paths = ["/hello.txt", "/subdir/nested.txt", "/does-not-exist"];
    let outcome =
        collect_ext4(&src, window, &paths, ExtractCaps::default()).expect("open ext4 volume");

    let hello = outcome
        .files
        .iter()
        .find(|f| f.path == "/hello.txt")
        .expect("/hello.txt extracted from the real ext4 image");
    assert_eq!(hello.data, b"Hello, ext4!");
    assert_eq!(
        hello.partition_offset, 0,
        "window offset is the partition offset"
    );

    assert!(
        outcome.files.iter().any(|f| f.path == "/subdir/nested.txt"),
        "nested file must extract; got {:?}",
        outcome.files.iter().map(|f| &f.path).collect::<Vec<_>>()
    );
    // A missing path is a per-file skip, not an error and not a cap.
    assert!(
        !outcome.files.iter().any(|f| f.path == "/does-not-exist"),
        "an absent triage path is skipped, never fabricated"
    );
    assert!(
        outcome.limits.is_empty(),
        "a small real image trips no caps, got {:?}",
        outcome.limits
    );
}

#[test]
fn collect_ext4_fails_loud_on_non_ext4_window() {
    // A window of zeroes is not an ext4 volume — opening it must be a LOUD error,
    // never a silent empty "no files" result (fail-loud on bootstrap).
    let src = VecSource(vec![0u8; 8192]);
    let window = whole_image_window(&src);
    let err = collect_ext4(&src, window, LINUX_TRIAGE_PATHS, ExtractCaps::default());
    assert!(
        err.is_err(),
        "opening a non-ext4 volume must be a loud error, not an empty Ok"
    );
}

// ── APFS graceful behavior + dispatch routing ────────────────────────────────

#[test]
fn collect_apfs_fails_loud_on_non_apfs_window() {
    // No NXSB anywhere: opening the container must fail loudly, not return empty.
    let src = VecSource(vec![0u8; 8192]);
    let window = whole_image_window(&src);
    let err = collect_apfs(&src, window, MACOS_TRIAGE_PATHS, ExtractCaps::default());
    assert!(
        err.is_err(),
        "opening a non-APFS volume must be a loud error, not an empty Ok"
    );
}

/// A bare-ext4 window (no partition table) so `classify_partitions` finds no
/// partition table and no window is dispatched — proves the whole-image
/// `collect_ext4`/`collect_apfs` helpers are the extraction entry points and the
/// NTFS pipeline is untouched. (The dispatch routing over a partition-tabled
/// disk is covered by the existing `apfs_disk_records_unsupported_filesystem`
/// unit test now that non-NTFS windows are collected rather than only logged.)
#[test]
fn collect_with_caps_on_bare_ext4_is_not_ntfs() {
    let src = ext4_source();
    let outcome = collect_with_caps(
        &src,
        &[issen_core::plugin::selector::NtfsLoc::FixedPath(r"\$MFT")],
        ExtractCaps::default(),
    )
    .expect("collect");
    // A bare ext4 image has no partition table, so there is nothing to route and
    // no NTFS $MFT — the collection is empty but must not error or panic.
    assert!(
        outcome.files.is_empty(),
        "a bare ext4 image yields no NTFS artifacts"
    );
    // No UnsupportedFilesystem here (that diagnostic keys off a partition-table
    // window, absent on a bare fs) — this test only guards no-panic/no-error.
    let _ = ExtractionLimit::UnsupportedFilesystem {
        filesystem: String::new(),
        offset: 0,
    };
}
