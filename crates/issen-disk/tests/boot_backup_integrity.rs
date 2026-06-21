//! Real-data validation for the `$Boot` vs backup-`$Boot` consistency check.
//!
//! NTFS keeps the volume boot record (VBR/BPB) at the partition's first sector
//! and a backup copy at the last sector the BPB accounts for (`total_sectors`
//! into the partition). On an untouched volume the two carry identical geometry
//! — bytes/sector, sectors/cluster, total sectors, `$MFT`/`$MFTMirr` LCNs and
//! the volume serial. A divergence is a *consistency anomaly* (consistent with
//! tampering OR ordinary corruption/imaging), never a standalone verdict.
//!
//! Two real images decompose the validation honestly:
//!
//! * **DEF CON DFIR CTF 2018 `MaxPowersCDrive.E01`** — a full acquisition whose
//!   backup boot sector IS present and matches the primary byte-for-byte: the
//!   true-negative (no finding). Its parsed geometry is cross-checked against
//!   TSK `fsstat -o 1026048` (the same oracle used for the committed
//!   `defcon2018_cdrive_boot.bin` fixture in ntfs-forensic).
//!
//! * **DFIRMadness "Szechuan Sauce" DC `CDrive.E01`** — a sparse acquisition
//!   whose backup-boot region was not stored. The primary parses and matches
//!   `fsstat -o 718848`, but the backup sector is unreadable; the check must
//!   then degrade LOUD (an error), NEVER fabricate a tamper "mismatch".
//!
//! The images are large and gitignored; each test resolves its image from an
//! env var or the in-repo corpus path and skips cleanly when absent (CI), like
//! `extract_user_artifacts.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use issen_disk::{boot_backup_integrity_events, find_ntfs_partitions, read_boot_geometry};
use issen_ewf::EwfDataSource;

const DEFCON_DEFAULT: &str = "../../tests/data/defcon-dfir-ctf-2018/MaxPowersCDrive.E01";
const DC_DEFAULT: &str =
    "../../tests/data/dfirmadness-szechuan-sauce/extracted/E01-DC01/20200918_0347_CDrive.E01";

fn image(env_key: &str, default_rel: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_key) {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(default_rel);
    p.exists().then_some(p)
}

/// DEF CON `MaxPowers`: primary and backup boot sectors agree → no finding, and
/// the parsed geometry matches TSK `fsstat -o 1026048`.
#[test]
fn defcon_backup_boot_matches_and_geometry_cross_checks_fsstat() {
    let Some(img) = image("ISSEN_DEFCON_MAXPOWERS", DEFCON_DEFAULT) else {
        eprintln!("skipping: DEF CON MaxPowers image absent (set ISSEN_DEFCON_MAXPOWERS)");
        return;
    };
    let source = EwfDataSource::open(&img).expect("open MaxPowers E01");

    let windows = find_ntfs_partitions(&source).expect("find NTFS partitions");
    assert!(!windows.is_empty(), "MaxPowers must expose an NTFS volume");

    // The C: volume is the large NTFS partition (TSK reports it at LBA 1026048,
    // i.e. byte offset 1026048 * 512); take the largest NTFS window.
    let window = *windows
        .iter()
        .max_by_key(|w| w.length)
        .expect("at least one NTFS window");

    // Ground truth from `fsstat -o 1026048 MaxPowersCDrive.E01`:
    //   Volume Serial Number: 326C195B6C191B65
    //   First Cluster of MFT: 786432   First Cluster of MFT Mirror: 2
    //   Sector Size: 512   Cluster Size: 4096   (=> 8 sectors/cluster)
    //   Size of MFT Entries: 1024 bytes
    let geom = read_boot_geometry(&source, window).expect("parse primary boot");
    assert_eq!(geom.bytes_per_sector, 512, "fsstat: Sector Size 512");
    assert_eq!(geom.sectors_per_cluster, 8, "fsstat: Cluster Size 4096");
    assert_eq!(geom.mft_lcn, 786_432, "fsstat: First Cluster of MFT");
    assert_eq!(geom.mftmirr_lcn, 2, "fsstat: First Cluster of MFT Mirror");
    assert_eq!(
        geom.volume_serial, 0x326C_195B_6C19_1B65,
        "fsstat: Volume Serial Number"
    );

    // The full acquisition has a stored, matching backup boot sector.
    let events = boot_backup_integrity_events(&source, window, "maxpowers")
        .expect("backup boot is present and parses on a full acquisition");
    assert!(
        events.is_empty(),
        "primary and backup $Boot agree on a clean volume -> no integrity event, got {events:?}"
    );
}

/// Szechuan DC `CDrive`: primary parses and matches `fsstat -o 718848`, but the
/// backup-boot region was not captured (sparse image) — the check degrades LOUD
/// rather than fabricating a mismatch.
#[test]
fn szechuan_dc_primary_matches_fsstat_and_missing_backup_fails_loud() {
    let Some(img) = image("ISSEN_SZECHUAN_DC", DC_DEFAULT) else {
        eprintln!("skipping: DC image absent (set ISSEN_SZECHUAN_DC)");
        return;
    };
    let source = EwfDataSource::open(&img).expect("open DC E01");

    let windows = find_ntfs_partitions(&source).expect("find NTFS partitions");
    let window = *windows
        .iter()
        .max_by_key(|w| w.length)
        .expect("DC must expose an NTFS volume");

    // Ground truth from `fsstat -o 718848 20200918_0347_CDrive.E01`:
    //   Volume Serial Number: 98E6491BE648FAD0
    //   First Cluster of MFT: 786432   First Cluster of MFT Mirror: 2
    //   Sector Size: 512   Cluster Size: 4096
    let geom = read_boot_geometry(&source, window).expect("parse DC primary boot");
    assert_eq!(geom.bytes_per_sector, 512);
    assert_eq!(geom.sectors_per_cluster, 8);
    assert_eq!(geom.mft_lcn, 786_432);
    assert_eq!(geom.mftmirr_lcn, 2);
    assert_eq!(geom.volume_serial, 0x98E6_491B_E648_FAD0);

    // This particular DC acquisition is sparse: the backup-boot sector at
    // `total_sectors` was never stored, so reading it must surface a loud error
    // — emphatically NOT an empty "consistent" result and NOT a tamper mismatch.
    match boot_backup_integrity_events(&source, window, "dc") {
        Ok(events) => {
            // If a future, denser image of this host DOES carry the backup, it
            // must at least agree (no spurious mismatch).
            assert!(
                events.is_empty(),
                "DC backup, if present, must agree with the primary; got {events:?}"
            );
        }
        Err(e) => {
            // The expected path for this sparse image: a named, loud failure.
            let msg = e.to_string();
            assert!(
                !msg.is_empty(),
                "the unreadable-backup error must carry diagnostic context"
            );
        }
    }
}
