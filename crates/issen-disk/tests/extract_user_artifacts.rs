//! Real-data validation: the per-user `.lnk` and per-SID `$Recycle.Bin\$I`
//! sweeps must actually pull those artifacts off genuine Windows images.
//!
//! Ground truth — the DFIRMadness "Szechuan Sauce" case:
//! * the workstation `DESKTOP-SDN1RPT` carries live Recent/Desktop shortcuts;
//! * the domain controller `CDrive` recycle bin holds the Administrator's
//!   deleted `$IU2L112.txt`, whose original path is
//!   `\FileShare\Secret\SECRET_beth.txt` — Beth's stolen recipe.
//!
//! These artifacts were *dark* (0 parsed events) because `extract_triage` never
//! collected the files. The two images decompose the validation honestly: the
//! WS recycle bins were emptied (so deleted-file evidence there is carve-only),
//! while the DC bin still holds the deletion record live.
//!
//! The images are large and gitignored; each test resolves its image from an
//! env var or the in-repo corpus path and skips cleanly when absent (CI), like
//! `parity_read.rs`.

use std::path::PathBuf;

use issen_disk::{extract_subdir_sweep, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

const WS_DEFAULT: &str =
    "../../tests/data/dfirmadness-szechuan-sauce/extracted/20200918_0417_DESKTOP-SDN1RPT.E01";
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

#[test]
fn recent_desktop_lnk_sweep_recovers_live_shortcuts() {
    let Some(img) = image("ISSEN_SZECHUAN_WS", WS_DEFAULT) else {
        eprintln!("skipping: WS image absent (set ISSEN_SZECHUAN_WS)");
        return;
    };
    let source = EwfDataSource::open(&img).expect("open WS E01");

    let mut lnks = Vec::new();
    for window in find_ntfs_partitions(&source).expect("find NTFS partitions") {
        for rel in [r"AppData\Roaming\Microsoft\Windows\Recent", "Desktop"] {
            lnks.extend(
                extract_subdir_sweep(&source, window, r"\Users", rel, &|n| {
                    n.to_ascii_lowercase().ends_with(".lnk")
                })
                .expect("sweep .lnk"),
            );
        }
    }

    assert!(
        !lnks.is_empty(),
        "WS image must yield live Recent/Desktop .lnk shortcuts (got 0)"
    );
    assert!(
        lnks.iter()
            .all(|f| f.path.to_ascii_lowercase().ends_with(".lnk")),
        "every swept file must be a .lnk"
    );
}

#[test]
fn recycle_bin_sweep_recovers_beths_deleted_secret() {
    let Some(img) = image("ISSEN_SZECHUAN_DC", DC_DEFAULT) else {
        eprintln!("skipping: DC image absent (set ISSEN_SZECHUAN_DC)");
        return;
    };
    let source = EwfDataSource::open(&img).expect("open DC E01");

    let mut recycle = Vec::new();
    for window in find_ntfs_partitions(&source).expect("find NTFS partitions") {
        recycle.extend(
            extract_subdir_sweep(&source, window, r"\$Recycle.Bin", "", &|n| {
                n.to_ascii_lowercase().starts_with("$i")
            })
            .expect("sweep $I"),
        );
    }

    assert!(
        !recycle.is_empty(),
        "DC recycle bin must yield $I deletion records (got 0)"
    );
    assert!(
        recycle.iter().all(|f| {
            f.path
                .rsplit('\\')
                .next()
                .is_some_and(|n| n.to_ascii_lowercase().starts_with("$i"))
        }),
        "every swept recycle file must be a $I record"
    );
    // Ground truth: one of the recovered $I records is Beth's deleted secret.
    // The original path is stored as UTF-16LE in the $I tail; assert its bytes
    // are present without re-implementing the parser (that runs end-to-end).
    let needle: Vec<u8> = "SECRET_beth.txt"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(
        recycle
            .iter()
            .any(|f| f.data.windows(needle.len()).any(|w| w == needle)),
        "the DC recycle sweep must recover Beth's deleted \\FileShare\\Secret\\SECRET_beth.txt $I record"
    );
}
