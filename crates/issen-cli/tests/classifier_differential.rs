//! Classifier correctness gate (issen #114, Stage 4).
//!
//! `detect_from_registry` (highest-priority matching selector wins) is now the
//! pipeline's classifier — the hand-written `detect_artifact_type` it replaced is
//! gone. This asserts it classifies a corpus of real artifact paths to the
//! expected types (including the `mft`/`prefetch` overlap that the priority order
//! must resolve), and that no two *different*-type selectors collide at equal
//! priority. (Through Stage 3 this compared old≡new; the equivalence it proved is
//! what made deleting the old classifier safe.)
//!
//! Runtime over the real inventory: `use issen_cli` force-links the anchors so
//! every parser's selector is present; an under-population guard prevents a false
//! pass.

use std::path::Path;

use issen_cli as _;
use issen_core::artifacts::ArtifactType;
use issen_core::plugin::registry::{detect_from_registry, ParserRegistration};

/// (path, expected classification — `""` means `None`). Paths point at
/// non-existent files so the `regf`/`SEGB` magic fallbacks return `false`.
const CORPUS: &[(&str, &str)] = &[
    ("/img/$MFT", "Mft"),
    ("/img/$LogFile", "LogFile"),
    ("/img/$MFTMirr", ""), // mirror is read by the cross-file check, not parsed as a full MFT
    ("/img/$Extend/$UsnJrnl", "UsnJournal"),
    ("/img/Windows/Prefetch/CMD.EXE-0AB12345.pf", "Prefetch"),
    ("/img/mft.pf", "Mft"), // overlap: mft (prio 99) beats prefetch (97)
    ("/img/prefetch_mft.pf", "Prefetch"), // "mft" but also "prefetch" → mft guard off
    (
        "/img/Windows/System32/winevt/Logs/Security.evtx",
        "EventLog",
    ),
    ("/img/Windows/System32/config/SYSTEM", "Registry"),
    ("/img/Windows/System32/config/SOFTWARE", "Registry"),
    ("/img/Windows/System32/config/SAM", "Registry"),
    ("/img/Windows/System32/config/SECURITY", "Registry"),
    ("/img/Users/beth/NTUSER.DAT", "Registry"),
    (
        "/img/Users/beth/AppData/Local/Microsoft/Windows/UsrClass.dat",
        "Registry",
    ),
    ("/img/exported/SYSTEM", ""), // bare "system", no config path / regf magic → None
    ("/img/Windows/AppCompat/Programs/Amcache.hve", "Amcache"),
    ("/img/Windows/System32/sru/SRUDB.dat", "Srum"),
    (
        "/img/Users/beth/AppData/Roaming/Microsoft/Windows/Recent/secret.lnk",
        "Lnk",
    ),
    ("/img/Users/beth/Desktop/Loot.lnk", "Lnk"),
    (
        "/img/Users/beth/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5d696d521de238c3.automaticDestinations-ms",
        "JumpLists",
    ),
    (
        "/img/Users/beth/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/5d696d521de238c3.customDestinations-ms",
        "JumpLists",
    ),
    (
        "/img/$Recycle.Bin/S-1-5-21-1-2-3-500/$IU2L112.txt",
        "RecycleBin",
    ),
    ("/img/$Recycle.Bin/S-1-5-21-1-2-3-500/$RU2L112.txt", ""), // $R, not $I → None
    ("/img/Windows/INF/setupapi.dev.log", "DeviceInstall"),
    ("/img/Windows/INF/setupapi.setup.log", "DeviceInstall"),
    ("/img/var/log/auth.log", "LoginHistory"),
    ("/img/var/log/auth.log.1", "LoginHistory"),
    ("/img/home/beth/.bash_history", "LoginHistory"),
    ("/img/var/log/syslog", "SystemInfo"),
    ("/img/var/log/syslog.2", "SystemInfo"),
    ("/img/var/log/cron", "CrontabConfig"),
    ("/img/var/log/cron.log", "CrontabConfig"),
    ("/img/var/log/system.log", "SystemInfo"),
    (
        "/img/private/var/db/diagnostics/foo.logarchive",
        "SystemInfo",
    ),
    ("/img/.fseventsd/0000000000000001", "SystemInfo"),
    ("/img/Users/beth/AppData/Local/Temp/evil.exe", "Pe"),
    ("/img/Users/Public/dropper.dll", "Pe"),
    ("/img/Windows/System32/svchost.exe", ""), // not suspicious → None
    ("/img/Users/beth/Documents/report.docx", ""),
    ("/img/random/notes.txt", ""),
];

fn require_populated() -> Vec<&'static ParserRegistration> {
    let regs: Vec<_> = inventory::iter::<ParserRegistration>.into_iter().collect();
    assert!(
        regs.len() >= 25,
        "parser inventory under-populated ({}) — anchors dropped from this test binary",
        regs.len()
    );
    regs
}

#[test]
fn registry_classifier_matches_expected_types() {
    require_populated();
    let mut wrong = Vec::new();
    for (path, expected) in CORPUS {
        let got = detect_from_registry(Path::new(path))
            .map(|t| format!("{t:?}"))
            .unwrap_or_default();
        if got != *expected {
            wrong.push(format!("{path}: expected {expected:?}, got {got:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "registry classifier misclassified:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn no_two_different_type_selectors_collide_at_equal_priority() {
    let regs = require_populated();
    let mut collisions = Vec::new();
    for (path, _) in CORPUS {
        let path = Path::new(path);
        let matched: Vec<(u8, ArtifactType)> = regs
            .iter()
            .filter(|r| (r.selector.matches)(path))
            .map(|r| (r.selector.priority, r.selector.artifact_type))
            .collect();
        for (i, (pa, ta)) in matched.iter().enumerate() {
            for (pb, tb) in &matched[i + 1..] {
                if pa == pb && ta != tb {
                    collisions.push(format!(
                        "{path:?}: priority {pa} matched by both {ta:?} and {tb:?}"
                    ));
                }
            }
        }
    }
    assert!(
        collisions.is_empty(),
        "equal-priority selectors of different types match one path (ambiguous routing):\n{}",
        collisions.join("\n")
    );
}
