//! Source-agnostic Linux artifact analysis — the live-vs-dead contract.
//!
//! ADR 0015 asks that the Linux rootkit / masquerade / persistence analysis run
//! on a Linux *disk image* (dead ext4/APFS/HFS+), not only on a UAC live-response
//! collection. A UAC collection captures **live-response** artifacts (running-process
//! lists, `/proc` snapshots, netstat, loaded modules) that a **dead** disk image
//! does NOT contain. So the analysis degrades gracefully **per indicator**:
//!
//! - **Dead-disk-derivable** indicators read on-disk filesystem state and run on
//!   either source (a disk image OR a collection).
//! - **Live-only** indicators need a live-response capture and are cleanly SKIPPED
//!   on a dead image, marked "not available for dead-disk evidence" — never
//!   fabricated, never an error.
//!
//! This module owns that classification as data (so it is testable and stays the
//! single source of truth) plus the dead-disk analysis entry point. The full
//! disk-image parity — actually extracting `/etc`, `/tmp`, cron/systemd units from
//! an ext4 image into a root this analysis can read — is gated on wiring an ext4
//! reader into the disk leg (see the module-level BLOCKER note below and ADR 0015).
//!
//! ## BLOCKER (why full parity is not yet wired)
//!
//! Two independent gaps stand between "detect a Linux disk image" and "run the
//! filesystem-derivable analysis on it", both larger than a front-door tweak:
//!
//! 1. **The disk leg extracts no ext4/APFS/HFS+ files.** `issen-disk` only *detects*
//!    a non-NTFS filesystem (recording `ExtractionLimit::UnsupportedFilesystem`);
//!    it has no ext4 reader, so no Linux filesystem root is ever produced for the
//!    detectors to read.
//! 2. **`commands::analyse` re-parses a UAC directory layout**, not the case-DB
//!    artifact set, so it cannot be driven from disk-extracted artifacts without a
//!    detector-level refactor onto a filesystem-root seam.
//!
//! What IS wired here: the classification contract and a `run_dead_disk_analysis`
//! that runs the filesystem-derivable subset over any Linux filesystem root —
//! ready for the disk leg to call once (1) lands.

use std::path::Path;

/// Whether a given Linux indicator can be derived from a dead disk image, or
/// needs a live-response capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// Derivable from on-disk filesystem state alone — runs on a dead disk image.
    DeadDiskDerivable,
    /// Needs a live-response capture (running processes, `/proc`, netstat, loaded
    /// modules); absent from a dead disk image, so skipped there.
    LiveOnly,
}

/// One Linux analysis indicator and where its data comes from — the
/// graceful-degradation contract, as data.
#[derive(Debug, Clone, Copy)]
pub struct Indicator {
    /// Stable id (matches the analyse.rs section / rootkit `check` vocabulary).
    pub id: &'static str,
    /// One-line description of what the indicator looks at.
    pub what: &'static str,
    /// Dead-disk-derivable or live-only.
    pub availability: Availability,
}

/// The complete Linux indicator set with its live-vs-dead classification.
///
/// This is the single source of truth for "which indicators run on a dead disk
/// image vs which are skipped as live-only". A disk-image analysis runs the
/// [`Availability::DeadDiskDerivable`] rows and reports the
/// [`Availability::LiveOnly`] rows as unavailable.
pub const INDICATORS: &[Indicator] = &[
    // ── Filesystem-derivable — survive on a dead ext4/APFS/HFS+ image ────────
    Indicator {
        id: "ld_preload",
        what: "/etc/ld.so.preload library injection",
        availability: Availability::DeadDiskDerivable,
    },
    Indicator {
        id: "pam_credential_staging",
        what: "PAM-hook credential staging files in /tmp,/var/tmp,/dev/shm,/run",
        availability: Availability::DeadDiskDerivable,
    },
    // ── Live-only — need a live-response capture, absent from a dead image ────
    Indicator {
        id: "hidden_processes",
        what: "/proc vs ps hidden-process delta",
        availability: Availability::LiveOnly,
    },
    Indicator {
        id: "kernel_module",
        what: "loaded rootkit kernel modules (lsmod)",
        availability: Availability::LiveOnly,
    },
    Indicator {
        id: "kernel_taint",
        what: "/proc/sys/kernel/tainted flags",
        availability: Availability::LiveOnly,
    },
    Indicator {
        id: "env_injection",
        what: "LD_PRELOAD/LD_LIBRARY_PATH in the live process environment",
        availability: Availability::LiveOnly,
    },
    Indicator {
        id: "network",
        what: "established connections (ss/netstat)",
        availability: Availability::LiveOnly,
    },
    Indicator {
        id: "cpu_anomaly",
        what: "near-100% CPU with no visible process (top)",
        availability: Availability::LiveOnly,
    },
];

/// The dead-disk-derivable indicators (run on a Linux disk image).
#[must_use]
pub fn dead_disk_indicators() -> Vec<&'static Indicator> {
    INDICATORS
        .iter()
        .filter(|i| i.availability == Availability::DeadDiskDerivable)
        .collect()
}

/// The live-only indicators (skipped on a dead image, reported unavailable).
#[must_use]
pub fn live_only_indicators() -> Vec<&'static Indicator> {
    INDICATORS
        .iter()
        .filter(|i| i.availability == Availability::LiveOnly)
        .collect()
}

/// Run the **dead-disk-derivable** Linux analysis over a plain Linux filesystem
/// root (an extracted/mounted ext4/APFS/HFS+ image), rendering the achievable
/// rootkit/persistence findings and explicitly noting the live-only indicators
/// as unavailable for dead-disk evidence.
///
/// This never errors and never fabricates a live-only result: a dead image that
/// lacks the running-process/netstat data simply reports those indicators as
/// unavailable. `fs_root` is the filesystem root — `fs_root/etc/ld.so.preload`,
/// `fs_root/tmp`, etc. are read directly.
pub fn run_dead_disk_analysis(fs_root: &Path) {
    use colored::Colorize;
    use issen_parser_uac::parsers::rootkit::{scan_filesystem_rootkit_indicators, RootkitSeverity};

    println!(
        "{}",
        "┌─ LINUX FILESYSTEM ANALYSIS (dead-disk evidence) ───────".bold()
    );
    println!("│  Root : {}", fs_root.display());
    println!("│");

    let findings = scan_filesystem_rootkit_indicators(fs_root);
    if findings.is_empty() {
        println!("│  No filesystem-derivable rootkit/persistence indicators found.");
    } else {
        for f in &findings {
            let sev = match f.severity {
                RootkitSeverity::Critical => "CRITICAL".red().bold(),
                RootkitSeverity::Warning => "WARNING".yellow().bold(),
                RootkitSeverity::Info => "INFO".cyan(),
            };
            println!("│  [{sev}] {} — {}", f.check, f.evidence);
        }
    }
    println!("│");

    // Graceful degradation: name the live-only indicators as unavailable, so the
    // analyst sees WHAT could not be checked (and why), rather than a silent gap.
    println!(
        "│  {} (need live-response capture; absent from a dead disk image):",
        "Not available for dead-disk evidence".dimmed()
    );
    for ind in live_only_indicators() {
        println!("│    · {} — {}", ind.id, ind.what);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_indicator_is_classified_exactly_once() {
        // No indicator is both dead-disk and live-only; the two partitions cover
        // the whole set with no overlap.
        let dead = dead_disk_indicators().len();
        let live = live_only_indicators().len();
        assert_eq!(dead + live, INDICATORS.len());
        assert!(
            dead >= 2,
            "at least ld_preload + pam staging run on a dead disk"
        );
        assert!(live >= 5, "the live-response captures are live-only");
    }

    #[test]
    fn filesystem_indicators_are_dead_disk_derivable() {
        // The two indicators the filesystem scanner implements must be classified
        // dead-disk-derivable, or the stage would skip them on a disk image.
        for id in ["ld_preload", "pam_credential_staging"] {
            let ind = INDICATORS
                .iter()
                .find(|i| i.id == id)
                .expect("indicator present");
            assert_eq!(
                ind.availability,
                Availability::DeadDiskDerivable,
                "{id} must be dead-disk-derivable"
            );
        }
    }

    #[test]
    fn live_response_indicators_are_live_only() {
        // Running-process / netstat / lsmod / taint / env / cpu are NOT on a dead
        // image — they must be classified live-only so the disk path skips them.
        for id in [
            "hidden_processes",
            "kernel_module",
            "kernel_taint",
            "env_injection",
            "network",
            "cpu_anomaly",
        ] {
            let ind = INDICATORS
                .iter()
                .find(|i| i.id == id)
                .expect("indicator present");
            assert_eq!(
                ind.availability,
                Availability::LiveOnly,
                "{id} must be live-only"
            );
        }
    }

    #[test]
    fn dead_disk_analysis_flags_on_disk_ld_preload_without_erroring() {
        // A planted /etc/ld.so.preload rootkit lib is flagged, and the call does
        // not error on the ABSENT live-only artifacts (no lsmod, no /proc, etc.).
        let dir = tempfile::tempdir().expect("tmpdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(
            root.join("etc/ld.so.preload"),
            "/usr/local/lib/libjynx.so\n",
        )
        .unwrap();

        // Directly assert on the underlying scanner (run_dead_disk_analysis only
        // prints); the analysis wrapper reuses it.
        let findings = issen_parser_uac::parsers::rootkit::scan_filesystem_rootkit_indicators(root);
        assert!(findings.iter().any(|f| f.check == "ld_preload"));

        // The renderer must not panic on a dead image lacking live-only data.
        run_dead_disk_analysis(root);
    }

    #[test]
    fn dead_disk_analysis_on_clean_root_is_quiet_and_lists_unavailable() {
        // A clean Linux root: no findings, but the live-only indicators are still
        // enumerated as unavailable (graceful degradation, not a silent skip).
        let dir = tempfile::tempdir().expect("tmpdir");
        run_dead_disk_analysis(dir.path());
        assert!(!live_only_indicators().is_empty());
    }
}
