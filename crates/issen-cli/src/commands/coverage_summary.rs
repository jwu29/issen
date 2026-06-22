//! Humble-Object formatting of a run's [`CoverageManifest`] for the CLI run
//! summary. All the *decisions* (merging per-source coverage, counting per
//! status, listing the forensically meaningful negatives) live in these pure,
//! unit-tested functions; the command layer only prints what they return.

use std::collections::BTreeMap;

use issen_core::artifacts::ArtifactType;
use issen_core::coverage::{CoverageEntry, CoverageManifest, CoverageStatus};

/// Merge per-source coverage manifests into one run-wide manifest.
///
/// An artifact class is `searched` if *any* source searched it; `found` and
/// `parsed` counts sum across sources. Classes are emitted in a deterministic
/// order (by `Debug` token) so the summary is stable run-to-run.
#[must_use]
pub fn merge_coverage(_manifests: &[CoverageManifest]) -> CoverageManifest {
    // RED stub — real merge lands in the GREEN commit.
    CoverageManifest::default()
}

#[allow(dead_code)]
fn class_names(coverage: &CoverageManifest, status: CoverageStatus) -> Vec<String> {
    coverage
        .entries
        .iter()
        .filter(|e| e.status() == status)
        .map(|e| format!("{:?}", e.artifact_type))
        .collect()
}

/// Format a coverage manifest into a human-readable multi-line summary.
///
/// Line 1 is a count per status (Parsed / FoundUnparsed / SearchedAbsent /
/// NotSearched). Then, when present, the two forensically meaningful negatives
/// each get their own line: the classes we *searched and found absent* ("we
/// looked, it isn't there") and the classes *discovered with no parser* (a
/// coverage gap, not a clean negative).
#[must_use]
pub fn format_coverage_summary(_coverage: &CoverageManifest) -> String {
    // RED stub — real formatting lands in the GREEN commit.
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(
        searched: &[ArtifactType],
        found: &[ArtifactType],
        parsed: &[ArtifactType],
    ) -> CoverageManifest {
        CoverageManifest::build(searched, found, parsed)
    }

    #[test]
    fn format_reports_counts_per_status_and_lists_searched_absent() {
        // Mft: parsed; Prefetch: found-unparsed; Srum: searched-absent;
        // Lnk: discovered with no parser (not-searched gap).
        let m = manifest(
            &[
                ArtifactType::Mft,
                ArtifactType::Prefetch,
                ArtifactType::Srum,
            ],
            &[ArtifactType::Mft, ArtifactType::Prefetch, ArtifactType::Lnk],
            &[ArtifactType::Mft],
        );
        let s = format_coverage_summary(&m);

        assert!(s.contains("1 parsed"), "should count Mft as parsed: {s}");
        assert!(
            s.contains("1 found-unparsed"),
            "should count Prefetch as found-unparsed: {s}"
        );
        assert!(
            s.contains("1 searched-absent"),
            "should count Srum as searched-absent: {s}"
        );
        assert!(
            s.contains("1 not-searched"),
            "should count the parser-less Lnk as a not-searched gap: {s}"
        );
        // The load-bearing line: the searched-but-absent negative is named.
        assert!(
            s.contains("Searched, absent: Srum"),
            "must list Srum as searched-absent: {s}"
        );
        // The coverage gap (discovered, no parser) is named too.
        assert!(
            s.contains("No parser (gap):  Lnk"),
            "must list Lnk as a coverage gap: {s}"
        );
    }

    #[test]
    fn format_omits_negative_lines_when_everything_parsed() {
        let m = manifest(
            &[ArtifactType::Mft],
            &[ArtifactType::Mft],
            &[ArtifactType::Mft],
        );
        let s = format_coverage_summary(&m);
        assert!(s.contains("1 parsed"), "{s}");
        assert!(
            !s.contains("Searched, absent:"),
            "no searched-absent line when none are absent: {s}"
        );
        assert!(
            !s.contains("No parser (gap):"),
            "no gap line when every class has a parser: {s}"
        );
    }

    #[test]
    fn merge_sums_found_and_parsed_and_ors_searched_across_sources() {
        // Source A: searched Mft+Srum, found+parsed 1 Mft, Srum absent.
        let a = manifest(
            &[ArtifactType::Mft, ArtifactType::Srum],
            &[ArtifactType::Mft],
            &[ArtifactType::Mft],
        );
        // Source B: searched only Mft, found+parsed 2 Mft.
        let b = manifest(
            &[ArtifactType::Mft],
            &[ArtifactType::Mft, ArtifactType::Mft],
            &[ArtifactType::Mft, ArtifactType::Mft],
        );
        let merged = merge_coverage(&[a, b]);

        let mft = merged
            .entry(ArtifactType::Mft)
            .expect("Mft entry in merged manifest");
        assert_eq!(
            (mft.found, mft.parsed),
            (3, 3),
            "found/parsed sum across sources"
        );
        assert!(mft.searched, "searched is OR across sources");

        // Srum was searched by A only and absent everywhere -> still a reportable
        // negative in the merged manifest.
        let srum = merged
            .entry(ArtifactType::Srum)
            .expect("Srum entry in merged manifest");
        assert_eq!(srum.status(), CoverageStatus::SearchedAbsent);
    }
}
