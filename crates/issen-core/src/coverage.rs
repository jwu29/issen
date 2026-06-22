//! Run-coverage manifest — distinguishes "searched and found nothing" from
//! "never searched", so an empty result is never silently indistinguishable
//! from a clean input.
//!
//! This is the bootstrap-vs-miss discipline applied to the whole run: for every
//! artifact class the pipeline *can* handle (a registered parser declares it),
//! the manifest records whether anything was found and whether it parsed. A
//! class that was searched but absent is a *meaningful negative*; a class that
//! was never searched is a *coverage gap* — and the two must not look the same.

use std::collections::{HashMap, HashSet};

use crate::artifacts::ArtifactType;

/// What one artifact class's coverage means forensically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    /// Something of this class was discovered but no registered parser handles
    /// it — a coverage gap, not a clean negative.
    NotSearched,
    /// A parser searched for this class but nothing was found (a meaningful,
    /// reportable negative — "we looked, it isn't there").
    SearchedAbsent,
    /// Found on disk but nothing parsed (collection succeeded, parsing did not).
    FoundUnparsed,
    /// Found and parsed.
    Parsed,
}

/// One artifact class's coverage across a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageEntry {
    pub artifact_type: ArtifactType,
    /// A registered parser declares this class (the pipeline knows how to handle it).
    pub searched: bool,
    /// Count of artifacts of this class discovered/collected.
    pub found: usize,
    /// Count of units of this class successfully parsed.
    pub parsed: usize,
}

impl CoverageEntry {
    #[must_use]
    pub fn status(&self) -> CoverageStatus {
        match (self.searched, self.found, self.parsed) {
            (false, _, _) => CoverageStatus::NotSearched,
            (true, 0, _) => CoverageStatus::SearchedAbsent,
            (true, _, 0) => CoverageStatus::FoundUnparsed,
            (true, _, _) => CoverageStatus::Parsed,
        }
    }
}

/// Per-class coverage for one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageManifest {
    pub entries: Vec<CoverageEntry>,
}

impl CoverageManifest {
    /// Build from the searched classes (the registry's `supported_artifacts`
    /// union), the artifact types discovered, and the artifact types parsed.
    #[must_use]
    pub fn build(
        searched: &[ArtifactType],
        found: &[ArtifactType],
        parsed: &[ArtifactType],
    ) -> Self {
        let mut found_counts: HashMap<ArtifactType, usize> = HashMap::new();
        for &a in found {
            *found_counts.entry(a).or_default() += 1;
        }
        let mut parsed_counts: HashMap<ArtifactType, usize> = HashMap::new();
        for &a in parsed {
            *parsed_counts.entry(a).or_default() += 1;
        }

        let searched_set: HashSet<ArtifactType> = searched.iter().copied().collect();

        // Every searched class, plus any class discovered without a parser
        // (NotSearched — a coverage gap that must still be surfaced).
        let mut classes: Vec<ArtifactType> = searched.to_vec();
        for &a in found_counts.keys() {
            if !searched_set.contains(&a) {
                classes.push(a);
            }
        }
        // Deterministic order (fleet output discipline): stable by Debug token.
        classes.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        classes.dedup();

        let entries = classes
            .into_iter()
            .map(|artifact_type| CoverageEntry {
                artifact_type,
                searched: searched_set.contains(&artifact_type),
                found: found_counts.get(&artifact_type).copied().unwrap_or(0),
                parsed: parsed_counts.get(&artifact_type).copied().unwrap_or(0),
            })
            .collect();
        Self { entries }
    }

    #[must_use]
    pub fn entry(&self, artifact_type: ArtifactType) -> Option<&CoverageEntry> {
        self.entries
            .iter()
            .find(|e| e.artifact_type == artifact_type)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_searched_absent_from_found_unparsed_and_parsed() {
        let searched = [
            ArtifactType::Mft,
            ArtifactType::Prefetch,
            ArtifactType::Srum,
        ];
        let found = [ArtifactType::Mft, ArtifactType::Mft, ArtifactType::Prefetch];
        let parsed = [ArtifactType::Mft, ArtifactType::Mft];
        let m = CoverageManifest::build(&searched, &found, &parsed);

        let mft = m.entry(ArtifactType::Mft).expect("Mft entry");
        assert_eq!((mft.found, mft.parsed), (2, 2));
        assert_eq!(mft.status(), CoverageStatus::Parsed);

        let pf = m.entry(ArtifactType::Prefetch).expect("Prefetch entry");
        assert_eq!((pf.found, pf.parsed), (1, 0));
        assert_eq!(pf.status(), CoverageStatus::FoundUnparsed);

        // The load-bearing distinction: searched but absent (a real negative).
        let srum = m.entry(ArtifactType::Srum).expect("Srum entry");
        assert_eq!(srum.found, 0);
        assert_eq!(srum.status(), CoverageStatus::SearchedAbsent);

        // Never searched → absent from the manifest entirely (distinct from
        // searched-absent): you cannot report a clean negative for a gap.
        assert!(
            m.entry(ArtifactType::Lnk).is_none(),
            "Lnk was never searched — must not masquerade as searched-absent"
        );
    }

    #[test]
    fn discovered_class_with_no_parser_is_flagged_not_searched() {
        let searched = [ArtifactType::Mft];
        let found = [ArtifactType::Lnk];
        let m = CoverageManifest::build(&searched, &found, &[]);
        let lnk = m.entry(ArtifactType::Lnk).expect("Lnk discovered");
        assert!(!lnk.searched);
        assert_eq!(lnk.status(), CoverageStatus::NotSearched);
    }
}
