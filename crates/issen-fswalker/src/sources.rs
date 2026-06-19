//! Resolve input evidence paths into attributable sources for a unified timeline.
//!
//! A unified multi-source timeline tags every event with a per-source
//! `evidence_source_id` so two hosts' otherwise-identical events stay distinct
//! and attributable. This module turns the CLI's evidence paths into that set of
//! sources: it expands a directory of disk images into one source per image and
//! derives a **collision-resistant** id, so two `CDrive.E01` files under
//! different host folders never alias onto one id and silently merge.

use std::path::PathBuf;

/// One attributable evidence source: a path to ingest plus its stable id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSource {
    /// The path the ingest pipeline opens (a container file or a loose-artifact dir).
    pub path: PathBuf,
    /// The collision-resistant per-source id stamped onto every event from `path`.
    pub source_id: String,
}

/// Expand and resolve input paths into attributable evidence sources.
///
/// - A directory containing recognized disk-image containers expands to one
///   source per container; a directory with none is one source (loose artifacts).
/// - A file is one source.
///
/// Each source gets a collision-resistant `source_id`.
#[must_use]
pub fn resolve_evidence_sources(paths: &[PathBuf]) -> Vec<EvidenceSource> {
    // STUB (RED): one source per input path, stem-only id, no expansion.
    paths
        .iter()
        .map(|p| EvidenceSource {
            path: p.clone(),
            source_id: p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("source")
                .to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn same_stem_different_dirs_get_distinct_ids() {
        let tmp = tempdir().unwrap();
        let a = tmp.path().join("hostA");
        let b = tmp.path().join("hostB");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let fa = a.join("CDrive.E01");
        let fb = b.join("CDrive.E01");
        fs::write(&fa, b"x").unwrap();
        fs::write(&fb, b"x").unwrap();

        let srcs = resolve_evidence_sources(&[fa, fb]);
        assert_eq!(srcs.len(), 2);
        assert_ne!(
            srcs[0].source_id, srcs[1].source_id,
            "same stem in different dirs must get distinct source_ids (no silent merge)"
        );
        assert!(srcs.iter().all(|s| s.source_id.starts_with("CDrive")));
    }

    #[test]
    fn directory_of_containers_expands_to_one_source_each() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("img1.E01"), b"x").unwrap();
        fs::write(tmp.path().join("img2.e01"), b"x").unwrap();
        fs::write(tmp.path().join("notes.txt"), b"x").unwrap();

        let srcs = resolve_evidence_sources(&[tmp.path().to_path_buf()]);
        assert_eq!(
            srcs.len(),
            2,
            "a directory of containers expands to one source per disk image"
        );
    }

    #[test]
    fn loose_artifact_dir_is_single_source() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("$J"), b"x").unwrap(); // no container extension
        let srcs = resolve_evidence_sources(&[tmp.path().to_path_buf()]);
        assert_eq!(
            srcs.len(),
            1,
            "a directory with no containers is one (loose-artifact) source"
        );
    }
}
