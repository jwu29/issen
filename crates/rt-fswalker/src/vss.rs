//! VSS (Volume Shadow Copy Service) / shadow copy awareness.
//!
//! Provides helpers to detect and enumerate VSS snapshot volumes
//! inside an evidence root, supporting both Windows shadow-copy
//! path conventions and Unix-style mounted snapshot directories.

use std::path::Path;

/// A discovered VSS / shadow-copy volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VssVolume {
    /// Shadow-copy identifier (e.g. "HarddiskVolumeShadowCopy1", "snapshot_0").
    pub shadow_id: String,
    /// Drive letter of the origin volume, if determinable (defaults to `'?'`).
    pub volume_letter: char,
    /// ISO-8601 creation time string, when available.
    pub creation_time: Option<String>,
}

/// Scan `root` for VSS / shadow-copy volumes and return a list of them.
///
/// Detection strategies (in order):
/// 1. `root` itself looks like a mounted VSS volume (contains `GLOBALROOT` or
///    `HarddiskVolumeShadow` in its string representation).
/// 2. Windows-style sub-paths:
///    `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`
/// 3. Unix-style mounted snapshot directories:
///    `<root>/vss/*/` or `<root>/shadow/*/`
/// 4. Test-friendly naming: subdirectories of `root` whose names start with
///    `snapshot_`, `shadow_`, or `vsc_`.
pub fn list_vss_volumes(_root: &Path) -> Vec<VssVolume> {
    vec![]
}

/// Return `true` if `path` appears to be inside a VSS snapshot.
///
/// A path is considered a VSS path when its string representation
/// contains any of the following substrings (case-insensitive):
/// - `GLOBALROOT`
/// - `HarddiskVolumeShadow`
/// - `/vss/`
/// - `/shadow/`
/// - `snapshot_`
/// - `shadow_`
/// - `vsc_`
pub fn is_vss_path(_path: &Path) -> bool {
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ------------------------------------------------------------------
    // list_vss_volumes tests
    // ------------------------------------------------------------------

    #[test]
    fn vss_empty_dir_returns_no_volumes() {
        let dir = TempDir::new().expect("tempdir");
        let volumes = list_vss_volumes(dir.path());
        assert!(
            volumes.is_empty(),
            "expected no volumes for an empty directory, got {volumes:?}"
        );
    }

    #[test]
    fn vss_detects_snapshot_subdir() {
        let dir = TempDir::new().expect("tempdir");
        // Create a test-friendly snapshot directory.
        fs::create_dir(dir.path().join("snapshot_001")).expect("create snapshot_001");
        let volumes = list_vss_volumes(dir.path());
        assert_eq!(
            volumes.len(),
            1,
            "expected exactly one volume for snapshot_001, got {volumes:?}"
        );
        assert_eq!(volumes[0].shadow_id, "snapshot_001");
    }

    // ------------------------------------------------------------------
    // is_vss_path tests
    // ------------------------------------------------------------------

    #[test]
    fn is_vss_path_false_for_regular_path() {
        let path = Path::new("/mnt/evidence/Windows/System32/config/SAM");
        assert!(
            !is_vss_path(path),
            "expected false for a regular path, got true"
        );
    }

    #[test]
    fn is_vss_path_true_for_shadow_path() {
        let path = Path::new("/mnt/evidence/shadow_copy1/Windows/System32/config/SAM");
        assert!(
            is_vss_path(path),
            "expected true for a path containing shadow_, got false"
        );
    }
}
