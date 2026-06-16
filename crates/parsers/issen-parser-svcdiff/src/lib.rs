//! Windows service install/modify parser for Issen (RED — implementation pending).

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn can_parse_system_hive() {
        assert!(SvcDiffParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SYSTEM"
        )));
    }

    #[test]
    fn can_parse_system_lowercase() {
        assert!(SvcDiffParser::can_parse(&PathBuf::from("/evidence/system")));
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(!SvcDiffParser::can_parse(&PathBuf::from(
            "/evidence/SOFTWARE"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!SvcDiffParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_svcdiff(Path::new("/nonexistent/SYSTEM"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_svcdiff(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "SYSTEM", "test").is_empty());
    }
}
