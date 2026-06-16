//! COM-hijacking persistence parser for Issen (RED — implementation pending).

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
    fn can_parse_ntuser_hive() {
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_software_hive() {
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SOFTWARE"
        )));
    }

    #[test]
    fn can_parse_ntuser_lowercase() {
        assert!(ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/ntuser.dat"
        )));
    }

    #[test]
    fn cannot_parse_sam_hive() {
        assert!(!ComHijackParser::can_parse(&PathBuf::from("/evidence/SAM")));
    }

    #[test]
    fn cannot_parse_security_hive() {
        assert!(!ComHijackParser::can_parse(&PathBuf::from(
            "/evidence/SECURITY"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_com_hijacking(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_com_hijacking(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "NTUSER.DAT", "test").is_empty());
    }
}
