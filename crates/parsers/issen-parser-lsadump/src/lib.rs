//! LSA / DCC2 cached-credential slot parser for Issen (RED — implementation pending).

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
    fn can_parse_security_hive() {
        assert!(LsaDumpParser::can_parse(&PathBuf::from(
            "/evidence/C/Windows/System32/config/SECURITY"
        )));
    }

    #[test]
    fn can_parse_security_lowercase() {
        assert!(LsaDumpParser::can_parse(&PathBuf::from(
            "/evidence/security"
        )));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!LsaDumpParser::can_parse(&PathBuf::from("/evidence/SYSTEM")));
    }

    #[test]
    fn cannot_parse_ntuser_hive() {
        assert!(!LsaDumpParser::can_parse(&PathBuf::from(
            "/evidence/NTUSER.DAT"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_lsadump(Path::new("/nonexistent/SECURITY"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_lsadump(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "SECURITY", "test").is_empty());
    }
}
