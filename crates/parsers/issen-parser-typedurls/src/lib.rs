//! IE/Edge TypedURLs web-activity parser for Issen (RED — implementation pending).

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
        assert!(TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/C/Users/jdoe/NTUSER.DAT"
        )));
    }

    #[test]
    fn can_parse_ntuser_lowercase() {
        assert!(TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/ntuser.dat"
        )));
    }

    #[test]
    fn cannot_parse_software_hive() {
        assert!(!TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/SOFTWARE"
        )));
    }

    #[test]
    fn cannot_parse_system_hive() {
        assert!(!TypedUrlsParser::can_parse(&PathBuf::from(
            "/evidence/SYSTEM"
        )));
    }

    #[test]
    fn parse_nonexistent_returns_empty() {
        let result = parse_typedurls(Path::new("/nonexistent/NTUSER.DAT"), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_empty_hive_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let result = parse_typedurls(tmp.path(), "test");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn events_from_garbage_bytes_is_empty() {
        assert!(events_from_bytes(b"not-a-hive", "NTUSER.DAT", "test").is_empty());
    }

    #[test]
    fn iso8601_parses_to_timestamp_ns() {
        // The companion `TypedURLsTime` FILETIME is surfaced as ISO 8601 by the
        // decoder; the parser must convert it to a real `timestamp_ns`.
        let ns = iso8601_to_ns("2021-03-04T05:06:07Z").expect("valid ISO 8601");
        assert!(ns > 0);
    }
}
