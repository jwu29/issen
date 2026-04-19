/// Parse a Google Drive file ID from various input formats:
/// - `gdrive://<id>`
/// - `https://drive.google.com/file/d/<id>/view`
/// - `https://drive.google.com/open?id=<id>`
/// - Bare ID (no slashes, no scheme)
///
/// Returns `None` for empty strings, unrecognised URLs, or bare IDs containing slashes.
pub fn parse_file_id(input: &str) -> Option<String> {
    todo!("implement parse_file_id")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_none() {
        assert_eq!(parse_file_id(""), None);
    }

    #[test]
    fn gdrive_scheme_prefix() {
        assert_eq!(
            parse_file_id("gdrive://1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"),
            Some("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms".to_string())
        );
    }

    #[test]
    fn drive_google_com_file_d_url() {
        assert_eq!(
            parse_file_id(
                "https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/view"
            ),
            Some("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms".to_string())
        );
    }

    #[test]
    fn drive_google_com_open_id_url() {
        assert_eq!(
            parse_file_id(
                "https://drive.google.com/open?id=1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"
            ),
            Some("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms".to_string())
        );
    }

    #[test]
    fn bare_id_without_slash_is_some() {
        assert_eq!(
            parse_file_id("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"),
            Some("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms".to_string())
        );
    }

    #[test]
    fn bare_id_with_slash_is_none() {
        assert_eq!(parse_file_id("some/path/with/slashes"), None);
    }

    #[test]
    fn unrecognised_url_with_scheme_is_none() {
        assert_eq!(parse_file_id("ftp://example.com/file"), None);
        assert_eq!(parse_file_id("s3://bucket/key"), None);
    }
}
