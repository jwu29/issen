use anyhow::Result;
use opendal::Operator;

/// Build an OpenDAL [`Operator`] for the given URI, and return the relative path
/// within that backend.
///
/// Supported URI schemes: `mem`, `s3`, `gcs`, `azblob`, `webdav`, `http`, `https`, `file`.
/// Returns an error for unknown schemes.
pub fn operator_for_uri(uri: &str) -> Result<(Operator, String)> {
    todo!("implement operator_for_uri")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_uri_returns_ok_with_path() {
        let (_, path) = operator_for_uri("mem://bucket/key").expect("should succeed for mem://");
        assert_eq!(path, "bucket/key");
    }

    #[test]
    fn unknown_scheme_returns_err() {
        let result = operator_for_uri("bad://host/path");
        assert!(result.is_err(), "expected error for unknown scheme");
    }
}
