use anyhow::Result;
use opendal::{EntryMode, Operator, blocking, options};
use std::io;

/// List all non-directory entries under `prefix` in `op`.
///
/// For each entry, writes a tab-separated line `"<path>\t<size_in_bytes>\n"` to `out`.
/// Returns the total count of files written.
///
/// # Errors
/// Returns an error if listing or reading metadata fails.
pub fn walk_remote_prefix(
    op: &Operator,
    prefix: &str,
    out: &mut dyn io::Write,
) -> Result<usize> {
    todo!("implement walk_remote_prefix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::operator_for_uri;

    #[tokio::test]
    async fn walk_returns_count_and_correct_line() {
        let (op, _) = operator_for_uri("mem://walkbucket/ignored").expect("mem op");
        // Write a test file into the mem backend using the async operator.
        op.write("artifacts/sample.txt", b"hello walk\n".to_vec())
            .await
            .expect("write sample file");

        let mut out = Vec::<u8>::new();
        let count =
            walk_remote_prefix(&op, "artifacts/", &mut out).expect("walk should succeed");
        assert_eq!(count, 1, "expected exactly one file");
        let text = String::from_utf8(out).expect("valid utf-8");
        // Line format: "<path>\t<size>\n"
        assert!(
            text.contains('\t'),
            "output line must contain a tab separator"
        );
        assert!(
            text.trim_end().ends_with("11"),
            "size of b\"hello walk\\n\" (11 bytes) should be last field; got: {text:?}"
        );
    }
}
