use anyhow::Result;

/// Fetch remote content at `uri` and return it as a UTF-8 string.
///
/// Works whether or not a Tokio runtime is already active.
pub fn fetch_remote_text(uri: &str) -> Result<String> {
    todo!("implement fetch_remote_text")
}
