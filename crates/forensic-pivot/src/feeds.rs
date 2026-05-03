// RED: stub — types declared but is_stale always returns false
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FeedKind {
    Sigma,
    Yara,
    Suricata,
    Zeek,
    Misp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSpec {
    pub name: String,
    pub url: String,
    pub kind: FeedKind,
    pub last_synced: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncManifest {
    pub feeds: Vec<FeedSpec>,
    pub updated_at: u64,
}

/// Returns the cache directory for a named feed.
/// RED stub: returns an empty path — tests will fail.
pub fn cache_path_for_feed(name: &str, cache_dir: &Path) -> PathBuf {
    let _ = name;
    let _ = cache_dir;
    PathBuf::new()
}

/// Returns true when the feed has not been synced within `threshold_secs`.
/// RED stub: always returns false — tests will fail.
pub fn is_stale(spec: &FeedSpec, threshold_secs: u64) -> bool {
    let _ = spec;
    let _ = threshold_secs;
    false
}
