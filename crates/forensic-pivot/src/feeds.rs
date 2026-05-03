use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
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

/// Returns the cache directory for a named feed: `<cache_dir>/<name>`.
#[must_use]
pub fn cache_path_for_feed(name: &str, cache_dir: &Path) -> PathBuf {
    cache_dir.join(name)
}

/// Returns true when the feed has not been synced within `threshold_secs`.
/// A feed with `last_synced == None` is always considered stale.
#[must_use]
pub fn is_stale(spec: &FeedSpec, threshold_secs: u64) -> bool {
    let Some(last) = spec.last_synced else {
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(last) > threshold_secs
}
