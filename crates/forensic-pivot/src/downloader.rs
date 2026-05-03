use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::feeds::{FeedSpec, SyncManifest};

const MANIFEST_FILE: &str = "manifest.json";

/// Serialize `manifest` to `<cache_dir>/manifest.json`.
///
/// # Errors
/// Returns an error if the file cannot be written or serialization fails.
pub fn save_manifest(manifest: &SyncManifest, cache_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(cache_dir)?;
    let path = cache_dir.join(MANIFEST_FILE);
    let json = serde_json::to_string_pretty(manifest)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load manifest from `<cache_dir>/manifest.json`.
/// Returns an empty `SyncManifest` if the file does not exist.
///
/// # Errors
/// Returns an error only for genuine I/O or parse failures (not missing file).
pub fn load_manifest(cache_dir: &Path) -> anyhow::Result<SyncManifest> {
    let path = cache_dir.join(MANIFEST_FILE);
    if !path.exists() {
        return Ok(SyncManifest {
            feeds: Vec::new(),
            updated_at: 0,
        });
    }
    let json = std::fs::read_to_string(path)?;
    let manifest: SyncManifest = serde_json::from_str(&json)?;
    Ok(manifest)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Return refs to feeds whose `last_synced` is older than `threshold_secs`
/// ago (or whose `last_synced` is `None`).
#[must_use]
pub fn stale_feeds(manifest: &SyncManifest, threshold_secs: u64) -> Vec<&FeedSpec> {
    let now = now_secs();
    manifest
        .feeds
        .iter()
        .filter(|f| match f.last_synced {
            None => true,
            Some(last) => now.saturating_sub(last) > threshold_secs,
        })
        .collect()
}

/// Create `<cache_dir>/<feed.name>/` if it does not exist; return the path.
///
/// # Errors
/// Returns an error if the directory cannot be created.
pub fn prepare_feed_cache(spec: &FeedSpec, cache_dir: &Path) -> anyhow::Result<PathBuf> {
    let feed_dir = cache_dir.join(&spec.name);
    std::fs::create_dir_all(&feed_dir)?;
    Ok(feed_dir)
}

/// Stub: will be implemented in Phase 5 with real HTTP.
///
/// # Errors
/// Currently always returns `Ok(())`. Phase 5 will return network errors.
#[allow(clippy::unnecessary_wraps)]
pub fn download_feed(_spec: &FeedSpec, _cache_dir: &Path) -> anyhow::Result<()> {
    Ok(())
}
