//! Browser type detection from file path / file name.

use std::path::Path;

/// Browser family classification.
#[derive(Debug, Clone, PartialEq)]
pub enum BrowserFamily {
    /// Chromium-based browsers: Chrome, Edge, Brave, Opera.
    Chromium,
    /// Mozilla Firefox.
    Firefox,
}

/// Detect the browser family from a file path.
///
/// Rules:
/// - File name is `"History"` (case-insensitive) AND any ancestor path
///   component contains `Chrome`, `Edge`, `Brave`, or `Opera` → `Chromium`
/// - File name is `"places.sqlite"` (case-insensitive) → `Firefox`
/// - Otherwise → `None`
pub fn detect_browser(path: &Path) -> Option<BrowserFamily> {
    todo!("implement detect_browser")
}
