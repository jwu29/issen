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
    let file_name = path.file_name()?.to_string_lossy();

    if file_name.eq_ignore_ascii_case("places.sqlite") {
        return Some(BrowserFamily::Firefox);
    }

    if file_name.eq_ignore_ascii_case("History") {
        // Check if any ancestor path component names a Chromium-family browser.
        let chromium_names = ["Chrome", "Edge", "Brave", "Opera"];
        let path_str = path.to_string_lossy();
        if chromium_names
            .iter()
            .any(|name| path_str.contains(name))
        {
            return Some(BrowserFamily::Chromium);
        }
    }

    None
}
