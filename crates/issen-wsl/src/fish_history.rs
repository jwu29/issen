//! Fish shell history parser (fish_history YAML-like format).
//!
//! Format:
//!   - cmd: <command>
//!     when: <unix timestamp>
//!     paths:
//!       - <path>

/// A single fish shell history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FishHistoryEntry {
    pub command: String,
    pub when_unix: Option<i64>,
    pub paths: Vec<String>,
}

/// Parse fish history bytes into a list of entries.
pub fn parse_fish_history(input: &[u8]) -> Vec<FishHistoryEntry> {
    let text = match std::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut entries: Vec<FishHistoryEntry> = Vec::new();
    let mut current: Option<FishHistoryEntry> = None;
    let mut in_paths = false;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("- cmd:") {
            // Start a new entry, saving any previous one.
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            in_paths = false;
            current = Some(FishHistoryEntry {
                command: rest.trim().to_string(),
                when_unix: None,
                paths: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("  when:") {
            in_paths = false;
            if let Some(entry) = current.as_mut() {
                if let Ok(ts) = rest.trim().parse::<i64>() {
                    entry.when_unix = Some(ts);
                }
            }
        } else if line.trim_end() == "  paths:" {
            in_paths = true;
        } else if in_paths {
            if let Some(rest) = line.strip_prefix("    - ") {
                if let Some(entry) = current.as_mut() {
                    entry.paths.push(rest.trim().to_string());
                }
            } else if !line.starts_with(' ') {
                in_paths = false;
            }
        }
    }

    if let Some(entry) = current {
        entries.push(entry);
    }

    entries
}
