//! Fish shell history parser (fish_history YAML-like format).

/// A single fish shell history entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FishHistoryEntry {
    pub command: String,
    pub when_unix: Option<i64>,
    pub paths: Vec<String>,
}

/// Parse fish history bytes into a list of entries.
pub fn parse_fish_history(_input: &[u8]) -> Vec<FishHistoryEntry> {
    todo!("implement parse_fish_history")
}
