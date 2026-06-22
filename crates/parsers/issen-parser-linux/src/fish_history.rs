//! Parser for fish shell history files (~/.local/share/fish/fish_history).
//!
//! Fish history format (YAML-like):
//!   - cmd: <command>
//!     when: <unix timestamp>
//!     paths:
//!       - <path>

use std::path::Path;

use chrono::Utc;
use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

fn ts_display(timestamp_ns: i64) -> String {
    if timestamp_ns != 0 {
        let secs = timestamp_ns / 1_000_000_000;
        #[allow(clippy::cast_sign_loss)]
        let nanos = (timestamp_ns % 1_000_000_000) as u32;
        chrono::DateTime::from_timestamp(secs, nanos).map_or_else(
            || timestamp_ns.to_string(),
            |dt: chrono::DateTime<Utc>| dt.to_rfc3339(),
        )
    } else {
        "1970-01-01T00:00:00Z".to_string()
    }
}

fn make_event(
    timestamp_ns: i64,
    artifact_path: &str,
    command: &str,
    paths: &[String],
    source_id: &str,
) -> TimelineEvent {
    let mut ev = TimelineEvent::new(
        timestamp_ns,
        ts_display(timestamp_ns),
        EventType::ProcessExec,
        ArtifactType::LoginHistory,
        artifact_path.to_string(),
        format!("Fish shell command: {command}"),
        source_id.to_string(),
    )
    .with_activity_category(issen_core::ActivityCategory::Execution)
    .with_metadata("command", serde_json::json!(command))
    .with_metadata("shell", serde_json::json!("fish"));

    if !paths.is_empty() {
        ev = ev.with_metadata("accessed_paths", serde_json::json!(paths));
    }
    ev
}

/// Parse a fish_history file at `path` and return [`TimelineEvent`]s.
pub fn parse_fish_history(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let content = match std::fs::read(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    Ok(parse_fish_history_bytes(
        &content,
        &path.to_string_lossy(),
        source_id,
    ))
}

/// Parse fish history from raw bytes (allows in-memory testing).
pub fn parse_fish_history_bytes(
    input: &[u8],
    artifact_path: &str,
    source_id: &str,
) -> Vec<TimelineEvent> {
    struct Entry {
        command: String,
        when_ns: i64,
        paths: Vec<String>,
    }

    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };

    let mut entries: Vec<Entry> = Vec::new();
    let mut current: Option<Entry> = None;
    let mut in_paths = false;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("- cmd:") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            in_paths = false;
            current = Some(Entry {
                command: rest.trim().to_string(),
                when_ns: 0,
                paths: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("  when:") {
            in_paths = false;
            if let Some(entry) = current.as_mut() {
                if let Ok(unix_secs) = rest.trim().parse::<i64>() {
                    entry.when_ns = unix_secs * 1_000_000_000;
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
        .into_iter()
        .map(|e| make_event(e.when_ns, artifact_path, &e.command, &e.paths, source_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_empty_file_returns_empty() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_fish_history(tmp.path(), "test").expect("parse");
        assert!(events.is_empty());
    }

    #[test]
    fn parse_single_command_with_timestamp() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        write!(tmp, "- cmd: ls -la\n  when: 1716000000\n").expect("write");
        tmp.flush().expect("flush");
        let events = parse_fish_history(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 1_716_000_000i64 * 1_000_000_000);
        assert_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("ls -la")
        );
        assert_eq!(
            events[0].metadata.get("shell").and_then(|v| v.as_str()),
            Some("fish")
        );
    }

    #[test]
    fn parse_command_without_timestamp_uses_zero() {
        let input = b"- cmd: whoami\n";
        let events = parse_fish_history_bytes(input, "/fake/fish_history", "src");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp_ns, 0);
    }

    #[test]
    fn parse_multiple_commands_ordered() {
        let input = b"- cmd: first\n  when: 100\n- cmd: second\n  when: 200\n";
        let events = parse_fish_history_bytes(input, "/fake", "src");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("first")
        );
        assert_eq!(
            events[1].metadata.get("command").and_then(|v| v.as_str()),
            Some("second")
        );
        assert!(events[0].timestamp_ns < events[1].timestamp_ns);
    }

    #[test]
    fn parse_paths_in_metadata() {
        let input = b"- cmd: cat /etc/shadow\n  when: 1716000100\n  paths:\n    - /etc/shadow\n";
        let events = parse_fish_history_bytes(input, "/fake", "src");
        assert_eq!(events.len(), 1);
        let paths = events[0]
            .metadata
            .get("accessed_paths")
            .expect("accessed_paths");
        assert!(paths
            .as_array()
            .is_some_and(|a| { a.iter().any(|v| v.as_str() == Some("/etc/shadow")) }));
    }

    #[test]
    fn missing_file_returns_ok_empty() {
        use std::path::PathBuf;
        let result = parse_fish_history(&PathBuf::from("/nonexistent/fish_history"), "src");
        assert!(result.is_ok());
        assert!(result.expect("ok").is_empty());
    }

    #[test]
    fn event_tagged_execution() {
        // A fish shell command is an Execution activity (CADET meaning axis).
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        write!(tmp, "- cmd: ls -la\n  when: 1716000000\n").expect("write");
        tmp.flush().expect("flush");
        let events = parse_fish_history(tmp.path(), "test-src").expect("parse");
        assert_eq!(
            events[0].activity_category,
            Some(issen_core::ActivityCategory::Execution)
        );
    }
}
