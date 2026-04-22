//! Parser for bash_history files.

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a bash_history file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files are
/// silently skipped (returns `Ok(vec![])`).
pub fn parse_bash_history(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    todo!("implement parse_bash_history")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use rt_core::timeline::event::EventType;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_bash_history(tmp.path(), "test-src").expect("parse_bash_history");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn missing_file_returns_empty_vec() {
        let events = parse_bash_history(Path::new("/nonexistent/.bash_history"), "test-src")
            .expect("missing file should return Ok(vec![])");
        assert!(events.is_empty());
    }

    #[test]
    fn timestamp_plus_command_emits_correct_ns() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        // Unix timestamp 1713171781 = 2024-04-15 07:03:01 UTC
        writeln!(tmp, "#1713171781").expect("write");
        writeln!(tmp, "ls -la").expect("write");
        tmp.flush().expect("flush");

        let events = parse_bash_history(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event");

        let ev = &events[0];
        // 1713171781 * 1_000_000_000
        assert_eq!(
            ev.timestamp_ns,
            1_713_171_781_i64 * 1_000_000_000,
            "timestamp_ns should match unix ts * 1e9"
        );
        assert_eq!(ev.event_type, EventType::ProcessExec);
        assert_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("ls -la"),
        );
    }

    #[test]
    fn command_without_timestamp_emits_event_with_zero_ns() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "whoami").expect("write");
        tmp.flush().expect("flush");

        let events = parse_bash_history(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event even without timestamp");

        let ev = &events[0];
        assert_eq!(
            ev.timestamp_ns, 0,
            "no preceding timestamp → timestamp_ns=0"
        );
        assert_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("whoami"),
        );
    }

    #[test]
    fn multiple_timestamped_commands() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "#1713171781").expect("write");
        writeln!(tmp, "ls -la").expect("write");
        writeln!(tmp, "#1713171790").expect("write");
        writeln!(tmp, "whoami").expect("write");
        writeln!(tmp, "#1713171800").expect("write");
        writeln!(tmp, "cat /etc/passwd").expect("write");
        tmp.flush().expect("flush");

        let events = parse_bash_history(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 3, "expected 3 events");

        assert_eq!(events[0].timestamp_ns, 1_713_171_781_i64 * 1_000_000_000);
        assert_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("ls -la")
        );
        assert_eq!(events[1].timestamp_ns, 1_713_171_790_i64 * 1_000_000_000);
        assert_eq!(events[2].timestamp_ns, 1_713_171_800_i64 * 1_000_000_000);
        assert_eq!(
            events[2].metadata.get("command").and_then(|v| v.as_str()),
            Some("cat /etc/passwd")
        );
    }
}
