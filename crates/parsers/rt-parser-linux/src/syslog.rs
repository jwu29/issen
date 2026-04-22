//! Parser for Linux syslog files.

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a syslog file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files and
/// unparseable lines are silently skipped (returns `Ok(vec![])`).
pub fn parse_syslog(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    todo!("implement parse_syslog")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use rt_core::timeline::event::EventType;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_syslog(tmp.path(), "test-src").expect("parse_syslog");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn missing_file_returns_empty_vec() {
        let events = parse_syslog(Path::new("/nonexistent/syslog"), "test-src")
            .expect("missing file should return Ok(vec![])");
        assert!(events.is_empty());
    }

    #[test]
    fn systemd_started_emits_process_start() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:02:00 hostname systemd[1]: Started OpenSSH Server Daemon."
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_syslog(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event");

        let ev = &events[0];
        assert_eq!(
            ev.event_type,
            EventType::ProcessExec,
            "Started lines should emit ProcessExec"
        );
        assert_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("systemd"),
            "process field should be systemd"
        );
    }

    #[test]
    fn generic_syslog_line_emits_event_with_message() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:00:00 hostname kernel: [12345.678] iptables: DROPPED: ..."
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_syslog(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event for kernel line");

        let ev = &events[0];
        assert!(
            ev.metadata.contains_key("message"),
            "metadata should have 'message' key"
        );
        assert_eq!(
            ev.metadata.get("process").and_then(|v| v.as_str()),
            Some("kernel"),
        );
    }
}
