//! Parser for Linux cron log files.

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse a cron log file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files and
/// unparseable lines are silently skipped (returns `Ok(vec![])`).
pub fn parse_cron_log(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    todo!("implement parse_cron_log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    use rt_core::timeline::event::EventType;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_cron_log(tmp.path(), "test-src").expect("parse_cron_log");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn cron_cmd_line_emits_process_start_with_user_and_command() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:00:01 hostname CRON[9999]: (root) CMD (run-parts /etc/cron.daily)"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_cron_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event for CRON CMD line");

        let ev = &events[0];
        assert_eq!(
            ev.event_type,
            EventType::ProcessExec,
            "should be ProcessExec"
        );
        assert_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("root"),
        );
        assert_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("run-parts /etc/cron.daily"),
        );
    }

    #[test]
    fn cron_cmd_line_alice_backup() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:05:00 hostname CRON[9998]: (alice) CMD (/home/alice/backup.sh)"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_cron_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1);

        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("alice"),
        );
        assert_eq!(
            ev.metadata.get("command").and_then(|v| v.as_str()),
            Some("/home/alice/backup.sh"),
        );
    }
}
