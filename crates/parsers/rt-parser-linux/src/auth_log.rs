//! Parser for Linux auth.log files.

use std::path::Path;

use rt_core::timeline::event::TimelineEvent;

/// Parse an auth.log file at `path` and return [`TimelineEvent`]s.
///
/// # Errors
/// Returns `Err` only on unexpected I/O failures. Missing files and
/// unparseable lines are silently skipped (returns `Ok(vec![])`).
pub fn parse_auth_log(_path: &Path, _source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    todo!("implement parse_auth_log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let events = parse_auth_log(tmp.path(), "test-src").expect("parse_auth_log");
        assert!(events.is_empty(), "empty file should produce no events");
    }

    #[test]
    fn missing_file_returns_empty_vec() {
        let events = parse_auth_log(Path::new("/nonexistent/path/auth.log"), "test-src")
            .expect("missing file should return Ok(vec![])");
        assert!(events.is_empty());
    }

    #[test]
    fn ssh_accepted_emits_event_with_user_and_ip() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:23:01 hostname sshd[1234]: Accepted publickey for root from 192.168.1.100 port 52341 ssh2"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event for ssh accepted line");

        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("root"),
            "user metadata should be 'root'"
        );
        assert_eq!(
            ev.metadata.get("source_ip").and_then(|v| v.as_str()),
            Some("192.168.1.100"),
            "source_ip should be parsed"
        );
        assert_eq!(
            ev.metadata.get("event_kind").and_then(|v| v.as_str()),
            Some("ssh_login"),
            "event_kind should be 'ssh_login'"
        );
    }

    #[test]
    fn sudo_line_emits_sudo_event() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:25:00 hostname sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event for sudo line");

        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("event_kind").and_then(|v| v.as_str()),
            Some("sudo"),
            "event_kind should be 'sudo'"
        );
        assert_eq!(
            ev.metadata.get("user").and_then(|v| v.as_str()),
            Some("alice"),
            "user should be alice"
        );
    }

    #[test]
    fn ssh_failed_emits_ssh_failed_event() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(
            tmp,
            "Apr 15 10:30:00 hostname sshd[1235]: Failed password for invalid user admin from 192.168.1.50 port 48811 ssh2"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        assert_eq!(events.len(), 1, "expected 1 event for failed password line");

        let ev = &events[0];
        assert_eq!(
            ev.metadata.get("event_kind").and_then(|v| v.as_str()),
            Some("ssh_failed"),
            "event_kind should be 'ssh_failed'"
        );
        assert_eq!(
            ev.metadata.get("source_ip").and_then(|v| v.as_str()),
            Some("192.168.1.50"),
        );
    }

    #[test]
    fn unparseable_lines_are_skipped() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(tmp, "this is not a valid auth.log line at all").expect("write");
        writeln!(tmp, "neither is this one!").expect("write");
        tmp.flush().expect("flush");

        let events = parse_auth_log(tmp.path(), "test-src").expect("parse");
        assert!(events.is_empty(), "garbage lines should yield no events");
    }
}
