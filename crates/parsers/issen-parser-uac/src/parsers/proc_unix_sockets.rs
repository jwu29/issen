//! Parse `/proc/<PID>/net/unix.txt` from UAC collections.
//!
//! UAC stores per-PID unix socket tables under
//! `live_response/process/proc/<PID>/net/unix.txt`.  Each line describes
//! one unix-domain socket held by the process — named filesystem paths
//! (e.g. `/run/systemd/journal/socket`), abstract names (prefixed with `@`
//! in UAC output), or unnamed sockets (no path column).
//!
//! This complements Volatility `AF_UNIX` rows in `output-sockstat`: the two
//! sources are redundant and can corroborate each other, but the proc file is
//! available even when no memory dump exists.

use serde::Serialize;

/// A single unix-domain socket entry from a per-PID `net/unix.txt` file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcUnixEntry {
    /// Filesystem path, abstract name (leading `@`), or empty for unnamed.
    pub path: String,
}

/// All unix-domain sockets observed for one PID.
#[derive(Debug, Clone, Serialize)]
pub struct PidUnixSockets {
    pub pid: u32,
    pub entries: Vec<ProcUnixEntry>,
}

/// Parse the content of a single `proc/<PID>/net/unix.txt` file.
///
/// Skips the header row (`Num  RefCount  Protocol  …`) and any line
/// that cannot be parsed.  Entries with no path column produce an entry
/// with `path = ""`.
#[must_use]
pub fn parse_proc_unix(content: &str) -> Vec<ProcUnixEntry> {
    todo!("RED: not yet implemented")
}

/// Walk `live_response/process/proc/*/net/unix.txt` under `root` and return
/// one `PidUnixSockets` per directory that contains such a file.
#[must_use]
pub fn read_all_proc_unix(root: &std::path::Path) -> Vec<PidUnixSockets> {
    todo!("RED: not yet implemented")
}

/// Return the distinct named paths from a `PidUnixSockets` collection
/// for a given PID.  Skips empty paths and abstract-socket names.
#[must_use]
pub fn named_paths_for_pid(all: &[PidUnixSockets], pid: u32) -> Vec<String> {
    todo!("RED: not yet implemented")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_proc_unix ───────────────────────────────────────────────────────

    #[test]
    fn parse_empty_returns_empty() {
        assert!(parse_proc_unix("").is_empty());
    }

    #[test]
    fn parse_header_only_returns_empty() {
        let header = "Num       RefCount Protocol Flags    Type St Inode Path\n";
        assert!(parse_proc_unix(header).is_empty());
    }

    #[test]
    fn parse_named_socket() {
        let content = "\
Num       RefCount Protocol Flags    Type St Inode Path
ffffffff80001234: 00000002 00000000 00010000 0001 03 12345 /run/systemd/journal/socket\n";
        let entries = parse_proc_unix(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/run/systemd/journal/socket");
    }

    #[test]
    fn parse_abstract_socket() {
        // UAC renders the null-byte prefix of abstract sockets as '@'.
        let content = "\
Num       RefCount Protocol Flags    Type St Inode Path
ffffffff80001235: 00000001 00000000 00010000 0005 01 12346 @/tmp/.X11-unix/X0\n";
        let entries = parse_proc_unix(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "@/tmp/.X11-unix/X0");
    }

    #[test]
    fn parse_unnamed_socket_produces_empty_path() {
        // Unnamed sockets have only 7 whitespace-separated fields (no path column).
        let content = "\
Num       RefCount Protocol Flags    Type St Inode Path
ffffffff80001236: 00000001 00000000 00000000 0001 00 12347\n";
        let entries = parse_proc_unix(content);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "");
    }

    #[test]
    fn parse_multiple_entries() {
        let content = "\
Num       RefCount Protocol Flags    Type St Inode Path
ffffffff80001234: 00000002 00000000 00010000 0001 03 12345 /run/systemd/journal/socket
ffffffff80001235: 00000002 00000000 00010000 0001 03 12346 /run/dbus/system_bus_socket
ffffffff80001236: 00000003 00000000 00010000 0001 03 12347 /run/user/1000/pipewire-0\n";
        let entries = parse_proc_unix(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].path, "/run/systemd/journal/socket");
        assert_eq!(entries[1].path, "/run/dbus/system_bus_socket");
        assert_eq!(entries[2].path, "/run/user/1000/pipewire-0");
    }

    #[test]
    fn parse_skips_malformed_lines() {
        // Lines with fewer than 7 fields are silently dropped.
        let content = "\
Num       RefCount Protocol Flags    Type St Inode Path
short line\n";
        assert!(parse_proc_unix(content).is_empty());
    }

    // ── read_all_proc_unix ────────────────────────────────────────────────────

    #[test]
    fn read_all_missing_proc_dir_returns_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(read_all_proc_unix(dir.path()).is_empty());
    }

    #[test]
    fn read_all_reads_pid_directory() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let unix_path = dir.path()
            .join("live_response/process/proc/977/net/unix.txt");
        std::fs::create_dir_all(unix_path.parent().unwrap()).expect("mkdir");
        std::fs::write(
            &unix_path,
            "Num       RefCount Protocol Flags    Type St Inode Path\n\
             ffffffff80001234: 00000002 00000000 00010000 0001 03 12345 /run/systemd/journal/socket\n\
             ffffffff80001235: 00000002 00000000 00010000 0001 03 12346 /run/dbus/system_bus_socket\n",
        ).expect("write");

        let result = read_all_proc_unix(dir.path());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 977);
        assert_eq!(result[0].entries.len(), 2);
    }

    #[test]
    fn read_all_handles_multiple_pids() {
        let dir = tempfile::tempdir().expect("tmpdir");
        for pid in [975u32, 977] {
            let path = dir.path()
                .join(format!("live_response/process/proc/{pid}/net/unix.txt"));
            std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
            std::fs::write(
                &path,
                format!(
                    "Num       RefCount Protocol Flags    Type St Inode Path\n\
                     ffffffff80001234: 00000002 00000000 00010000 0001 03 12345 /run/pid-{pid}-socket\n"
                ),
            ).expect("write");
        }
        let mut result = read_all_proc_unix(dir.path());
        result.sort_by_key(|r| r.pid);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].pid, 975);
        assert_eq!(result[1].pid, 977);
    }

    // ── named_paths_for_pid ───────────────────────────────────────────────────

    #[test]
    fn named_paths_skips_abstract_and_empty() {
        let all = vec![PidUnixSockets {
            pid: 977,
            entries: vec![
                ProcUnixEntry { path: "/run/systemd/journal/socket".into() },
                ProcUnixEntry { path: "@abstract".into() },
                ProcUnixEntry { path: "".into() },
            ],
        }];
        let paths = named_paths_for_pid(&all, 977);
        assert_eq!(paths, vec!["/run/systemd/journal/socket".to_string()]);
    }

    #[test]
    fn named_paths_unknown_pid_returns_empty() {
        let all: Vec<PidUnixSockets> = vec![];
        assert!(named_paths_for_pid(&all, 977).is_empty());
    }
}
