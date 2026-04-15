//! Parse `memory_dump/output-sockstat` — Volatility 3 `linux.sockstat` TSV.
//!
//! When UAC collects a memory dump and Volatility is available, it may
//! produce `output-sockstat`: a tab-separated file where each row describes
//! a socket held open by a process, including hidden processes not visible
//! to userspace tools.
//!
//! Format (tab-separated, header row present):
//! ```text
//! NetNS  Process Name  PID  TID  FD  Sock Offset  Family  Type  Proto
//!        Source Addr   Source Port  Destination Addr  Destination Port
//!        State  Filter
//! ```

use serde::Serialize;

/// A single socket entry from Volatility `linux.sockstat` output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SockstatEntry {
    /// Process name as reported by the kernel (may differ from ps/comm).
    pub process_name: String,
    pub pid: u32,
    /// Thread ID (may equal PID for the main thread).
    pub tid: u32,
    pub family: String,
    pub proto: String,
    pub src_addr: String,
    pub src_port: Option<u16>,
    pub dst_addr: String,
    pub dst_port: Option<u16>,
    pub state: String,
}

/// Parse the content of `memory_dump/output-sockstat`.
///
/// Skips the header row and any lines that cannot be parsed.
#[must_use]
pub fn parse_mem_sockstat(content: &str) -> Vec<SockstatEntry> {
    todo!("parse_mem_sockstat not yet implemented")
}

/// Read and parse `memory_dump/output-sockstat` from a UAC collection root.
///
/// Returns an empty vec if the file is absent.
#[must_use]
pub fn read_mem_sockstat(root: &std::path::Path) -> Vec<SockstatEntry> {
    todo!("read_mem_sockstat not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> &'static str {
        "NetNS\tProcess Name\tPID\tTID\tFD\tSock Offset\tFamily\tType\tProto\tSource Addr\tSource Port\tDestination Addr\tDestination Port\tState\tFilter\n"
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(parse_mem_sockstat("").is_empty());
    }

    #[test]
    fn header_only_returns_empty() {
        assert!(parse_mem_sockstat(header()).is_empty());
    }

    #[test]
    fn parses_tcp_established_row() {
        let content = format!(
            "{}\
             4026531840\tsh\t939\t939\t0\t0x8c7cc4059300\tAF_INET\tSTREAM\tTCP\t192.168.4.22\t22\t192.168.4.35\t48411\tESTABLISHED\t-\n",
            header()
        );
        let entries = parse_mem_sockstat(&content);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.process_name, "sh");
        assert_eq!(e.pid, 939);
        assert_eq!(e.tid, 939);
        assert_eq!(e.proto, "TCP");
        assert_eq!(e.src_addr, "192.168.4.22");
        assert_eq!(e.src_port, Some(22));
        assert_eq!(e.dst_addr, "192.168.4.35");
        assert_eq!(e.dst_port, Some(48411));
        assert_eq!(e.state, "ESTABLISHED");
    }

    #[test]
    fn parses_listen_row_with_wildcard_dst() {
        let content = format!(
            "{}\
             4026531840\tssh\t975\t975\t4\t0x8c7cc404a900\tAF_INET6\tSTREAM\tTCP\t::1\t3333\t::\t0\tLISTEN\t-\n",
            header()
        );
        let entries = parse_mem_sockstat(&content);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.process_name, "ssh");
        assert_eq!(e.pid, 975);
        assert_eq!(e.src_port, Some(3333));
        assert_eq!(e.state, "LISTEN");
    }

    #[test]
    fn parses_miner_disguised_as_top() {
        // PID 977 names itself "top" but threads reveal libuv (XMRig).
        let content = format!(
            "{}\
             4026531840\ttop\t977\t977\t17\t0x8c7cc405c280\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n\
             4026531840\tlibuv-worker\t977\t978\t17\t0x8c7cc405c280\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n",
            header()
        );
        let entries = parse_mem_sockstat(&content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].process_name, "top");
        assert_eq!(entries[0].pid, 977);
        assert_eq!(entries[0].dst_port, Some(3333));
        assert_eq!(entries[1].process_name, "libuv-worker");
        assert_eq!(entries[1].pid, 977);
    }

    #[test]
    fn skips_malformed_lines() {
        let content = format!("{}\nnot\tenough\tfields\n", header());
        let entries = parse_mem_sockstat(&content);
        assert!(entries.is_empty());
    }

    #[test]
    fn read_mem_sockstat_missing_file_returns_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        assert!(read_mem_sockstat(dir.path()).is_empty());
    }

    #[test]
    fn read_mem_sockstat_reads_file() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let mem_dir = dir.path().join("memory_dump");
        std::fs::create_dir_all(&mem_dir).expect("mkdir");
        let content = format!(
            "{}\
             4026531840\ttop\t977\t977\t17\t0xABC\tAF_INET\tSTREAM\tTCP\t127.0.0.1\t59182\t127.0.0.1\t3333\tESTABLISHED\t-\n",
            header()
        );
        std::fs::write(mem_dir.join("output-sockstat"), content).expect("write");
        let result = read_mem_sockstat(dir.path());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 977);
    }
}
