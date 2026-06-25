//! Real-dump **differential census** for the memf-windows netscan scanners
//! against the DFIR Madness "Stolen Szechuan Sauce" domain-controller memory
//! image (`citadeldc01.mem`, Windows Server 2012 R2, kernel build 9600).
//!
//! Where [`szechuan_netstat`](szechuan_netstat.rs) asserts the single verified
//! C2 connection (`coreupdater.exe -> 203.78.103.109:443`), this test reconciles
//! the **whole-image counts** memf recovers against an independent oracle —
//! Volatility 3 `windows.netscan` (v2.28.0). It is the committed home of the
//! census that previously lived only in an uncommitted scratch test.
//!
//! ## Oracle (Volatility 3 2.28.0 `windows.netscan` on this image)
//!
//! ```text
//! UDPv4 13095   UDPv6 6416                       -> UDP total 19511
//! TCPv4   81 (2 conn + 79 listening)
//! TCPv6   93 (49 conn + 44 listening)
//! TCP ESTABLISHED 35   CLOSED 16                 -> TCP "connections" 51
//! TCP LISTENING 123 (79 v4 + 44 v6)              -> listeners 123
//! ```
//!
//! memf splits the same population across three scanners, which map onto vol3's
//! proto x state breakdown as:
//!
//! | memf scanner            | vol3 equivalent                              | count |
//! |-------------------------|----------------------------------------------|-------|
//! | `scan_tcp_endpoints`    | TCP rows with State != LISTENING (EST+CLOSED)| 51    |
//! | `scan_udp_endpoints`    | UDPv4 + UDPv6                                 | 19511 |
//! | `scan_tcp_listeners`    | TCP rows with State == LISTENING             | 123   |
//!
//! The IPv4/IPv6 split is asserted too (TCP conn 2 v4 / 49 v6; listeners 79 v4 /
//! 44 v6; UDP 13095 v4 / 6416 v6).
//!
//! ## How the expected counts are obtained
//!
//! When `vol` (Volatility 3) is on `PATH`, the test runs `windows.netscan` on the
//! same dump at test time and derives every expected count from its CSV output —
//! a live differential, nothing hardcoded. When `vol` is absent, it falls back to
//! the documented oracle census above (a committed snapshot of the vol3 2.28.0
//! run), so the test still reconciles offline. The fallback constants and the
//! live derivation must agree; the table above is their provenance.
//!
//! `#[ignore]`d by default because it needs the 2 GB `citadeldc01.mem` extract,
//! which is gitignored (see `tests/data/README.md` / `docs/corpus-catalog.md`):
//!
//! ```bash
//! SZECHUAN_DC_MEM=/tmp/szechuan-extracted/citadeldc01.mem \
//!   cargo test -p issen-mem --test szechuan_netscan_census -- --ignored --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::process::Command;

use issen_mem::dispatch::build_reader;

/// One census of the netscan population, split exactly as the three memf
/// scanners and the vol3 proto x state breakdown both split it.
#[derive(Debug, PartialEq, Eq)]
struct Census {
    /// TCP rows that are NOT listening (ESTABLISHED + CLOSED), IPv4.
    tcp_conn_v4: usize,
    /// TCP rows that are NOT listening (ESTABLISHED + CLOSED), IPv6.
    tcp_conn_v6: usize,
    /// UDP rows, IPv4.
    udp_v4: usize,
    /// UDP rows, IPv6.
    udp_v6: usize,
    /// TCP rows in the LISTENING state, IPv4.
    tcp_listen_v4: usize,
    /// TCP rows in the LISTENING state, IPv6.
    tcp_listen_v6: usize,
}

impl Census {
    fn tcp_conn(&self) -> usize {
        self.tcp_conn_v4 + self.tcp_conn_v6
    }
    fn udp(&self) -> usize {
        self.udp_v4 + self.udp_v6
    }
    fn tcp_listen(&self) -> usize {
        self.tcp_listen_v4 + self.tcp_listen_v6
    }
}

/// The committed Volatility 3 2.28.0 `windows.netscan` census of this image
/// (provenance: the module doc-comment table). Used when `vol` is not on `PATH`.
const ORACLE_FALLBACK: Census = Census {
    tcp_conn_v4: 2,
    tcp_conn_v6: 49,
    udp_v4: 13095,
    udp_v6: 6416,
    tcp_listen_v4: 79,
    tcp_listen_v6: 44,
};

/// Locate `citadeldc01.mem` via `SZECHUAN_DC_MEM`, falling back to the in-repo
/// corpus path (relative to this crate's `tests/` directory).
fn citadel_dc_mem() -> Option<PathBuf> {
    if let Some(p) = std::env::var("SZECHUAN_DC_MEM").ok().map(PathBuf::from) {
        if p.exists() {
            return Some(p);
        }
    }
    let local = Path::new("../../tests/data/dfirmadness-szechuan-sauce/extracted/citadeldc01.mem");
    if local.exists() {
        Some(local.to_path_buf())
    } else {
        None
    }
}

/// Run Volatility 3 `windows.netscan` on `dump` and derive the census from its
/// CSV output. Returns `None` when `vol` is not installed or the run fails, so
/// the test can fall back to the committed oracle census.
fn vol3_census(dump: &Path) -> Option<Census> {
    let out = Command::new("vol")
        .args(["-q", "-r", "csv", "-f"])
        .arg(dump)
        .arg("windows.netscan")
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "vol windows.netscan exited {:?}; falling back to committed oracle",
            out.status.code()
        );
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let header = lines.next()?;
    let cols: Vec<&str> = header.split(',').collect();
    let proto_i = cols.iter().position(|c| *c == "Proto")?;
    let state_i = cols.iter().position(|c| *c == "State")?;

    let mut c = Census {
        tcp_conn_v4: 0,
        tcp_conn_v6: 0,
        udp_v4: 0,
        udp_v6: 0,
        tcp_listen_v4: 0,
        tcp_listen_v6: 0,
    };
    for line in lines {
        // CSV fields here are simple (no embedded commas in Proto/State); a plain
        // split is sufficient for the two columns this census reads.
        let f: Vec<&str> = line.split(',').collect();
        let (Some(proto), Some(state)) = (f.get(proto_i), f.get(state_i)) else {
            continue;
        };
        let v6 = proto.ends_with("v6");
        if proto.starts_with("TCP") {
            if *state == "LISTENING" {
                if v6 {
                    c.tcp_listen_v6 += 1;
                } else {
                    c.tcp_listen_v4 += 1;
                }
            } else if v6 {
                c.tcp_conn_v6 += 1;
            } else {
                c.tcp_conn_v4 += 1;
            }
        } else if proto.starts_with("UDP") {
            if v6 {
                c.udp_v6 += 1;
            } else {
                c.udp_v4 += 1;
            }
        }
    }
    Some(c)
}

/// Whole-image netscan census: memf's three scanners reconcile, count-for-count
/// and v4/v6-split-for-split, with Volatility 3 `windows.netscan`.
#[test]
#[ignore = "needs the 2 GB DFIR Madness citadeldc01.mem; set SZECHUAN_DC_MEM"]
fn szechuan_netscan_census_matches_volatility3() {
    let Some(dump) = citadel_dc_mem() else {
        eprintln!("citadeldc01.mem not found; skipping (set SZECHUAN_DC_MEM)");
        return;
    };
    let (_fmt, reader) = build_reader(&dump, None, None).expect("build reader from dump");

    // memf census.
    let tcp = memf_windows::network::scan_tcp_endpoints(&reader).expect("tcp endpoint scan");
    let udp = memf_windows::network::scan_udp_endpoints(&reader).expect("udp endpoint scan");
    let lst = memf_windows::network::scan_tcp_listeners(&reader).expect("tcp listener scan");

    let v6 = |p: &str| p.ends_with("v6");
    let memf = Census {
        tcp_conn_v4: tcp.iter().filter(|c| !v6(&c.protocol)).count(),
        tcp_conn_v6: tcp.iter().filter(|c| v6(&c.protocol)).count(),
        udp_v4: udp.iter().filter(|c| !v6(&c.protocol)).count(),
        udp_v6: udp.iter().filter(|c| v6(&c.protocol)).count(),
        tcp_listen_v4: lst.iter().filter(|c| !v6(&c.protocol)).count(),
        tcp_listen_v6: lst.iter().filter(|c| v6(&c.protocol)).count(),
    };

    // Oracle census: live vol3 when available, else the committed snapshot.
    let (oracle, source) = match vol3_census(&dump) {
        Some(c) => (c, "vol3 windows.netscan (live)"),
        None => (ORACLE_FALLBACK, "committed vol3 2.28.0 census (fallback)"),
    };

    eprintln!(
        "memf:   TCP-conn {} ({}v4/{}v6) | UDP {} ({}v4/{}v6) | listeners {} ({}v4/{}v6)",
        memf.tcp_conn(),
        memf.tcp_conn_v4,
        memf.tcp_conn_v6,
        memf.udp(),
        memf.udp_v4,
        memf.udp_v6,
        memf.tcp_listen(),
        memf.tcp_listen_v4,
        memf.tcp_listen_v6,
    );
    eprintln!(
        "oracle: TCP-conn {} ({}v4/{}v6) | UDP {} ({}v4/{}v6) | listeners {} ({}v4/{}v6)  [{source}]",
        oracle.tcp_conn(),
        oracle.tcp_conn_v4,
        oracle.tcp_conn_v6,
        oracle.udp(),
        oracle.udp_v4,
        oracle.udp_v6,
        oracle.tcp_listen(),
        oracle.tcp_listen_v4,
        oracle.tcp_listen_v6,
    );

    assert_eq!(
        memf, oracle,
        "memf netscan census diverges from {source}: memf={memf:?} oracle={oracle:?}"
    );
}
