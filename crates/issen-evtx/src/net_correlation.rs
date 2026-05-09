//! Network correlation: PCAP time-window filter, DNS tunneling heuristics, Zeek conn-log join.

use winevt_core::EvtxEvent;

/// A Zeek conn.log entry for correlation with Sysmon EID 3.
#[derive(Debug, Clone)]
pub struct ZeekConnEntry {
    /// Start of connection in nanoseconds since epoch.
    pub ts_ns: i64,
    /// Source IP address.
    pub src_ip: String,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol (e.g. "tcp", "udp").
    pub proto: String,
    /// Total bytes transferred.
    pub bytes: u64,
}

/// Result of correlating a Sysmon network event with a Zeek conn entry.
#[derive(Debug, Clone)]
pub struct ZeekCorrelation {
    /// The Sysmon EID 3 event.
    pub evtx_event: EvtxEvent,
    /// Matched Zeek entry, if any.
    pub zeek_entry: Option<ZeekConnEntry>,
    /// True when a Zeek entry was found within the time window.
    pub matched: bool,
}

/// BPF-style filter string derived from Sysmon EID 3 events.
#[derive(Debug, Clone)]
pub struct PcapFilter {
    /// BPF filter expression.
    pub expression: String,
    /// Time window start (nanoseconds).
    pub start_ns: i64,
    /// Time window end (nanoseconds).
    pub end_ns: i64,
}

/// A DNS tunneling hit from Shannon-entropy analysis.
#[derive(Debug, Clone)]
pub struct DnsTunnelingHit {
    /// The DNS query event.
    pub event: EvtxEvent,
    /// The queried domain name.
    pub query_name: String,
    /// Shannon entropy of the subdomain portion.
    pub entropy: f64,
}

/// Extract PCAP time-window filter expressions from Sysmon EID 3 (network connect) events.
///
/// Groups events by time window (default: 60-second buckets) and produces
/// one BPF filter per bucket: `host <dst_ip> and port <dst_port>`.
pub fn pcap_filter_from_sysmon(events: &[EvtxEvent], window_secs: u64) -> Vec<PcapFilter> {
    todo!()
}

/// Compute Shannon entropy of a string (bits per symbol).
pub fn shannon_entropy(s: &str) -> f64 {
    todo!()
}

/// Detect DNS tunneling candidates using Shannon entropy on the subdomain portion.
///
/// Returns events where the leftmost label of `QueryName` has entropy >= `threshold`.
/// Default threshold: 3.5 bits/symbol (empirically separates human-readable from encoded).
pub fn detect_dns_tunneling(events: &[EvtxEvent], entropy_threshold: f64) -> Vec<DnsTunnelingHit> {
    todo!()
}

/// Correlate Sysmon EID 3 (network connect) events with Zeek conn.log entries.
///
/// Matches by (dst_ip, dst_port) within a configurable time window (default: 5 seconds).
pub fn correlate_with_zeek(
    events: &[EvtxEvent],
    zeek: &[ZeekConnEntry],
    time_window_ns: i64,
) -> Vec<ZeekCorrelation> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sysmon_3(dst_ip: &str, dst_port: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("DestinationIp".into(), dst_ip.into());
        data.insert("DestinationPort".into(), dst_port.into());
        data.insert("SourceIp".into(), "10.0.0.5".into());
        EvtxEvent {
            event_id: 3,
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn sysmon_22(query: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("QueryName".into(), query.into());
        EvtxEvent {
            event_id: 22,
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    // ── Shannon entropy ───────────────────────────────────────────────────────

    #[test]
    fn entropy_of_uniform_string_is_zero() {
        let e = shannon_entropy("aaaaaaaaaa");
        assert!(e.abs() < 0.001, "all-same chars should have ~0 entropy, got {e}");
    }

    #[test]
    fn entropy_of_ab_string_is_one() {
        let e = shannon_entropy("ababababab");
        assert!((e - 1.0).abs() < 0.001, "alternating 2 chars should have ~1.0 bits, got {e}");
    }

    #[test]
    fn entropy_of_base64_blob_is_high() {
        let e = shannon_entropy("aGVsbG93b3JsZHRlc3RkYXRh");
        assert!(e > 3.5, "base64-like string should have entropy >3.5, got {e}");
    }

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    // ── PCAP filter ───────────────────────────────────────────────────────────

    #[test]
    fn pcap_filter_empty_events_returns_empty() {
        let filters = pcap_filter_from_sysmon(&[], 60);
        assert!(filters.is_empty());
    }

    #[test]
    fn pcap_filter_single_event_produces_one_filter() {
        let events = vec![sysmon_3("192.168.1.100", "4444", 1_000_000_000)];
        let filters = pcap_filter_from_sysmon(&events, 60);
        assert!(!filters.is_empty(), "one event should produce at least one filter");
        assert!(
            filters[0].expression.contains("192.168.1.100"),
            "filter should mention the destination IP"
        );
        assert!(
            filters[0].expression.contains("4444"),
            "filter should mention the destination port"
        );
    }

    #[test]
    fn pcap_filter_groups_by_time_window() {
        let ns = 1_000_000_000_i64;
        let events = vec![
            sysmon_3("1.1.1.1", "80", 0),
            sysmon_3("2.2.2.2", "443", 120 * ns), // 2-minute gap → second window
        ];
        let filters = pcap_filter_from_sysmon(&events, 60);
        assert!(filters.len() >= 2, "events 2 minutes apart should be in different windows");
    }

    // ── DNS Tunneling ─────────────────────────────────────────────────────────

    #[test]
    fn dns_tunneling_empty_events() {
        assert!(detect_dns_tunneling(&[], 3.5).is_empty());
    }

    #[test]
    fn dns_tunneling_high_entropy_subdomain_flagged() {
        let events = vec![sysmon_22("aGVsbG93b3JsZHRlc3RkYXRh.evil-tunnel.com", 1_000_000_000)];
        let hits = detect_dns_tunneling(&events, 3.5);
        assert!(!hits.is_empty(), "base64-like subdomain should be flagged");
        assert!(hits[0].entropy > 3.5);
    }

    #[test]
    fn dns_tunneling_normal_domain_not_flagged() {
        let events = vec![sysmon_22("www.microsoft.com", 1_000_000_000)];
        let hits = detect_dns_tunneling(&events, 3.5);
        assert!(hits.is_empty(), "normal domain should not be flagged");
    }

    // ── Zeek correlation ──────────────────────────────────────────────────────

    #[test]
    fn zeek_correlation_empty_events_returns_empty() {
        let result = correlate_with_zeek(&[], &[], 5_000_000_000);
        assert!(result.is_empty());
    }

    #[test]
    fn zeek_correlation_matched_when_ip_port_and_time_align() {
        let ns = 1_000_000_000_i64;
        let events = vec![sysmon_3("10.0.0.100", "443", 100 * ns)];
        let zeek = vec![ZeekConnEntry {
            ts_ns: 100 * ns + 500_000_000, // 0.5s after
            src_ip: "10.0.0.5".into(),
            dst_ip: "10.0.0.100".into(),
            dst_port: 443,
            proto: "tcp".into(),
            bytes: 1024,
        }];
        let result = correlate_with_zeek(&events, &zeek, 5 * ns);
        assert_eq!(result.len(), 1);
        assert!(result[0].matched, "should match within 5-second window");
    }

    #[test]
    fn zeek_correlation_unmatched_when_no_entry() {
        let events = vec![sysmon_3("99.99.99.99", "9999", 1_000_000_000)];
        let result = correlate_with_zeek(&events, &[], 5_000_000_000);
        assert_eq!(result.len(), 1);
        assert!(!result[0].matched, "no Zeek entry should leave matched=false");
    }
}
