//! Network correlation: PCAP time-window filter, DNS tunneling heuristics, Zeek conn-log join.

use forensicnomicon::heuristics::evtx::{EID_SYSMON_NETWORK_CONNECT, EID_SYSMON_DNS_QUERY, SYSMON_CHANNEL};
use winevt_core::EvtxEvent;

/// A Zeek conn.log entry for correlation with Sysmon EID 3.
#[derive(Debug, Clone)]
pub struct ZeekConnEntry {
    pub ts_ns: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub bytes: u64,
}

/// Result of correlating a Sysmon network event with a Zeek conn entry.
#[derive(Debug, Clone)]
pub struct ZeekCorrelation {
    pub evtx_event: EvtxEvent,
    pub zeek_entry: Option<ZeekConnEntry>,
    pub matched: bool,
}

/// BPF-style filter string derived from Sysmon EID 3 events.
#[derive(Debug, Clone)]
pub struct PcapFilter {
    pub expression: String,
    pub start_ns: i64,
    pub end_ns: i64,
}

/// A DNS tunneling hit from Shannon-entropy analysis.
#[derive(Debug, Clone)]
pub struct DnsTunnelingHit {
    pub event: EvtxEvent,
    pub query_name: String,
    pub entropy: f64,
}

/// Extract PCAP time-window filter expressions from Sysmon EID 3 events.
///
/// Groups events into `window_secs`-wide buckets and produces one BPF filter per bucket.
pub fn pcap_filter_from_sysmon(events: &[EvtxEvent], window_secs: u64) -> Vec<PcapFilter> {
    use std::collections::HashMap;

    if window_secs == 0 { return vec![]; }
    let window_ns = (window_secs as i64) * 1_000_000_000;

    // Filter EID 3 (Sysmon network connect)
    let net_events: Vec<&EvtxEvent> = events
        .iter()
        .filter(|e| e.event_id == EID_SYSMON_NETWORK_CONNECT && e.channel == SYSMON_CHANNEL)
        .collect();

    if net_events.is_empty() { return vec![]; }

    let min_ts = net_events.iter().map(|e| e.timestamp_ns).min().unwrap_or(0);

    // Group into buckets
    let mut buckets: HashMap<i64, (i64, i64, Vec<String>)> = HashMap::new();
    for ev in &net_events {
        let bucket_key = ((ev.timestamp_ns - min_ts) / window_ns) * window_ns + min_ts;
        let entry = buckets.entry(bucket_key).or_insert((ev.timestamp_ns, ev.timestamp_ns, Vec::new()));
        entry.0 = entry.0.min(ev.timestamp_ns);
        entry.1 = entry.1.max(ev.timestamp_ns);
        if let (Some(ip), Some(port)) = (
            ev.data.get("DestinationIp"),
            ev.data.get("DestinationPort"),
        ) {
            let expr = format!("host {ip} and port {port}");
            if !entry.2.contains(&expr) {
                entry.2.push(expr);
            }
        }
    }

    let mut filters: Vec<PcapFilter> = buckets
        .into_values()
        .filter(|(_, _, exprs)| !exprs.is_empty())
        .map(|(start, end, exprs)| PcapFilter {
            expression: exprs.join(" or "),
            start_ns: start,
            end_ns: end,
        })
        .collect();

    filters.sort_by_key(|f| f.start_ns);
    filters
}

/// Compute Shannon entropy of a string (bits per symbol).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let len = s.len() as f64;
    let mut freq = [0usize; 256];
    for b in s.bytes() { freq[b as usize] += 1; }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Detect DNS tunneling candidates using Shannon entropy on the subdomain portion.
pub fn detect_dns_tunneling(events: &[EvtxEvent], entropy_threshold: f64) -> Vec<DnsTunnelingHit> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SYSMON_DNS_QUERY && e.channel == SYSMON_CHANNEL)
        .filter_map(|e| {
            let qname = e.data.get("QueryName")?;
            let subdomain = qname.split('.').next().unwrap_or(qname.as_str());
            let entropy = shannon_entropy(subdomain);
            if entropy >= entropy_threshold {
                Some(DnsTunnelingHit {
                    event: e.clone(),
                    query_name: qname.clone(),
                    entropy,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Correlate Sysmon EID 3 events with Zeek conn.log entries by (dst_ip, dst_port) within time_window_ns.
pub fn correlate_with_zeek(
    events: &[EvtxEvent],
    zeek: &[ZeekConnEntry],
    time_window_ns: i64,
) -> Vec<ZeekCorrelation> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SYSMON_NETWORK_CONNECT && e.channel == SYSMON_CHANNEL)
        .map(|ev| {
            let dst_ip = ev.data.get("DestinationIp").map(String::as_str).unwrap_or("");
            let dst_port: u16 = ev.data.get("DestinationPort")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0);

            let best = zeek.iter()
                .filter(|z| z.dst_ip == dst_ip && z.dst_port == dst_port)
                .filter(|z| (z.ts_ns - ev.timestamp_ns).abs() <= time_window_ns)
                .min_by_key(|z| (z.ts_ns - ev.timestamp_ns).unsigned_abs());

            if let Some(entry) = best {
                ZeekCorrelation {
                    evtx_event: ev.clone(),
                    zeek_entry: Some(entry.clone()),
                    matched: true,
                }
            } else {
                ZeekCorrelation {
                    evtx_event: ev.clone(),
                    zeek_entry: None,
                    matched: false,
                }
            }
        })
        .collect()
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
        EvtxEvent { event_id: 3, channel: "Microsoft-Windows-Sysmon/Operational".into(), timestamp_ns: ts, computer: "WS01".into(), user_sid: None, logon_id: None, process_id: None, thread_id: None, data }
    }

    fn sysmon_22(query: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("QueryName".into(), query.into());
        EvtxEvent { event_id: 22, channel: "Microsoft-Windows-Sysmon/Operational".into(), timestamp_ns: ts, computer: "WS01".into(), user_sid: None, logon_id: None, process_id: None, thread_id: None, data }
    }

    #[test]
    fn entropy_of_uniform_string_is_zero() {
        let e = shannon_entropy("aaaaaaaaaa");
        assert!(e.abs() < 0.001);
    }

    #[test]
    fn entropy_of_ab_string_is_one() {
        let e = shannon_entropy("ababababab");
        assert!((e - 1.0).abs() < 0.001, "got {e}");
    }

    #[test]
    fn entropy_of_base64_blob_is_high() {
        let e = shannon_entropy("aGVsbG93b3JsZHRlc3RkYXRh");
        assert!(e > 3.5, "got {e}");
    }

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn pcap_filter_empty_events_returns_empty() {
        assert!(pcap_filter_from_sysmon(&[], 60).is_empty());
    }

    #[test]
    fn pcap_filter_single_event_produces_one_filter() {
        let events = vec![sysmon_3("192.168.1.100", "4444", 1_000_000_000)];
        let filters = pcap_filter_from_sysmon(&events, 60);
        assert!(!filters.is_empty());
        assert!(filters[0].expression.contains("192.168.1.100"));
        assert!(filters[0].expression.contains("4444"));
    }

    #[test]
    fn pcap_filter_groups_by_time_window() {
        let ns = 1_000_000_000_i64;
        let events = vec![
            sysmon_3("1.1.1.1", "80", 0),
            sysmon_3("2.2.2.2", "443", 120 * ns),
        ];
        let filters = pcap_filter_from_sysmon(&events, 60);
        assert!(filters.len() >= 2);
    }

    #[test]
    fn dns_tunneling_empty_events() {
        assert!(detect_dns_tunneling(&[], 3.5).is_empty());
    }

    #[test]
    fn dns_tunneling_high_entropy_subdomain_flagged() {
        let events = vec![sysmon_22("aGVsbG93b3JsZHRlc3RkYXRh.evil-tunnel.com", 1_000_000_000)];
        let hits = detect_dns_tunneling(&events, 3.5);
        assert!(!hits.is_empty());
        assert!(hits[0].entropy > 3.5);
    }

    #[test]
    fn dns_tunneling_normal_domain_not_flagged() {
        let events = vec![sysmon_22("www.microsoft.com", 1_000_000_000)];
        assert!(detect_dns_tunneling(&events, 3.5).is_empty());
    }

    #[test]
    fn zeek_correlation_empty_events_returns_empty() {
        assert!(correlate_with_zeek(&[], &[], 5_000_000_000).is_empty());
    }

    #[test]
    fn zeek_correlation_matched_when_ip_port_and_time_align() {
        let ns = 1_000_000_000_i64;
        let events = vec![sysmon_3("10.0.0.100", "443", 100 * ns)];
        let zeek = vec![ZeekConnEntry { ts_ns: 100 * ns + 500_000_000, src_ip: "10.0.0.5".into(), dst_ip: "10.0.0.100".into(), dst_port: 443, proto: "tcp".into(), bytes: 1024 }];
        let result = correlate_with_zeek(&events, &zeek, 5 * ns);
        assert_eq!(result.len(), 1);
        assert!(result[0].matched);
    }

    #[test]
    fn zeek_correlation_unmatched_when_no_entry() {
        let events = vec![sysmon_3("99.99.99.99", "9999", 1_000_000_000)];
        let result = correlate_with_zeek(&events, &[], 5_000_000_000);
        assert_eq!(result.len(), 1);
        assert!(!result[0].matched);
    }
}
