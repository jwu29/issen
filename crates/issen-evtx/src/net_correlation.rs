//! Network correlation: PCAP time-window filter, DNS tunneling heuristics, Zeek conn-log join.

use std::collections::HashMap;

use forensicnomicon::heuristics::evtx::{EID_SYSMON_NETWORK_CONNECT, EID_SYSMON_DNS_QUERY, SYSMON_CHANNEL};
use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};
use winevt_core::{EvtxEvent, LogonSession};

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
            let dst_ip = ev.data.get("DestinationIp").map_or("", String::as_str);
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

/// Enrich `NetworkConnect` timeline events by joining on `metadata["logon_id"]`
/// against the session map.
///
/// For each event with `event_type == NetworkConnect` that carries a `logon_id`
/// matching a known session:
/// - Pushes `EntityRef::Session(logon_id)` onto `event.entity_refs`
/// - Adds `session_ip_mismatch` tag when `metadata["src_ip"]` differs from
///   `session.src_ip` — signals potential IP-spoofing or NAT-traversal anomaly
///
/// Non-network events and events without a `logon_id` metadata field are
/// left untouched.
pub fn enrich_network_events_with_sessions(
    events: &mut [TimelineEvent],
    sessions: &HashMap<u64, LogonSession>,
) {
    for event in events {
        if event.event_type != EventType::NetworkConnect {
            continue;
        }
        let Some(logon_id) = event.metadata.get("logon_id").and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let Some(session) = sessions.get(&logon_id) else {
            continue;
        };
        event.entity_refs.push(EntityRef::Session(logon_id));
        if let Some(session_ip) = &session.src_ip {
            let event_src_ip = event
                .metadata
                .get("src_ip")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !event_src_ip.is_empty() && event_src_ip != session_ip.as_str() {
                event.tags.push("session_ip_mismatch".into());
            }
        }
    }
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
        assert!(shannon_entropy("").abs() < f64::EPSILON);
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

    // ── enrich_network_events_with_sessions tests (Step 5 RED) ───────────────

    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};
    use winevt_core::LogonSession;

    fn make_network_event(logon_id: u64, src_ip: &str) -> TimelineEvent {
        TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::NetworkConnect,
            ArtifactType::EventLog,
            "Microsoft-Windows-Sysmon/Operational".to_string(),
            "NetworkConnect".to_string(),
            "evidence-001".to_string(),
        )
        .with_metadata("logon_id", serde_json::json!(logon_id))
        .with_metadata("src_ip", serde_json::json!(src_ip))
    }

    fn make_net_session(logon_id: u64, session_src_ip: Option<&str>) -> LogonSession {
        LogonSession {
            logon_id,
            logon_type: 3,
            username: "alice".to_string(),
            domain: "CORP".to_string(),
            src_ip: session_src_ip.map(std::string::ToString::to_string),
            logon_time_ns: 1_700_000_000_000_000_000,
            logoff_time_ns: None,
            duration_secs: None,
            processes: Vec::new(),
            is_orphaned: false,
        }
    }

    #[test]
    fn network_enrich_adds_session_entity_ref() {
        let mut events = vec![make_network_event(0x59b61, "10.0.0.5")];
        let mut sessions = std::collections::HashMap::new();
        sessions.insert(0x59b61_u64, make_net_session(0x59b61, Some("10.0.0.50")));

        enrich_network_events_with_sessions(&mut events, &sessions);

        assert!(
            events[0].entity_refs.contains(&EntityRef::Session(0x59b61)),
            "Session entity ref must be added for matching logon_id"
        );
    }

    #[test]
    fn network_enrich_tags_session_ip_mismatch_when_ips_differ() {
        let mut events = vec![make_network_event(0x59b61, "10.0.0.5")];
        let mut sessions = std::collections::HashMap::new();
        // session.src_ip differs from event's src_ip
        sessions.insert(0x59b61_u64, make_net_session(0x59b61, Some("192.168.1.50")));

        enrich_network_events_with_sessions(&mut events, &sessions);

        assert!(
            events[0].tags.iter().any(|t| t == "session_ip_mismatch"),
            "session_ip_mismatch tag expected when src IPs differ, got {:?}",
            events[0].tags
        );
    }

    #[test]
    fn network_enrich_no_mismatch_when_ips_same() {
        let mut events = vec![make_network_event(0x59b61, "10.0.0.5")];
        let mut sessions = std::collections::HashMap::new();
        // session.src_ip matches event src_ip
        sessions.insert(0x59b61_u64, make_net_session(0x59b61, Some("10.0.0.5")));

        enrich_network_events_with_sessions(&mut events, &sessions);

        assert!(
            !events[0].tags.iter().any(|t| t == "session_ip_mismatch"),
            "no session_ip_mismatch when IPs match, got {:?}",
            events[0].tags
        );
    }

    #[test]
    fn network_enrich_no_mismatch_when_session_has_no_src_ip() {
        let mut events = vec![make_network_event(0x59b61, "10.0.0.5")];
        let mut sessions = std::collections::HashMap::new();
        sessions.insert(0x59b61_u64, make_net_session(0x59b61, None));

        enrich_network_events_with_sessions(&mut events, &sessions);

        assert!(
            !events[0].tags.iter().any(|t| t == "session_ip_mismatch"),
            "no session_ip_mismatch when session has no src_ip"
        );
    }

    #[test]
    fn network_enrich_skips_non_network_events() {
        let event = TimelineEvent::new(
            1_700_000_000_000_000_000,
            "2023-11-14T22:13:20Z".to_string(),
            EventType::ProcessExec,
            ArtifactType::EventLog,
            "Security".to_string(),
            "ProcessExec".to_string(),
            "evidence-001".to_string(),
        )
        .with_metadata("logon_id", serde_json::json!(0x59b61_u64))
        .with_metadata("src_ip", serde_json::json!("10.0.0.5"));

        let original_refs = event.entity_refs.clone();
        let mut events = vec![event];
        let mut sessions = std::collections::HashMap::new();
        sessions.insert(0x59b61_u64, make_net_session(0x59b61, Some("192.168.1.50")));

        enrich_network_events_with_sessions(&mut events, &sessions);

        assert_eq!(events[0].entity_refs, original_refs, "non-network events must not be modified");
    }
}
