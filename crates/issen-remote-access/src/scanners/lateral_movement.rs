use std::collections::HashMap;

use crate::model::{
    DetectionSource, Finding, HitArtifactType, RawArtifactHit, RemoteAccessCategory,
};
use crate::providers::{ArtifactProvider, EventLogQuery};
use crate::scanners::{CategoryScanner, ScanError};

/// Scanner for lateral movement tools: PsExec, WMI, and Kerberoasting.
///
/// Detects:
/// - **PsExec**: Event 7045 where `ServiceName` contains "PSEXESVC"
/// - **WMI**: Event 5857 from provider "Microsoft-Windows-WMI-Activity"
/// - **Kerberoasting / explicit-credential / NTLM**: EID 4648/4769/4776 via
///   `winevt_extract::lateral_movement()` when the provider exposes a Security
///   EVTX path; falls back to `event_log_search()` for EID 4769 RC4 only.
pub struct LateralMovementScanner;

impl LateralMovementScanner {
    /// Create a new `LateralMovementScanner`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan for PsExec usage via service installation events.
    ///
    /// Event 7045 (new service installed) where `ServiceName` contains
    /// "PSEXESVC" is a strong indicator of PsExec lateral movement.
    fn scan_psexec(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(7045),
            provider_name: Some("Service Control Manager".into()),
            log_file: Some("System".into()),
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let service_name = event
                    .data
                    .get("ServiceName")
                    .map(String::as_str)
                    .unwrap_or("");
                if service_name.to_uppercase().contains("PSEXESVC") {
                    let image_path = event.data.get("ImagePath").cloned().unwrap_or_default();
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "System".into(),
                        value: format!("PsExec service installed: {service_name} ({image_path})"),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "7045".into()),
                            ("service_name".into(), service_name.to_owned()),
                            ("image_path".into(), image_path),
                        ]),
                    });
                }
            }
        }

        hits
    }

    /// Scan for WMI-based lateral movement.
    ///
    /// Event 5857 from "Microsoft-Windows-WMI-Activity" indicates WMI
    /// provider operations, which are commonly abused for lateral movement.
    fn scan_wmi(&self, provider: &dyn ArtifactProvider) -> Vec<RawArtifactHit> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(5857),
            provider_name: Some("Microsoft-Windows-WMI-Activity".into()),
            log_file: None,
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let provider_name = event.data.get("ProviderName").cloned().unwrap_or_default();
                hits.push(RawArtifactHit {
                    artifact_type: HitArtifactType::EventLog,
                    source_path: event.log_file.clone(),
                    value: format!("WMI provider loaded: {provider_name}"),
                    timestamp: event.timestamp,
                    context: HashMap::from([
                        ("event_id".into(), "5857".into()),
                        ("provider_name".into(), provider_name),
                    ]),
                });
            }
        }

        hits
    }

    /// Extract lateral movement events from a Security EVTX file via winevt_extract.
    ///
    /// Returns grouped findings for EID 4648 (ExplicitCredentialLogon),
    /// EID 4769 RC4 non-machine-account (Kerberoasting), and EID 4776 (NtlmAuth).
    fn scan_lateral_movement_events(
        &self,
        provider: &dyn ArtifactProvider,
    ) -> Result<Vec<Finding>, ScanError> {
        let Some(path) = provider.evtx_path("Security") else {
            // Fallback: legacy event_log_search for EID 4769 RC4 only.
            return Ok(self.scan_kerberoasting_fallback(provider));
        };

        let events = winevt_extract::lateral_movement(&path)
            .map_err(|e| ScanError::Internal(e.to_string()))?;

        let mut explicit_hits: Vec<RawArtifactHit> = Vec::new();
        let mut kerb_hits: Vec<RawArtifactHit> = Vec::new();
        let mut ntlm_hits: Vec<RawArtifactHit> = Vec::new();

        for ev in &events {
            let ts_nanos = chrono::DateTime::parse_from_rfc3339(&ev.timestamp)
                .ok()
                .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0));

            match ev.event_id {
                4648 => {
                    let user = ev.source_user.as_deref().unwrap_or("-");
                    let target = ev.target_user.as_deref().unwrap_or("-");
                    let host = ev.target_host.as_deref().unwrap_or("-");
                    explicit_hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "Security".into(),
                        value: format!(
                            "Explicit credential logon: {user} → {target} @ {host}"
                        ),
                        timestamp: ts_nanos,
                        context: HashMap::from([
                            ("event_id".into(), "4648".into()),
                            ("source_user".into(), user.to_owned()),
                            ("target_user".into(), target.to_owned()),
                            ("target_host".into(), host.to_owned()),
                        ]),
                    });
                }
                4769 => {
                    // winevt_extract translates "0x17" → "RC4"
                    let enc = ev.encryption_type.as_deref().unwrap_or("");
                    let user = ev.source_user.as_deref().unwrap_or("");
                    if enc == "RC4" && !user.ends_with('$') {
                        let spn = ev.target_user.as_deref().unwrap_or("-");
                        kerb_hits.push(RawArtifactHit {
                            artifact_type: HitArtifactType::EventLog,
                            source_path: "Security".into(),
                            value: format!(
                                "Kerberoasting: RC4 ticket for {user} (SPN: {spn})"
                            ),
                            timestamp: ts_nanos,
                            context: HashMap::from([
                                ("event_id".into(), "4769".into()),
                                ("target_user".into(), user.to_owned()),
                                ("encryption_type".into(), "RC4".into()),
                                ("service_name".into(), spn.to_owned()),
                            ]),
                        });
                    }
                }
                4776 => {
                    let user = ev.source_user.as_deref().unwrap_or("-");
                    let host = ev.target_host.as_deref().unwrap_or("-");
                    ntlm_hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "Security".into(),
                        value: format!("NTLM auth attempt: {user} from {host}"),
                        timestamp: ts_nanos,
                        context: HashMap::from([
                            ("event_id".into(), "4776".into()),
                            ("source_user".into(), user.to_owned()),
                            ("target_host".into(), host.to_owned()),
                        ]),
                    });
                }
                _ => {}
            }
        }

        let mut findings = Vec::new();
        for (hits, tool_name) in [
            (explicit_hits, "ExplicitCredentialLogon"),
            (kerb_hits, "Kerberoasting"),
            (ntlm_hits, "NtlmAuth"),
        ] {
            if !hits.is_empty() {
                let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
                let last_seen = hits.iter().filter_map(|h| h.timestamp).max();
                findings.push(Finding {
                    id: uuid::Uuid::new_v4().to_string(),
                    tool_name: tool_name.into(),
                    category: RemoteAccessCategory::LateralMovement,
                    artifacts: hits,
                    first_seen,
                    last_seen,
                    detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
                });
            }
        }

        Ok(findings)
    }

    /// Fallback: detect Kerberoasting via event_log_search when no EVTX path is available.
    fn scan_kerberoasting_fallback(&self, provider: &dyn ArtifactProvider) -> Vec<Finding> {
        let mut hits = Vec::new();

        let query = EventLogQuery {
            event_id: Some(4769),
            provider_name: Some("Microsoft-Windows-Security-Auditing".into()),
            log_file: Some("Security".into()),
            keyword: None,
        };

        if let Ok(events) = provider.event_log_search(&query) {
            for event in &events {
                let enc_type = event
                    .data
                    .get("TicketEncryptionType")
                    .map(String::as_str)
                    .unwrap_or("");
                let target_user = event
                    .data
                    .get("TargetUserName")
                    .map(String::as_str)
                    .unwrap_or("");

                if enc_type == "0x17" && !target_user.ends_with('$') {
                    let service_name = event.data.get("ServiceName").cloned().unwrap_or_default();
                    hits.push(RawArtifactHit {
                        artifact_type: HitArtifactType::EventLog,
                        source_path: "Security".into(),
                        value: format!(
                            "Kerberoasting: RC4 ticket for {target_user} (SPN: {service_name})"
                        ),
                        timestamp: event.timestamp,
                        context: HashMap::from([
                            ("event_id".into(), "4769".into()),
                            ("target_user".into(), target_user.to_owned()),
                            ("encryption_type".into(), enc_type.to_owned()),
                            ("service_name".into(), service_name),
                        ]),
                    });
                }
            }
        }

        if hits.is_empty() {
            return vec![];
        }
        let first_seen = hits.iter().filter_map(|h| h.timestamp).min();
        let last_seen = hits.iter().filter_map(|h| h.timestamp).max();
        vec![Finding {
            id: uuid::Uuid::new_v4().to_string(),
            tool_name: "Kerberoasting".into(),
            category: RemoteAccessCategory::LateralMovement,
            artifacts: hits,
            first_seen,
            last_seen,
            detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
        }]
    }
}

impl Default for LateralMovementScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CategoryScanner for LateralMovementScanner {
    fn category(&self) -> RemoteAccessCategory {
        RemoteAccessCategory::LateralMovement
    }

    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError> {
        let mut findings = Vec::new();

        // PsExec (EID 7045) — not in winevt-extract, keep event_log_search path
        let psexec_hits = self.scan_psexec(provider);
        if !psexec_hits.is_empty() {
            let first_seen = psexec_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = psexec_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "PsExec".into(),
                category: RemoteAccessCategory::LateralMovement,
                artifacts: psexec_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
            });
        }

        // WMI (EID 5857) — keep event_log_search path
        let wmi_hits = self.scan_wmi(provider);
        if !wmi_hits.is_empty() {
            let first_seen = wmi_hits.iter().filter_map(|h| h.timestamp).min();
            let last_seen = wmi_hits.iter().filter_map(|h| h.timestamp).max();
            findings.push(Finding {
                id: uuid::Uuid::new_v4().to_string(),
                tool_name: "WMI".into(),
                category: RemoteAccessCategory::LateralMovement,
                artifacts: wmi_hits,
                first_seen,
                last_seen,
                detection_source: DetectionSource::CategoryScanner("lateral_movement".into()),
            });
        }

        // EID 4648/4769/4776 — delegate to winevt_extract when path available
        findings.extend(self.scan_lateral_movement_events(provider)?);

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{EventLogEntry, MockArtifactProvider, ProviderCapability};

    #[test]
    fn test_psexec_service_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 7045,
            provider_name: "Service Control Manager".into(),
            log_file: "System".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("ServiceName".into(), "PSEXESVC".into()),
                ("ImagePath".into(), r"C:\Windows\PSEXESVC.exe".into()),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "PsExec");
        assert_eq!(findings[0].category, RemoteAccessCategory::LateralMovement);
        assert_eq!(
            findings[0].detection_source,
            DetectionSource::CategoryScanner("lateral_movement".into())
        );
        assert!(!findings[0].artifacts.is_empty());
        assert_eq!(
            findings[0].artifacts[0].artifact_type,
            HitArtifactType::EventLog
        );
        assert!(findings[0].artifacts[0].value.contains("PSEXESVC"));
    }

    #[test]
    fn test_no_lateral_movement_found() {
        let mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "expected no findings on empty mock, got {}",
            findings.len()
        );
    }

    #[test]
    fn test_wmi_activity_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 5857,
            provider_name: "Microsoft-Windows-WMI-Activity".into(),
            log_file: "Microsoft-Windows-WMI-Activity/Operational".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([("ProviderName".into(), "WmiPerfClass".into())]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "WMI");
        assert!(findings[0].artifacts[0].value.contains("WmiPerfClass"));
    }

    #[test]
    fn test_kerberoasting_detected() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 4769,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("TicketEncryptionType".into(), "0x17".into()),
                ("TargetUserName".into(), "svc_sql".into()),
                ("ServiceName".into(), "MSSQLSvc/db01.corp.local:1433".into()),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool_name, "Kerberoasting");
        assert!(findings[0].artifacts[0].value.contains("svc_sql"));
    }

    #[test]
    fn test_kerberoasting_ignores_machine_accounts() {
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        // Machine account (ends with $) should be ignored
        mock.add_event_log(EventLogEntry {
            event_id: 4769,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("TicketEncryptionType".into(), "0x17".into()),
                ("TargetUserName".into(), "WORKSTATION01$".into()),
                ("ServiceName".into(), "krbtgt/CORP.LOCAL".into()),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        assert!(
            findings.is_empty(),
            "machine accounts should not trigger Kerberoasting detection"
        );
    }

    // ── winevt-extract delegation tests (RED: add_evtx_path not yet on MockArtifactProvider) ──

    #[test]
    fn lateral_movement_4648_detected_via_winevt_extract() {
        use std::path::PathBuf;
        // Corpus from sibling workspace; skip gracefully if absent.
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../winevt-forensic/tests/data/fox-it-danderspritz/post-Security.evtx",
        );
        if !corpus.exists() {
            return;
        }

        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        // add_evtx_path does not yet exist → compile error (RED state)
        mock.add_evtx_path("Security", corpus);

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");

        // post-Security.evtx contains 1 EID 4648 explicit-credential logon
        let lat = findings
            .iter()
            .find(|f| f.tool_name == "ExplicitCredentialLogon");
        assert!(
            lat.is_some(),
            "expected ExplicitCredentialLogon finding from EID 4648 in corpus, got: {:?}",
            findings
                .iter()
                .map(|f| f.tool_name.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(lat.unwrap().category, RemoteAccessCategory::LateralMovement);
    }

    #[test]
    fn kerberoasting_event_log_search_fallback_works_without_evtx_path() {
        // No evtx_path on provider → scanner must fall back to event_log_search.
        // Verifies backward-compatibility of the fallback path.
        let mut mock = MockArtifactProvider {
            caps: vec![ProviderCapability::EventLogs],
            ..MockArtifactProvider::default()
        };
        mock.add_event_log(EventLogEntry {
            event_id: 4769,
            provider_name: "Microsoft-Windows-Security-Auditing".into(),
            log_file: "Security".into(),
            timestamp: Some(1_700_000_000_000_000_000),
            data: HashMap::from([
                ("TicketEncryptionType".into(), "0x17".into()),
                ("TargetUserName".into(), "svc_backup".into()),
                (
                    "ServiceName".into(),
                    "backupSvc/server01.corp.local".into(),
                ),
            ]),
        });

        let scanner = LateralMovementScanner::new();
        let findings = scanner.scan(&mock).expect("scan should succeed");
        let kerb = findings.iter().find(|f| f.tool_name == "Kerberoasting");
        assert!(
            kerb.is_some(),
            "expected Kerberoasting finding via event_log_search fallback"
        );
        assert!(kerb.unwrap().artifacts[0].value.contains("svc_backup"));
    }
}
