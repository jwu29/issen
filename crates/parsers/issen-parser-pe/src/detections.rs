//! PE forensic detectors: suspicious imports, packed PE, AV exclusion strings, IOCs.

use crate::parser::PeInfo;

/// Category of PE-level detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeDetectionKind {
    /// Imports known process-injection or privilege-escalation APIs (T1055 / T1134).
    SuspiciousImport,
    /// One or more sections show packer/protector markers (T1027.002).
    PackedExecutable,
    /// String table contains AV exclusion registry/path fragments (T1562.001).
    AvExclusionStrings,
    /// String table or section names match known QWCrypt/RedCurl IOCs.
    QWCryptPeIoc,
}

/// A single detection result produced by a PE detector.
#[derive(Debug, Clone)]
pub struct PeDetection {
    pub kind: PeDetectionKind,
    pub mitre_technique_id: &'static str,
    pub tactic: &'static str,
    pub description: String,
    /// Evidence strings (import names, section names, matched fragments).
    pub evidence: Vec<String>,
}

/// Detect imports of known process-injection / privilege-escalation APIs (T1055 / T1134).
///
/// Returns one detection per suspicious import found.
pub fn detect_suspicious_imports(pe: &PeInfo) -> Vec<PeDetection> {
    todo!()
}

/// Detect packed or protected PE binaries (T1027.002).
///
/// Fires when any section has a name in [`PACKED_SECTION_NAMES`] or entropy ≥
/// [`PACKED_SECTION_THRESHOLD`].
pub fn detect_packed_pe(pe: &PeInfo) -> Vec<PeDetection> {
    todo!()
}

/// Detect AV exclusion path or registry fragments in the PE string table (T1562.001).
///
/// AV-tampering malware frequently embeds the exact registry paths it will write to
/// as string literals in its .data or .rdata section.
pub fn detect_av_exclusion_strings(pe: &PeInfo) -> Vec<PeDetection> {
    todo!()
}

/// Detect known QWCrypt / RedCurl PE IOC strings in the binary.
pub fn detect_qwcrypt_pe_iocs(pe: &PeInfo) -> Vec<PeDetection> {
    todo!()
}

/// Run all PE detectors and aggregate results.
pub fn detect_all(pe: &PeInfo) -> Vec<PeDetection> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{PeSection};

    fn make_pe(imports: Vec<&str>, sections: Vec<PeSection>, strings: Vec<&str>) -> PeInfo {
        PeInfo {
            machine: 0x8664,
            compile_timestamp: 0x5F00_0000,
            is_dll: false,
            imports: imports.into_iter().map(String::from).collect(),
            sections,
            strings: strings.into_iter().map(String::from).collect(),
        }
    }

    fn make_section(name: &str, entropy: f32, executable: bool) -> PeSection {
        PeSection {
            name: name.to_string(),
            virtual_size: 0x1000,
            raw_size: 0x1000,
            entropy,
            is_executable: executable,
            is_writable: false,
        }
    }

    // ── detect_suspicious_imports ─────────────────────────────────────────────

    #[test]
    fn suspicious_import_virtualalloc_detected() {
        let pe = make_pe(vec!["VirtualAlloc", "WriteProcessMemory"], vec![], vec![]);
        let hits = detect_suspicious_imports(&pe);
        assert!(!hits.is_empty(), "VirtualAlloc must trigger SuspiciousImport");
        assert!(hits.iter().all(|h| h.kind == PeDetectionKind::SuspiciousImport));
        assert_eq!(hits[0].mitre_technique_id, "T1055");
    }

    #[test]
    fn suspicious_import_benign_api_not_detected() {
        let pe = make_pe(
            vec!["CreateFile", "ReadFile", "WriteFile", "CloseHandle", "GetLastError"],
            vec![],
            vec![],
        );
        assert!(detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn suspicious_import_empty_pe_not_detected() {
        let pe = make_pe(vec![], vec![], vec![]);
        assert!(detect_suspicious_imports(&pe).is_empty());
    }

    #[test]
    fn suspicious_import_multiple_findings() {
        let pe = make_pe(
            vec!["VirtualAllocEx", "CreateRemoteThread", "WriteProcessMemory", "OpenProcess"],
            vec![],
            vec![],
        );
        let hits = detect_suspicious_imports(&pe);
        assert!(hits.len() >= 4, "all four suspicious imports should produce findings");
    }

    // ── detect_packed_pe ──────────────────────────────────────────────────────

    #[test]
    fn packed_pe_detected_on_upx0_section() {
        let pe = make_pe(
            vec![],
            vec![make_section("UPX0", 7.8, true), make_section("UPX1", 7.9, true)],
            vec![],
        );
        let hits = detect_packed_pe(&pe);
        assert!(!hits.is_empty(), "UPX section names must trigger PackedExecutable");
        assert!(hits.iter().any(|h| h.kind == PeDetectionKind::PackedExecutable));
    }

    #[test]
    fn packed_pe_detected_on_high_entropy() {
        let pe = make_pe(
            vec![],
            vec![make_section(".text", 7.5, true)],   // entropy > 6.8 threshold
            vec![],
        );
        let hits = detect_packed_pe(&pe);
        assert!(!hits.is_empty(), "section entropy 7.5 must trigger PackedExecutable");
    }

    #[test]
    fn packed_pe_normal_section_not_detected() {
        let pe = make_pe(
            vec![],
            vec![make_section(".text", 5.2, true), make_section(".data", 3.1, false)],
            vec![],
        );
        assert!(detect_packed_pe(&pe).is_empty());
    }

    #[test]
    fn packed_pe_empty_pe_not_detected() {
        let pe = make_pe(vec![], vec![], vec![]);
        assert!(detect_packed_pe(&pe).is_empty());
    }

    // ── detect_av_exclusion_strings ───────────────────────────────────────────

    #[test]
    fn av_exclusion_defender_path_detected() {
        let pe = make_pe(
            vec![],
            vec![],
            vec!["SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"],
        );
        let hits = detect_av_exclusion_strings(&pe);
        assert!(!hits.is_empty(), "Defender exclusion path must be detected");
        assert_eq!(hits[0].kind, PeDetectionKind::AvExclusionStrings);
        assert_eq!(hits[0].mitre_technique_id, "T1562.001");
    }

    #[test]
    fn av_exclusion_mpcmdrun_detected() {
        let pe = make_pe(vec![], vec![], vec!["MpCmdRun.exe -RemoveDynamicSignature"]);
        let hits = detect_av_exclusion_strings(&pe);
        assert!(!hits.is_empty(), "MpCmdRun pattern must trigger AV exclusion detection");
    }

    #[test]
    fn av_exclusion_benign_strings_not_detected() {
        let pe = make_pe(
            vec![],
            vec![],
            vec!["C:\\Windows\\System32\\notepad.exe", "Hello World", "error occurred"],
        );
        assert!(detect_av_exclusion_strings(&pe).is_empty());
    }

    #[test]
    fn av_exclusion_empty_pe_not_detected() {
        let pe = make_pe(vec![], vec![], vec![]);
        assert!(detect_av_exclusion_strings(&pe).is_empty());
    }

    // ── detect_qwcrypt_pe_iocs ────────────────────────────────────────────────

    #[test]
    fn qwcrypt_ioc_qwcrypt_extension_detected() {
        let pe = make_pe(vec![], vec![], vec!["encrypted file extension: .qwCrypt"]);
        let hits = detect_qwcrypt_pe_iocs(&pe);
        assert!(!hits.is_empty(), ".qwCrypt string must be detected as QWCrypt IOC");
        assert_eq!(hits[0].kind, PeDetectionKind::QWCryptPeIoc);
    }

    #[test]
    fn qwcrypt_ioc_workers_dev_detected() {
        let pe = make_pe(
            vec![],
            vec![],
            vec!["https://payload.workers.dev/stage2.dll"],
        );
        let hits = detect_qwcrypt_pe_iocs(&pe);
        assert!(!hits.is_empty(), "workers.dev C2 string must be detected");
    }

    #[test]
    fn qwcrypt_ioc_excludevm_flag_detected() {
        let pe = make_pe(vec![], vec![], vec!["--excludeVM GatewayVM"]);
        let hits = detect_qwcrypt_pe_iocs(&pe);
        assert!(!hits.is_empty(), "excludeVM CLI flag must be detected");
    }

    #[test]
    fn qwcrypt_ioc_benign_pe_not_detected() {
        let pe = make_pe(
            vec!["CreateFile", "ReadFile"],
            vec![make_section(".text", 4.0, true)],
            vec!["C:\\Program Files\\MyApp\\app.exe"],
        );
        assert!(detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    #[test]
    fn qwcrypt_ioc_empty_pe_not_detected() {
        let pe = make_pe(vec![], vec![], vec![]);
        assert!(detect_qwcrypt_pe_iocs(&pe).is_empty());
    }

    // ── detect_all ────────────────────────────────────────────────────────────

    #[test]
    fn detect_all_empty_pe_returns_empty() {
        let pe = make_pe(vec![], vec![], vec![]);
        assert!(detect_all(&pe).is_empty());
    }

    #[test]
    fn detect_all_aggregates_multiple_detectors() {
        let pe = make_pe(
            vec!["VirtualAlloc", "CreateRemoteThread"],
            vec![make_section("UPX0", 7.8, true)],
            vec!["Windows Defender\\Exclusions\\Paths"],
        );
        let hits = detect_all(&pe);
        assert!(hits.len() >= 2, "should aggregate suspicious imports + packed PE + AV exclusion");
    }
}
