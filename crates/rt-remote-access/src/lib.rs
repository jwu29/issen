//! Remote access detection crate — public scan API.
//!
//! Orchestrates the LOLRMM/custom rule engine and category scanners,
//! returning merged [`Finding`]s via a single [`scan()`] entry point.

pub mod aggregator;
pub mod model;
pub mod providers;
pub mod rules;
pub mod scanners;
pub mod store;

use std::path::PathBuf;

use crate::model::{Finding, RemoteAccessCategory};
use crate::providers::{ArtifactProvider, ProviderCapability};
use crate::rules::detection_rule::compile_lolrmm;
use crate::rules::evaluator::evaluate_all;
use crate::rules::lolrmm::load_lolrmm_directory;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a scan run.
#[derive(Debug, Clone, Default)]
pub struct ScanConfig {
    /// Directory containing LOLRMM YAML definition files.
    pub lolrmm_dir: Option<PathBuf>,
    /// Directory containing custom YAML detection rules.
    pub custom_rules_dir: Option<PathBuf>,
    /// Category filter — `None` means scan all categories.
    pub categories: Option<Vec<RemoteAccessCategory>>,
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// The output of a [`scan()`] invocation.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Merged findings (deduplicated per tool + category).
    pub findings: Vec<Finding>,
    /// Capabilities advertised by the provider.
    pub available_capabilities: Vec<ProviderCapability>,
    /// Categories that were actually scanned.
    pub categories_scanned: Vec<RemoteAccessCategory>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run a full remote-access scan against the given provider.
///
/// Three phases:
/// 1. **Rule engine** — load LOLRMM and/or custom YAML, compile to
///    [`DetectionRule`](rules::detection_rule::DetectionRule)s, evaluate.
/// 2. **Category scanners** — run each [`CategoryScanner`](scanners::CategoryScanner),
///    optionally filtered by `config.categories`.
/// 3. **Merge** — deduplicate findings via [`aggregator::merge_findings`].
pub fn scan(provider: &dyn ArtifactProvider, config: &ScanConfig) -> ScanResult {
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut categories_scanned: Vec<RemoteAccessCategory> = Vec::new();

    // ------------------------------------------------------------------
    // Phase 1: Rule engine (LOLRMM + custom YAML)
    // ------------------------------------------------------------------
    let rule_findings = run_rule_engine(provider, config);
    all_findings.extend(rule_findings);

    // ------------------------------------------------------------------
    // Phase 2: Category scanners
    // ------------------------------------------------------------------
    let scanners = scanners::all_scanners();
    for scanner in &scanners {
        let cat = scanner.category();

        // Apply category filter if configured.
        if let Some(ref allowed) = config.categories {
            if !allowed.contains(&cat) {
                continue;
            }
        }

        match scanner.scan(provider) {
            Ok(findings) => {
                if !categories_scanned.contains(&cat) {
                    categories_scanned.push(cat);
                }
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(error = %e, "category scanner failed");
            }
        }
    }

    // ------------------------------------------------------------------
    // Phase 3: Merge
    // ------------------------------------------------------------------
    let findings = aggregator::merge_findings(all_findings);
    let available_capabilities = provider.capabilities();

    ScanResult {
        findings,
        available_capabilities,
        categories_scanned,
    }
}

// ---------------------------------------------------------------------------
// Internal: rule engine
// ---------------------------------------------------------------------------

/// Load LOLRMM and custom YAML directories, compile rules, and evaluate.
fn run_rule_engine(provider: &dyn ArtifactProvider, config: &ScanConfig) -> Vec<Finding> {
    let mut rules = Vec::new();

    // LOLRMM directory
    if let Some(ref dir) = config.lolrmm_dir {
        if dir.exists() {
            match load_lolrmm_directory(dir) {
                Ok(defs) => {
                    for def in &defs {
                        let source = dir
                            .join(format!("{}.yaml", def.name.to_lowercase()))
                            .display()
                            .to_string();
                        rules.push(compile_lolrmm(def, &source));
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load LOLRMM directory");
                }
            }
        }
    }

    // Custom rules directory (same format)
    if let Some(ref dir) = config.custom_rules_dir {
        if dir.exists() {
            match load_lolrmm_directory(dir) {
                Ok(defs) => {
                    for def in &defs {
                        let source = dir
                            .join(format!("{}.yaml", def.name.to_lowercase()))
                            .display()
                            .to_string();
                        rules.push(compile_lolrmm(def, &source));
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load custom rules directory");
                }
            }
        }
    }

    if rules.is_empty() {
        return Vec::new();
    }

    evaluate_all(&rules, provider)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{MockArtifactProvider, ProviderCapability, RegistryEntry};

    #[test]
    fn test_scan_with_mock_provider() {
        // Mock with RDP enabled: fDenyTSConnections = 0
        let mut mock = MockArtifactProvider {
            caps: vec![
                ProviderCapability::RegistryKeys,
                ProviderCapability::EventLogs,
            ],
            ..MockArtifactProvider::default()
        };

        // The BuiltinRemoteScanner checks registry_values at this path
        // for fDenyTSConnections == "0".
        let ts_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server";
        mock.add_registry_value(
            ts_path,
            RegistryEntry {
                path: ts_path.into(),
                name: "fDenyTSConnections".into(),
                value: "0".into(),
                data_type: "REG_DWORD".into(),
                timestamp: None,
            },
        );

        let config = ScanConfig::default(); // no LOLRMM dir, scan all categories
        let result = scan(&mock, &config);

        // Should detect RDP as a finding.
        let rdp_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.tool_name == "RDP")
            .collect();
        assert!(
            !rdp_findings.is_empty(),
            "should detect RDP finding; got {:?}",
            result.findings
        );

        // Capabilities should be present.
        assert!(result
            .available_capabilities
            .contains(&ProviderCapability::RegistryKeys));

        // BuiltInRemoteAccess should be among scanned categories.
        assert!(
            result
                .categories_scanned
                .contains(&RemoteAccessCategory::BuiltInRemoteAccess),
            "BuiltInRemoteAccess should be in categories_scanned; got {:?}",
            result.categories_scanned
        );
    }

    #[test]
    fn test_scan_empty_provider() {
        let mock = MockArtifactProvider::default(); // no caps, no data
        let config = ScanConfig::default();
        let result = scan(&mock, &config);

        assert!(
            result.findings.is_empty(),
            "empty provider should produce no findings"
        );
        assert!(
            result.available_capabilities.is_empty(),
            "empty provider should have no capabilities"
        );
    }
}
