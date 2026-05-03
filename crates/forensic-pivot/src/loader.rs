use std::path::Path;

use serde::Deserialize as _;

use crate::feeds::{FeedKind, FeedSpec};
use crate::rule::PivotRule;

// ---------------------------------------------------------------------------
// Bundled rules — compiled into the binary via include_str!
// ---------------------------------------------------------------------------

const RULE_001: &str = include_str!("../rules/001-xmrig-miner.yml");
const RULE_002: &str = include_str!("../rules/002-stratum-port.yml");
const RULE_003: &str = include_str!("../rules/003-ld-preload-rootkit.yml");

/// Parse a YAML string (one or more `---`-separated documents) into rules.
///
/// # Errors
/// Returns an error if the string is not valid YAML or if any document
/// cannot be deserialized into a [`PivotRule`].
pub fn load_rules_from_yaml_str(yaml: &str) -> anyhow::Result<Vec<PivotRule>> {
    let mut rules = Vec::new();
    for doc in serde_yaml::Deserializer::from_str(yaml) {
        let rule = PivotRule::deserialize(doc)?;
        rules.push(rule);
    }
    Ok(rules)
}

/// Walk `dir` for `*.yml` / `*.yaml` files and load rules from each.
/// Never fails — directories that do not exist return empty; bad files are
/// silently skipped.
#[must_use]
pub fn load_rules_from_dir(dir: &Path) -> Vec<PivotRule> {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut rules = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(mut parsed) = load_rules_from_yaml_str(&content) {
            rules.append(&mut parsed);
        }
    }
    rules
}

/// Return the default threat intelligence feed registry.
///
/// All feeds have `last_synced = None` (never synced) so they will be
/// treated as stale by [`crate::downloader::stale_feeds`] on first run.
#[must_use]
pub fn default_feeds() -> Vec<FeedSpec> {
    vec![
        FeedSpec {
            name: "sigma-rules".to_string(),
            url: "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip".to_string(),
            kind: FeedKind::Sigma,
            last_synced: None,
        },
        FeedSpec {
            name: "yara-rules".to_string(),
            url: "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
                .to_string(),
            kind: FeedKind::Yara,
            last_synced: None,
        },
        FeedSpec {
            name: "suricata-et".to_string(),
            url: "https://rules.emergingthreats.net/open/suricata-5.0/emerging.rules.tar.gz"
                .to_string(),
            kind: FeedKind::Suricata,
            last_synced: None,
        },
    ]
}

/// Return the built-in rule set compiled into the binary.
#[must_use]
pub fn bundled_rules() -> Vec<PivotRule> {
    let sources = [RULE_001, RULE_002, RULE_003];
    let mut rules = Vec::with_capacity(sources.len());
    for src in &sources {
        if let Ok(mut parsed) = load_rules_from_yaml_str(src) {
            rules.append(&mut parsed);
        }
    }
    rules
}
