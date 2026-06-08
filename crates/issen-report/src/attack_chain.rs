//! Build an [`AttackChainInput`] from scan findings.
//!
//! Sigma (and other) findings carry ATT&CK tactic tags such as
//! `attack.execution` or `attack.defense_evasion`. This module groups the
//! findings by recognized tactic and emits one node per tactic, ordered by the
//! ATT&CK kill-chain phase, so the report can render a left-to-right
//! "what happened" chain.
//!
//! The ordering is the canonical ATT&CK phase order, **not** a proven causal
//! sequence — it shows which tactics were *observed*, ordered by where they
//! sit in the kill chain. It is an observation, never a conclusion.

use crate::{AttackChainEdge, AttackChainInput, AttackChainNode, AttackTactic, FindingRow};

/// Map a finding's tags to the set of recognized ATT&CK tactics.
///
/// Recognizes the lowercase, underscore-or-hyphen tactic form emitted by Sigma
/// (`attack.initial_access`, `attack.defense_evasion`, `attack.c2`, …). Tags
/// that are not `attack.<known-tactic>` are ignored. The returned vec is
/// de-duplicated and preserves first-seen order.
#[must_use]
pub fn tactic_from_tags(tags: &[String]) -> Vec<AttackTactic> {
    let mut out: Vec<AttackTactic> = Vec::new();
    for tag in tags {
        if let Some(t) = parse_tactic_tag(tag) {
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out
}

/// Parse a single `attack.<tactic>` tag into an [`AttackTactic`].
fn parse_tactic_tag(tag: &str) -> Option<AttackTactic> {
    let lower = tag.to_ascii_lowercase();
    let name = lower.strip_prefix("attack.").unwrap_or(&lower);
    let normalized = name.replace('-', "_");
    match normalized.as_str() {
        "initial_access" => Some(AttackTactic::InitialAccess),
        "execution" => Some(AttackTactic::Execution),
        "persistence" => Some(AttackTactic::Persistence),
        "defense_evasion" => Some(AttackTactic::DefenseEvasion),
        "command_and_control" | "c2" => Some(AttackTactic::CommandAndControl),
        "impact" => Some(AttackTactic::Impact),
        _ => None,
    }
}

/// Canonical ATT&CK kill-chain order for the tactics this report renders.
/// Lower is earlier in the chain. Tactics not listed are not charted.
fn tactic_order(t: &AttackTactic) -> usize {
    match t {
        AttackTactic::InitialAccess => 0,
        AttackTactic::Execution => 1,
        AttackTactic::Persistence => 2,
        AttackTactic::DefenseEvasion => 3,
        AttackTactic::CommandAndControl => 4,
        AttackTactic::Impact => 5,
        AttackTactic::Unknown => 6,
    }
}

/// Human-readable label for a tactic.
fn tactic_label(t: &AttackTactic) -> &'static str {
    match t {
        AttackTactic::InitialAccess => "Initial Access",
        AttackTactic::Execution => "Execution",
        AttackTactic::Persistence => "Persistence",
        AttackTactic::DefenseEvasion => "Defense Evasion",
        AttackTactic::CommandAndControl => "Command & Control",
        AttackTactic::Impact => "Impact",
        AttackTactic::Unknown => "Other",
    }
}

/// Build an [`AttackChainInput`] from scan findings.
///
/// One node is emitted per recognized ATT&CK tactic present across the
/// findings, ordered by [`tactic_order`]. Each node's label is the tactic name
/// plus the count of findings that mapped to it. Consecutive nodes are joined
/// by an edge. Findings whose tags carry no recognized tactic do not appear.
#[must_use]
pub fn findings_to_attack_chain(findings: &[FindingRow]) -> AttackChainInput {
    // Count findings per recognized tactic.
    let mut counts: Vec<(AttackTactic, usize)> = Vec::new();
    for f in findings {
        for t in tactic_from_tags(&f.tags) {
            if let Some(entry) = counts.iter_mut().find(|(et, _)| *et == t) {
                entry.1 += 1;
            } else {
                counts.push((t, 1));
            }
        }
    }

    // Order by kill-chain phase.
    counts.sort_by_key(|(t, _)| tactic_order(t));

    let mut input = AttackChainInput::default();
    for (i, (tactic, count)) in counts.iter().enumerate() {
        let id = format!("n{i}");
        input.nodes.push(AttackChainNode {
            id: id.clone(),
            label: format!("{} ({count})", tactic_label(tactic)),
            tactic: tactic.clone(),
        });
        if i > 0 {
            input.edges.push(AttackChainEdge {
                from: format!("n{}", i - 1),
                to: id,
            });
        }
    }

    input
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(tags: &[&str]) -> FindingRow {
        FindingRow {
            engine: "Sigma".to_string(),
            rule_name: "rule".to_string(),
            severity: "high".to_string(),
            target: "Security.evtx".to_string(),
            description: "desc".to_string(),
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn tactic_from_tags_recognizes_execution() {
        assert_eq!(
            tactic_from_tags(&["attack.execution".to_string()]),
            vec![AttackTactic::Execution]
        );
    }

    #[test]
    fn tactic_from_tags_handles_hyphen_and_c2_alias() {
        assert_eq!(
            tactic_from_tags(&["attack.defense-evasion".to_string()]),
            vec![AttackTactic::DefenseEvasion]
        );
        assert_eq!(
            tactic_from_tags(&["attack.c2".to_string()]),
            vec![AttackTactic::CommandAndControl]
        );
    }

    #[test]
    fn tactic_from_tags_ignores_non_attack_and_dedups() {
        let tags = vec![
            "malware".to_string(),
            "attack.t1059.001".to_string(), // technique-only, not a tactic
            "attack.execution".to_string(),
            "attack.execution".to_string(), // dup
        ];
        assert_eq!(tactic_from_tags(&tags), vec![AttackTactic::Execution]);
    }

    #[test]
    fn empty_findings_produce_no_nodes() {
        let chain = findings_to_attack_chain(&[]);
        assert!(chain.nodes.is_empty());
        assert!(chain.edges.is_empty());
    }

    #[test]
    fn findings_without_recognized_tactic_are_skipped() {
        let chain = findings_to_attack_chain(&[finding(&["malware"]), finding(&["attack.t1003"])]);
        assert!(chain.nodes.is_empty(), "no tactic tags -> no chart nodes");
    }

    #[test]
    fn single_tactic_yields_one_node_with_count() {
        let chain = findings_to_attack_chain(&[finding(&["attack.execution"])]);
        assert_eq!(chain.nodes.len(), 1);
        assert_eq!(chain.nodes[0].tactic, AttackTactic::Execution);
        assert!(
            chain.nodes[0].label.contains("Execution") && chain.nodes[0].label.contains("(1)"),
            "label should name the tactic and the count: {}",
            chain.nodes[0].label
        );
        assert!(chain.edges.is_empty(), "single node -> no edges");
    }

    #[test]
    fn tactics_are_ordered_by_kill_chain_and_chained_by_edges() {
        // Provide them out of kill-chain order; expect canonical ordering.
        let chain = findings_to_attack_chain(&[
            finding(&["attack.impact"]),
            finding(&["attack.initial_access"]),
            finding(&["attack.execution"]),
        ]);
        let tactics: Vec<&AttackTactic> = chain.nodes.iter().map(|n| &n.tactic).collect();
        assert_eq!(
            tactics,
            vec![
                &AttackTactic::InitialAccess,
                &AttackTactic::Execution,
                &AttackTactic::Impact
            ]
        );
        // Edges chain consecutive nodes: n0->n1, n1->n2.
        assert_eq!(chain.edges.len(), 2);
        assert_eq!(chain.edges[0].from, "n0");
        assert_eq!(chain.edges[0].to, "n1");
        assert_eq!(chain.edges[1].from, "n1");
        assert_eq!(chain.edges[1].to, "n2");
    }

    #[test]
    fn repeated_tactic_increments_count_not_node_count() {
        let chain = findings_to_attack_chain(&[
            finding(&["attack.execution"]),
            finding(&["attack.execution"]),
            finding(&["attack.execution"]),
        ]);
        assert_eq!(chain.nodes.len(), 1);
        assert!(
            chain.nodes[0].label.contains("(3)"),
            "three execution findings -> count 3: {}",
            chain.nodes[0].label
        );
    }
}
