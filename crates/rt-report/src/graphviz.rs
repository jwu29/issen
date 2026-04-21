//! Graphviz DOT format generation and PNG rendering for attack chains.

use std::path::Path;

use crate::{AttackChainInput, AttackTactic};

/// Generate a Graphviz DOT string from an `AttackChainInput`.
#[must_use]
pub fn render_attack_chain_dot(_input: &AttackChainInput) -> String {
    todo!("implement render_attack_chain_dot")
}

/// Write DOT to a temp file, then shell out to `dot -Tpng`.
///
/// # Errors
///
/// Returns `Err` if `dot` is not found or conversion fails.
pub fn render_attack_chain_png(_input: &AttackChainInput, _output: &Path) -> anyhow::Result<()> {
    todo!("implement render_attack_chain_png")
}

/// Generate Mermaid syntax and render via `mmdc`.
///
/// # Errors
///
/// Returns `Err` if `mmdc` is not found.
pub fn render_mermaid_png(_mermaid_src: &str, _output: &Path) -> anyhow::Result<()> {
    todo!("implement render_mermaid_png")
}

fn tactic_color(tactic: &AttackTactic) -> &'static str {
    match tactic {
        AttackTactic::InitialAccess => "#1a5276",
        AttackTactic::Execution => "#d35400",
        AttackTactic::Persistence => "#7d3c98",
        AttackTactic::DefenseEvasion => "#1e8449",
        AttackTactic::CommandAndControl => "#0e6655",
        AttackTactic::Impact => "#922b21",
        AttackTactic::Unknown => "#5d6d7e",
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackChainEdge, AttackChainNode, AttackChainInput, AttackTactic};

    fn two_node_input() -> AttackChainInput {
        AttackChainInput {
            nodes: vec![
                AttackChainNode {
                    id: "A".into(),
                    label: "Phishing".into(),
                    tactic: AttackTactic::InitialAccess,
                },
                AttackChainNode {
                    id: "B".into(),
                    label: "PowerShell".into(),
                    tactic: AttackTactic::Execution,
                },
            ],
            edges: vec![AttackChainEdge {
                from: "A".into(),
                to: "B".into(),
            }],
        }
    }

    #[test]
    fn dot_output_contains_digraph() {
        let dot = render_attack_chain_dot(&two_node_input());
        assert!(dot.contains("digraph"), "DOT output must contain 'digraph'");
    }

    #[test]
    fn dot_includes_all_node_ids() {
        let input = two_node_input();
        let dot = render_attack_chain_dot(&input);
        for node in &input.nodes {
            assert!(
                dot.contains(&node.id),
                "DOT output must contain node id '{}'",
                node.id
            );
        }
    }

    #[test]
    fn dot_includes_edges() {
        let dot = render_attack_chain_dot(&two_node_input());
        assert!(
            dot.contains("A -> B"),
            "DOT output must contain edge 'A -> B'"
        );
    }
}
