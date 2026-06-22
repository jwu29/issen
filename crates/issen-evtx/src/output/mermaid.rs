//! Mermaid diagram serializers for ProcessTree and LogonChain maps.

use crate::logon_chain::LogonChain;
use crate::process_tree::ProcessTree;
use std::collections::HashMap;

/// Serialize a `ProcessTree` to a Mermaid `graph TD` diagram string.
pub fn process_tree_to_mermaid(tree: &ProcessTree) -> String {
    let mut lines = vec!["graph TD".to_string()];
    for (key, node) in tree.nodes() {
        let label = format!("{}: {}", key, node.image);
        let safe_key = key.replace(['{', '}', '-'], "_");
        lines.push(format!(
            "    {}[\"{}\"]\n",
            safe_key,
            label.replace('"', "'")
        ));
        if let Some(parent) = &node.parent_key {
            let safe_parent = parent.replace(['{', '}', '-'], "_");
            lines.push(format!("    {safe_parent} --> {safe_key}"));
        }
    }
    lines.join("\n")
}

/// Serialize a map of `LogonChain`s to a Mermaid `graph LR` diagram string.
pub fn logon_chains_to_mermaid(chains: &HashMap<u64, LogonChain>) -> String {
    let mut lines = vec!["graph LR".to_string()];
    for (logon_id, chain) in chains {
        let has_priv = chain.has_special_privileges();
        let label = if has_priv {
            format!("0x{logon_id:X} [PRIV]")
        } else {
            format!("0x{logon_id:X}")
        };
        lines.push(format!("    N{logon_id}[\"{label}\"]"));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logon_chain::LogonChain;
    use crate::process_tree::ProcessTree;

    #[test]
    fn process_tree_empty_produces_mermaid_header() {
        let output = process_tree_to_mermaid(&ProcessTree::default());
        assert!(output.contains("graph") || output.contains("flowchart"));
    }

    #[test]
    fn process_tree_with_events_contains_node_info() {
        use winevt_core::EvtxEvent;
        let mut data = std::collections::HashMap::new();
        data.insert("Image".into(), "C:\\Windows\\System32\\cmd.exe".into());
        data.insert("ProcessGuid".into(), "{AAAA}".into());
        data.insert("ParentProcessGuid".into(), String::new());
        data.insert("CommandLine".into(), "cmd.exe".into());
        let ev = EvtxEvent {
            event_id: 1,
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp_ns: 1_000_000_000,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: Some(1234),
            thread_id: None,
            data,
        };
        let tree = ProcessTree::from_events(&[ev]);
        let output = process_tree_to_mermaid(&tree);
        assert!(output.contains("cmd.exe") || output.contains("AAAA"));
    }

    #[test]
    fn logon_chains_empty_produces_mermaid_header() {
        let chains: HashMap<u64, LogonChain> = HashMap::new();
        let output = logon_chains_to_mermaid(&chains);
        assert!(output.contains("graph") || output.contains("flowchart"));
    }

    #[test]
    fn logon_chains_single_chain_appears_in_output() {
        let mut chains = HashMap::new();
        chains.insert(
            0xABCD_u64,
            LogonChain {
                logon_id: 0xABCD,
                logon_time_ns: Some(1_000_000_000),
                privilege_time_ns: Some(2_000_000_000),
                process_pids: vec![1234],
                logoff_time_ns: None,
                is_orphaned: true,
            },
        );
        let output = logon_chains_to_mermaid(&chains);
        assert!(output.contains("ABCD") || output.contains("43981"));
    }
}
