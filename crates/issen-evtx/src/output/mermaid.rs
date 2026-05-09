//! Mermaid diagram serializers for ProcessTree and LogonChain maps.

use crate::process_tree::ProcessTree;
use crate::logon_chain::LogonChain;
use std::collections::HashMap;

/// Serialize a `ProcessTree` to a Mermaid `graph TD` diagram string.
///
/// Each node is labeled `"<key>: <image_basename>"`.
/// Edges connect parent → child via `parent_key`.
pub fn process_tree_to_mermaid(tree: &ProcessTree) -> String {
    todo!()
}

/// Serialize a map of `LogonChain`s to a Mermaid `graph LR` diagram string.
///
/// Each logon session is a node labeled `"<logon_id>"`.
/// Privilege escalations (chains with `has_special_privileges()`) are highlighted.
pub fn logon_chains_to_mermaid(chains: &HashMap<u64, LogonChain>) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_tree::{ProcessTree, ProcessNode};
    use crate::logon_chain::LogonChain;
    use std::collections::HashMap;

    fn empty_process_tree() -> ProcessTree {
        ProcessTree::default()
    }

    #[test]
    fn process_tree_empty_produces_mermaid_header() {
        let output = process_tree_to_mermaid(&empty_process_tree());
        assert!(
            output.contains("graph") || output.contains("flowchart"),
            "output should contain a Mermaid graph directive, got: {output}"
        );
    }

    #[test]
    fn process_tree_with_events_contains_node_info() {
        use winevt_core::EvtxEvent;
        let mut data = std::collections::HashMap::new();
        data.insert("Image".into(), "C:\\Windows\\System32\\cmd.exe".into());
        data.insert("ProcessGuid".into(), "{AAAA}".into());
        data.insert("ParentProcessGuid".into(), "".into());
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
        assert!(
            output.contains("cmd.exe") || output.contains("AAAA"),
            "process node info should appear in Mermaid output, got: {output}"
        );
    }

    #[test]
    fn logon_chains_empty_produces_mermaid_header() {
        let chains: HashMap<u64, LogonChain> = HashMap::new();
        let output = logon_chains_to_mermaid(&chains);
        assert!(
            output.contains("graph") || output.contains("flowchart"),
            "output should contain a Mermaid graph directive"
        );
    }

    #[test]
    fn logon_chains_single_chain_appears_in_output() {
        let mut chains = HashMap::new();
        let chain = LogonChain {
            logon_id: 0xABCD,
            logon_time_ns: Some(1_000_000_000),
            privilege_time_ns: Some(2_000_000_000),
            process_pids: vec![1234],
            logoff_time_ns: None,
            is_orphaned: true,
        };
        chains.insert(0xABCD, chain);
        let output = logon_chains_to_mermaid(&chains);
        assert!(
            output.contains("ABCD") || output.contains("43981"),
            "logon_id should appear in Mermaid output (hex or decimal)"
        );
    }
}
