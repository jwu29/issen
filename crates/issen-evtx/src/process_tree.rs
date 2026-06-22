//! Process tree reconstruction from Sysmon EID 1 + Security EID 4688 events.
//!
//! Sysmon EID 1 provides `ProcessGuid`/`ParentProcessGuid` chains for reliable
//! parent-child linking. Security EID 4688 provides `NewProcessId`/`ProcessId`
//! as a fallback when Sysmon is unavailable.

use std::collections::HashMap;

use forensicnomicon::heuristics::evtx::{
    EID_PROCESS_CREATE, EID_SYSMON_PROCESS_CREATE, SYSMON_CHANNEL, SYSMON_FIELD_COMMAND_LINE,
    SYSMON_FIELD_IMAGE, SYSMON_FIELD_PARENT_PROCESS_GUID, SYSMON_FIELD_PROCESS_GUID,
};
use winevt_core::EvtxEvent;

/// A node in the reconstructed process tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessNode {
    /// Sysmon ProcessGuid or "pid:<id>" when GUID unavailable.
    pub key: String,
    /// Parent key (None for root / orphan).
    pub parent_key: Option<String>,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub image: String,
    pub command_line: Option<String>,
    pub timestamp_ns: i64,
    pub logon_id: Option<u64>,
}

/// Reconstructed process tree keyed by `ProcessNode::key`.
#[derive(Debug, Default)]
pub struct ProcessTree {
    nodes: HashMap<String, ProcessNode>,
}

impl ProcessTree {
    /// Build a process tree from a mixed slice of Sysmon EID 1 + Security EID 4688 events.
    pub fn from_events(events: &[EvtxEvent]) -> Self {
        let mut nodes = HashMap::new();
        for ev in events {
            if let Some(node) = extract_node(ev) {
                nodes.insert(node.key.clone(), node);
            }
        }
        Self { nodes }
    }

    /// All nodes in the tree.
    pub fn nodes(&self) -> &HashMap<String, ProcessNode> {
        &self.nodes
    }

    /// Direct children of `key`.
    pub fn children_of(&self, key: &str) -> Vec<&ProcessNode> {
        self.nodes
            .values()
            .filter(|n| n.parent_key.as_deref() == Some(key))
            .collect()
    }

    /// Full ancestor chain from `key` toward the root (exclusive of `key` itself).
    /// Returns an empty vec if `key` is not found or has no parent.
    pub fn ancestors_of(&self, key: &str) -> Vec<&ProcessNode> {
        let mut result = Vec::new();
        let mut current_key = key.to_string();
        let mut visited = std::collections::HashSet::new();
        while let Some(node) = self.nodes.get(&current_key) {
            let Some(parent_key) = node.parent_key.as_deref() else {
                break;
            };
            if !visited.insert(parent_key.to_string()) {
                break; // cycle guard
            }
            let Some(parent) = self.nodes.get(parent_key) else {
                break;
            };
            result.push(parent);
            current_key = parent_key.to_string();
        }
        result
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

fn parse_hex_pid(s: &str) -> Option<u32> {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

fn extract_node(ev: &EvtxEvent) -> Option<ProcessNode> {
    if ev.event_id == EID_SYSMON_PROCESS_CREATE && ev.channel == SYSMON_CHANNEL {
        let guid = ev.data.get(SYSMON_FIELD_PROCESS_GUID)?.clone();
        let parent_guid = ev.data.get(SYSMON_FIELD_PARENT_PROCESS_GUID).cloned();
        let image = ev.data.get(SYSMON_FIELD_IMAGE).cloned().unwrap_or_default();
        let pid = ev.data.get("ProcessId").and_then(|s| s.parse::<u32>().ok());
        let command_line = ev.data.get(SYSMON_FIELD_COMMAND_LINE).cloned();
        return Some(ProcessNode {
            key: guid,
            parent_key: parent_guid,
            pid,
            parent_pid: None,
            image,
            command_line,
            timestamp_ns: ev.timestamp_ns,
            logon_id: ev.logon_id,
        });
    }

    if ev.event_id == EID_PROCESS_CREATE && ev.channel == "Security" {
        let new_pid = ev.data.get("NewProcessId").and_then(|s| parse_hex_pid(s))?;
        let parent_pid = ev.data.get("ProcessId").and_then(|s| parse_hex_pid(s));
        let image = ev.data.get("NewProcessName").cloned().unwrap_or_default();
        let key = format!("pid:{new_pid}");
        let parent_key = parent_pid.map(|p| format!("pid:{p}"));
        return Some(ProcessNode {
            key,
            parent_key,
            pid: Some(new_pid),
            parent_pid,
            image,
            command_line: None,
            timestamp_ns: ev.timestamp_ns,
            logon_id: ev.logon_id,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sysmon_create(guid: &str, parent_guid: &str, image: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("ProcessGuid".into(), guid.into());
        data.insert("ParentProcessGuid".into(), parent_guid.into());
        data.insert("Image".into(), image.into());
        data.insert("ProcessId".into(), "1234".into());
        data.insert("CommandLine".into(), format!("{image} --flag"));
        EvtxEvent {
            event_id: 1,
            channel: "Microsoft-Windows-Sysmon/Operational".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }
    }

    fn sec_4688(new_pid: u32, parent_pid: u32, image: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        data.insert("NewProcessId".into(), format!("0x{new_pid:x}"));
        data.insert("ProcessId".into(), format!("0x{parent_pid:x}"));
        data.insert("NewProcessName".into(), image.into());
        EvtxEvent {
            event_id: 4688,
            channel: "Security".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: Some(0xABC),
            process_id: None,
            thread_id: None,
            data,
        }
    }

    #[test]
    fn process_tree_empty_from_no_events() {
        let tree = ProcessTree::from_events(&[]);
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn process_tree_builds_from_sysmon_eid1() {
        let events = vec![
            sysmon_create("{A}", "{ROOT}", r"C:\Windows\System32\cmd.exe", 1_000),
            sysmon_create("{B}", "{A}", r"C:\Windows\System32\whoami.exe", 2_000),
        ];
        let tree = ProcessTree::from_events(&events);
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn children_of_returns_direct_children() {
        let events = vec![
            sysmon_create("{A}", "{ROOT}", r"cmd.exe", 1_000),
            sysmon_create("{B}", "{A}", r"whoami.exe", 2_000),
            sysmon_create("{C}", "{A}", r"ipconfig.exe", 3_000),
        ];
        let tree = ProcessTree::from_events(&events);
        let kids = tree.children_of("{A}");
        assert_eq!(kids.len(), 2);
    }

    #[test]
    fn ancestors_of_walks_to_root() {
        let events = vec![
            sysmon_create("{A}", "{ROOT}", r"explorer.exe", 1_000),
            sysmon_create("{B}", "{A}", r"cmd.exe", 2_000),
            sysmon_create("{C}", "{B}", r"powershell.exe", 3_000),
        ];
        let tree = ProcessTree::from_events(&events);
        let ancestors = tree.ancestors_of("{C}");
        let images: Vec<_> = ancestors.iter().map(|n| n.image.as_str()).collect();
        assert!(images.contains(&"cmd.exe"));
        assert!(images.contains(&"explorer.exe"));
    }

    #[test]
    fn process_tree_falls_back_to_security_4688() {
        let events = vec![sec_4688(1234, 500, r"C:\cmd.exe", 1_000)];
        let tree = ProcessTree::from_events(&events);
        assert_eq!(tree.len(), 1);
        let node = tree.nodes().values().next().unwrap();
        assert_eq!(node.pid, Some(1234));
    }

    #[test]
    fn process_tree_ignores_irrelevant_event_ids() {
        let mut data = HashMap::new();
        data.insert("TargetUserName".into(), "user".into());
        let events = vec![EvtxEvent {
            event_id: 4624,
            channel: "Security".into(),
            timestamp_ns: 1_000,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: None,
            process_id: None,
            thread_id: None,
            data,
        }];
        let tree = ProcessTree::from_events(&events);
        assert!(tree.is_empty());
    }
}
