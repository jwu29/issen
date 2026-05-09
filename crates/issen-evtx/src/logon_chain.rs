//! Logon chain graph: trace a LogonId across 4624 → 4672 → 4688 → 4634/4647.
//!
//! Windows logon chain semantics:
//!  - 4624: Logon established, assigns LogonId (TargetLogonId)
//!  - 4672: Special privileges assigned to new logon (SubjectLogonId)
//!  - 4688: Process created under this logon (SubjectLogonId)
//!  - 4634/4647: Logoff (TargetLogonId)

use std::collections::HashMap;

use forensicnomicon::heuristics::evtx::{
    EID_LOGOFF, EID_LOGOFF_USER, EID_LOGON, EID_PROCESS_CREATE, EID_SPECIAL_LOGON,
};
use winevt_core::EvtxEvent;

/// All activity correlated to a single Windows logon session via LogonId.
#[derive(Debug, Clone, Default)]
pub struct LogonChain {
    pub logon_id: u64,
    /// Timestamp of the 4624 logon event (nanoseconds).
    pub logon_time_ns: Option<i64>,
    /// Timestamp of the 4672 special-privilege event.
    pub privilege_time_ns: Option<i64>,
    /// PIDs of processes created (from 4688) under this logon.
    pub process_pids: Vec<u32>,
    /// Timestamp of the 4634/4647 logoff event.
    pub logoff_time_ns: Option<i64>,
    /// True when a logon event was seen but no corresponding logoff.
    pub is_orphaned: bool,
}

impl LogonChain {
    /// True when this logon was granted special privileges (4672 seen).
    pub fn has_special_privileges(&self) -> bool {
        self.privilege_time_ns.is_some()
    }

    /// Duration in seconds from logon to logoff, or None if logoff unseen.
    pub fn duration_secs(&self) -> Option<u64> {
        let logon = self.logon_time_ns?;
        let logoff = self.logoff_time_ns?;
        let delta_ns = (logoff - logon).unsigned_abs();
        Some(delta_ns / 1_000_000_000)
    }
}

/// Build logon chains from a slice of EVTX events.
///
/// Events with no recognisable logon-related EID are ignored.
pub fn build_logon_chains(events: &[EvtxEvent]) -> HashMap<u64, LogonChain> {
    let mut chains: HashMap<u64, LogonChain> = HashMap::new();

    for ev in events {
        match ev.event_id {
            id if id == EID_LOGON => {
                if let Some(lid) = logon_id_from_event(ev, "TargetLogonId") {
                    let chain = chains.entry(lid).or_insert_with(|| LogonChain {
                        logon_id: lid,
                        ..Default::default()
                    });
                    chain.logon_time_ns = Some(ev.timestamp_ns);
                    chain.is_orphaned = true;
                }
            }
            id if id == EID_SPECIAL_LOGON => {
                if let Some(lid) = logon_id_from_event(ev, "SubjectLogonId") {
                    let chain = chains.entry(lid).or_insert_with(|| LogonChain {
                        logon_id: lid,
                        is_orphaned: true,
                        ..Default::default()
                    });
                    chain.privilege_time_ns = Some(ev.timestamp_ns);
                }
            }
            id if id == EID_PROCESS_CREATE => {
                if let Some(lid) = logon_id_from_event(ev, "SubjectLogonId") {
                    let chain = chains.entry(lid).or_insert_with(|| LogonChain {
                        logon_id: lid,
                        is_orphaned: true,
                        ..Default::default()
                    });
                    if let Some(pid_str) = ev.data.get("NewProcessId") {
                        if let Ok(pid) =
                            u32::from_str_radix(pid_str.trim_start_matches("0x"), 16)
                        {
                            chain.process_pids.push(pid);
                        }
                    }
                }
            }
            id if id == EID_LOGOFF || id == EID_LOGOFF_USER => {
                if let Some(lid) = logon_id_from_event(ev, "TargetLogonId") {
                    let chain = chains.entry(lid).or_insert_with(|| LogonChain {
                        logon_id: lid,
                        ..Default::default()
                    });
                    chain.logoff_time_ns = Some(ev.timestamp_ns);
                    chain.is_orphaned = false;
                }
            }
            _ => {}
        }
    }

    chains
}

fn logon_id_from_event(ev: &EvtxEvent, field: &str) -> Option<u64> {
    if let Some(s) = ev.data.get(field) {
        return u64::from_str_radix(s.trim_start_matches("0x"), 16).ok();
    }
    // Fall back to the EvtxEvent-level logon_id field
    ev.logon_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ev(event_id: u32, logon_id_hex: &str, ts: i64) -> EvtxEvent {
        let mut data = HashMap::new();
        let lid = u64::from_str_radix(logon_id_hex.trim_start_matches("0x"), 16).unwrap();
        let formatted = format!("0x{lid:016x}");
        // Different events use different field names for the logon ID
        match event_id {
            4624 | 4634 | 4647 => {
                data.insert("TargetLogonId".into(), formatted);
            }
            4672 | 4688 => {
                data.insert("SubjectLogonId".into(), formatted);
                if event_id == 4688 {
                    data.insert("NewProcessId".into(), "0x4d2".into()); // pid 1234
                }
            }
            _ => {}
        }
        EvtxEvent {
            event_id,
            channel: "Security".into(),
            timestamp_ns: ts,
            computer: "WS01".into(),
            user_sid: None,
            logon_id: Some(lid),
            process_id: None,
            thread_id: None,
            data,
        }
    }

    #[test]
    fn build_logon_chains_empty_input() {
        let chains = build_logon_chains(&[]);
        assert!(chains.is_empty());
    }

    #[test]
    fn build_logon_chains_single_logon() {
        let events = vec![ev(4624, "0x1234", 1_000_000)];
        let chains = build_logon_chains(&events);
        assert_eq!(chains.len(), 1);
        let chain = &chains[&0x1234];
        assert_eq!(chain.logon_time_ns, Some(1_000_000));
        assert!(chain.is_orphaned);
    }

    #[test]
    fn build_logon_chains_logon_and_logoff_not_orphaned() {
        let events = vec![
            ev(4624, "0x5678", 1_000_000),
            ev(4634, "0x5678", 2_000_000),
        ];
        let chains = build_logon_chains(&events);
        let chain = &chains[&0x5678];
        assert_eq!(chain.logoff_time_ns, Some(2_000_000));
        assert!(!chain.is_orphaned);
    }

    #[test]
    fn build_logon_chains_records_4688_pids() {
        let events = vec![
            ev(4624, "0xABCD", 1_000),
            ev(4688, "0xABCD", 2_000),
        ];
        let chains = build_logon_chains(&events);
        let chain = &chains[&0xABCD];
        assert!(!chain.process_pids.is_empty());
    }

    #[test]
    fn build_logon_chains_records_4672_privilege() {
        let events = vec![
            ev(4624, "0xFEED", 1_000),
            ev(4672, "0xFEED", 1_500),
        ];
        let chains = build_logon_chains(&events);
        let chain = &chains[&0xFEED];
        assert_eq!(chain.privilege_time_ns, Some(1_500));
        assert!(chain.has_special_privileges());
    }

    #[test]
    fn duration_secs_some_when_logoff_seen() {
        let chain = LogonChain {
            logon_id: 1,
            logon_time_ns: Some(0),
            logoff_time_ns: Some(5_000_000_000), // 5 s in ns
            ..Default::default()
        };
        assert_eq!(chain.duration_secs(), Some(5));
    }

    #[test]
    fn duration_secs_none_when_orphaned() {
        let chain = LogonChain {
            logon_id: 1,
            logon_time_ns: Some(0),
            logoff_time_ns: None,
            is_orphaned: true,
            ..Default::default()
        };
        assert_eq!(chain.duration_secs(), None);
    }
}
