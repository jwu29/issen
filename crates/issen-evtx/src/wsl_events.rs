//! WSL event extraction from Windows Event Logs.
//!
//! Covers two sources:
//! 1. Security.evtx Event ID 4688 where NewProcessName contains wsl.exe / wslhost.exe
//! 2. Microsoft-Windows-WSL/Operational channel (Event IDs 1=start, 2=stop)

use winevt_core::EvtxEvent;

/// A WSL session start/stop event extracted from EVTX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WslEvtxEvent {
    pub kind: WslEventKind,
    pub timestamp_ns: i64,
    pub distro: Option<String>,
    pub windows_pid: Option<u32>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WslEventKind {
    /// wsl.exe process launched (4688 from Security log).
    WslProcessStart,
    /// wsl.exe process exited (4689 from Security log).
    WslProcessStop,
    /// WSL instance started (Event ID 1 from WSL Operational log).
    WslInstanceStart,
    /// WSL instance stopped (Event ID 2 from WSL Operational log).
    WslInstanceStop,
}

const WSL_OPERATIONAL_CHANNEL: &str = "Microsoft-Windows-WSL/Operational";
const WSL_EXE_SUFFIXES: &[&str] = &[r"\wsl.exe", r"\wslhost.exe", r"\wslrelay.exe"];

/// Filter and classify WSL-related events from a slice of EVTX events.
pub fn extract_wsl_events(events: &[EvtxEvent]) -> Vec<WslEvtxEvent> {
    events.iter().filter_map(classify_event).collect()
}

fn classify_event(ev: &EvtxEvent) -> Option<WslEvtxEvent> {
    // WSL Operational log channel.
    if ev.channel == WSL_OPERATIONAL_CHANNEL {
        let kind = match ev.event_id {
            1 => WslEventKind::WslInstanceStart,
            2 => WslEventKind::WslInstanceStop,
            _ => return None,
        };
        return Some(WslEvtxEvent {
            kind,
            timestamp_ns: ev.timestamp_ns,
            distro: ev.data.get("DistributionName").cloned(),
            windows_pid: ev.process_id,
            user: ev.data.get("UserName").cloned(),
        });
    }

    // Security log 4688 / 4689 — filter by process name.
    if ev.event_id == 4688 {
        let proc_name = ev.data.get("NewProcessName")?;
        let is_wsl = WSL_EXE_SUFFIXES.iter().any(|suffix| {
            proc_name.to_ascii_lowercase().ends_with(&suffix.to_ascii_lowercase())
        });
        if !is_wsl {
            return None;
        }
        return Some(WslEvtxEvent {
            kind: WslEventKind::WslProcessStart,
            timestamp_ns: ev.timestamp_ns,
            distro: None, // not available from 4688 alone
            windows_pid: ev.data.get("NewProcessId")
                .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()),
            user: ev.data.get("SubjectUserName").cloned(),
        });
    }

    if ev.event_id == 4689 {
        let proc_name = ev.data.get("ProcessName")?;
        let is_wsl = WSL_EXE_SUFFIXES.iter().any(|suffix| {
            proc_name.to_ascii_lowercase().ends_with(&suffix.to_ascii_lowercase())
        });
        if !is_wsl {
            return None;
        }
        return Some(WslEvtxEvent {
            kind: WslEventKind::WslProcessStop,
            timestamp_ns: ev.timestamp_ns,
            distro: None,
            windows_pid: ev.data.get("ProcessId")
                .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()),
            user: ev.data.get("SubjectUserName").cloned(),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(event_id: u32, channel: &str, data: Vec<(&str, &str)>, pid: Option<u32>) -> EvtxEvent {
        EvtxEvent {
            event_id,
            channel: channel.to_string(),
            timestamp_ns: 1_716_000_000_000_000_000,
            computer: "DESKTOP-TEST".to_string(),
            user_sid: None,
            logon_id: None,
            process_id: pid,
            thread_id: None,
            data: data.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        }
    }

    // ── Test 1: non-WSL events are filtered out ───────────────────────────

    #[test]
    fn non_wsl_events_filtered() {
        let ev = make_event(4688, "Security", vec![
            ("NewProcessName", r"C:\Windows\System32\notepad.exe"),
        ], None);
        let result = extract_wsl_events(&[ev]);
        assert!(result.is_empty(), "notepad.exe should be filtered");
    }

    // ── Test 2: 4688 with wsl.exe is extracted ────────────────────────────

    #[test]
    fn event_4688_wsl_exe_extracted() {
        let ev = make_event(4688, "Security", vec![
            ("NewProcessName", r"C:\Windows\System32\wsl.exe"),
            ("SubjectUserName", "alice"),
            ("NewProcessId", "0x1A4"),
        ], None);
        let result = extract_wsl_events(&[ev]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, WslEventKind::WslProcessStart);
        assert_eq!(result[0].user.as_deref(), Some("alice"));
        assert_eq!(result[0].windows_pid, Some(0x1A4));
    }

    // ── Test 3: wslhost.exe also captured ────────────────────────────────

    #[test]
    fn event_4688_wslhost_exe_captured() {
        let ev = make_event(4688, "Security", vec![
            ("NewProcessName", r"C:\Windows\System32\wslhost.exe"),
        ], None);
        let result = extract_wsl_events(&[ev]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, WslEventKind::WslProcessStart);
    }

    // ── Test 4: WSL Operational Event ID 1 = WslInstanceStart ────────────

    #[test]
    fn wsl_operational_event_1_is_instance_start() {
        let ev = make_event(1, WSL_OPERATIONAL_CHANNEL, vec![
            ("DistributionName", "Ubuntu-22.04"),
            ("UserName", "alice"),
        ], Some(1234));
        let result = extract_wsl_events(&[ev]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, WslEventKind::WslInstanceStart);
        assert_eq!(result[0].distro.as_deref(), Some("Ubuntu-22.04"));
        assert_eq!(result[0].windows_pid, Some(1234));
    }

    // ── Test 5: WSL Operational Event ID 2 = WslInstanceStop ─────────────

    #[test]
    fn wsl_operational_event_2_is_instance_stop() {
        let ev = make_event(2, WSL_OPERATIONAL_CHANNEL, vec![
            ("DistributionName", "Debian"),
        ], Some(5678));
        let result = extract_wsl_events(&[ev]);
        assert_eq!(result[0].kind, WslEventKind::WslInstanceStop);
        assert_eq!(result[0].distro.as_deref(), Some("Debian"));
    }

    // ── Test 6: WSL Operational Event ID 99 is ignored ───────────────────

    #[test]
    fn wsl_operational_unknown_event_id_ignored() {
        let ev = make_event(99, WSL_OPERATIONAL_CHANNEL, vec![], None);
        let result = extract_wsl_events(&[ev]);
        assert!(result.is_empty());
    }

    // ── Test 7: 4689 with wsl.exe = WslProcessStop ───────────────────────

    #[test]
    fn event_4689_wsl_exe_is_stop() {
        let ev = make_event(4689, "Security", vec![
            ("ProcessName", r"C:\Windows\System32\wsl.exe"),
            ("ProcessId", "0x1A4"),
        ], None);
        let result = extract_wsl_events(&[ev]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, WslEventKind::WslProcessStop);
        assert_eq!(result[0].windows_pid, Some(0x1A4));
    }

    // ── Test 8: empty input returns empty ────────────────────────────────

    #[test]
    fn empty_input_returns_empty() {
        assert!(extract_wsl_events(&[]).is_empty());
    }

    // ── Test 9: mixed events returns only WSL ones ────────────────────────

    #[test]
    fn mixed_events_only_wsl_returned() {
        let non_wsl = make_event(4688, "Security", vec![
            ("NewProcessName", r"C:\Windows\notepad.exe"),
        ], None);
        let wsl = make_event(1, WSL_OPERATIONAL_CHANNEL, vec![
            ("DistributionName", "Ubuntu"),
        ], Some(42));
        let result = extract_wsl_events(&[non_wsl, wsl]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].kind, WslEventKind::WslInstanceStart);
    }

    // ── Test 10: timestamp is preserved ───────────────────────────────────

    #[test]
    fn timestamp_preserved() {
        let mut ev = make_event(1, WSL_OPERATIONAL_CHANNEL, vec![], None);
        ev.timestamp_ns = 9_999_999_999_999i64;
        let result = extract_wsl_events(&[ev]);
        assert_eq!(result[0].timestamp_ns, 9_999_999_999_999i64);
    }
}
