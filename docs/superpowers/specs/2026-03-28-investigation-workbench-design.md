# Investigation Workbench TUI: Design Spec

## Overview

Extend `rt-navigator` (`rt-nav`) to support a second mode: **investigation mode**. When the user passes a forensic collection archive (UAC `.tar.gz` or Velociraptor `.zip`) instead of an MFT file, `rt-nav` auto-detects the format, ingests the collection via `rt-unpack` + `rt-parser-uac`/`rt-parser-velociraptor`, and launches an interactive investigation workbench TUI with a dashboard overview and drill-in views for each artifact category.

## Goals

- **One command** — `rt-nav collection.tar.gz` ingests and opens the workbench
- **Dashboard landing** — summary counts, timeline activity sparkline, top findings
- **Interactive drill-in views** — Tab-switchable views for Timeline (bodyfile), Network, Processes, Logins, Packages, Configs, Hashes, Chkrootkit findings
- **Search** — `/` search across all views with background threading (reuse existing search pattern)
- **Detail panel** — right-side panel showing full details of selected item
- **Zero new binaries** — extends existing `rt-nav`, same binary
- **CTF-ready** — solve Hal Pomeranz's Linux Forensic Scenario from the TUI

## Non-Goals

- DuckDB integration (parsed data stays in memory — UAC collections are small enough)
- Report export from TUI (use `rt report` separately)
- Scan/signature engine integration in this phase
- Velociraptor-specific views (Velociraptor extracts to files that the existing MFT mode handles)

---

## Architecture

### Mode Detection

```
rt-nav <path>
  → is directory or MFT file?  → existing MFT tree mode
  → is file + rt-unpack recognizes it?  → investigation mode
  → neither?  → error with usage hint
```

In `main.rs`, before `resolve_sources()`, probe the path with `rt_unpack::registry::open_collection()`. If it succeeds, branch into investigation mode. Otherwise fall through to existing MFT mode.

### Data Model

Investigation mode does NOT use DuckDB or `TimelineStore`. The parsed UAC data is held in memory as the typed structs from `rt-parser-uac::parsers`:

```rust
pub struct InvestigationData {
    pub metadata: CollectionMetadata,       // from rt-unpack
    pub bodyfile: Vec<BodyfileEntry>,        // from parsers::bodyfile
    pub network: Vec<NetworkConnection>,     // from parsers::network
    pub processes: Vec<ProcessInfo>,         // from parsers::process
    pub crontabs: Vec<CrontabEntry>,         // from parsers::process
    pub logins: Vec<LoginRecord>,            // from parsers::system
    pub system_info: Option<SystemInfo>,     // from parsers::system
    pub packages: Vec<InstalledPackage>,     // from parsers::packages
    pub hashes: Vec<HashedExecutable>,       // from parsers::hash_execs
    pub chkrootkit: Vec<ChkrootkitFinding>, // from parsers::chkrootkit
    pub configs: Vec<ConfigFile>,            // from parsers::configs
    pub hardware: Option<HardwareInfo>,      // from parsers::hardware
    pub mounts: Vec<MountInfo>,             // from parsers::storage
}
```

### TUI State Machine

```rust
pub enum InvestigationView {
    Dashboard,
    Timeline,    // bodyfile entries, sorted by time
    Network,     // connections table
    Processes,   // process list + crontabs
    Logins,      // login records
    Packages,    // installed packages
    Configs,     // system configs
    Hashes,      // executable hashes
    Chkrootkit,  // rootkit scan findings
}

pub struct InvestigationApp {
    pub data: InvestigationData,
    pub view: InvestigationView,
    pub selected: usize,              // cursor position in current view's list
    pub scroll_offset: usize,         // virtual scrolling
    pub show_detail: bool,            // toggle right panel
    pub search_query: String,         // active search
    pub search_matches: Vec<usize>,   // matching indices in current view
    pub sort_ascending: bool,
}
```

### Keyboard Map

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Next/prev view |
| `1`-`9` | Jump to view by number |
| `j`/`k` or `↑`/`↓` | Navigate list |
| `Enter` | From Dashboard: drill into selected category. From list: toggle detail panel |
| `Backspace` / `Esc` | Return to Dashboard |
| `/` | Enter search mode |
| `n`/`N` | Next/prev search match |
| `s` | Cycle sort mode (varies per view) |
| `q` | Quit |
| `?` | Help modal |

### View Layouts

**Dashboard:**
```
┌─────────────────────────────────────────────────────────┐
│ RT Investigation: <hostname>  OS: <os>  Collected: <ts> │
├─────────────────────┬───────────────────────────────────┤
│ SUMMARY             │ TIMELINE ACTIVITY                 │
│ ▶ Bodyfile: 47,832  │ ▁▂▃▅▇█▇▅▃▂▁▁▁▁▁▁▂▅▇████▇▅▃▂▁  │
│   Network:  23      │ 19:00----19:30----20:00----20:30  │
│   Processes: 142    │                                   │
│   Logins:   8       │ ALERTS                            │
│   Packages: 1,204   │ ! Reverse shell in netstat        │
│   Configs:  89      │ ! Hidden proc (high CPU)          │
│   Hashes:   2,341   │ ! Suspicious /tmp executables     │
│   Rootkit:  3       │ ! ld.so.preload modification      │
├─────────────────────┴───────────────────────────────────┤
│ [Tab] switch view  [Enter] drill in  [/] search  [q] q │
└─────────────────────────────────────────────────────────┘
```

**Drill-in view (e.g., Network):**
```
┌─────────────────────────────────────────────────────────┐
│ RT Investigation: <hostname>  View: [Network]           │
├──────────────────────────────────┬──────────────────────┤
│ Proto  Local           Remote   │ Detail               │
│ ▶tcp   0.0.0.0:22     LISTEN   │ Protocol: tcp        │
│  tcp   10.0.0.5:4444  ESTAB    │ Local: 0.0.0.0:22    │
│  tcp   192.168.4.35   ESTAB    │ State: LISTEN        │
│  udp   0.0.0.0:68     -        │ PID: 834             │
│                                 │ Program: sshd        │
├──────────────────────────────────┴──────────────────────┤
│ [Tab] next view  [Esc] dashboard  23 connections        │
└─────────────────────────────────┘──────────────────────┘
```

### Alert Detection (Lightweight Heuristics)

On ingest, run simple pattern-matching to surface alerts on the dashboard:

```rust
pub struct Alert {
    pub severity: AlertSeverity,  // Info, Warning, Critical
    pub category: &'static str,
    pub message: String,
    pub detail: String,
}

pub enum AlertSeverity { Info, Warning, Critical }
```

Built-in checks (no external rules, just pattern matching):
- Network: connections to non-RFC1918 IPs, reverse shell patterns in process names
- Process: high CPU with no visible name, processes running from /tmp or /dev/shm
- Chkrootkit: any "INFECTED" findings
- Configs: ld.so.preload present, suspicious crontab entries, passwd/shadow anomalies
- Bodyfile: recently created executables in /tmp, /var/tmp, /dev/shm

### Timeline Sparkline

The dashboard shows a sparkline of bodyfile activity over time. Built from bodyfile mtime distribution:

```rust
fn build_sparkline(entries: &[BodyfileEntry], width: usize) -> Vec<u64> {
    // Bucket mtimes into `width` time bins
    // Return counts per bin for ratatui::widgets::Sparkline
}
```

---

## File Structure

New files in `crates/rt-navigator/src/`:

```
investigation/
├── mod.rs           — InvestigationApp state machine + handle_key
├── data.rs          — InvestigationData struct + loading from manifest
├── alerts.rs        — Alert detection heuristics
├── dashboard.rs     — Dashboard view rendering
├── views/
│   ├── mod.rs       — ViewRenderer trait, view dispatch
│   ├── timeline.rs  — Bodyfile timeline view
│   ├── network.rs   — Network connections view
│   ├── process.rs   — Process list + crontab view
│   ├── logins.rs    — Login records view
│   ├── packages.rs  — Package list view
│   ├── configs.rs   — System configs view
│   ├── hashes.rs    — Hash executables view
│   └── chkrootkit.rs — Rootkit findings view
└── detail.rs        — Detail panel rendering (right side)
```

Modified files:
- `main.rs` — add collection detection branch, `run_investigation_loop()`
- `Cargo.toml` — add `rt-unpack`, `rt-parser-uac`, `rt-parser-velociraptor` deps

Unchanged files:
- `app.rs` — existing MFT tree mode (untouched)
- `ui.rs` — existing MFT tree rendering (untouched)
- `search.rs` — existing search engine (untouched, not reused initially)
- `sources.rs` — existing artifact resolution (untouched)

---

## Dependencies

New workspace deps for rt-navigator:
```toml
rt-unpack = { workspace = true }
rt-parser-uac = { workspace = true }
rt-parser-velociraptor = { workspace = true }
inventory = { workspace = true }
```

Existing deps already available: `ratatui`, `crossterm`, `clap`, `anyhow`, `chrono`.

---

## Testing Strategy

- Unit tests for alert detection (pattern matching on known-bad data)
- Unit tests for sparkline bucketing
- Unit tests for `InvestigationData` loading from temp dir with synthetic UAC layout
- Integration test: load real UAC test data, verify all categories populated
- No TUI rendering tests (visual verification only)
