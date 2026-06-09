> **ARCHIVED 2026-06-09 — superseded by `docs/plans/2026-06-09-issen-grand-plan.md`.** Session-enrichment feature — parked; enabled by the P3 super-timeline engine in the grand plan.

---

# Session Enrichment Plan

Implement the "what did this session do?" layer: link Windows logon sessions to the
process launches, network connections, and file activity that occurred within them,
and expose the result through `issen-cli session`.

## Context

`winevt-forensic` (sibling workspace) handles session *extraction*:
- `winevt_extract::sessions_multi(&[&Path])` correlates EID 4624/4634/4647 across
  multiple EVTX files and returns `Vec<winevt_extract::LogonSession>`.

`issen` handles session *enrichment* — joining session identity against every other
artifact source. This plan closes that gap.

**Read before starting:**
- `crates/issen-evtx/src/session.rs` — `correlate_sessions`, `link_processes_to_sessions`,
  `find_lateral_movement`, `find_orphaned_sessions` are already implemented.
- `crates/issen-core/src/timeline/event.rs` — `TimelineEvent`, `EntityRef`, `EventType`.
- `crates/issen-correlation/src/model.rs` — `Evidence`, `SubjectRef::Session`.
- `crates/issen-cli/src/main.rs` — existing CLI commands pattern.

**Key types:**
```rust
// winevt-core (used by issen-evtx::session):
pub struct LogonSession {
    pub logon_id: u64,
    pub logon_type: u8,
    pub username: String,
    pub domain: String,
    pub src_ip: Option<String>,
    pub logon_time_ns: i64,
    pub logoff_time_ns: Option<i64>,
    pub duration_secs: Option<u64>,
    pub processes: Vec<u32>,   // PIDs linked by link_processes_to_sessions()
    pub is_orphaned: bool,
}

// issen-core (the pipeline's canonical event):
pub struct TimelineEvent {
    pub timestamp_ns: i64,
    pub event_type: EventType,  // ProcessExec, NetworkConnect, LogonSuccess, …
    pub metadata: HashMap<String, serde_json::Value>,
    pub entity_refs: Vec<EntityRef>,  // ← session link goes here
    pub tags: Vec<String>,
    // …
}

pub enum EntityRef { FilePath(String), Process(String), User(String), Ip(String) }
// Session variant is MISSING — Step 1 adds it.
```

---

## What Is Already Done

| Component | File | Status |
|---|---|---|
| Session correlation (4624/4634/4647 → LogonSession) | `issen-evtx/src/session.rs::correlate_sessions` | ✓ done |
| Process → session linking (4688 → `LogonSession.processes`) | `issen-evtx/src/session.rs::link_processes_to_sessions` | ✓ done |
| Lateral movement detection | `issen-evtx/src/session.rs::find_lateral_movement` | ✓ done |
| Orphaned session detection | `issen-evtx/src/session.rs::find_orphaned_sessions` | ✓ done |
| Evidence enrichment skeleton | `issen-correlation/src/enrich.rs` | ✓ done |
| `SubjectRef::Session(String)` in correlation model | `issen-correlation/src/model.rs:73` | ✓ done |

---

## Gaps To Close (implement in order)

### Step 1 — Add `EntityRef::Session(u64)` to `issen-core`

**File:** `crates/issen-core/src/timeline/event.rs`

Add the variant:
```rust
pub enum EntityRef {
    FilePath(String),
    Process(String),
    User(String),
    Ip(String),
    Session(u64),   // ← new: Windows logon session ID
}
```

This is the structural hook that lets every downstream module (timeline, correlation,
query, export) find "which session did this event belong to?" without parsing free-text
metadata.

**TDD:** Write unit tests that roundtrip `EntityRef::Session(0xDEADBEEF)` through serde
and verify `Display` (use `Session(0xdeadbeef)` hex format). RED commit first.

---

### Step 2 — Populate `logon_id` in `issen-parser-evtx` output

**File:** `crates/parsers/issen-parser-evtx/src/lib.rs`

The EVTX parser currently extracts Channel, Computer, and description into
`TimelineEvent`. For `EventType::ProcessExec` (EID 4688) events it must also
extract `SubjectLogonId` / `TargetLogonId` from `EventData` and store it in
`metadata["logon_id"]` as a `serde_json::Value::Number(u64)`.

Parse the hex string Windows writes (`"0x0000000000059b61"`) with
`u64::from_str_radix(s.trim_start_matches("0x"), 16)`.

Similarly for `EventType::LogonSuccess` (4624): extract `TargetLogonId` into
`metadata["logon_id"]` and `metadata["logon_type"]`.

**TDD:** Unit-test parsing a minimal EVTX JSON record (use inline JSON string, not a
real file) and assert `metadata["logon_id"]` is present and correct. RED first.

---

### Step 3 — Session-enrichment pass on `TimelineEvent` slice

**File:** `crates/issen-evtx/src/session.rs` (add at the bottom)

```rust
use issen_core::timeline::event::{EntityRef, EventType, TimelineEvent};

/// Attach session context to timeline events that carry a logon_id in metadata.
///
/// For every ProcessExec or LogonSuccess event whose `metadata["logon_id"]`
/// matches a known session, this function:
///   - pushes `EntityRef::Session(logon_id)` into `event.entity_refs`
///   - adds tags: "session:interactive", "session:orphaned", "session:lateral_movement"
///   - inserts metadata keys: "session_username", "session_domain",
///     "session_logon_type", "session_src_ip"
///
/// Events with no logon_id in metadata are left unchanged.
pub fn enrich_timeline_events(
    events: &mut [TimelineEvent],
    sessions: &std::collections::HashMap<u64, winevt_core::LogonSession>,
) {
    for event in events {
        let logon_id = match event.metadata.get("logon_id").and_then(|v| v.as_u64()) {
            Some(id) => id,
            None => continue,
        };
        let session = match sessions.get(&logon_id) {
            Some(s) => s,
            None => continue,
        };
        event.entity_refs.push(EntityRef::Session(logon_id));
        event.metadata.insert("session_username".into(), session.username.clone().into());
        event.metadata.insert("session_domain".into(), session.domain.clone().into());
        event.metadata.insert("session_logon_type".into(), session.logon_type.into());
        if let Some(ip) = &session.src_ip {
            event.metadata.insert("session_src_ip".into(), ip.clone().into());
        }
        if session.is_orphaned {
            event.tags.push("session:orphaned".into());
        }
        // logon_type 3 = Network, 10 = RemoteInteractive (RDP)
        let logon_type_name = winevt_core::logon_type_name(session.logon_type);
        event.tags.push(format!("session:{}", logon_type_name.to_lowercase()));
    }
}
```

**TDD:** Build a `Vec<TimelineEvent>` + `HashMap<u64, LogonSession>` in a test,
call `enrich_timeline_events`, assert `entity_refs` contains `EntityRef::Session`,
`metadata["session_username"]` is correct, and orphaned sessions get the tag. RED first.

---

### Step 4 — `issen session` CLI command

**Files:**
- `crates/issen-cli/src/commands/session.rs` (new file)
- `crates/issen-cli/src/main.rs` (add `Session` variant to `Cmd` enum + dispatch)

The command should:
1. Accept one or more `--evtx-dir PATH` or `--evtx-file PATH` (variadic) arguments.
2. Discover `.evtx` files with `issen_evtx::find_evtx_files`.
3. Parse all files to `Vec<EvtxEvent>` (use the existing parser in `issen-parser-evtx`
   or `issen-evtx::analyze`).
4. Call `issen_evtx::session::correlate_sessions(&events)`.
5. Extract process events and call `link_processes_to_sessions`.
6. Call `find_lateral_movement` and `find_orphaned_sessions`.
7. Call `enrich_timeline_events` (Step 3) on the parsed `TimelineEvent` slice.
8. Output JSON to stdout (default) or a summary table (with `--summary` flag).

```
USAGE:
  issen session [--evtx-dir <PATH>]... [--evtx-file <FILE>]... [--json] [--summary]
                [--lateral-only] [--orphaned-only]

OUTPUT (JSON):
{
  "sessions": [ { "logon_id": "0x59b61", "username": "alice", "domain": "CORP",
                  "logon_type": 3, "logon_type_name": "Network",
                  "logon_time": "2024-01-15T08:32:11Z",
                  "logoff_time": "2024-01-15T08:45:03Z",
                  "duration_secs": 772,
                  "src_ip": "10.0.0.42",
                  "process_count": 7,
                  "is_orphaned": false } ],
  "lateral_movements": [ ... ],
  "orphaned_count": 3,
  "total_sessions": 41
}
```

**TDD:** Integration test using a small synthetic EVTX fixture (write one via
`winevt-writer` or copy from `winevt-forensic`'s test corpus). Assert exit code 0,
JSON output parses, `sessions` array is non-empty. RED first.

---

### Step 5 — Network session enrichment in `net_correlation`

**File:** `crates/issen-evtx/src/net_correlation.rs`

After correlating Sysmon EID 3 (NetworkConnect) with Zeek conn.log, also join
against the session map by `logon_id` in the Sysmon event's `SubjectLogonId`:
- Tag the network correlation finding with `session_src_ip` if the session has one
  (flag: "session_ip_mismatch" if the network source IP differs from the session
  logon IP — indicator of IP spoofing or NAT-traversal anomaly)
- Add `EntityRef::Session(logon_id)` to the relevant `TimelineEvent`

This step is lower priority than Steps 1-4. Implement it last.

**TDD:** Unit test with a mock network finding + mock session, assert tag is applied.
RED first.

---

## TDD Contract — MANDATORY

Every step requires **two separate git commits**:

1. **RED commit** — tests only, no implementation. Tests must fail to compile or
   fail at runtime. Commit message prefix: `test(red): …`
2. **GREEN commit** — minimal implementation that makes the RED tests pass, plus any
   updates to adjacent tests broken by the new code. Commit message prefix:
   `feat: …` or `fix: …`

Do not combine RED and GREEN into one commit. The RED commit is the verifiable proof
that tests were written first.

---

## Dependency Notes

- `issen-evtx/Cargo.toml` must already have `issen-core` as a dependency for
  Step 3. If not, add it.
- `issen-parser-evtx/Cargo.toml` — check it has `serde_json` (it does).
- `issen-cli/Cargo.toml` — must have `issen-evtx`, `issen-parser-evtx`, `winevt-core`
  as dependencies for the session command.
- No circular dependencies: `issen-core` ← `issen-evtx` ← `issen-cli`. Never the
  reverse.

## Success Criteria

```
cargo test -p issen-core          # Step 1 passes
cargo test -p issen-parser-evtx   # Step 2 passes
cargo test -p issen-evtx          # Step 3 passes
cargo test -p issen-cli           # Step 4 passes (integration test)
issen session --evtx-dir /path/to/evtx --json | jq '.sessions | length'
# → non-zero
```
