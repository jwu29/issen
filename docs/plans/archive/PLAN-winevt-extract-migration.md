> **ARCHIVED 2026-06-09 — superseded by `docs/plans/2026-06-09-issen-grand-plan.md`.** winevt-extract migration era; the codebase has moved well past it (parked).

---

# Migration Plan: issen → winevt-extract

## Context

`winevt-forensic` is a sibling workspace at `../winevt-forensic`. It has been
refactored so that all EID-aware typed extraction lives in one place:

| Layer | Location | Responsibility |
|---|---|---|
| Raw binary parsing | `winevt-forensic/crates/winevt-core` | `EvtxEvent`, `LogonSession`, `ProcessEvent` structs |
| Typed field extraction | `winevt-forensic/crates/winevt-extract` | `lateral_movement()`, `rdp_sessions()`, `process_cmdlines()`, etc. |
| Semantic schemas | `forensicnomicon/src/evtx.rs` | `LateralMovementEvent`, `RdpSessionEvent`, `ProcessExecution`, `EvtxEvent` enum |

**issen currently only depends on `winevt-core`** and re-implements EID-aware
field extraction in two places:

1. `crates/issen-remote-access/src/scanners/lateral_movement.rs` — parses EID
   4648/4769/4776 from raw EVTX directly, duplicating `winevt_extract::lateral_movement()`
2. `crates/issen-evtx/src/session.rs::extract_process_events()` — parses EID
   4688 process events from raw EVTX, duplicating `winevt_extract::process_cmdlines()`

**What is NOT a duplicate and must be kept:**

- `issen-evtx::LateralMovementFinding { src_ip, sessions, reason }` — a
  correlation output that aggregates logon sessions by source IP. Different
  from `forensicnomicon::evtx::LateralMovementEvent` (a per-event extraction).
- `issen-evtx::find_lateral_movement()` — correlation logic over `LogonSession`
  slices. Keep.
- `issen-evtx::correlate_sessions()` — session correlation. Keep.
- `issen-navigator::analyze_lateral_movement()` — detection heuristic. Keep.

---

## Goal

Replace the two duplication sites with calls to `winevt-extract`, so issen
owns correlation and detection while winevt-forensic owns extraction.

---

## Step 1 — Add `winevt-extract` to the workspace

**File:** `Cargo.toml` (workspace root)

In `[workspace.dependencies]`, under the winevt-forensic block, add:

```toml
winevt-extract  = { path = "../winevt-forensic/crates/winevt-extract" }
```

The existing entry is:
```toml
winevt-core     = { path = "../winevt-forensic/crates/winevt-core" }
```

Add the new line directly below it.

---

## Step 2 — Migrate `issen-remote-access` lateral movement scanner

**File:** `crates/issen-remote-access/Cargo.toml`

Add `winevt-extract.workspace = true` to `[dependencies]`.

**File:** `crates/issen-remote-access/src/scanners/lateral_movement.rs`

`LateralMovementScanner` currently opens the EVTX file and iterates raw
records looking for EID 4648/4769/4776. Replace its EVTX parsing with a call
to `winevt_extract::lateral_movement(path)`, which returns
`Vec<forensicnomicon::evtx::LateralMovementEvent>`.

Each `LateralMovementEvent` has:
- `timestamp: String`
- `event_id: u32` (4648, 4769, or 4776)
- `source_user: Option<String>`
- `target_user: Option<String>`
- `target_host: Option<String>`
- `logon_type: Option<u32>`
- `auth_package: Option<String>`
- `encryption_type: Option<String>`

Map these fields to the existing `RemoteAccessFinding` output struct.
The scanner's public interface (`CategoryScanner` impl, `scan()` signature)
must not change — only the internal parsing is replaced.

**TDD:** Write tests first asserting the scanner produces correct findings
from a known EVTX corpus file. The existing tests in `lateral_movement.rs`
(lines ~241–339) already cover this — update them to use the new code path.

---

## Step 3 — Migrate `issen-evtx::extract_process_events()`

**File:** `crates/issen-evtx/Cargo.toml`

Add `winevt-extract.workspace = true` to `[dependencies]`.

**File:** `crates/issen-evtx/src/session.rs`

`extract_process_events(events: &[EvtxEvent]) -> Vec<ProcessEvent>` currently
filters raw `EvtxEvent` slices for EID 4688 and extracts process fields.

Replace with `winevt_extract::process_cmdlines(path)`, which returns
`Vec<forensicnomicon::evtx::ProcessExecution>`. Each `ProcessExecution` has:
- `timestamp: String`
- `event_id: u32`
- `pid: u64`, `parent_pid: u64`
- `image: String`, `command_line: String`
- `parent_image: Option<String>`
- `is_lolbin: bool`

The function signature of `extract_process_events` changes from taking
`&[EvtxEvent]` to taking `&Path`. Update all call sites — they are in
`session.rs` itself and `lib.rs::analyse_evtx_sessions()`.

`winevt-core::ProcessEvent` can be replaced by
`forensicnomicon::evtx::ProcessExecution` at the call sites, or a thin
`From<ProcessExecution> for ProcessEvent` impl can bridge them if
`ProcessEvent` is used widely elsewhere in issen.

**TDD:** Write tests first asserting `extract_process_events` returns the
correct process list from a corpus file containing EID 4688 events.

---

## Step 4 — Verify no remaining raw EVTX EID parsing in issen

After Steps 2 and 3, run:

```bash
grep -rn "4648\|4769\|4776\|4688\|EvtxParser\|records_json_value" \
  crates/issen-remote-access/src \
  crates/issen-evtx/src
```

Any remaining hits for `EvtxParser` or `records_json_value` that duplicate
extraction already in `winevt-extract` should be reviewed and migrated.
Hits in correlation/session code that operate on already-parsed structs are fine.

---

## Step 5 — Compile and test

```bash
cargo check --workspace
cargo test --workspace
```

All existing tests must pass. The public API surface of `issen-evtx` and
`issen-remote-access` must not change (callers in `issen-cli`, `issen-navigator`,
etc. should compile without modification).

---

## What stays in issen (do not migrate)

| Code | Location | Reason |
|---|---|---|
| `correlate_sessions()` | `issen-evtx/src/session.rs` | Session correlation, not extraction |
| `find_lateral_movement()` | `issen-evtx/src/session.rs` | Correlation over `LogonSession` slices |
| `LateralMovementFinding` struct | `issen-evtx/src/session.rs` | Correlation output, different from `LateralMovementEvent` |
| `find_orphaned_sessions()` | `issen-evtx/src/session.rs` | Correlation logic |
| `analyze_lateral_movement()` | `issen-navigator/src/investigation/analysis.rs` | Detection heuristic |
| `frequency_analysis()` | `issen-evtx/src/analyze.rs` | Statistical analysis |
| `pivot_sessions_by_src_ip()` | `issen-evtx/src/analyze.rs` | Correlation pivot |
| All of `logon_chain.rs` | `issen-evtx/src/` | Chain-of-custody correlation |
| All of `net_correlation.rs` | `issen-evtx/src/` | Network correlation |

---

## Strict TDD requirement

Per project standards: **two separate commits per change**:

1. **RED commit** — write failing tests that assert the new behaviour (calling
   `winevt_extract::*` functions). Tests must fail before implementation.
2. **GREEN commit** — implement the migration to make tests pass.

Do not write implementation before tests. Do not combine RED and GREEN in one
commit.
