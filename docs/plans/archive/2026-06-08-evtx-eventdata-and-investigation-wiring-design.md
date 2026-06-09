# Design — EVTX EventData enrichment + wiring the investigation engine

Date: 2026-06-08. Author: Claude (Opus 4.8).

> **ARCHIVED 2026-06-09 — Part 1 (EVTX EventData flattening) IMPLEMENTED** via commits `78d34ce` (RED) / `b4d43f3` (GREEN): `record_to_event` now losslessly flattens EventData/UserData into `TimelineEvent.metadata`. **Part 2 (wire the investigation `analyze()` engine) was NOT implemented** — `analyze()` remains unwired dead code; that work is tracked by the active `2026-06-09-closing-case001-capability-gaps.md` (Workstream C+D — ATT&CK findings). Kept for the Part 2 design + open questions.

## Problem

1. **EVTX is parsed shallow.** `issen-parser-evtx::record_to_event`
   (`crates/parsers/issen-parser-evtx/src/lib.rs:162`) takes the third-party
   `evtx` crate's full per-record JSON (System **and** EventData) but copies only
   System fields (`event_id`, `record_id`, `provider`, `channel`) into
   `TimelineEvent.metadata`, plus 3 hardcoded EventData fields (`logon_id` for
   4688/4624, `logon_type` for 4624). Every other EventData field — `Image`,
   `CommandLine`, `ParentImage`, `TargetFilename`, `SubjectUserName`,
   `IpAddress`, `ServiceName`, `ServiceFileName` … — is discarded. Consequence:
   real SigmaHQ rules (which match those fields) cannot fire; only
   `event_id`/`provider`/`Description`-keyed rules work.

2. **A richer ATT&CK investigation engine is dead code.**
   `issen-navigator/src/investigation/analysis.rs` — `analyze(alerts, input) ->
   Vec<AnalysisResult>` with 11 IR-question analyzers (system_compromised,
   initial_access, malware_tools, rootkit, resource_abuse, persistence,
   active_access, lateral_movement, hidden_processes, evidence_tampering,
   attack_timeline), each producing `answer ∈ {Yes,No,Inconclusive}`,
   `confidence`, narrative `interpretation`, and `mitre_techniques`. Nothing
   calls it. Its `AlertInput` (`alerts/types.rs:93`) bundles parsed artifacts;
   the Windows-relevant fields are `windows_events: &[WindowsEvent]`,
   `mft_entries: &[MftFileEntry]`, `connection_log: &[TimestampedConnection]`.
   `WindowsEvent.description` is documented as "assembled from EventData fields".

**The link:** Part 1 is a prerequisite for Part 2 quality — the Windows IR
analyzers reason over `WindowsEvent.description` + event semantics; that
description is only as rich as the EventData we extract.

## Constraints

- **No GPL contamination.** Hayabusa is GPL-3.0. We replicate the *capability*
  (full EventData flattening, Sigma-ready field maps) using clean-room logic and
  Microsoft's public event schemas. No Hayabusa source is read or copied.
- **Knowledge → forensicnomicon.** Field *catalogs* / aliases are knowledge;
  flattening *logic* is mechanical and stays in the parser layer.
- **Strict TDD**, separate RED/GREEN commits.
- The third-party `evtx` crate is Apache-2.0/MIT — fine. (winevt-forensic's
  binxml is currently System-only and *less* capable, so we do not route through
  it for this change.)

## Part 1 — EVTX EventData flattening (implement now, TDD)

### Approach
Replace the hardcoded `match event_id { 4688 => …, 4624 => … }` block in
`record_to_event` with a generic flattener that walks `Event.EventData` and
`Event.UserData` and inserts every `Name → value` pair into `metadata`.

A new pure helper (parser layer):
```
fn collect_event_data(data: &Value, out: &mut HashMap<String, Value>)
```
Handles the two JSON shapes the `evtx` crate emits:
- **Named map**: `"EventData": { "TargetUserName": "jdoe", "LogonType": "10" }`
  → insert each key/value.
- **Data array**: `"EventData": { "Data": [ {"#attributes":{"Name":"Image"},
  "#text":"C:\\…"}, {"#text":"orphan"} ] }` → for each element, key =
  `#attributes.Name`, value = `#text`; unnamed `Data` entries collected under a
  synthetic `Data` (or `DataN`) key so nothing is silently dropped.
- Skips the JSON-meta keys `#attributes` / `#text` as literal metadata keys.
- Values: keep strings as-is; stringify scalars (number/bool) for Sigma string
  matching; skip nested objects/null (no deep recursion beyond the two shapes).

### Robustness (distrust real data)
- **Cap** per-record fields (e.g. ≤ 64) and per-value length (e.g. ≤ 4096 chars,
  truncate with marker) to defend against pathological records / metadata bloat.
- Field-name collision with System keys: EventData wins for its own namespace but
  never overwrites `event_id`/`record_id` (System set first; EventData skips
  those reserved keys).
- Never panic; missing EventData → no-op.

### Backward compatibility
Keep emitting `logon_id` (parsed int) and `logon_type` (parsed int) for 4688/4624
so existing consumers/tests stay green — derived *after* the generic flatten, from
the now-present raw `SubjectLogonId`/`TargetLogonId`/`LogonType`.

### TDD test list (RED → GREEN)
1. 4624 with rich EventData → metadata has `TargetUserName`, `IpAddress`,
   `WorkstationName`, `LogonType`, `TargetLogonId` (raw) **and** legacy
   `logon_id`/`logon_type`.
2. Sysmon-1-style EventData {Image, CommandLine, ParentImage, User} → all four in
   metadata.
3. `Data`-array shape with `#attributes.Name` → named keys extracted, no literal
   `#attributes`/`#text` keys leak.
4. Unnamed `Data` entry → preserved under fallback key, not dropped.
5. Value-length cap truncates an oversized CommandLine.
6. Field-count cap respected.
7. Reserved keys (`event_id`/`record_id`) not clobbered by malicious EventData.
8. No EventData / UserData present → behaves like today (System-only metadata).
9. UserData (provider-specific) flattened.

### Downstream payoff (no extra code)
`scanning::event_to_map` already clones `metadata` into the Sigma evaluation map,
so flattened fields become Sigma-matchable immediately → real SigmaHQ Windows
rules fire → `findings_to_attack_chain` renders a real multi-tactic chain.

### Optional knowledge layer (defer unless cheap)
A `forensicnomicon` field-alias catalog (Sigma field name ⇄ EVTX field) +
high-value-event list — the clean-room analogue of Hayabusa's `eventkey_alias`.
Flagged as follow-up; the generic flattener delivers the core capability without
it.

## Part 2 — Wire the investigation engine (design; implement after critique)

### Current reachability gap
`analyze()` needs (a) `Vec<Alert>` and (b) `AlertInput`. On the disk-image path
only `windows_events`, `mft_entries`, `connection_log` are populatable; the
UAC/Linux slices stay empty. Need: an adapter that builds `AlertInput` from the
ingested timeline + a `WindowsEvent` projection from EVTX TimelineEvents (now
rich, thanks to Part 1), an alert producer, and a surface for `AnalysisResult`.

### Proposed wiring (smallest viable)
1. **Projection**: `timeline (EventLog rows) -> Vec<WindowsEvent>` — map
   event_id/channel/provider/computer/timestamp; build `description` from the
   flattened EventData (Part 1). `mft_entries` from MFT rows.
2. **Alerts**: reuse the existing `investigation::alerts` detector (confirm its
   entry point) to turn `AlertInput` into `Vec<Alert>`.
3. **Analyze**: `analyze(&alerts, &input) -> Vec<AnalysisResult>`.
4. **Surface**: render `AnalysisResult` in the HTML report as an "Investigation"
   section (IR question → answer/confidence/MITRE/narrative), above the attack
   chain. Optionally a `issen investigate <db>` subcommand emitting the same.
5. Keep epistemics honest: answers are `Inconclusive` by default; narratives use
   "consistent with", MITRE is "consistent with", never a verdict.

### Open questions for the critic
- Is the timeline DuckDB a sufficient source to reconstruct `WindowsEvent`/MFT
  inputs, or do the analyzers need raw artifacts not persisted to the timeline?
- The analyzers were written for UAC/Linux semantics; how many actually fire
  meaningfully on a Windows-disk `AlertInput` where only windows_events/mft are
  populated? Which degrade to `Inconclusive` noise and should be filtered?
- Build a `WindowsEvent` projection vs. populating `AlertInput` straight from
  parsed records before they're lossily flattened into the timeline?
- Risk of double-maintaining two ATT&CK surfaces (findings→chain vs.
  analyze()→AnalysisResult). Should the chain be *derived from* AnalysisResult
  instead, unifying them?

## Sequencing
Part 1 first (unlocks real detections + improves Part 2 inputs), shipped via
TDD. Part 2 implemented only after this design survives adversarial review and
the open questions are resolved.
