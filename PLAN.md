# Development Plan

## Goal

Align RapidTriage's current code with the promised scenario output and close the gap between:

- what the code actually observes
- what the correlation layer infers
- what the CLI prints
- what the documentation claims is "verbatim"

The immediate target is the Linux CTF / forensic scenario and the `rt analyse` flow, but the plan is structured so the improvements generalize to future cases.

## Core Principle

RapidTriage should distinguish clearly between:

- `Observed`
  - directly present in parsed artifacts
- `Correlated`
  - derived by joining observed facts across sources
- `Inferred`
  - likely explanation, but not directly proven

This distinction should exist in:

- internal evidence models
- correlation findings
- CLI output
- documentation wording

## Current Gaps

### 1. Thread Display Semantics

Current parser behavior:

- `process_name` comes from the main thread (`tid == pid`)
- `thread_names` only contains non-main-thread names

This means the current code would surface:

- `process_name = "top"`
- `thread_names = ["libuv-worker"]`

It would not surface:

- `Thread names: libuv-worker, top`

### 2. Hardcoded Narrative Strings

`rt analyse` still contains hardcoded miner / rootkit / tunnel prose in `crates/rt-cli/src/commands/analyse.rs`.

That creates drift between:

- current detection logic
- current correlation rules
- current docs

### 3. Correlation Findings Are Not Human-Readable Enough

Current correlation findings expose:

- `rule_id`
- `title`
- `severity`
- `evidence_ids`

They do not expose:

- rendered evidence lines
- calibrated explanation text
- confidence
- assertion level

### 4. Tunnel / Miner Claims Are Overstated

Current logic can support:

- hidden `ssh` process
- local port `3333`
- remote connection to port `22`
- hidden process connected to `127.0.0.1:3333`

Current logic cannot fully prove:

- the forward destination is a mining pool
- all miner traffic exits only as SSH
- the exact remote `<pool>` target

### 5. Rootkit Hook Claims Are Overstated

Current code detects:

- `ld_preload` indicator

Current code does not prove:

- exact hooked libc functions for `libymv.so.3`

### 6. Documentation Drift

The scenario document is still not truly verbatim against current code, even after revision.

## What We Can Build

### Yes

We can truthfully build:

- richer hidden-process/thread presentation
- `CORRELATION FINDINGS` output
- human-readable evidence rendering
- calibrated correlation explanations
- correlation-driven narrative output
- a truly verbatim documented sample generated from current code

### Yes, But As Inference

We can support these only as calibrated inferences:

- `likely XMRig or compatible miner`
- `consistent with SSH local-port-forward carrying miner traffic`

### No, Not Honestly, Without New Capabilities

We should not print these as facts unless new evidence sources are added:

- exact hooked functions like `readdir64()` / `opendir()`
- actual `<pool>` destination behind the SSH tunnel
- definitive statement that all miner traffic exits only as SSH

## Workstreams

## Workstream 1: Evidence Truth Model

### Objective

Extend findings and output so the system can explicitly mark whether a claim is observed, correlated, or inferred.

### Changes

- extend `rt-correlation::model::Finding`
- add:
  - `summary`
  - `explanation`
  - `confidence`
  - `assertion_level`
  - `evidence_rendered`

### Assertion Level Enum

Add something like:

- `Observed`
- `Correlated`
- `Inferred`

### TDD Sequence

1. Add failing tests for finding model carrying assertion/confidence/rendered evidence
2. Implement model changes
3. Update correlation engine outputs
4. Update CLI rendering tests

## Workstream 2: Hidden Process Thread Model

### Objective

Make the parser capable of supporting both:

- machine-accurate semantics
- richer CLI display semantics

### Changes

In `rt-parser-uac` hidden process analysis:

- keep main thread / process name semantics explicit
- add:
  - `main_thread_name`
  - `non_main_thread_names`
  - `all_thread_names`

Possible shape:

- keep `process_name` as-is for compatibility
- rename `thread_names` to `non_main_thread_names`
- add `thread_names_all`

If a compatibility rename is too disruptive in one step:

- keep `thread_names` as current behavior
- add `all_thread_names`

### TDD Sequence

1. Add failing parser test proving `all_thread_names` includes both `top` and `libuv-worker`
2. Implement model extension in `rt-parser-uac`
3. Update CLI display logic to use `all_thread_names` when desired
4. Preserve current hidden-process tests for non-main-thread behavior

## Workstream 3: Human-Readable Evidence Rendering

### Objective

Replace raw evidence IDs like `rk-1, proc-14, net-16` with meaningful rendered lines.

### Changes

Add an evidence rendering layer in `rt-correlation`:

- render rootkit evidence
- render process evidence
- render network evidence
- render CPU anomaly evidence

Examples:

- `ld_preload /lib/x86_64-linux-gnu/libymv.so.3`
- `PID 977 "top" [thread: libuv-worker]`
- `127.0.0.1:59182 -> 127.0.0.1:3333 [ESTABLISHED]`

### TDD Sequence

1. Add failing tests for evidence rendering by kind/source/attrs
2. Implement render helpers
3. Attach rendered evidence to findings
4. Update `rt analyse` output tests

## Workstream 4: Correlation-Driven Narrative

### Objective

Stop encoding miner/rootkit/tunnel explanations directly in `analyse.rs`.

### Changes

Move explanation ownership into:

- correlation rule metadata
- rendered findings

Then reduce `build_narrative()` until it either:

- delegates entirely to correlation findings, or
- only prints generic fallback text when no correlation finding exists

### TDD Sequence

1. Add failing integration test for `rt analyse` output using correlation-generated summaries
2. Extend YAML rule schema with:
  - `summary_template`
  - `explanation_template`
  - `assertion_level`
  - `default_confidence`
3. Implement template rendering in `rt-correlation`
4. Update `analyse.rs` to render correlation findings instead of hardcoded miner prose
5. Remove duplicated logic from `build_narrative()`

## Workstream 5: Terminology Cleanup

### Objective

Make naming consistent with the current architecture.

### Changes

- replace `PIVOT FINDINGS` with `CORRELATION FINDINGS`
- rename `evaluate_pivot` module/function over time to `evaluate_correlation`
- keep temporary compatibility aliases only if needed during transition

### TDD Sequence

1. Add failing output test expecting `CORRELATION FINDINGS`
2. Update CLI output
3. Rename function/module surfaces
4. Remove stale "pivot" wording from docs/comments/tests where possible

## Workstream 6: Calibrated Miner / Tunnel Claims

### Objective

Make miner and SSH-tunnel output say only what the current evidence supports.

### Changes

Rule outputs should distinguish:

#### Observed

- hidden process exists
- `libuv-worker` thread observed
- hidden process connects to `127.0.0.1:3333`
- hidden `ssh` process has `3333` listener
- hidden `ssh` process has established connection to remote `:22`

#### Correlated

- hidden miner likely using local port-forwarding over SSH

#### Inferred

- likely XMRig or compatible miner
- likely tunneling miner traffic through SSH

### Output Policy

Prefer:

- `consistent with`
- `likely`
- `compatible miner`

Avoid:

- `proves`
- `all traffic exits as SSH`
- explicit `<pool>` unless actually observed

### TDD Sequence

1. Add failing tests for calibrated finding wording
2. Move tunnel/miner wording into rule metadata
3. Update CLI output

## Workstream 7: Rootkit Narrative Calibration

### Objective

Stop claiming exact hook behavior unless it is actually evidenced.

### Changes

Default wording should become:

- `LD_PRELOAD rootkit/library configured`
- `consistent with userspace process hiding`

Only print exact hooked functions if one of these exists:

- reverse-engineering module for the library
- YARA/signature metadata identifying the family and its hooks
- catalog entry in `forensic-catalog` with evidentiary basis

### TDD Sequence

1. Add failing output test rejecting exact hook-function claims by default
2. Update `analyse.rs` / correlation rule templates
3. Add optional extension point for family-specific enrichment later

## Workstream 8: Verbatim Output Regeneration

### Objective

Make the scenario doc truly match current code.

### Changes

Add a full integration / snapshot test for this scenario:

- run `rt analyse` against the scenario fixture
- snapshot the output
- update documentation from the snapshot

If the fixture cannot be checked into the repo:

- create a stable fixture harness that synthesizes the relevant artifacts

### TDD Sequence

1. Add failing integration test for full `rt analyse` output
2. Capture snapshot
3. Make code changes until snapshot matches desired calibrated output
4. Update `docs/ctf-submission-linux-forensic-scenario.md`
5. Change wording from `verbatim` to `representative` only if a real snapshot cannot be maintained

## Workstream 9: Stronger Miner Confirmation

### Objective

Support stronger conclusions when stronger evidence exists.

### Changes

Introduce tiered miner conclusions:

- `likely_xmrig_or_compatible`
  - from `libuv-worker` + miner ports + hidden process + CPU anomaly
- `confirmed_xmrig`
  - requires one of:
    - process name `xmrig`
    - YARA hit
    - binary hash / signature hit
    - direct command-line artifact

### TDD Sequence

1. Add failing rule tests for `likely` vs `confirmed`
2. Add enrichment tags from YARA/signature/process-name sources
3. Update rule pack and output rendering

## Recommended Order

1. Add integration snapshot test for the scenario
2. Rename `PIVOT FINDINGS` to `CORRELATION FINDINGS`
3. Add evidence rendering in `rt-correlation`
4. Extend findings with summary/explanation/confidence/assertion level
5. Add `all_thread_names` support in `rt-parser-uac`
6. Rework `analyse.rs` to use correlation-driven rendering
7. Recalibrate tunnel/miner/rootkit wording
8. Add stronger miner confirmation tiers
9. Regenerate the scenario doc from actual output

## Deliverables

### Parser Layer

- richer hidden-process thread model

### Correlation Layer

- richer finding model
- evidence rendering
- calibrated summary/explanation templates
- assertion levels

### CLI Layer

- `CORRELATION FINDINGS`
- reduced hardcoded narrative logic
- snapshot-tested scenario output

### Docs

- scenario doc updated to match actual current output
- wording calibrated to evidence level

## Success Criteria

The plan is complete when:

- the current code can generate output that is either truly verbatim or intentionally marked as representative
- miner/rootkit/tunnel conclusions are calibrated to available evidence
- the doc no longer promises behavior the code does not implement
- `rt analyse` relies primarily on structured correlation findings rather than hardcoded scenario prose
