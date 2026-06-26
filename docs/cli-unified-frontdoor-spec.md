# Design Spec: One Front Door for issen — answers, not stages

Status: **prototype built + validated (2026-06-26)** — decisions locked (see below),
implemented on branch `feat/unified-frontdoor` with strict TDD, and validated
end-to-end on the Case-001 four-source set. Scope: the user-facing CLI surface
only; no analyzer/parser logic changes.

**Validation (Case-001, all 4 sources, one `issen <DC.E01> <DESKTOP.E01> <DC.mem>
<DESKTOP.mem>`):** ingest 434.8s → 2,337,355 events · memory 13.1s → 186 events ·
correlate 222.9s → 9,381 findings · scan 0.0s (no feeds). Case DB: timeline
2,337,541, correlations 9,381, pipeline_state 4×done. **Resume:** re-running the
same four sources skipped all four stages in **0.1s**.

## Executive Summary

**Decision asked:** collapse the analyst-facing pipeline from four overlapping verbs
(`ingest`, `correlate`, `scan`, `analyse`/`supertimeline`) into **one opinionated
front door** that, given evidence, just produces the answer. The stages stay as
internals (for caching, resume, and power-user re-runs) but stop being something the
analyst must understand or sequence.

**Recommendation:** ship a single default command — `issen <evidence…>` (bare, no
subcommand) — that auto-detects disk vs. memory inputs and runs the **full pipeline
complete-by-default**: ingest → correlate → threat-intel scan → memory legs →
findings + plain-English narrative. Completeness is the default; reducing it is an
explicit opt-*out* (`--no-scan`, `--triage`). The default streams high-signal triage
findings first, then completes the full sweep (progressive results), so the analyst
gets first answers fast without choosing a mode. The command is **resumable and
re-entrant**: running `issen <evidence…>` again continues from wherever it stopped and
re-runs only stages whose inputs changed — so there is no need to expose the pipeline
stages as verbs at all. `ingest`, `correlate`, `scan`-as-a-stage are **removed**, not
demoted; their work happens inside the bare path. No `stage` namespace, no `--reuse`.

**Why:** the target persona (an IR analyst mid-incident) should type the evidence path
and get "here's what happened." Today they meet a menu of five commands with
overlapping, undocumented differences — the exact cognitive-load failure the
*common-path-fewest-decisions* and *secure/complete-by-default* principles exist to
prevent.

## Current state (verified this session)

| Command | ingest | correlate | scan | memory | narrative/report |
|---|---|---|---|---|---|
| `ingest` | ✅ | — | only with `--scan` | — | — |
| `correlate` | ✅ | ✅ | — | — | ✅ findings |
| `analyse` | ✅ | ✅ (+memory) | partial | ✅ | ✅ plain-English |
| `supertimeline` | ✅ | ✅ temporal | — | — | ✅ narrative |
| `scan` | — | — | ✅ | — | — |
| `memory` | — | — | — | ✅ | — |
| `report` | — | — | — | — | ✅ HTML from a DB |

`ingest` writes `timeline` / `evidence_sources` / `ingest_log`; `correlate` writes
`correlations` / `correlation_members`; the scan phase (gated behind `ingest --scan`,
`scan: bool` default false) writes `scan_findings`. A bare `ingest` therefore leaves
the correlation and scan tables empty by design — which is what triggered this review.

The problem is not "nothing is combined" — it's **four front doors that each combine a
different subset**, with no single obvious "give me the answer" entry.

## Proposed design

### The default path

```
issen <evidence…>                 # one or many: disk images, collections, memory dumps
  → classify each input (disk vs memory) automatically
  → ingest disk evidence into one unified timeline (per-source tagging)
  → STREAM high-signal triage findings as soon as available  (progressive results)
  → run correlation rules            (fills correlations / correlation_members)
  → run threat-intel scan            (fills scan_findings; bundled signatures always,
                                       cached feeds layered on if present)
  → run memory legs                  (issen memory analyzers, merged into the case)
  → emit: top findings + plain-English narrative to the terminal; full DB on disk
```

Zero flags, zero pipeline vocabulary. **Progressive results:** the analyst sees the
first high-signal triage findings within seconds-to-minutes, while the full sweep
continues to completion underneath — first answers fast, complete answers guaranteed,
no mode to pick. A pointer to the timeline DB and an optional `--report` HTML follow.

### Flags (opt-*out*, for control — not required for the common case)

- `--rerun` (`--force`) — ignore saved stage-state and redo everything (e.g. after a
  parser/rule bugfix). Default is resume — see "Resumable & re-entrant" below.
- `--only <stage>` / `--from <stage>` — power-user/debug escape hatch to force a single
  stage; not needed in normal use (re-running the bare command resumes automatically).
- `--no-scan` / `--no-correlate` — drop a stage when not wanted.
- `--triage` — explicit fast-pass-*only*: skip the full MFT/file-event sweep, emit
  just the high-signal artifacts and stop (for a first look on a huge image when the
  analyst does not want the complete run). Distinct from the default, which *streams*
  triage findings first and then still completes the full sweep.
- `--narrative` / `--report <path.html>` — output shape (terminal story vs HTML).
- `-o <db>` — timeline DB path (already exists).

### Resumable & re-entrant (this is what removes the stage verbs)

`issen <evidence…>` is a declarative target — "bring this case up to date" — not a
sequence of steps. It is safe to run repeatedly and cheap to re-run:

- The case DB records per-stage state: `(stage, status, input-fingerprint)`. Stages:
  ingest (already per-unit resumable, #115), correlate, scan, memory.
- Each run recomputes fingerprints — the evidence set, the correlation-ruleset version,
  the feed snapshot — and runs **only** the stages that are missing, incomplete, or
  stale. Everything up to date is skipped.
- Therefore: interrupted after ingest → next run resumes at correlate; updated feeds →
  next run re-does only scan; edited a rule → next run re-does only correlate. The
  analyst never invokes a stage by name; they just re-run the one command.
- Resume is keyed off the case DB (deterministic path from the evidence, or `-o <db>`),
  so there is no `--reuse` flag — pointing at the same case *is* the resume.

### Degradation rules (never silently do less — fail loud, then continue)

The default runs everything it *can* and names what it couldn't, so "complete by
default" never quietly becomes partial:

- **No cached threat-intel feeds** → scan with bundled signatures only and print
  `threat-intel scan limited: no feeds cached — run 'issen feed update'`. Never skip
  silently; never block.
- **Memory symbols unavailable** (offline/air-gapped workstation) → run the
  symbol-free memory analyzers, print which memory analyses were skipped and why.
- **Large image / time pressure** → still completes; suggest `--triage` in the
  progress banner if ingest exceeds a threshold.

This matches the fleet's batteries-included + fail-loud disciplines: the absence of a
capability is reported with the remedy, not absorbed into an empty result.

### Migration of the existing verbs (one concept, one name) — HARD CUT

No deprecation window, no aliases. Existing callers break at the cut; pre-1.0 semver
permits it and the clean surface is worth more than back-compat here.

The test for whether a verb survives: does it have a use **outside** the case pipeline
that re-running the bare path doesn't already serve?

- `analyse`, `supertimeline`, combined `correlate` (the "give me findings" verbs) →
  **removed**. Their behavior *is* the bare front door now.
- `ingest`, `correlate` (and `scan` *as a pipeline stage*) → **removed as verbs**. They
  are pure stages with no standalone meaning; the resumable bare path runs them and
  `--only <stage>` covers the rare force-one-stage case. No `stage` namespace.
- `memory`, `scan` → survive **only** as ad-hoc tools, not pipeline stages — interactive
  single-dump inspection (`issen memory dump.mem --command netstat`) and scanning loose
  files/IOCs against feeds. Inside a case, both run automatically.
- `pivot` → **folded** (it was a transitional front-end to the correlation engine):
  `pivot sync` = `feed update`; `pivot eval` = the correlate stage (runs inside the
  bare path; the evaluate-an-external-JSON-evidence angle, if kept at all, is a hidden
  integration affordance, not a verb); `pivot rules` → the new `rules` verb below.
- `report`, `timeline`, `info`, `feed`, **`rules`** → distinct verbs that stay
  (render, query, inspect, manage feeds, **list detections**). `rules` is new: lists
  the bundled + dir-loaded correlation/detection rules so an analyst can see "what
  detections do you have?" without running a case.

## What stays separable under the hood (and why that's fine)

Keep the stages as internal functions exactly as today — ingest is the costly,
cacheable foundation; correlate/scan are cheap passes over an existing timeline.
That separability is what makes the resumable, re-entrant bare path possible (run only
the stale stages). The change is purely that the **human** never names a stage: the
pipeline orchestrates them off persisted stage-state; the analyst just re-runs
`issen <evidence…>`.

## Non-goals

- No change to parsers, correlation rules, scan signatures, or the report model.
- No new analysis capability — this is packaging/UX, not detection.
- Not removing power-user control — every current stage stays runnable, just relocated.

## Decisions (locked 2026-06-26)

1. **Front-door form:** bare `issen <evidence…>` — no subcommand, most idiotproof. (An
   explicit `run` alias is optional, not required.)
2. **Old verb names:** **hard cut**, no deprecation/aliases. `analyse`,
   `supertimeline`, combined `correlate`, **and the `ingest`/`correlate` stage verbs**
   are removed — the resumable bare path makes them unnecessary. No `stage` namespace.
   `memory`/`scan` survive only as ad-hoc tools; `report`/`timeline`/`info`/`feed`/
   `rules` stay (`rules` is new — list detections). `pivot` is **folded**: `sync`→
   `feed update`, `eval`→the correlate stage, `rules`→the new `rules` verb. Stage
   control is flags on the bare command (`--rerun`, `--only`).
3. **Scan posture:** **bundled-signatures floor** — scan always runs with the compiled-in
   signatures; cached feeds layer on if present; never blocks, never silently skips.
4. **Triage:** **progressive results** by default (stream high-signal findings first,
   then complete the full sweep). `--triage` is an explicit fast-pass-*only* opt-in.
   Large-evidence handling is *auto-suggest* in the progress banner, never auto-switch
   (auto-switch would silently do less than complete-by-default).

## Validation when built

Re-run the Case-001 four-source set (`CLAUDE.md` → convergence/release validation
corpus): bare `issen <DC.E01> <DESKTOP.E01> <DC.mem> <DESKTOP.mem>` must produce a
populated timeline **plus** non-empty `correlations` and (with feeds) `scan_findings`,
and a terminal narrative — in one invocation, no stage flags.
