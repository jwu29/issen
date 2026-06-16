# Unified Timeline Workflow — Design

**Status:** approved (2026-06-16). Implementation in phases, strict TDD.
**Reviewers:** Claude (Opus 4.8) author; Codex adversarial critique folded in.

## Executive Summary

`issen` has three timeline-facing commands whose powers don't compose:

- **`ingest`** runs the *real* pipeline — `issen_fswalker::orchestrator::run_auto` auto-discovers
  and parses **all** artifacts via the 20-parser inventory registry → DuckDB `TimelineStore`
  (plus an optional YARA/Sigma/IOC scan phase).
- **`timeline <db>`** queries that DuckDB (raw events, filters, export).
- **`supertimeline <collection>`** is a **stub**: it bypasses `run_auto` and hand-reads exactly
  **three hardcoded files** (`chkrootkit/etc_ld_so_preload.txt`, `memory_dump/output-sockstat`,
  `hidden_pids_for_ps_command.txt`), all with `timestamp = 0`, then runs five bundled
  `TemporalRule`s over them. Its docstring falsely claims "parses all artifacts." The temporal-rule
  *engine* is good; its event *source* is fake (a No-Special-Cases violation).

**The fix and the simplification are the same change:** route `supertimeline`'s narrative through
the real pipeline, then make the narrative a *view over the persisted DuckDB* rather than a re-parse.
The analyst stops choosing between "fast narrative" and "reusable DB" — one command gives both.

**Guiding principle (Codex's load-bearing correction): parse once, persist *explicitly*, analyze
many ways — querying must NEVER silently mutate state.** `timeline` stays a pure read; all
ingest/cache/orchestration "magic" lives only in `supertimeline`, which loudly announces which DB it
used or created and never writes inside the evidence tree.

## Command surface (target)

```
issen ingest <evidence> -o case.duckdb        # explicit parse -> DB (run_auto + optional scan)   [unchanged]
issen timeline case.duckdb [--filters] [--format table|jsonl|csv]   # PURE query of raw events; never ingests
issen timeline case.duckdb --narrative        # temporal-rule narrative over the DB
issen correlate case.duckdb                   # cross-artifact findings over the same DB (rename -> `findings` later)
issen supertimeline <evidence|db> [--workspace DIR] [--reingest] [--db-out PATH]
                                              # smart front door: ingest-if-evidence (announced) -> persist -> narrate
issen report case.duckdb                      # HTML report over the DB
```

Three analysis surfaces over ONE substrate — keep them distinct (different abstraction levels):
1. **timeline events** — normalized facts.
2. **temporal rule hits** (`--narrative`) — relationships over timing/sequence.
3. **cross-artifact findings** (`correlate`) — higher-level detections.
Unify the *input* (one DuckDB) and *rule ownership* (`issen_correlation`), not the output surfaces.

## Phased implementation (each phase = RED commit + GREEN commit, separate)

**Phase 0 — stub-fix (FIRST, self-contained, highest value).**
Replace `supertimeline`'s 3-file `collect_events_from_dir` with `run_auto`. The narrative now
operates on all artifacts; temporal rules get real timestamps. RED: a `$J` (USN journal) fixture is
surfaced by supertimeline's event collection (fails on the stub). GREEN: `collect_events_from_dir`
delegates to `run_auto`. No schema change.

**Phase 1 — narrative as a view over the DB.**
`issen timeline <db> --narrative`: load events from the DuckDB, apply temporal rules, emit narrative.
RED: `--narrative` over a DB with a hollow-process pair yields the finding. GREEN: implement the flag.

**Phase 2 — rule registry in `issen_correlation`.**
Move the five bundled `TemporalRule`s out of the CLI into a shared registry so `correlate` and
`--narrative` share one rule set. RED: registry returns the named rules. GREEN: relocate + re-export;
CLI consumes the registry.

**Phase 3 — `supertimeline` smart front door.**
Accept evidence OR a `.duckdb`. If evidence: ingest to a managed workspace DB (NEVER in the evidence
tree), announce the DB path + ingest summary, then run the Phase-1 narrative view over it. `--reingest`
forces re-parse; otherwise reuse a cached DB whose manifest still matches. RED: given evidence,
supertimeline creates a DB outside the evidence dir and prints its path; second run reuses it. GREEN:
implement workspace + manifest + announce.

**Phase 4 — forensic soundness (designed in, not retrofitted).**
- **Provenance per event** in `TimelineStore`: parser name+version, source artifact path, original
  timestamp field name, normalization, byte offset / record id, ingest id. Every narrative line and
  rule hit points back to event ids.
- **`timestamp_quality`** (or nullable timestamp): `0` must not mean "unknown"; rules distinguish
  known-epoch from missing.
- **Partial-ingest honesty**: narrative declares completeness ("based on 18/20 parsers; 2 failed").
- **Visible, manifest-keyed cache**: key on canonical path + size/mtime + parser-inventory-version +
  issen version + scan config (not path alone); print what was reused; lock file for concurrency;
  schema-migration / refusal behavior.
- **Deterministic ordering** (timestamp, source priority, event id; equal timestamps are common) and
  an explicit display-timezone policy (UTC internal).

## Forensic guardrails (binding for every phase)

- **Querying never parses/persists.** Only `ingest` and `supertimeline` touch evidence, and
  `supertimeline` announces every DB it creates/reuses.
- **No writes inside the evidence tree** — no DBs, sidecars, lock files, temp, or extraction there.
- **A narrative without provenance is unauditable** — provenance is a Phase-4 *requirement*, not
  polish.

## Out of scope (future)

`correlate` -> `findings` rename; remote-source streaming (currently a stub in `ingest`); GUI.
