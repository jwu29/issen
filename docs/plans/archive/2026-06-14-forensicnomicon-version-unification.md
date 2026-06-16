# forensicnomicon Version Unification — Plan

## Executive Summary

The fleet is fragmented across **three forensicnomicon majors simultaneously** —
`0.3.1`, `0.4.2`, and `0.5.4` all coexist in issen's dependency graph. issen
cannot adopt any 0.5 feature (the immediate driver: the new
`forensicnomicon::report::navigator` ATT&CK-layer API, needed for an
`issen … --navigator-layer` CLI flag) until every crate it bridges is on the
same major. This is the **two-versions-of-a-trait** problem: a trial bump of
issen `0.4 → 0.5` immediately broke `issen-parser-prefetch`, because
`prefetch-forensic`'s `PrefetchAnomaly` implements forensicnomicon **0.4**'s
`Observation` trait and issen-on-0.5 looks for the **0.5** trait's `.code()`.

**Scope:** ~19 external fleet crates across ~10 repos need a forensicnomicon dep
bump + republish, plus issen's own 7 crates. **Most are mechanical version
alignment** (the API is largely forward-compatible — the prefetch break was a
pure version mismatch, not a signature change), but a few touch genuine
breaking points (the report-model evolution and the `#69` `history::profiles →
SourceTemporalProfile` registry change) and need per-crate fixes. Each step ends
in an **irreversible `cargo publish`**. The `memf-*` crates are **gated** on
memory-forensic's in-progress work landing clean.

**Recommendation:** phased, leaf-first, one repo at a time; defer the gated
memory-forensic crates; treat issen-on-0.5 + the navigator flag as the terminal
phase. This is a multi-session campaign, not a single change.

## Current fragmentation (issen `Cargo.lock`, 2026-06-14)

| forensicnomicon | # crates | crates |
|---|---|---|
| **0.3.1** | 18 | apm/gpt/mbr-partition-forensic, gpt/mbr-partition-core, iso9660-forensic, **disk-forensic 0.5.0**, ntfs-core, ntfs-forensic, vmdk-forensic, winevt-core/extract/analysis, browser-core, browser-firefox, memf-correlate, memf-linux, memf-windows |
| **0.4.2** | 8 | **issen-cli, issen-correlation, issen-evtx, issen-parser-pe, issen-parser-prefetch, issen-signatures, issen-timeline** (issen's own) + **prefetch-forensic** |
| **0.5.4** | 3 | shellitem, srum-parser, winreg-artifacts (this session's work) |

Note: the disk-forensic 0.5.0 just published for #71 still pulls forensicnomicon
0.3.1 — registry-izing a dep does **not** align its transitive forensicnomicon.

## Target state

One forensicnomicon major (`^0.5`) across every crate issen consumes, and across
issen's own crates. No duplicate forensicnomicon in the graph.

## Execution order (leaf-first / topological)

**Phase 0 — forensicnomicon `0.5.4`** ✅ DONE (the leaf; already published).

**Phase 1 — readers (`*-core`), no inter-fleet deps.** Bump forensicnomicon →
`^0.5`, compile-verify, version-bump, republish:
- `ntfs-core` (repo: ntfs-forensic)
- `mbr-partition-core`, `gpt-partition-core` (their repos)
- `winevt-core` (repo: winevt-forensic)
- `browser-core` (repo: browser-forensic)
- `memf-*` core-side — **GATED** (memory-forensic)

**Phase 2 — analyzers (`*-forensic`), depend on a core + forensicnomicon.**
Same bump; these may surface report-model breaks:
- `mbr/gpt/apm-partition-forensic`, `ntfs-forensic`, `winevt-analysis`,
  `winevt-extract`, `browser-firefox`, `vmdk-forensic`, `iso9660-forensic`,
  `prefetch-forensic`
- `disk-forensic` — re-bump from 0.3.1 → 0.5 (and re-publish 0.5.1)
- `memf-correlate` — **GATED** (memory-forensic)

**Phase 3 — issen's own crates.** Bump the workspace `forensicnomicon = "0.4"`
→ `"0.5"`, fix the trait-bridge breaks (now that the fleet crates are on 0.5
they resolve), rebuild + test the workspace.

**Phase 4 — wire `issen … --navigator-layer out.json`** (the original goal):
call `forensicnomicon::navigator::report_to_navigator_layer(&report, name)` on
the unified report, behind a CLI flag, with strict TDD.

## Per-crate recipe

1. `forensicnomicon = "0.5"` (or `^0.5`) in the crate's Cargo.toml.
2. `cargo build` — most compile unchanged (API forward-compatible).
3. Fix breaks where forensicnomicon's API shifted across the major:
   - report-model changes (findings schema from `#30`/`#31`),
   - `history::profiles` → `SourceTemporalProfile` registry (`#69`),
   - any `Observation`/`Finding` builder signature changes.
4. `cargo test` (+ clippy `-D warnings` direct, fmt) green.
5. Version-bump (patch/minor), `cargo publish`, push.
6. Sweep dependents' lockfiles forward.

## Risks & constraints

- **Per-crate breaking points** are the real cost: 0.3 → 0.5 spans two majors of
  report-model evolution. Verify each by compile, not assume mechanical.
- **memory-forensic gate:** `memf-linux/windows/correlate` are on 0.3.1; the repo
  had 63 uncommitted files (active memf-windows work) on 2026-06-14. Full
  unification is blocked on that landing clean — do not clobber it. See
  `project_issen_pathdeps_memory_forensic`.
- **Irreversibility:** ~19 `cargo publish` operations. Each needs authorization.
- **Overlap with other tracks:** this subsumes part of **#71** (browser-forensic,
  winevt-forensic publishes also unblock #71 registry flips) and relates to
  **#70** (fleet hierarchy reorg). Sequence them together to avoid double work.
- **No new-crate rate limit** (all are updates), but pace politely.

## Decision

Full unification is the right end-state (one forensicnomicon, no trait splits,
the navigator CLI flag reachable, and several #71 flips unblocked as a
by-product). It is a deliberate multi-session campaign. Recommended start: the
**non-gated Phase 1 readers** (`ntfs-core`, `mbr/gpt-partition-core`,
`winevt-core`, `browser-core`) — lowest risk, no inter-fleet deps — then walk up
the phases, deferring memory-forensic until its tree is clean.

## Progress log

**2026-06-14 — Phase 1 partial (partition trio complete).** Published on
forensicnomicon 0.5: `gpt-partition-core`/`-forensic` 0.5.0,
`mbr-partition-core`/`-forensic` 0.5.0, `apm-partition-core`/`-forensic` 0.5.0
(mbr's optional `gpt-partition-forensic` dep also aligned to 0.5.0). **Every bump
was mechanical — no forensicnomicon 0.3→0.5 API breaks** (confirms the
forward-compatible hypothesis). The partition trio now unblocks `disk-forensic`'s
Phase-2 re-bump (still on 0.3.1).

Remaining Phase-1 readers are blocked by **active uncommitted work** (do not
clobber): `ntfs-forensic` (deleted fuzz target + lock), `winevt-forensic` (59
dirty files). `browser-forensic` has only a dirty `Cargo.lock` (a multi-crate
repo — browser-core/chrome/firefox/safari — left for a focused pass).
