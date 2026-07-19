# issen — capstone orchestrator

**The SecurityRonin forensic-fleet constitution now lives at `~/src/ronin-issen/CLAUDE.md`.**
issen's `CLAUDE.md` was ~95% fleet-wide governance, so it was lifted to the umbrella root on
2026-07-19 (the fleet/capstone split). Every fleet component inherits it — directly via the
`@import` below now, and via parent-dir `CLAUDE.md` loading once repos move under
`ronin-issen/components/`. See `~/src/ronin-issen/REORG.md` §5.5 / §7.9 for the decision.

@~/src/ronin-issen/CLAUDE.md

---

## issen-specific (capstone) guidance

issen is the fleet's **orchestrator / capstone**: it ingests evidence, runs the disk and memory
legs, correlates, and emits the super-timeline into DuckDB. All fleet law — the layer hierarchy,
the `forensicnomicon::report` model, crate naming, the reader/analyzer (`core`/`forensic`) split,
dependency preference, the Paranoid-Gatekeeper security standard, batteries-included builds, the
egui GUI standard, the README / corpus / validation / release / secrets / distribution standards —
is inherited from the constitution above; do not restate it here.

issen's own design lives under `docs/` (`ARCHITECTURE.md`, `issen-vs-plaso-architecture.md`, the
correlation/ingestion/timeline ADRs in `docs/decisions/`, the `docs/validation.md` capstone
validation report, and the Case-001 Szechuan convergence walkthrough). Put guidance that applies
to **more than one** fleet repo in the constitution, not here; keep this file to what is specific
to the issen orchestrator itself.

<!-- Post-reorg note: once issen moves to ronin-issen/components/orchestrator/issen, the @import
     above becomes redundant with parent-dir CLAUDE.md auto-loading and can be dropped. -->
