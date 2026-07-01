# 0001. Multi-repo fleet architecture with five navigation primitives

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

Digital forensics spans radically different sources — disk images, memory dumps,
event logs, live-endpoint queries, content-addressed stores — and each demands
deep, format-specific expertise to parse correctly. A single monolithic tool
that tried to own all of it would be shallow everywhere and impossible to version
or test in isolation. We also wanted each artifact-family library to be reusable
by others (published to crates.io) independent of the correlation tool on top.

## Decision

issen is a **thin orchestrator** layered over a family of standalone forensic
libraries; each library is a deep, self-contained expert in one artifact family,
and issen provides the wiring, cross-artifact correlation, timeline, and CLI.

The architecture is organized around **five navigation primitives**, each with
its own address space and traversal rule:

- `[P]` **Disk** — `name → inode → block` (filesystem tree traversal)
- `[M]` **Memory** — `PID → EPROCESS → virtual address → physical address` (page-table walk)
- `[L]` **Log** — `timestamp / record-number → record boundary → field decode` (stream seek)
- `[Q]` **Live Query** — `(endpoint, query, cursor) → result rows` (data produced, not retrieved)
- `[C]` **Content-Addressed** — `hash → blob → content graph` (Merkle DAG traversal)

Crates are organized into architectural layers (KNOWLEDGE, CONTAINER, FILESYSTEM,
PAGING, OS STRUCTURE, LOG FORMAT, QUERY ENGINE, GRAPH NAVIGATION, PARSER,
ORCHESTRATION) with a strict downward dependency direction. A cross-cutting
state-history functor `[H]` lifts each base primitive to a time-indexed variant.

## Consequences

Each library versions, tests, fuzzes, and publishes independently; a fix to one
parser ships without touching the fleet. The five-primitive model gives a
consistent mental model for adding a new source: identify its address space, then
its layer. PARSER crates are medium-agnostic (they accept `Path`/`&[u8]`/records
and never import a container or filesystem crate), so the same parser serves a
live path, a mounted image, and carved memory bytes.

The cost is coordination overhead: a change touching many crates was a
multi-publish, topological campaign across ~25 polyrepos (the forensicnomicon-1.0
migration published ~70 crate versions). That pain motivated the later monorepo
consolidation (`docs/plans/2026-06-29-fleet-monorepo-consolidation.md`), which
keeps this layered architecture and per-crate crates.io publishing while
collapsing the source into one workspace with coordinated releases.

## References

- `CLAUDE.md` — "Multi-Repo Architecture", "The Layer Hierarchy", "The five navigation primitives", "Practical Decision Rule"
- `docs/plans/2026-06-29-fleet-monorepo-consolidation.md` — coordinated-release evolution
- The original 2026-06-09 fleet-hierarchy-reorg design (layer taxonomy) is in git history: `git log --follow -- docs/plans/2026-06-09-fleet-hierarchy-reorg.md`
- Orchestration crates: `crates/issen-*`, `crates/forensic-pivot`, `crates/issen-correlation`
