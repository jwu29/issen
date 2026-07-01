# PLAN — Fleet monorepo consolidation

**Supersedes:** the earlier 2026-06-09 fleet-hierarchy-reorg design (folder-move A/B/C options; in
git history) and item **#70** in `2026-06-22-monday-morning-plan.md` ("fleet hierarchy reorg —
DEFERRED, gated on backup"). **Date:** 2026-06-29 · **Status:** proposal, gated on backup (see Gate 0).

## Executive Summary

The 2026-06-09 plan framed the fleet's manageability problem as a *folder* problem and proposed
moving ~25 independent git repos into a hierarchical directory tree, while keeping each as its own
repo. It correctly identified that any physical move was **gated on de-risking the cross-repo
`path = "../x"` dependencies by moving them to registry (crates.io) versions** (its Phase 2).

**That gate is now cleared.** The forensicnomicon-1.0 fleet migration (2026-06-29) published ~70
crate versions and moved every dependent onto registry deps at a single `forensicnomicon = "1"`.
The fleet is registry-linked end to end.

**Recommendation: do not resume the folder move. Consolidate the fn-coupled fleet into a single
cargo workspace monorepo instead.** A monorepo achieves all three goals the old plan chased —
discoverability, folder ergonomics, dependency de-risk — and adds the one thing the migration
proved we are missing: **coordinated releases**. The taxonomy from the old plan becomes the
workspace's directory layout; each crate still publishes to crates.io under its own name; one
release-plz config replaces ~38 hand-run `cargo publish` invocations.

**Why now, in one sentence:** the migration we just finished was a 70-publish, topological,
stale-caret-trap, local-ahead-strand campaign *because* the fleet is polyrepo; a monorepo collapses
the next such change to one commit + one release PR.

**This is the most irreversible fleet change to date** (it merges ~25 git histories). It is **hard-
gated on the backup capability** under construction on `feat/archive-backing` (Gate 0).

---

## Evidence from the fn-1.0 migration (why polyrepo hurts)

The migration is the empirical case for consolidation. What polyrepo cost us:

- **~70 manual `cargo publish` calls** in dependency order across 38 repos. Dependent repos ship
  only `ci/docs/fuzz` workflows — **no release automation** — so every release was hand-run.
- **Topological republish ordering:** aggregators (`disk-forensic`, `useract`, `memory`, `issen`,
  `forensic-mount`) failed to compile with *two* forensicnomicon majors in the graph until every
  sibling was republished first. Leaf → aggregator → app ordering had to be hand-managed.
- **Stale-caret traps:** a released crate pinning a sibling at `"0.8"` could not reach the sibling's
  new `0.9` minor, silently re-dragging fn 0.11. Required blind patch-releases of `winreg-artifacts`,
  `mbr-partition-forensic`, `trash-core`, `usnjrnl-forensic` — each discovered only when a downstream
  aggregator's `cargo tree` showed a second major.
- **Local-ahead strands:** `git-core` had API on disk (`all_refs_checked`) never published, so
  `git-forensic` could not resolve until `git-core 0.2.0` was cut by hand.
- **Recon missed repos:** `hfsplus-forensic` and `4n6mount` were only found by tracing the dep graph,
  not the initial scan.

In a single workspace **every one of these vanishes**: cargo resolves the whole graph atomically
(no two-major windows, no stale carets), path deps mean no local-ahead strands, and the member list
*is* the recon.

---

## Target end-state

One git repo, one cargo virtual-workspace, members grouped by the 2026-06-09 taxonomy:

```
<umbrella>/                      # one .git at the root; root carries NO [package]
  Cargo.toml                     # [workspace] + [workspace.dependencies] (single source of truth)
  Cargo.lock                     # one lockfile for the whole fleet
  rust-toolchain.toml            # one pinned toolchain
  release-plz.toml               # one release config, per-crate independent versions
  .github/workflows/             # one CI (path-filtered), one release-plz workflow
  knowledge/      forensicnomicon (core/data/facade), state-history-forensic
  container/      ewf, ewf-forensic, vhdx-, vmdk-, vhd, dd, qcow2-, aff4, dmg, dar-
  filesystem/     ntfs-, ext4fs-, hfsplus-, udf-, iso9660-
  mount/          4n6mount (forensic-mount)
  partition/      mbr-, gpt-, apm-partition-forensic
  memory/         memory-forensic (memf-*, mem4n6)
  log/            winevt-, journald-forensic
  parser/         browser-forensic (br4n6), srum-, exec-pe-, winreg-forensic
  graph/          git-forensic, cas-[planned], sigstore-[planned]
  orchestration/  issen (issen-* crates), disk-forensic
  util/           blazehash?, lzo?         # see Scope — standalone products may stay out
```

**Publishing is unchanged from crates.io's point of view.** Each member keeps its crate name and
publishes independently (`cargo publish -p ntfs-core`). docs.rs pages, downstream dependents, and
crate ownership are unaffected — crates.io is per-crate and indifferent to repo layout. What changes
is *where the source lives* and *how releases are driven*.

---

## What consolidation resolves from the old plan

| 2026-06-09 concern | Resolution in a monorepo |
|---|---|
| 31 cross-repo `path = "../x"` deps break on move | They become **intra-workspace** path+version deps — location-independent, resolved atomically. |
| CI hard-codes flat-sibling checkouts (`../4n6mount`, `../forensicnomicon`) | One CI checks out one repo; no sibling checkouts exist. |
| "Inside issen is a trap — nested git repos" | No nested `.git`: absorbed repos become **workspace members**, not repos. The trap was specific to keeping them independent. |
| Phase 2 registry de-risk is the precondition | **Done** by the fn-1.0 migration. |
| Discoverability (need #1) + folder ergonomics (need #2) | The member tree *is* the grouped map; `cargo metadata` enumerates it. |
| No release automation across the fleet | One release-plz drives per-crate version bumps + ordered publishes. |

The old plan's Option A (`FLEET.md` index) is still worth keeping as a generated README of the
workspace; Options B (symlink view) and C (physical move of independent repos) are obsoleted by
consolidation.

---

## Gates and phases

### Gate 0 — BACKUP FIRST (binding, blocks everything)

Consolidation collapses ~25 independent git histories into one. It is far less reversible than a
folder move. **No absorption proceeds until:**

1. The backup/archive capability on `feat/archive-backing` is shipped and exercised.
2. A **full backup of every source repo** (working tree + `.git` + remotes + tags) is taken and
   verified restorable. This is the literal "after backup" gate from monday-morning #70.
3. Every source repo is **clean** — no uncommitted changes, no unpushed commits (carried over from
   the old plan's binding safety rule). The migration left a few repos dirty/ahead (notably issen
   itself, ~45 commits ahead on `feat/archive-backing`); these must be landed and pushed first.

### Phase 1 — Decide umbrella + scope

- **Umbrella repo/name (decision):** issen is *already* a ~64-crate workspace, so the lowest-churn
  path is to **promote issen into the umbrella** (root becomes a virtual workspace; the `issen` CLI
  crate moves to `orchestration/issen`). Alternative: a fresh `~/src/4n6` that absorbs issen too
  (the 2026-06-09 Codex verdict preferred `~/src/4n6/` over demoting issen — revisit now that the
  goal is one workspace, not a folder of repos).
- **Scope (decision):** which repos come in. Tightly fn-coupled `*-forensic`/`*-core` crates: yes.
  Genuinely standalone products with their own README/privacy/terms/GH-Pages identity
  (`blazehash`, `lzo`, `chat4n6`): likely **stay separate** — consolidating them dilutes their
  product story for no dependency benefit (they don't pin forensicnomicon).
- **Exclusions** (from 2026-06-09): `mft` (third-party), `jsonguard` (general util), and confirm the
  `usnjrnl-forensic` deprecation note (it was *not* deprecated — it was migrated to fn 1.0 at 0.8.1
  this round; update the taxonomy).

### Phase 2 — Absorb repos with history preserved (incremental, one at a time)

For each source repo, in dependency order (leaves first):

1. `git subtree add --prefix=<layer>/<repo> <repo-remote> main` **or** `git-filter-repo` to rewrite
   the repo's history under the target subdir, then merge. Preserves commit history and authorship.
2. Decide **tag strategy**: per-crate release tags (`ntfs-core-v0.9.0`, …) either namespace-import or
   are dropped in favor of release-plz's going-forward tags. Recommend keeping crates.io as the
   historical record and starting fresh tags in the monorepo.
3. After each absorption: `cargo metadata` resolves, `cargo check --workspace` is green, commit.
   **One repo per commit** so any absorption is individually revertible.

### Phase 3 — Unify the workspace

- Single root `[workspace]` + `[workspace.dependencies]`; convert the migration's registry deps to
  `{ path = "<layer>/<crate>", version = "X" }` workspace deps (path for local builds, version for
  publish). One `rust-toolchain.toml`, one `Cargo.lock`, shared `[workspace.lints]`.
- One **path-filtered CI** (build only the crates a change touches; `cargo` workspace handles the
  graph). Delete the per-repo flat-sibling checkout hacks.
- One **release-plz** (`release-plz.toml` with per-package independent versions — it natively
  handles a monorepo of independently-versioned crates) + the `release_commits` allowlist already
  proven on forensicnomicon to avoid changelog churn.

### Phase 4 — Decommission source repos

- Archive each source repo on GitHub (read-only), with a README pointer to the monorepo. crates.io
  crates continue publishing **from the monorepo** under the same names (no ownership change needed).
- Sweep hardcoded `~/src/<repo>` refs (CLAUDE.md, corpus catalog, scripts, IDE workspaces) to the
  new paths — a grep-driven pass, same as the old plan's Phase 3 residual sweep but now the *only*
  ref breakage, since path deps are gone.

---

## Risks and reversibility

- **Irreversibility of history merge** — mitigated by Gate 0 backup + keeping source repos archived
  read-only (not deleted). A botched absorption is reverted commit-by-commit (Phase 2 is one-repo-
  per-commit).
- **crates.io continuity** — publishing from a new repo path is fine (crates.io tracks crate names,
  not source URLs); only `repository =` metadata changes. Verify each crate's `repository` field +
  CI `CARGO_REGISTRY_TOKEN` before first monorepo publish.
- **CI wall-clock** — a 100+ crate workspace builds slower; mitigate with path-filtered jobs and a
  shared `target/` cache. One full `cargo test --workspace` gate before release, per the fleet's
  test-runner-resource rule (one heavy suite at a time).
- **Loss of per-repo issues/access control** — accept for internal fleet crates; keep standalone
  products separate (Phase 1 scope).
- **Big-bang temptation** — resist. Absorb incrementally, green build after each. The fn-1.0
  migration's lesson is that fleet-wide changes want a coordinator and per-step verification.

---

## What it buys (measured against this week)

- Next `forensicnomicon` bump: **one commit + one release-plz PR**, versus 70 manual publishes in
  topological order across 38 repos.
- **No stale-caret traps, no two-major windows, no local-ahead strands** — cargo resolves one graph.
- Discoverability and the grouped tree the 2026-06-09 plan wanted, for free.

## Open decisions

1. Umbrella: **promote issen** (lowest churn — it's already the big workspace) vs **fresh `~/src/4n6`**
   absorbing issen too.
2. Scope: confirm which standalone products (`blazehash`, `lzo`, `chat4n6`) stay out.
3. Tag strategy: import per-crate historical tags vs start fresh in the monorepo.
4. Timing: this is post-Gate-0 only. Confirm the `feat/archive-backing` backup is the intended gate.
