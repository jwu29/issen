# Fleet forensicnomicon 0.11.0 Convergence Plan

Status: **COMPLETE (2026-06-25)** — all 21 fleet repos republished against forensicnomicon 0.11.0 and issen converged to a single-fn lock (`cargo check --workspace` green, 521 crates). The plan below is retained as the executed record.

## Executive Summary

forensicnomicon `0.11.0` is live on crates.io. The fleet does **not** use one
forensicnomicon: issen's lock carries **three** versions simultaneously —
`0.5.8` (the disk / partition / NTFS / browser / winevt / srum / prefetch / lnk /
sqlite / segb world, ~33 crate refs), `0.7.0` (issen-parser-registry alone), and
`0.10.0` (the memf memory crates). The skew is **structural**: each version pin
lives *inside a published intermediate crate*, so issen cannot fix it by editing
its own `Cargo.toml`. Converging the fleet onto `0.11.0` requires **republishing
~28 external crates across 20 repos in dependency order**, then updating issen's
own members and its requirement.

- **Why it matters:** `forensicnomicon::report::{Observation, Finding, Report}`
  are version-specific Rust types. A `Finding` from fn-0.5.8 and one from
  fn-0.11.0 are *distinct types*; issen's job is aggregating findings into one
  `Report`, so true single-version convergence is what makes cross-artifact
  correlation type-check. The skew is a latent correctness issue, not just hygiene.
- **Cost:** ~20 tag-driven releases (each irreversible on crates.io), each needing
  a version bump. Grouped by dependency layer, this is 5 waves.
- **Recommendation:** execute layer-by-layer (leaf crates first), waiting for the
  crates.io index between waves; settle every version number *before* tagging;
  validate issen end-to-end against a real image at the end (the report
  aggregation is precisely what the skew threatens).
- **Do the whole chain or none.** A partial pass leaves issen pulling a mix again —
  the skew persists until the last dependent (issen-cli) resolves to one fn.

## Why this can't be fixed in issen alone

issen declares `forensicnomicon = "0.5"`. A caret requirement `"0.5"` means
`>=0.5, <0.6` — `cargo update` *cannot* cross it to `0.11` (the "layer-1"
staleness from the dependency-freshness discipline: the requirement is too narrow,
the build stays green, the lock looks fine). Even widening issen's own requirement
does nothing for the transitive pins: `ntfs-forensic` (published) requires fn
`0.5`, so cargo resolves a second fn `0.5.8` no matter what issen asks for. The
fix has to move up the publish chain, leaf-first.

## Republish order (dependency layers)

External, separately-published crates only. Republish a layer fully (and let the
crates.io index settle ~30 s) before starting the next, because each layer
depends on the one below.

| Layer | Crates (current fn) | Repo |
|---|---|---|
| **L1** (leaf readers/cores) | ntfs-core, sqlite-core, gpt-partition-core, mbr-partition-core, winevt-core, winevt-extract, browser-forensic-core, cfb-forensic, shellitem, segb-forensic, prefetch-forensic, vmdk-forensic, apm-partition-forensic, iso9660-forensic, livedisk-forensic, srum-parser | ntfs-forensic · sqlite-forensic · gpt-partition-forensic · mbr-partition-forensic · winevt-forensic · browser-forensic · cfb-forensic · shellitem · segb-forensic · prefetch-forensic · vmdk-forensic · apm-partition-forensic · iso9660-forensic · livedisk-forensic · srum-forensic |
| **L1** (memf — already 0.10.0) | memf-correlate | memory-forensic |
| **L2** | ntfs-forensic, browser-forensic-firefox, gpt-partition-forensic, lnk-core, winevt-analysis, winreg-artifacts, memf-linux, memf-windows | ntfs-forensic · browser-forensic · gpt-partition-forensic · lnk-forensic · winevt-forensic · winreg-forensic · memory-forensic |
| **L3** | mbr-partition-forensic, useract-forensic | mbr-partition-forensic · useract-forensic |
| **L4** | disk-forensic | disk-forensic |

(`issen-*` crates appear in the resolved graph at L1–L5 but are issen's **own**
workspace members — they need only a dependency edit, not a republish; see below.)

### 20 repos in play

apm-partition-forensic, browser-forensic, cfb-forensic, disk-forensic,
gpt-partition-forensic, iso9660-forensic, livedisk-forensic, lnk-forensic,
mbr-partition-forensic, memory-forensic, ntfs-forensic, prefetch-forensic,
segb-forensic, shellitem, sqlite-forensic, srum-forensic, useract-forensic,
vmdk-forensic, winevt-forensic, winreg-forensic.

## Per-repo procedure (each crate)

1. Widen the forensicnomicon requirement to `"0.11"` — usually one edit in
   `[workspace.dependencies]` (workspace inheritance), occasionally a per-crate
   `forensicnomicon = "0.11"`.
2. `cargo update -p forensicnomicon` to pull 0.11.0 into the lock.
3. **Build + clippy + test against 0.11.** Expect possible API drift: these
   crates were written against the fn-0.5 `report`/`Observation` API and we are
   crossing many minors. The report model is `#[non_exhaustive]` + builders
   (additive by design), so most should compile clean, but each must be verified —
   do not assume. Fix any `Observation`/`to_finding` drift in place (RED/GREEN).
4. **Bump the crate's own version** (a republish cannot reuse a published
   version — crates.io rejects it).
5. Commit, push, tag `vX.Y.Z` (signed) → `release.yml` publishes. Verify the run
   produced the publish (`gh run watch`; fail-fast matrix can skip the crate job).
6. Wait for the crates.io index (~30 s) before the layer's dependents.

## issen itself (final step, after all 20 repos)

- Widen `Cargo.toml`: `forensicnomicon = "0.5"` → `"0.11"`.
- Update issen's own members that pin fn (issen-core, issen-correlation,
  issen-report, issen-timeline, issen-evtx, issen-signatures, issen-parser-pe,
  issen-parser-prefetch, issen-parser-lnk, issen-parser-regcatalog,
  issen-parser-registry) to `"0.11"`. issen-parser-registry is the lone `0.7.0`
  outlier — bump it too.
- `cargo update` to pull every republished dependent at its fn-0.11 version.
- **Acceptance gate:** the lock contains exactly one `forensicnomicon` version
  (`grep 'forensicnomicon [0-9]' Cargo.lock | sort -u` → a single `0.11.x`).
- Full `cargo check --workspace`, clippy, tests; then an end-to-end ingest of a
  real image to confirm cross-artifact `Report` aggregation works across the
  (now unified) analyzers.

## Risks & gotchas

- **Irreversible.** Every tag publishes permanently; a wrong version can't be
  recalled (only yanked). Settle all version numbers before the first tag.
- **API drift across 0.5 → 0.11.** The earlier `code()` method error was a
  *coexistence* symptom (two fn versions' `Observation` traits in one graph), which
  single-version convergence removes — but crates last built against 0.5 may still
  need small `report`/`Observation` updates to compile against 0.11. Budget for a
  fix-per-crate, not a pure bump.
- **Keep batteries-included.** Do not reach for `default-features = false` to
  sidestep a build or license gate during the bump (fleet rule); fix the gate.
- **Commit `Cargo.lock`** in each app/binary repo so CI resolves the converged
  graph.
- **Prevent recurrence:** set Renovate `rangeStrategy: "bump"` (it does **not**
  widen ranges by default) scoped to the fleet namespace, so a future fn minor
  widens requirements automatically instead of silently stranding behind a caret.
- **gitsign:** start the credential cache before the wave so 20 repos × (commits +
  tags) don't each trigger a browser OIDC flow.

## Suggested sequencing

One coordinated wave per layer (L1 → L4 → issen), each repo: bump → verify →
tag → confirm publish. ~20 release runs total. The memf crates (already 0.10.0)
are the cheapest (clean bump to 0.11); the L1 readers are the bulk. issen is last
and is the acceptance gate (single-fn lock + real-image ingest).
