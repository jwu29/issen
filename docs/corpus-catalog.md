# Corpus Catalog — moved to `ronin-issen`

**The SecurityRonin fleet corpus catalog now lives at
[`~/src/ronin-issen/docs/corpus-catalog.md`](../../ronin-issen/docs/corpus-catalog.md).**

It was lifted to the fleet-governance home on 2026-07-19 — it indexes **every** fleet repo's
corpora (provenance, license, real-vs-synthetic classification, ground-truth vs robustness), so it
is fleet-wide, not issen-specific. Decision and reference-sweep plan:
`~/src/ronin-issen/REORG.md` §5.5 / §7.9.

This redirect keeps the ~40 fleet repos that relative-link `issen/docs/corpus-catalog.md`
resolving during the flat-layout transition. The reorg reference sweep (REORG.md §5.4) repoints
those links to the new location and removes this stub.
