# 0015. Generalize Linux artifact analysis beyond UAC collections (disk-image parity)

Status: Proposed (follow-up to [0014](0014-frontdoor-collection-evidence.md))

## Context

ADR 0014 restored UAC-collection support to the front door: `issen <uac.tar.gz> -o
<db>` routes to the Collection leg (detected by `UacProvider::probe` — `uac.log`
=> `High`, `/bodyfile/`|`/live_response/`|`/system/` => `Medium`, in
`issen-parser-uac/src/probe.rs`) and runs the rootkit / hidden-process /
masquerade analysis (`commands/analyse.rs`), the supertimeline narrative
(`commands/supertimeline.rs`), and the forensic-pivot pack (`commands/pivot.rs`)
over the collection via `run_auto`.

But a **Linux disk image** (ext4 `.E01`/`.dd`) is **not** a UAC collection — it
carries no `uac.log`, so `is_uac_collection` returns `None` and it routes to the
**Disk leg**. The Disk leg (ext4/APFS filesystem support added in the t2
filesystem work — `issen-disk::detect_filesystem` already reports
`ext`/`APFS`/`HFS+`) extracts Linux filesystem artifacts into the case DB, but does
**not** run the rootkit/masquerade/supertimeline/pivot analysis.

So the same Linux host yields different analytical depth depending on whether it
arrived as a UAC package or a raw image. The analysis is currently coupled to its
*source* (a UAC collection consumed by `run_auto`), not to the fact that the
*evidence is Linux*.

## Decision (proposed)

Decouple the Linux rootkit/masquerade/supertimeline/pivot analysis from the
UAC-collection input and run it as a **post-ingest stage keyed on Linux evidence,
regardless of source**:

1. After the ingest stage populates the case DB, run the analysis stage whenever
   the evidence is Linux — a UAC collection (Collection leg) **or** a Linux
   filesystem (Disk leg, where `detect_filesystem` already classifies `ext` /
   `APFS` / `HFS+`).
2. Refactor `analyse.rs`/`supertimeline.rs`/`pivot.rs` to consume the **case-DB
   artifact set** (source-agnostic) rather than a `run_auto` collection handle
   directly. The Collection leg becomes one producer of that artifact set; the
   ext4/APFS Disk leg is another.

## Consequences

- Linux disk images gain analysis parity with UAC collections — the same
  rootkit/masquerade/pivot pass runs on either input.
- The analysis becomes input-source-agnostic (case-DB-driven) — a cleaner
  architecture than binding it to the Collection leg.
- **Larger than 0014.** 0014 *reused* the existing analysis over a collection;
  this *moves* the analysis into the shared post-ingest stage machinery in
  `pipeline_run.rs`, which is under active ingestion-pipeline rework — so it must
  be **sequenced with that work**, not dropped in mid-flight.
- Tests: add a Linux ext4 disk-image fixture asserting the same rootkit/masquerade
  findings the UAC-collection tests assert, proving parity.
- Open question: some UAC-collected inputs (e.g. `live_response/` volatile
  captures) have no disk-image equivalent — the analysis must degrade gracefully
  per-artifact (already the pattern), surfacing whatever the source provides
  rather than failing when a UAC-only artifact is absent.
