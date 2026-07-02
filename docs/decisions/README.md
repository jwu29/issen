# Architecture Decision Records

This directory records the architectural decisions that shaped **issen** and the
forensic fleet it orchestrates. Each record follows the
[Michael Nygard ADR format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions):
a short document capturing the *context* that forced a choice, the *decision*
taken, and the *consequences* that follow.

These are **reverse-written** — they document decisions already made and shipped,
not proposals. An ADR is **immutable once Accepted**: we do not edit a record to
reflect a later change of mind. When a decision is reversed or refined, we add a
*new* ADR that supersedes the old one and mark the old one `Superseded by NNNN`.
The archaeology lives in git and the plan files under `docs/plans/`; each ADR
holds the standing conclusion.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-multi-repo-fleet-five-navigation-primitives.md) | Multi-repo fleet architecture with five navigation primitives | Accepted |
| [0002](0002-forensicnomicon-knowledge-leaf-and-report-model.md) | forensicnomicon as the zero-dependency KNOWLEDGE leaf and shared report model | Accepted |
| [0003](0003-core-reader-forensic-analyzer-split.md) | The `<x>-core` reader / `<x>-forensic` analyzer split | Accepted |
| [0004](0004-collectionprovider-for-logical-containers.md) | CollectionProvider for logical containers, distinct from the disk pipeline | Accepted |
| [0005](0005-duckdb-timeline-store-columnar-appender.md) | DuckDB as the timeline store, loaded via the columnar Appender | Accepted |
| [0006](0006-pure-rust-container-reading-zip-and-zran.md) | Pure-Rust container reading: zip-direct and zran for bounded-RAM DEFLATE | Accepted |
| [0007](0007-resumable-ingestion-content-fingerprint.md) | Resumable ingestion keyed on per-artifact content fingerprint | Accepted |
| [0008](0008-fail-loud-on-unsupported-filesystem.md) | Fail loud on an unsupported filesystem; never a silent empty result | Accepted |
| [0009](0009-batteries-included-single-static-binary.md) | Batteries-included single static binary | Accepted |
| [0010](0010-disk-forensic-as-disk-image-access-abstraction.md) | disk-forensic as the disk-image access abstraction (collapse per-format wrappers) | Proposed |
