# 0007. Resumable ingestion keyed on per-artifact content fingerprint

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

Ingesting a full case takes minutes and previously buffered every event in RAM
(`CollectingEmitter`) and persisted once at the end. So a kill/restart lost all
work, huge artifacts risked OOM, and re-running re-parsed everything. A file-based
completion log has a crash window (commit DB, crash before writing the log,
resume re-parses, committed events duplicate). We needed a resume that never
duplicates and never falsely reports a partial unit as complete.

## Decision

Ingestion is **streaming and unit-checkpointed, resumable by default.** The unit
of work is `(artifact, parser)` with a reproducible `unit_id` (for a loose file,
`evidence_relpath + parser`; for a nested-container artifact,
`container_identity + inner_relpath + parser`, where `container_identity` is a
content hash of the container header — stable across runs even though temp
extraction dirs are not). Each unit's events insert and its `ingest_log` row is
marked `complete` in **one atomic DuckDB transaction**, so "events flushed" and
"unit complete" can never disagree across a crash.

Resume re-parses the **complement** — every unit not marked complete — matched by
`evidence_key` (canonical path + size/mtime or content hash), so you cannot resume
against a different image. `--refresh` (or `ingest.refresh`) forces a clean
re-ingest by deleting that evidence's rows first. A unit counts complete only when
the parser reaches clean EOF *and* the commit succeeds.

## Consequences

A warm re-run skips already-complete units and drops from **7.36s to 0.20s** on
the reference case; kill/restart survives with no duplicates. Because the store
dedups on `record_hash`, re-parsing an incomplete unit from a deterministic parser
re-emits identical hashes and duplicates are dropped automatically — resume is
idempotent for free, with `DELETE ... WHERE ingest_unit_id=?` kept as a backstop
for non-deterministic parsers.

The honest limit: the key is the **evidence content, not the parser version.** If
a decoder is fixed, the units are still marked complete against the same evidence,
so a stale timeline is *not* automatically re-parsed — the operator must pass
`--refresh` to pick up a parser fix. This is a deliberate trade (cheap resume over
automatic invalidation); it also depends on a trustworthy parser-completion
contract, so lenient parsers that return `Ok` on truncated input had to be fixed
first.

## References

- `crates/issen-cli` / `crates/issen-fswalker` — the per-unit commit + content-fingerprint skip
- The original 2026-06-17 resumable-ingestion design + Codex critique is in git history: `git log --follow -- docs/plans/2026-06-17-resumable-ingestion-design.md`
- Crate: `crates/issen-timeline` (`ingest.rs`, `ingest_log`), `crates/issen-fswalker` (`isolate.rs`)
- Measured: warm resume 7.36s → 0.20s (parse-skip)
