# 0005. DuckDB as the timeline store, loaded via the columnar Appender

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

A super-timeline over a full case is tens of millions of events. The workload is
analytical: sort by time, filter by source/category, join events across artifacts
for correlation, and do it without holding the entire timeline in RAM. A
row-oriented embedded store, or worse a per-event `INSERT` loop, does not fit that
shape — profiling showed ingest was bottlenecked on per-event inserts (not on
decompression or parsing).

## Decision

The timeline is stored in **DuckDB**, an embedded columnar analytical database,
and events are loaded through the **columnar Appender** rather than per-row
`INSERT`s. This gives out-of-core, columnar analytical queries and joins over the
whole case. Switching the ingest path to the Appender cut the ingest stage from
**194s to 17s** (roughly 11x) on the reference case with no change to the event
count.

DuckDB is single-writer, so ingest under parallel parsing routes per-unit event
batches through a bounded channel to a single writer thread; the ingestion log
lives in the same DuckDB so event insertion and unit-completion commit atomically
(see ADR 0007).

## Consequences

Timeline queries, correlation joins, and thresholding run as columnar SQL that
scales past RAM. The Appender is the canonical write primitive
(`insert_batch` / `insert_batch_at_epoch`), and it carries set-based dedup on
`record_hash`, which makes resumable re-ingest idempotent for deterministic
parsers.

The trade-offs: DuckDB's single-writer constraint forces the single-writer-thread
reconciliation pattern under parallel parse, and reads reconstruct
`TimelineEvent`s from raw rows (a serial DuckDB cursor feeding a parallel
reconstruct step). The database file is the case's system of record, which the
resumable-ingestion and epoch-dimension designs build directly on.

## References

- `CLAUDE.md` — "Convergence / release end-to-end validation corpus" (`issen ingest ... -o /tmp/<name>.duckdb`)
- Crate: `crates/issen-timeline` (`ingest.rs`, `events.rs`, `epoch.rs`, `correlations.rs`)
- Measured 194s→17s Appender result (reference case ingest)
