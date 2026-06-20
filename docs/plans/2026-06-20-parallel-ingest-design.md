# Parallel Ingest — Design Plan

_Status: DRAFT — **revised after Codex critique (verdict: revise, don't implement as-is)** · 2026-06-20 · pairs with the per-unit commit model (#115)_

> **Codex corrections (all verified against source) — read before the body below; they override the
> original claims where they conflict:**
> 1. **Reproducibility claim was false.** `timeline.id DEFAULT nextval('timeline_seq')` (store.rs:63) and
>    `ingested_at DEFAULT current_timestamp` (store.rs:79) make parallel-commit output non-identical
>    (IDs + ingest time vary). Exports/narrative/correlation order **only** by `timestamp_ns` (no
>    tie-break), so same-timestamp row order is already non-deterministic. **Required:** add
>    `ORDER BY timestamp_ns, record_hash` (stable tie-break) at every read/export *before* parallelizing;
>    decide whether `id`/`ingested_at` may vary (they are non-evidentiary metadata — likely acceptable if
>    documented, but exports must not key on `id`).
> 2. **`record_hash` dedup claim was false for this path.** `commit_unit_body` deletes by `ingest_unit_id`
>    then inserts every event unconditionally (ingest.rs:380-385) — **no record_hash dedup** (that lives in
>    `insert_batch_at_epoch`). Order-independence rests on per-unit `unit_id` idempotency, not record_hash.
> 3. **Pre-existing resumability bug to fix FIRST.** `parse_units` ignores `stats.completion`
>    (orchestrator.rs:502) and the CLI commits every unit complete (ingest.rs:167), but `ParseCompletion`
>    says only `Complete`/`CompleteWithRecoveries` may be marked done. Parallelizing entrenches this.
> 4. **Measure before building.** Commit is row-by-row prepared INSERT in one transaction (ingest.rs:385),
>    NOT the bulk appender (ingest.rs:206) — commit may dominate a 1.58 M-event ingest, Amdahl-capping the
>    parse-parallelism gain. **The bigger win may be bulk-appending the serial commit, not parallel parse.**
> 5. Concurrency spec to tighten: `Connection` isn't `Send` → open the store *inside* the committer thread
>    (or commit on main thread + scoped rayon pool); no shared store; no `send().unwrap()`; clean shutdown
>    on commit error; `run_isolated` must wrap the parse (the existing parallel fn calls `parse` directly,
>    orchestrator.rs:570); preserve the CLI `evidence_source_id` re-stamp (ingest.rs:179); byte-aware memory
>    bound (a single MFT unit ≈ 766k events; channel bounds *count*, not bytes).
>
> **Re-sequenced:** (0) benchmark parse vs commit → (1) fix the completion-status bug → (2) add the
> `ORDER BY` tie-breaks → (3) *then* parallelize parse **or** just bulk-appender the commit if that's the
> bottleneck. `--jobs 1` stays default until benchmarks justify otherwise. The `skip: &(dyn Fn + Sync)`
> bound was confirmed correct.

## Executive Summary

Artifact **parsing is CPU-bound and embarrassingly parallel**, but the production ingest path
(`ingest::run` → `run_auto_units` → `parse_units`) runs it **single-threaded** — a nested
`for artifact { for parser { parse } }` loop. A complete rayon parallel pipeline already exists
(`run_pipeline_parallel`/`run_auto_parallel`) but is **dead in production** (only `#[cfg(test)]` calls it)
because it predates the resumable rework and returns a *flat* `Vec<TimelineEvent>` with no per-unit
boundaries — incompatible with resume/skip/commit.

**Recommendation:** don't revive the stranded flat-output functions. Instead **parallelize `parse_units`
across artifacts and pipeline it into a single-threaded committer** — a parse fan-out feeding a bounded
channel drained by one thread that owns the DuckDB connection. This is the shape that *pairs naturally
with the per-unit commit model*: each `ParsedUnit` is already an independent, atomically-committed,
idempotent unit, so commit order is irrelevant and a mid-run crash leaves completed units durable (resume
finishes the rest). It overlaps CPU parsing (N cores) with I/O commit (1 writer) **and** bounds memory
(backpressure) — incidentally delivering #115 step 5 (streaming, replace collect-all-in-RAM).

**Hard constraint (verified):** `TimelineStore` holds a **single `duckdb::Connection` (`store.rs:24`)**,
which is not safe for concurrent writes. So the design is **parallel parse, serial commit** — never
multiple writers.

---

## Current state (verified)

- **Ingest path:** `ingest::run` → `run_auto_units` (orchestrator.rs:379) → `parse_units` (460) → sequential
  `for artifact { open source; for parser { run_isolated(parse) → ParsedUnit } }`. The CLI handler then
  commits sequentially: `for pu in units { store.commit_unit(&unit, &restamped) }`.
- **Stranded parallel path:** `run_pipeline_parallel` (536), `run_auto_parallel` (640) use rayon
  `par_iter()` but return flat `(Vec<TimelineEvent>, IngestResult)` and are called **only** by tests
  (orchestrator.rs:1205/1219/1234/1268). No resume, no units.
- **`run_isolated`** (isolate.rs:64) = `std::panic::catch_unwind(AssertUnwindSafe(f))` — pure panic
  isolation, **no fork/subprocess**, safe to call from rayon workers (each catches its own panic).
- **`CollectingEmitter`** = `Mutex<Vec<TimelineEvent>>` (Sync); `parse_units` already uses a *fresh emitter
  per unit*, so no cross-thread sharing of an emitter is needed.
- **`ProgressReporter`** = `Arc<AtomicU64>`-backed (Sync) — already safe for concurrent updates.
- **`TimelineStore.conn: duckdb::Connection`** (store.rs:24) — one connection, not Sync. `commit_unit`
  (ingest.rs:327) runs `begin → delete-by-unit_id → insert → mark complete → commit` on it.
- **`skip: &dyn Fn(&ArtifactType,&Path,&str)->bool`** (parse_units:464) — captures the `completed` HashSet
  by shared ref; needs a `+ Sync` bound to cross rayon workers (trivial — HashSet is Sync).
- **`ParsedUnit`** (432) = `{artifact_type, path, parser: String, events: Vec<TimelineEvent>, bytes}` — all
  fields `Send` ⇒ movable across threads / through a channel.

---

## Design

### Topology: parse fan-out → bounded channel → single committer

```
 rayon par_iter over artifacts (N workers)         1 committer thread (owns Connection)
 ┌───────────────────────────────┐                ┌─────────────────────────────┐
 │ open source · run_isolated()  │  ParsedUnit    │ recv() →                    │
 │ per matching parser → unit ───┼──► [bounded ───┼─► commit_unit(unit)         │
 │ skip() filters completed      │    channel]    │   (begin/delete/insert/mark)│
 └───────────────────────────────┘   backpressure └─────────────────────────────┘
```

- **Producers (rayon):** `artifacts.par_iter()`; per artifact, apply `skip` (now `Sync`), open
  `FileDataSource` once, run each pending parser under `run_isolated`, `send(ParsedUnit)` into a
  **bounded** `sync_channel(cap)`. Errors and the skipped-count are aggregated thread-safely (a `Mutex`
  or a second channel).
- **Consumer (one thread):** owns the `TimelineStore`/`Connection`, loops `recv()` → `commit_unit`,
  accumulating `inserted`. Bounded channel = backpressure → in-flight units capped → memory bounded (the
  #115 step-5 streaming win, for free).
- **Why order-independence is safe:** `commit_unit` keys on a stable `unit_id` (delete-first → idempotent)
  and dedups events by `record_hash`; timeline order is by `timestamp_ns` at *query* time, not insertion.
  So parallel parse → non-deterministic *insertion* order → **identical final DB content** (forensic
  reproducibility preserved: same evidence ⇒ same events/findings, order-independent).

### Boundaries / what stays serial
- **Commit is single-threaded** (one Connection) — non-negotiable.
- **Per-source loop stays sequential** for v1 (the multi-source handler ingests sources one at a time);
  cross-source parallelism is a separate, harder step (shared store + case lock) — out of scope.
- **Extraction stays sequential** — it's I/O-bound on a single container and the `ewf`/`vmdk` readers
  aren't trivially `Sync` for concurrent seeks; low ROI — out of scope.

### Concurrency control
- **Thread-pool size configurable**, default `min(cores, ?)` — an evidence workstation shouldn't be
  saturated by default. Expose `--jobs N` (and/or `ingest.jobs`); `--jobs 1` reproduces today's behaviour
  exactly (a determinism/debug escape hatch). Use a scoped rayon pool, not the global one, so the setting
  is honored and doesn't leak to other rayon users.
- Keep `run_isolated` per-parse so one parser panic kills only its unit, not the worker/pool.

### API shape (minimal, additive)
- Add `parse_units_parallel(artifacts, parsers, progress, skip, jobs)` **or** thread a committer callback
  into a new `parse_and_commit(...)`. Prefer the **streaming** form: `fn ingest_streaming(artifacts,
  parsers, progress, skip: &(dyn Fn + Sync), commit: impl FnMut(ParsedUnit) -> Result<u64>)` so the store
  write stays in the CLI/orchestration layer and `issen-fswalker` never depends on `issen-timeline`
  (preserve the layer direction). Bound `skip` with `+ Sync`.
- `parse_units` (sequential) stays as the `--jobs 1` path / test oracle (differential test: parallel and
  sequential must produce the same unit set).

---

## TDD plan (strict RED → GREEN, separate signed commits)
1. **Differential-equivalence test** (RED first): on a multi-artifact synthetic dir, assert
   `parallel`-produced unit set == `sequential` unit set (same `(unit_id, sorted record_hashes)` multiset),
   independent of order. RED against the not-yet-written parallel fn.
2. **GREEN:** `parse_units_parallel` / streaming committer; `skip` `+ Sync`; scoped rayon pool + `--jobs`.
3. **Resume-under-parallel test:** kill after K commits (inject a committer that stops), re-run, assert the
   union equals a clean run and no unit is double-committed (idempotent `unit_id`).
4. **Real-data validation:** re-run the DC+WS unified ingest under `--jobs N`; assert identical event count
   + identical per-source attribution vs the `--jobs 1` baseline, and record wall-clock speedup.

## Risks (Codex bait — probe these)
- **Hidden order-dependence:** does any existing test/consumer rely on ingest *insertion* order? (The
  USN→DuckDB integration test notes "same timestamp ⇒ stable insertion order" — but it uses `insert_batch`,
  not `parse_units`; verify no `parse_units`/timeline test asserts order.)
- **DuckDB single-writer:** confirm no path tries to write from a worker; the committer must be the sole
  writer; appender/transaction semantics under a steady stream.
- **`run_isolated` + rayon:** `catch_unwind` interplay with rayon's own panic propagation (a panic in a
  `par_iter` closure aborts the parallel iterator unless caught *inside*; we catch per-parse, so confirm
  the closure never panics outside `run_isolated`).
- **Backpressure deadlock:** bounded `sync_channel` + producers blocking on `send` while the single
  consumer is also a rayon participant — keep the committer on a **dedicated** `std::thread`, not a rayon
  task, to avoid pool starvation.
- **Determinism claim:** is "identical content, different order" truly acceptable for every downstream
  (bodyfile export ordering? `--format csv` row order)? May need a final `ORDER BY` guarantee at export.
- **Memory:** `Vec<TimelineEvent>` per unit can be large (MFT = 766k events in one unit); the channel
  bounds *unit count*, not bytes — a few huge units could still spike RAM. Consider a bytes-aware bound.
- **Gain reality:** commit (single-writer DuckDB) may become the bottleneck; measure parse:commit ratio to
  confirm the speedup is real, not Amdahl-capped by serial commit.

## Out of scope
Cross-source parallelism; parallel extraction; replacing the sequential `parse_units` (kept as oracle).
