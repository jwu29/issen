# issen vs. Plaso / the super timeline — a critical architecture comparison

**Status:** analysis · **Date:** 2026-06-23 · **Method:** both sides grounded in source —
Plaso against the official docs (readthedocs build `20260512`) + GitHub; issen against its code
(file:line). A Codex pass critiqued this draft for overstatement and fairness.

## Executive Summary

Plaso and issen solve overlapping problems with different architectural centres of gravity.
Plaso is an *extraction* engine: parse everything as close to the source as possible, emit one
flat, comprehensive **super timeline**, and leave higher-level reasoning to a separate stage
(psort filters/tags, Timesketch, or the analyst). issen is a *correlation* engine: extract into a
queryable store, then run cross-artifact rules in-engine and emit **graded findings** alongside
events.

These are not the same kind of tool, and they are **not equally mature**. Plaso is the
established extraction/timeline engine with broad parser coverage and a long operational history;
issen is a younger, correlation-oriented implementation with a narrower extraction front end.

- **Plaso** has substantially broader parser/source coverage and a much longer operational
  history — broad parser and plugin families, dfVFS reads inside E01/raw images, partitions,
  **VSS snapshots**, and archives without pre-extraction, and roughly fifteen years of field
  hardening. For "parse every artifact on this image into a timeline," Plaso is a reference
  standard, and its normal interactive analysis layer (Timesketch) is a mature workbench.
- **issen's main architectural difference is in-engine correlation and finding generation** — it
  performs cross-artifact reasoning that Plaso core leaves to a downstream stage, persists to a
  *queryable* columnar store rather than a flat event log, folds the evidence source into its
  dedup key so multi-host evidence stays attributable, and emits severity-scored findings against
  a normalized vocabulary.
- **They relate conceptually.** Plaso-style super timelines could feed an issen-like correlation
  layer, but no Plaso-to-issen importer exists today, so the relationship is a design idea, not an
  available integration. The useful comparison is not "which wins" but **where correlation is
  implemented** — downstream in a purpose-built interactive workbench (Plaso + Timesketch) or
  in-engine (issen) — and what each choice trades away. issen has far less breadth and maturity;
  Plaso core leaves narrative correlation to psort/Timesketch/analyst workflows and does not
  expose its store as a columnar SQL analysis database.

This document compares the two by stage: extraction, parser model, data model, storage,
correlation, and output — then states where each is the right tool, and issen's honest gaps.

## Terminology — what "Plaso" and "super timeline" mean here

These terms are frequently conflated; this report keeps them distinct:

- **Super timeline** — a *methodology / output*, not a tool: a unified, chronologically-sorted
  timeline merging filesystem MAC times with registry, application-artifact, and log internals
  ("a timeline of timelines"). Coined in Kristinn Guðjónsson's 2010 SANS GCFA Gold paper,
  *Mastering the Super Timeline With log2timeline*.
- **log2timeline** — the *original tool* (Perl, ~2009–2010) that produced super timelines; the one
  taught in early SANS FOR508/GCFA.
- **Plaso** — the *Python successor* of that Perl tool; its front-end command is now
  `log2timeline.py`. So "Plaso" is the **engine that produces** a super timeline (the Perl original
  is retired) — Plaso is not itself "the super timeline."
- **Timesketch** (Google) — Plaso's usual *analysis/visualization front-end*: it ingests `.plaso`
  output and is where analysts actually triage the timeline. Not a generator.
- **Adjacent / alternative workflows** — the main rival for Windows artifact timelining is
  **KAPE + Eric Zimmerman's tools + Timeline Explorer**; **mactime / The Sleuth Kit** is the
  filesystem-only ancestor; **Hayabusa / Chainsaw** are EVTX/Sigma log-timeline tools. In open
  source, Plaso has no direct head-to-head competitor for "parse every artifact into one timeline."

Throughout this report, **Plaso** = the extraction engine (modern log2timeline), and **super
timeline** = the flat timeline it produces.

## The two architectures at a glance

This table states **what each tool does** at each stage — architectural facts, not scores.

| Stage | Plaso | issen |
|---|---|---|
| Shape | Two-stage: `log2timeline.py` (extract) → `.plaso` store → `psort.py` (sort/tag/output) | Layered: container → filesystem/log/memory → parser → orchestration → DuckDB |
| Source access | dfVFS path-specs (reads inside images, partitions, **VSS**, archives) | Container/FS crates (ewf/vhdx/ntfs/…) + a medium-agnostic `DataSource` trait |
| Parallelism | Collector + N extraction workers + a storage process (multi-process) | In the fswalker collection path: discover artifacts first, then per-artifact `rayon` dispatch |
| Parser input | A dfVFS file entry / path-spec (file-bound) | A `DataSource` random-access byte interface (file/slice/container impls); `source_path()`-dependent parsers stay path-bound |
| Unit of work | A file entry; events streamed to the mediator | A stable `IngestUnit` id (evidence+type+path+parser → SHA-256), resumable |
| Event model | `EventData` + `EventDataStream` + N `EventObject`s (one per timestamp) | One typed `TimelineEvent` per fact (24 `EventType`s + fallback) |
| Output unit | A flat list of events (CSV/JSON/Timesketch) | Events **and** graded `Finding`/`Report` rows (severity + category) |
| Cross-artifact reasoning | Normally via psort filters/tags, Timesketch, or analyst workflows | In-engine rule correlation (`EntityRef` joins, temporal rules) |
| Store | `.plaso` SQLite attribute-container store (events + sessions; tags/analysis added later) | DuckDB columnar, dedup on `record_hash`, SQL-queryable |
| Multi-host | Events merged; source/session metadata tracked in the store | `evidence_source_id` is **part of `record_hash`** → identical rows from different sources stay distinct |

## 1. Extraction & collection

**Plaso** runs four operations — preprocessing, collection/extraction, analysis, output — split
across a *collector*, *N workers*, and a *storage* process. Preprocessing first fingerprints the
source (OS, hostname) and auto-selects a **parser preset**; dfVFS then enumerates work as path
specifications, which is what lets Plaso read inside E01/raw images, partitions, VSS stores, and
archives without a separate extraction step. Source scope is controlled by `--partitions`,
`--vss_stores`, and collection filters (YAML path include/exclude). dfVFS provides **transparent
VSS traversal** from supported images — a genuine Plaso strength.

**issen** separates discovery from parsing. In the fswalker collection path it opens a
collection/image, **discovers artifacts first** (a recursive walk + a registry-driven
`ArtifactSelector`/`detect_from_registry` classifier), keeps the extracted collection tempdir
alive (`with_evidence`, `crates/issen-fswalker/src/orchestrator.rs:128`), and can dispatch
per-artifact parsing with rayon (`parse_units_parallel` → `par_iter`,
`crates/issen-fswalker/src/orchestrator.rs:511`). The architectural move that differs from Plaso
is the **`DataSource` trait** (`crates/issen-core/src/plugin/traits.rs:54`): a parser receives a
random-access byte interface (`read_at`, `len`) rather than a file entry, and the repo ships
file, slice, and several image/container-backed implementations (ewf, vhdx, vmdk, qcow2, vhd, iso,
aff4, dd). The trait carries an optional `source_path()` that defaults to `None`; the discovered
artifacts in the fswalker path are opened through `FileDataSource`
(`crates/issen-fswalker/src/orchestrator.rs:465`), and parsers that require `source_path()` remain
file/path-dependent. A memory-region-backed `DataSource` is architectural intent — this document
does not claim memory-image parser reuse because no concrete memory-backed `DataSource` path was
cited in the orchestration code inspected.

*Trade-off:* Plaso's dfVFS gives broader, more mature **source** coverage (transparent VSS, nested
archives). issen has VSS/shadow-copy **path-detection** helpers (`list_vss_volumes`, `is_vss_path`,
`crates/issen-fswalker/src/vss.rs:31` and `:146`) but no evidence of Plaso-equivalent automatic VSS
enumeration/traversal inside image containers. issen's `DataSource` gives a single byte interface
that several container readers and slice sources implement, while currently reaching fewer
container/snapshot formats than dfVFS.

## 2. Parser model

**Plaso:** a *parser* owns a file format; *plugins* attach to a host parser that understands a
container format and dispatch on sub-content (`sqlite` + plugins, `winreg` + plugins, `esedb`,
`olecf`, `plist`, `text` + format plugins — hence the `text/winiis` plugin-prefix). In the
documented/current Plaso parser API, parsers build an `EventData` container and submit it with
`ParserMediator.ProduceEventData(...)`; the mediator also tracks parser-chain provenance, so every
item's producing parser is known. Presets bundle parsers per OS. The breadth here is the headline
fact: Plaso documents broad parser and plugin coverage, including SQLite, Registry, ESE, plist,
OLECF, text, and other families. It is one of the most mature open-source timeline extraction
engines.

**issen:** a `ForensicParser` trait with a `parse(input, emitter)` signature, registered at
compile time via `inventory::submit!`. Two structural differences stand out:

- **A `ParseCompletion` state machine** (`Complete / Undeclared / Unsupported / CorruptFatal /
  Incomplete`) returned in `ParseStats`. The default is `Undeclared` = *not complete* — so an
  `Ok(())` return alone does **not** mark a unit done. This is a secure-by-default stance: a parser
  must *explicitly* declare success, which makes "we looked and finished" distinguishable from "it
  didn't error." Plaso's mediator model records *what was produced*; it does not carry an explicit
  per-unit completion verdict in the same way.
- **A `DataSource` byte interface** (§1) — the same parser over file or slice/container bytes,
  subject to the `source_path()` caveat.

*Trade-off:* Plaso's parser ecosystem is far larger and more battle-tested. issen's per-parser
contract is stricter (explicit completion, declared supported-artifacts), but its parser **count is
a fraction of Plaso's**, and issen's own notes flag that several wrappers surface only part of the
capability their underlying crate owns ("parser depth"). On raw artifact coverage, Plaso is far
ahead.

## 3. Data model — events vs. findings

This is the sharpest conceptual divergence.

**Plaso** models *source-level* events. The 2020 storage change split the old single object into
`EventData` (the parsed record's fields, free-form), `EventDataStream` (path-spec + hashes + Yara),
and `EventObject` (a single `timestamp` + `timestamp_desc`). A single `EventData` can carry
**multiple `dfDateTime` values**, and **each timestamp can materialize as its own `EventObject`** —
so one source record can become multiple timeline rows, for example one per available MACB-style
timestamp (the exact number depends on the parser/timeliner mapping and the timestamps present).
Plaso is explicit that *higher-level conceptual events* (a "log-in" abstracting many records; a
process start+stop merged into a duration) are **for analysis plugins to derive later**, not for
parsers. Time is preserved at source granularity via dfDateTime (dynamic time, since 2021); the
normalized `timestamp` is UTC microseconds.

**issen** emits one strongly-typed `TimelineEvent` per fact. The struct
(`crates/issen-core/src/timeline/event.rs:129`) carries `timestamp_ns`, `timestamp_display`, a
typed `EventType`, `source`, `artifact_path`, `metadata`/`tags`, optional `EntityRef`s, and an
optional CADET `ActivityCategory`. (There is no MITRE field on `TimelineEvent` itself; MITRE
references should be mentioned only where the specific event/finding field is cited.) issen also
has a *second* analyst-facing output Plaso core does not mirror directly: a **finding/report
model**. issen findings use `forensicnomicon` severity/category concepts in its detection and
correlation paths, and are stored and rendered through issen's own report rows — `crates/issen-report`
defines `ReportData`, `ReportSummary`, and `FindingRow` (`crates/issen-report/src/lib.rs:146`, `:113`,
`:128`) rather than serializing a `forensicnomicon::report::Report` directly. Plaso instead
represents analyst meaning through tags, analysis-plugin output, psort output, and Timesketch
annotations/workflows. issen emits graded observations (`Info…Critical`) against a published code
vocabulary, with the discipline that findings are *observations* ("consistent with"), never
verdicts.

*Trade-off:* Plaso's free-form `EventData` is more flexible and imposes no schema on new artifacts;
issen's typed model + finding vocabulary is more opinionated (a new artifact must map to the
taxonomy) but yields machine-rankable output. Plaso's "one timestamp = one event" maximizes
fidelity at the cost of volume; issen's per-fact event is leaner but encodes the MAC times as fields
rather than separate rows (a different, not strictly better, choice — Plaso's is arguably more
faithful to "every timestamp is an event").

## 4. Storage

**Plaso:** the `.plaso` file is a **SQLite-backed attribute-container store** (acstore) for
serialized Plaso containers (events, event_data, event_data_stream, tags, sessions, warnings,
preprocessing artifacts), with JSON serializers for complex attributes (dfDateTime, path-spec).
Extraction writes event-related containers through storage-writer APIs, and later processing can
add tags/analysis metadata depending on psort options and workflow. Processing **sessions** record
tool version, enabled parsers, and completion, supporting repeat runs into one store. A Redis-backed
task store buffers worker output during multi-process extraction.

**issen:** a **DuckDB columnar** store with two distinct write paths:

- The **batch/epoch ingest path** (`insert_batch_at_epoch`,
  `crates/issen-timeline/src/ingest.rs:199`) uses a temp table (`_ingest_stage`), deduplicates
  *within the batch* via `row_number() OVER (PARTITION BY record_hash)`, and against existing rows
  via an anti-join on `record_hash` — set-based, with no per-event `SELECT`.
- The **resumable `commit_unit()` path** (`crates/issen-timeline/src/ingest.rs:333`) instead commits
  each unit transactionally: it deletes prior rows for the same `ingest_unit_id`
  (`DELETE FROM timeline WHERE ingest_unit_id = ?`, `:405`) and re-inserts the unit's rows, so a
  re-parsed unit is idempotent. A stable `IngestUnit` id (evidence + artifact type + artifact path +
  parser → SHA-256) keys this path; events carry that id and an ingest-log status, and only
  `Complete`/`CompleteWithRecoveries` statuses enter the resume skip set (so incomplete units can
  have rows written and are re-parsed later). Because the store is DuckDB, **triage is SQL** over a
  columnar engine, not iteration over a serialized event log.

*Trade-off:* Plaso's session model + container store is mature and supports incremental
re-processing cleanly. issen's DuckDB store is directly queryable (the analyst writes SQL, or the
`supertimeline`/`analyse` commands do) — but DuckDB is an analytical store, and issen does not (yet)
carry Plaso's rich session/provenance container family inside the store itself.

## 5. Correlation

**Plaso core does not provide a built-in rule engine that emits cross-artifact correlated
findings.** Its analysis plugins examine events through a per-event `ExamineEvent()` API and may
maintain state and `CompileReport()` — documented built-ins include tagging (filter-expression →
label), hash reputation (virustotal/nsrlsvr), browser-search extraction, unique-domain summaries,
and sessionizing. So a plugin *can* accumulate state and emit an aggregate report; what the
documented built-ins are is tagging/reputation/session/domain-style analyses rather than a general
cross-artifact relationship engine. **A tag by itself is not a correlation:** it labels an event
that matches an expression; it does not relate two events from different artifacts. Cross-event /
cross-artifact reasoning, pivoting, and narrative are normally performed outside Plaso core —
especially in **Timesketch** (search/aggregations/graphs/stories) or analyst-authored workflows.

**issen runs a curated set of cross-artifact correlations in-engine.** A post-ingest rule engine
(disk-leg rules across tiers A/B/D today) joins events on a normalized `EntityRef` (FilePath,
Process, User, Ip, Session) via a storage-free `EventView` trait. The rules express *relationships*
— e.g. a logon event in tight temporal proximity to a file created in a world-writable path (a
generalized PAM-hook signal), brute-force burst-then-success on one IP, `$SI < $FN` timestomp
leads. These are the "log-in abstracts many records" / cross-source-correlation conceptual events
Plaso leaves to a later stage.

*This is the main "compare and contrast" axis:* the useful comparison is **where correlation is
implemented**. issen encodes selected correlations in-engine, while Plaso normally hands timeline
output to psort/Timesketch/analyst workflows for interactive, open-ended correlation. Each choice
has a cost. issen's in-engine rules are finite and hand-built (8 disk-leg rules today, not a general
query surface), so a question the rules don't encode still needs manual SQL — whereas Timesketch
over a Plaso store is a *general* interactive analysis surface that, in skilled hands, can express
correlations issen's fixed rule set does not. issen automates a curated set of high-value
correlations; Plaso + Timesketch offers open-ended analyst-driven correlation in a purpose-built
workbench. Curated automated findings vs. an interactive analyst workbench.

## 6. Output & the analyst's workflow

**Plaso → flat super timeline.** psort sorts chronologically, applies filters/tags, and writes
through output modules such as L2T CSV / dynamic text, JSON/JSONL-style output, xlsx, KML,
OpenSearch/Elasticsearch-oriented outputs (`opensearch`/`opensearch_ts`), and Timesketch upload
support; exact module names are version-dependent. Because every source timestamp can be its own
event and every artifact is parsed, output is routinely **millions of rows**. The analyst's job
*continues* here — historically grep/spreadsheet, today **Timesketch**, a purpose-built
collaborative search/tag/aggregate/annotate workbench. The strength is completeness; the cost is
that meaning is downstream work, performed in that interactive workbench rather than a built-in
rule engine.

**issen → queryable store + findings.** Output is a DuckDB store plus a `Report` of graded
findings; the analyst queries SQL or reads ranked findings (`analyse`, `correlate`,
`supertimeline`). The strength is that the tool emits candidate findings and correlation output
without requiring a separate UI workflow; the cost is the opinionated taxonomy and a far narrower
artifact base feeding it.

## 7. Multi-source & deduplication

A concrete architectural contrast. **issen** folds `evidence_source_id` **into the dedup
`record_hash`** (`crates/issen-core/src/timeline/event.rs` — the hash covers `timestamp_ns`,
`event_type`, `source`, `artifact_path`, `description`, and `evidence_source_id`) — so Host A and
Host B emitting an otherwise-identical event produce two distinct, attributable rows that never
collide on dedup. For multi-host incident work (the common case), issen's "which host" is a
structural property of the dedup key.

**[UNVERIFIED]** for the Plaso side: `.plaso` event data streams include path-spec/source context
and the store tracks sessions and source metadata, so Plaso does not structurally lose
host/source attribution. A precise statement of Plaso's dedup behavior — whether two identical-looking
events from different sources are merged — requires citing the exact psort/storage dedup semantics,
which this comparison did not confirm from a primary source. The verifiable contrast is narrower:
issen's dedup key includes the evidence source by construction.

## 8. Performance & maturity — Plaso's lead

Stated plainly, without issen self-grading: **Plaso is Python**, and full-image processing is
hours-scale; its entire collector/worker/Redis-task architecture exists to parallelize around that
cost. issen is Rust, and its set-based DuckDB batch ingest avoids per-event round-trips — a
different performance profile. But performance is not where the honest comparison should lead,
because the larger facts favor Plaso on the axes that matter most for adoption: roughly fifteen
years of maturity, a much larger parser ecosystem, a deeper test corpus, transparent VSS/archive
handling, a large user community, and **Timesketch as a mature analysis UI/workbench**. issen is
younger, with a narrower parser base, partial log-format coverage, a memory leg still stabilizing,
and (per its own notes) parser-depth and subprocess-isolation work outstanding.

## Where each is the right tool

- **Reach for Plaso when** the goal is maximal artifact coverage into a timeline, you need VSS /
  nested-archive extraction, or you will analyze interactively in Timesketch. Its breadth, maturity,
  and workbench are well ahead in open source.
- **Reach for issen when** you want graded findings and an automated, curated set of cross-artifact
  correlations (logon↔file, brute-force, timestomp) without a separate UI step, queryable columnar
  output, a dedup key that keeps multi-host evidence distinct, a `DataSource` byte interface across
  file and container sources, and Rust-speed, resumable, atomic ingest — and you can accept a much
  narrower artifact base.
- **Conceptually they could compose:** a Plaso-style super timeline is the kind of substrate an
  issen-style correlation layer reasons over. No Plaso-to-issen importer exists today, so this is a
  design idea, not an available integration. issen is not "a faster Plaso"; it implements the
  reasoning stage Plaso core externalizes, with its own (currently narrower) extraction front end
  attached.

## issen's honest gaps vs. Plaso

1. **Parser breadth/depth and validation maturity.** Plaso's parser/plugin set and test corpus far
   exceed issen's current parser surface; issen also has internal "parser depth" gaps where a
   wrapper surfaces a fraction of its crate's capability, and less field hardening against malformed
   or unusual real-world artifacts.
2. **Source coverage / VSS.** Plaso's dfVFS provides transparent VSS-snapshot and nested-archive
   traversal inside images. issen has VSS/shadow-copy path-detection helpers but no Plaso-equivalent
   automatic VSS enumeration/traversal inside image containers.
3. **Maturity & ecosystem, including UI.** Plaso has long field history and a mature Timesketch
   UI/workbench. issen is newer; any issen UI/navigator should be described separately with its own
   current maturity and feature coverage, not implied to be at parity with Timesketch.
4. **Open-ended analysis.** issen's correlation is a finite curated rule set; Timesketch over Plaso
   is a general analyst workbench that can express correlations issen's rules do not.
5. **In-progress legs.** memory (Tier M) stabilizing, log formats partial (EVTX done;
   journal/tracev3/PCAP planned), graph/CAS planned, subprocess isolation not yet integrated.

issen's reciprocal differentiators — in-engine correlation, graded findings, queryable store, a
medium-spanning `DataSource` interface, multi-host attribution in the dedup key, resumable atomic
ingest, Rust performance — are stated above as architectural facts, not as a scored win.

## Sources & provenance

- **Plaso:** official docs (`plaso.readthedocs.io`, build `20260512`) + GitHub `log2timeline/plaso`
  + the Plaso API reference; super-timeline methodology from Guðjónsson, *Mastering the Super
  Timeline With log2timeline* (SANS/GIAC Gold, 2010). Items the research pass could not confirm from
  a primary source (e.g. exact psort/storage dedup semantics, exact timezone-flag spelling, full
  current output-module and analysis-plugin rosters) are **not** load-bearing in this comparison;
  where they appear they are framed as general behavior, marked `[UNVERIFIED]`, or noted as
  version-dependent, not as exact API.
- **issen:** the issen source tree (file:line citations verified for this revision —
  `crates/issen-core/src/timeline/event.rs`, `crates/issen-core/src/plugin/traits.rs`,
  `crates/issen-fswalker/src/{orchestrator,vss}.rs`, `crates/issen-timeline/src/ingest.rs`,
  `crates/issen-report/src/lib.rs`), `docs/ARCHITECTURE.md`, and the layered model in `CLAUDE.md`.
- This draft was reviewed by a Codex critic pass for overstatement and fairness, and this revision
  applies that critique.
