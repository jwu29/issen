# All-Encompassing Supertimeline — Surfacing-Mechanism Review & Design

**Status:** draft for Codex critique (2026-06-16). Author: Claude (Opus 4.8).
**Trigger:** dark winreg-artifacts (com_hijacking/lsadump/svc_diff/typed_urls/lxss) — a *symptom*
of an ungated surfacing mechanism. Goal: make the supertimeline provably all-encompassing.

## Executive Summary

The supertimeline is assembled by `run_auto` → `discover_artifacts` (classify files) →
`all_parsers()` (compile-time `inventory` of linked parsers) → **all-match dispatch** (run every
parser whose `supported_artifacts()` contains the file's `ArtifactType`). The dispatch is already
correct (it runs *every* matching parser per artifact and each parser self-filters internally — no
`can_parse` gate to wrongly exclude). **The problem is not dispatch — it is that completeness
emerges from an ungated manual chain with five silent-omission modes and no gate anywhere.**

For forensics this is the cardinal sin: a silent omission is indistinguishable from a true negative,
so the analyst cannot tell "artifact absent" from "artifact present but never parsed/classified/
linked." The fix is **not** "parse everything" (unprovable) but: *every file is either parsed or
reported as unparsed, every linked parser's contribution is counted, and CI gates prevent regression.*

## The five silent-omission modes (each verified in code)

1. **No wrapper** — a fleet reader module exists with no `issen-parser-*` wrapper. (com_hijacking et al.)
2. **Unlinked wrapper** — a wrapper crate exists but is not a dependency of `issen-cli`, so
   `inventory::iter::<ParserRegistration>` never sees it. `all_parsers()`'s own test says "we can't
   assert a specific count" → **no gate**. Silent.
3. **Unclassified file** — `detect_artifact_type` is a hardcoded filename/extension list; a file it
   returns `None` for is dropped in `walk_directory` and is **never even counted** (`artifacts_found`
   counts only classified files). Machine hives need `full.contains("registry"|"config")` → a hive
   extracted to a flat directory is invisible. Silent.
4. **ArtifactType mismatch** — a parser's `supported_artifacts()` disagrees with the classifier's
   label (e.g. Amcache.hve is classified `Amcache`, so `[Registry]` parsers never run on it).
5. **Stub / empty `parse()`** — a linked, dispatched parser that always returns zero events.

`IngestResult { artifacts_found, artifacts_parsed, total_events, total_bytes, errors }` is a partial
manifest: it counts classified-and-attempted artifacts and parse errors, but is blind to unclassified
files, per-parser event counts, the linked-parser set, and dark (zero-event) parsers.

## Codex adversarial critique (folded in — 2026-06-16)

Codex confirmed all five modes with code citations and **corrected the keystone**: a `CoverageManifest`
is *observability, not a mechanism* — "metadata on a broken pipeline" unless the structural gaps are
blocked in CI. **Block structural incompleteness at build time; report only case-specific gaps at
runtime.** Verified findings that sharpen the picture:

- **Mode 2 is concrete and large.** `issen-cli/src/main.rs:12-23` force-links exactly **12** parser
  crates (amcache, evtx, prefetch, registry, runkeys, sam, shellbags, shimcache, srum, uac,
  userassist, velociraptor). Workspace crates `pe`, `lnk`, `linux`, `macos`, `setupapi` are **not**
  force-linked → never in `all_parsers()` → never run. The winreg dark artifacts are a small slice.
- **Mode 5 is widespread.** `macos`, `linux`, `lnk`, `setupapi` `ForensicParser::parse` return empty
  `ParseStats` (stubs) — dark even if linked. `run_pipeline` counts a zero-event completion as
  "parsed" with no signal.

Four **additional** silent-omission / correctness modes Codex found:
- **(6A) Declared `ArtifactType` with no classifier producer.** `Lnk`, `BiomeMenuItem`, `Bodyfile`,
  and Linux/macOS variants are never returned by `detect_artifact_type` → a fully-implemented,
  linked parser for them is *dead on arrival* (the file is walked but never labelled their type).
- **(6B) Dirty-hive under-parse.** `.LOG1/.LOG2` transaction logs aren't replayed before hive parse;
  cells committed only to the logs are silently absent, yet the hive counts as "parsed."
- **(6C) Nested archive / VHD / VSS non-recursion.** `run_collection_pipeline` extracts one layer;
  `walk_directory` recurses dirs only — shadow copies / nested containers are silently absent.
- **(6D) Partial-read truncation (a real bug).** `FileDataSource::read_at` (`Read::read`) may fill
  fewer bytes than requested; runkeys/amcache/userassist pass the *full preallocated* buffer to the
  parser even when only `off` bytes were filled (registry parser correctly truncates to `filled`).
  Trailing-zero corruption on FUSE/remote/interrupted sources.
- **(6E) Unsorted output (a real bug).** Rayon parses in parallel into a mutex-backed vec returned
  **unsorted**; `supertimeline` renders in input order. The timeline isn't chronological.

**Catalog feasibility (corrected).** forensicnomicon's catalog carries `artifact_type/hive/key_path/
value_name` + `HiveTarget` + `filter_by_hive`, but registry descriptors have `file_path: None` — it
says "needs the SOFTWARE hive," not "this collected file *is* the SOFTWARE hive." So discovery must be
**container-first**: identify hive containers by **file magic + filename/path globs** (a dedicated
*discovery manifest* mapping logical `HiveTarget` → physical globs), then run catalog descriptors
*inside* a matched container. Do **not** turn the catalog into a glob database (two responsibilities,
different test demands).

**Breadth/depth dedup (corrected).** `catalog_scan`/`regcatalog` will overlap the specialized
registry parsers. Two-layer identity: `registry_record_identity` (hive + normalized key path + value
name + value type + raw-value hash) for exact dedup; `semantic_identity` (RunKey command, UserAssist
GUID, SAM RID, Shimcache path) to link breadth↔depth aliases. Policy: **keep the depth parser's event
as primary** (richer semantics); attach the breadth hit as a coverage annotation, never a duplicate.

## Decision: discovery knowledge belongs to forensicnomicon (not issen's orchestrator)

`detect_artifact_type`'s hardcoded `if`-ladder is a **layering violation** — forensic
format/artifact knowledge living in the ORCHESTRATION layer. Per the fleet charter forensicnomicon
is the KNOWLEDGE leaf ("magic bytes, record markers, format header offsets, field schemas"); the
*discovery* knowledge belongs there too. So Codex's "separate discovery manifest" lives **inside
forensicnomicon**, not issen:

- **Extend the catalog descriptor** (or add a discovery catalog) with the **physical** facts needed to
  find an artifact: container filename / path globs (e.g. `HklmSoftware` → `**/System32/config/SOFTWARE`
  + bare `SOFTWARE`), and a **container magic signature** (registry `regf`, ESE, EVTX `ElfFile`, …).
  Registry descriptors today carry `file_path: None`; this fills that gap as first-class knowledge.
- **issen's `detect_artifact_type` becomes a thin catalog consumer**: walk file → ask forensicnomicon
  "does this name/magic match a known container?" → `ArtifactType`. **Zero hardcoded forensic rules in
  the orchestrator.** New artifact in forensicnomicon → issen discovers + classifies it automatically
  (complete-by-construction for classification).
- The same catalog then drives **breadth decode** (`catalog_scan`/`regcatalog`): every descriptor for
  a matched container is evaluated. Specialized parsers remain DEPTH on top. Knowledge (what/where/how
  to decode) lives once, in forensicnomicon; issen only orchestrates.

This unifies plan items 3, 5, and 8 under one move — *migrate discovery knowledge to forensicnomicon,
make issen a thin consumer* — and removes the mode-3 / mode-6A hardcoding at the root rather than
patching the `if`-ladder.

## Implementation order (Codex-ranked: structural gaps in CI first, observability second)

1. **Link-completeness CI gate** (very high / low) — every `crates/parsers/issen-parser-*` member is
   force-linked in `issen-cli` AND present by name in `all_parsers()`. Kills mode 2 + the force-link list.
2. **Stub-parse CI gate** (very high / medium) — a parser returning zero events on a positive fixture
   fails the build. Kills mode 5.
3. **`detect_artifact_type` producer coverage** (very high / medium) — every `ArtifactType` a linked
   parser supports must have a classifier producer; gate it. Kills mode 6A.
4. **CoverageManifest** in supertimeline output (high / medium) — unclassified files, per-parser
   dispatch/event counts, dark-parser flags. Reports modes 3/5/case-specific gaps. (Observability.)
5. **Machine-hive discovery by file magic + filename** (high / medium) — remove the `config`/`registry`
   path-gate. Kills the mode-3 flat-dir drop.
6. **Registry transaction-log replay** before hive parse (high / medium-high) — mode 6B.
7. **Sort supertimeline by timestamp** (high / low — cheap win) — mode 6E.
8. **Catalog-driven registry breadth scanner** (medium-high / high) — container-first per above.
9. **Breadth/depth dedup identity model** (medium-high / medium-high).
10. **Fleet-capability cross-repo manifest gate** (medium / high).
11. **Recursive nested archive / VHD / VSS discovery** (medium-high / very high) — mode 6C; biggest.

Also fix **(6D) partial-read truncation** opportunistically (truncate every parser's buffer to bytes
actually filled — mirror the registry parser) — a correctness bug independent of ranking.

## Superseded design notes (kept for context)

The numbered "Design" subsections below predate the Codex pass; the keystone there (CoverageManifest)
is demoted to item 4 above. CI gates (items 1-3) are the keystone.

### 1. Coverage Manifest (was "keystone"; now observability — see item 4 above)
`run_auto` returns a `CoverageManifest` alongside events:
- `files_walked` (every regular file seen by `walk_directory`, classified or not)
- `classified` per `ArtifactType` + **`unclassified: Vec<{path, ext}>`** (the currently-invisible set)
- `parsers_linked: Vec<&str>` (names from `all_parsers()`), `parsers_dispatched`, and
  `per_parser_events: Map<name, u64>` → `parsers_zero_events` (dark-parser candidates)
- `errors` (already present)

The supertimeline header becomes a coverage report: "walked 14,920 files; classified 9,210 across 18
types; 5,710 unclassified; 41/41 parsers linked, 38 produced events, 3 produced none (review)."
This is the unified-timeline **Phase-4 partial-ingest-honesty** generalized, and the single
highest-value change — modes 2/3/5 all become visible without proving completeness.

### 2. Link-completeness gate (kills mode 2)
A test enumerating `crates/parsers/issen-parser-*` workspace members and asserting each is (a) an
`issen-cli` dependency and (b) present by name in `all_parsers()`. Deterministic; fails CI the moment
a wrapper is unlinked or silently dropped from the inventory. Cheap, high-value.

### 3. Catalog-driven classification + registry breadth (kills modes 1 & 3 for the registry domain)
- `detect_artifact_type` should consult **forensicnomicon's catalog** (`HiveTarget`/filenames) rather
  than a hand-maintained `if`-ladder, so a new catalog artifact also teaches *discovery* to find it.
  Delete the `full.contains("config")` exclusion for machine hives (classify by hive name; use the
  directory only as a confidence signal, never a silent exclude).
- Wire `winreg_artifacts::catalog_scan` → `issen-parser-regcatalog` so the **entire** forensicnomicon
  registry catalog surfaces (breadth). New catalog entries → timeline events with zero issen code.
  Specialized parsers (sam/shimcache/amcache) remain as **depth** on top of the breadth layer.

### 4. Fleet-capability coverage gate (kills mode 1 generally)
Promote `docs/fleet-capability-inventory.md` from prose to a checked manifest: enumerate fleet
reader-library artifact modules (e.g. `winreg-artifacts` `pub mod`s) vs wrappers; a test/audit fails
or warns loudly when a module is unwrapped-and-unexempted. (Cross-repo → likely a checked-in
expected-coverage file + audit, not a hard per-PR gate.)

### 5. Dispatch unchanged (already all-match). Optional `can_parse` fast-path for perf only — never a
completeness gate.

## What "all-encompassing" means (precise claim)
Not "nothing is ever missed." Rather: **(a)** every walked file is parsed or appears in
`unclassified`; **(b)** every linked parser's event count is reported, so dark parsers are visible;
**(c)** the parser link-set and registry-catalog coverage are CI-gated against regression; **(d)** the
registry long tail is complete-by-construction from the catalog. Completeness becomes *auditable*.

## Open questions for Codex
- Is the Coverage Manifest the right keystone, or is a hard classification-coverage gate better?
- Catalog-driven `detect_artifact_type`: does forensicnomicon's catalog actually carry the
  filename/HiveTarget needed to drive discovery, or only decode? If only decode, what's the source of
  truth for "which files are artifacts"?
- Does `catalog_scan` breadth *subsume* any specialized parser (double-emit risk)? Dedup strategy?
- Cross-repo capability gate: hard CI gate vs periodic audit — which is maintainable without becoming
  a rubber stamp?
- Any sixth silent-omission mode missed (e.g., discovery not recursing into nested archives/VSS, or
  `walk_directory` symlink/junction handling, or per-user hive enumeration across many profiles)?
