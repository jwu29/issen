# Design Spec — Native Timeline Query Subcommands for `issen`

**Status:** Draft · **Owner crate:** `issen-timeline` (query layer) + `issen-cli` (surface) · **Date:** 2026-06-24
**Supersedes:** the raw `duckdb <db> -c "SELECT …"` lines used throughout
`docs/workshop-3hr/gamma-script.md` and `docs/szechuan-sauce-quickstart.md`.

---

## Executive Summary

Today, an analyst answering Case 001 with issen ingests evidence into a DuckDB timeline — and
then **drops to raw SQL** (`duckdb dc01.duckdb -c "SELECT …"`) for ~20 of the answers. That is
three problems at once:

1. **It breaks the product promise.** "One command, one output, the full narrative" collapses the
   moment the analyst must hand-write `json_extract_string(metadata,'$.IpAddress')`. The competitor
   we are displacing (Volatility + EZ tools + KAPE) at least never asked the analyst to write SQL.
2. **It is not secure by design.** Raw SQL over an evidence database invites injection, accidental
   writes, and silently-wrong results (a typo'd `LIKE` returns `0 rows`, indistinguishable from a
   clean finding). Evidence tooling must make the wrong query *structurally hard*, not merely
   discouraged.
3. **It is not idiotproof.** The schema (`timeline` columns, the JSON keys inside `metadata`) is
   tribal knowledge. A junior analyst cannot answer "who logged on?" without first learning that
   logon users live in `metadata.$.TargetUserName` and that machine accounts end in `$`.

**Recommendation.** Add a **typed, injection-safe query layer** to `issen`, in two tiers:

- **Tier 1 — an enriched `issen timeline`**: a general filter / project / aggregate engine driven
  by *typed flags*, never SQL. It can express every one of the 20 query shapes in the deck.
- **Tier 2 — intent subcommands** (`issen logons`, `issen files`, `issen persistence`,
  `issen hosts`) that answer a named question in one verb, plus a **DuckDB mode** for the existing
  `issen frequency` and `issen session` so they run against an ingested case, not only loose EVTX.

A guarded, read-only `issen query --sql` escape hatch remains for power users, explicitly labelled
and sandboxed. After this, **zero** deck answers require `duckdb`.

This spec is design-only: no code. It defines the surface, the semantics, the output contract, the
security model, and a TDD phasing plan.

---

## Motivation — the 20 queries we must replace

Extracted verbatim from the workshop deck (`gamma-script.md`). Every raw query reduces to one of
**seven capabilities**:

| # | Raw query shape (abbreviated) | Capability | Today's deck question |
|---|---|---|---|
| 1 | `WHERE event_type='LogonSuccess' AND metadata LIKE '%<ip>%'` → project type/ip/user | logon filter + project | Q5, Q8 |
| 2 | `SELECT event_type, count(*) GROUP BY event_type` | event-type histogram | Q4 |
| 3 | `SELECT DISTINCT artifact_path WHERE path LIKE '%X%'` | path filter + distinct | Q6.4 |
| 4 | `SELECT min(timestamp_display) WHERE path LIKE '%X%'` | path filter + first-seen | Q6.5 |
| 5 | `SELECT ts,event_type,source WHERE path LIKE '%loot.zip%' ORDER BY ts` | artifact history | Q8.3, Q12 |
| 6 | `WHERE event_type='ServiceInstall' AND metadata LIKE '%X%'` → project ServiceName | service-install filter | Q6.9 |
| 7 | `SELECT DISTINCT WorkstationName, IpAddress WHERE ip LIKE '10.42.%'` | host/IP inventory | Q9 |
| 8 | `SELECT ts,event_type WHERE path LIKE '%beth%'` | artifact history | Q12 |
| 9 | `SELECT max(timestamp_display) WHERE event_type='Logoff'` | last-of | Q13 |
| 10 | `SELECT DISTINCT TargetUserName WHERE type IN (2,10,11) AND u NOT LIKE '%$'` | interactive users | B4, B5 |
| 11 | `SELECT DISTINCT basename(path) WHERE path LIKE '%X%'` | distinct filenames | B7, B8 |
| 12 | `SELECT count(DISTINCT TargetLogonId), min, max WHERE ip=X` | session count + window | Extra (sessions) |
| 13 | `WHERE source='Registry' AND path LIKE '%run%' AND metadata LIKE '%X%'` | run-key lookup | Extra (persistence) |
| 14 | `SELECT IpAddress, count(*) GROUP BY ip ORDER BY count ASC` | field frequency | Extra (rare source) |
| 15 | `SELECT DISTINCT basename(path) WHERE path LIKE '%.lnk' …` | typed-artifact filter | Extra (LNK) |

**The common primitives:** filter by `event_type` / `source` / `artifact_path`-substring /
`metadata` JSON field; project chosen columns + extracted metadata keys; aggregate
(`count`, `count distinct`, `min`/`max`, `group by … order by`); reduce a path to its basename;
range/limit/sort. None of these should require the analyst to know SQL or the schema.

---

## The timeline schema (what the query layer sees)

The ingested `timeline` table (DuckDB), as of this writing:

| Column | Type | Notes |
|---|---|---|
| `timestamp_ns` | bigint | sort key; UTC nanoseconds |
| `timestamp_display` | varchar | ISO-8601 string (host clock) |
| `event_type` | varchar | `LogonSuccess`, `ServiceInstall`, `FileCreate`, `FileRename`, `FileDelete`, `Other("…")`, … |
| `source` | varchar | `EventLog`, `Mft`, `UsnJournal`, `Registry`, `Srum`, `memory`, … |
| `artifact_path` | varchar | file path / registry key / object path |
| `description` | varchar | human summary |
| `metadata` | varchar (JSON) | source-specific keys: `IpAddress`, `LogonType`, `TargetUserName`, `TargetLogonId`, `ServiceName`, `WorkstationName`, `event_id`, … |
| `user_account`, `hostname`, `tags`, `evidence_source`, `activity_category`, `epoch`, … | varchar | normalized columns (some sparse) |

**Key design fact:** the high-value selectors (`IpAddress`, `LogonType`, `ServiceName`,
`TargetUserName`, `TargetLogonId`) live *inside* the `metadata` JSON blob. The query layer must
expose these as **first-class, named filters** — the analyst should never type `json_extract_string`.
A curated **field registry** (name → JSON path + type + which `event_type`/`source` populates it) is
the heart of this design; it turns tribal schema knowledge into a discoverable, typed surface
(`issen timeline --list-fields`).

---

## Design principles (binding)

- **Secure by default.** The default surface emits **no SQL** and accepts **no SQL**. Filters are
  typed values bound as parameters; an evidence DB is opened **read-only**. The wrong query is
  structurally unreachable, not merely undocumented.
- **Idiotproof the schema.** Named filters (`--ip`, `--user`, `--service`, `--path`) map to the
  field registry; the analyst never learns `metadata.$.X`. `--list-fields` and tab-completion make
  the surface self-describing.
- **One concept, one name.** `--path` means artifact path everywhere; `--source` is the ingest
  source everywhere; `event_type` filtering is `--event-type` everywhere. No `--dir`/`--folder`
  synonyms; no `-rt` vs `-triage` drift.
- **Intent first, primitives underneath.** "Who logged on?" is `issen logons --users`, not a filter
  expression. The intent verbs are thin wrappers over the Tier-1 engine, so there is one code path
  and one output contract.
- **Reuse, don't reinvent.** Extend the existing `timeline`, `frequency`, `session`, `processes`
  subcommands; do not fork a parallel query tool. `frequency`/`session` gain a DuckDB input mode
  alongside their current EVTX mode.
- **Fail loud, never silent-zero.** A filter naming an unknown field, or a value that matches no
  rows *because the field was never populated for any ingested source*, is a **diagnostic**, not an
  empty table (the Bootstrap-failure-≠-not-found discipline). "0 rows" must be distinguishable from
  "that field isn't in this case."

---

## Tier 1 — the enriched `issen timeline`

`issen timeline <DB> [filters] [projection] [aggregation] [output]`

### Filters (typed, AND-combined, injection-safe)

| Flag | Meaning | Replaces |
|---|---|---|
| `--event-type <T>` (repeatable) | match `event_type` (exact, OR within the flag) | existing |
| `--source <S>` (repeatable) | match `source` | existing |
| `--path <GLOB>` | `artifact_path` glob/substring (e.g. `*coreupdater*`, `*.lnk`) | shapes 3,4,5,8,11,15 |
| `--field <NAME><OP><VAL>` (repeatable) | typed metadata filter; `NAME` from the field registry; `OP` ∈ `=`,`!=`,`~` (contains), `in:` | shapes 1,6,7,10,12,13 |
| `--ip <V>` `--user <V>` `--service <V>` `--logon-type <N,…>` | **sugar** for the most common `--field` selectors | shapes 1,6,10,12 |
| `--after <TS>` `--before <TS>` | time-range on `timestamp_ns` | (new, common need) |
| `--exclude-machine-accounts` | drop `user`/account values ending in `$` | shape 10 |

`OP` values are bound parameters; `--path` compiles to a parameterized `LIKE` with escaped
metacharacters. There is **no string interpolation** of analyst input into SQL.

### Projection

| Flag | Meaning |
|---|---|
| `--show <COL|FIELD,…>` | choose output columns; `COL` = a table column, `FIELD` = a registry field (auto-extracted from `metadata`). Default: `timestamp_display,event_type,source,artifact_path`. |
| `--basename` | render `artifact_path` as its final path component (shapes 11,15) |

### Aggregation (mutually exclusive with row output)

| Flag | Meaning | Replaces |
|---|---|---|
| `--count` | total matching rows | shapes 2(part),13 |
| `--distinct <COL|FIELD>` | distinct values (optionally `--count` for cardinality) | shapes 3,7,10,11,15 |
| `--group-by <COL|FIELD>` | histogram: value, count — `--sort asc|desc` | shapes 2,14 |
| `--first` / `--last` | min/max `timestamp_ns` of the matched set (+ its row) | shapes 4,9,12 |
| `--sessions-by <FIELD>` | `count(distinct FIELD)` + first/last window | shape 12 |

### Output

`--format text|json|jsonl|csv` (default `text`); `--limit N`; `--sort asc|desc` (by time).
`csv`/`json` go through `jsonguard` (CSV-injection / bidi-safe) — evidence output is attacker-
controlled and must be sanitized by construction.

### Worked replacements (deck → Tier 1)

```bash
# Q5 initial vector (was: duckdb … LogonSuccess AND metadata LIKE '%194.61.24.102%')
issen timeline dc01.duckdb --event-type LogonSuccess --ip 194.61.24.102 \
  --show timestamp_display,logon_type,ip,user --limit 1

# Q4 breach histogram (was: GROUP BY event_type)
issen timeline dc01.duckdb --group-by event-type

# Q6.5 first-seen (was: min(timestamp_display) WHERE path LIKE '%coreupdater%')
issen timeline dc01.duckdb --path '*coreupdater*' --first

# B4/B5 who logged on (was: DISTINCT TargetUserName … type IN (2,10,11) … NOT LIKE '%$')
issen timeline dc01.duckdb --event-type LogonSuccess --logon-type 2,10,11 \
  --exclude-machine-accounts --distinct user

# Extra sessions (was: count(distinct TargetLogonId), min, max)
issen timeline dc01.duckdb --event-type LogonSuccess --ip 194.61.24.102 --sessions-by logon-id

# Extra rare source (was: IpAddress, count(*) GROUP BY ip ORDER BY count ASC)
issen timeline dc01.duckdb --event-type LogonSuccess --group-by ip --sort asc
```

---

## Tier 2 — intent subcommands (answer a question in one verb)

Thin wrappers over Tier 1, each owning sensible defaults and a question-shaped output. They exist
because "who logged on?" should not require the analyst to remember `--logon-type 2,10,11
--exclude-machine-accounts`.

### `issen logons <DB>`
Logon/logoff analytics. Flags: `--users` (distinct interactive users), `--from <IP/host>`,
`--user <name>`, `--sessions` (count + window per source identity), `--failures` (4625),
`--interactive-only` (types 2/10/11, machine accounts dropped by default).
Covers Q5, Q8, Q13, B4, B5, and Extra-sessions.

```bash
issen logons dc01.duckdb --users                 # B4/B5
issen logons dc01.duckdb --from 194.61.24.102 --sessions   # Extra: 4 sessions, 03:21→03:56
issen logons desktop.duckdb --from 10.42.85.10   # Q8 lateral
```

### `issen files <DB>`
Artifact-path history. Positional `<GLOB>`; flags `--first`, `--last`, `--names` (distinct
basenames), `--type lnk|exe|zip|…` (extension sugar), `--source mft|usn|registry`.
Covers Q6.4/6.5/6.6, Q11, Q12, B7/B8, Extra-LNK.

```bash
issen files dc01.duckdb '*coreupdater*' --first            # Q6.4/6.5
issen files desktop.duckdb '*loot.zip*'                    # Q8.3 history
issen files dc01.duckdb '*beth*' --names                   # B7/B8 filenames
issen files dc01.duckdb --type lnk '*secret*|*szechuan*'   # Extra LNK
```

### `issen persistence <DB>`
Persistence inventory across mechanisms: `--services` (7045 + ServiceInstall), `--run-keys`
(`…\CurrentVersion\Run*`), `--tasks` (scheduled tasks), `--all` (default). Optional `--name <X>`
to filter to an IOC. Covers Q6.9 and Extra-dual-persistence in one view, naming each mechanism.

```bash
issen persistence dc01.duckdb --name coreupdater   # service + run key, both shown
```

### `issen hosts <DB>`
Host / network inventory: distinct `WorkstationName` ↔ `IpAddress` ↔ subnet, from logon + EVTX
metadata. Covers Q9. (Registry interface extraction is a separate, later enrichment — flag it as
`partial` until the registry value-parser lands.)

### DuckDB mode for existing verbs
- `issen frequency <DB> --field <NAME>` — the Events-Ripper rare-event technique over *any* registry
  field (default `ip`), not only loose EVTX. Covers Extra-frequency.
- `issen session <DB>` — logon-session correlation from the ingested timeline (today it requires raw
  EVTX files). Same output, new input.

These are **input-mode additions**, not new commands — `frequency`/`session` keep one name and one
output contract whether fed EVTX or a DB (one-concept-one-name).

---

## The escape hatch — `issen query` (guarded, opt-in)

Power users will occasionally need an expression the typed surface doesn't cover. Provide it, but
make it safe and obviously a sharp tool:

- `issen query <DB> --filter '<typed-DSL>'` — a small, **parsed** boolean filter DSL over the field
  registry (`event_type=LogonSuccess and ip=194.61.24.102 and path~coreupdater`). Compiles to a
  parameterized query; cannot express writes, joins, or subqueries. This is the *default* power path.
- `issen query <DB> --sql '<SELECT …>'` — raw read-only SQL, **explicitly** behind `--sql`, opened
  on a read-only connection with a statement allowlist (`SELECT`/`WITH` only; `ATTACH`/`PRAGMA`/DML
  rejected). Carries a one-line "unsafe: results are not schema-validated" notice. This is the
  `_unchecked` of the query surface: present, named, never the default.

Rationale (secure-by-design): the safe path is zero-config and typed; raw SQL requires a deliberate,
annotated opt-in — exactly the "no unsafe-but-fast escape hatch in the default surface" rule.

---

## Output contract (stable across tiers)

- One renderer for all query output (Humble-Object: the verbs decide *what* to ask; one library
  function decides *how* to render), so `text/json/jsonl/csv` behave identically everywhere.
- Column order is stable and documented; `--format json` emits typed values (numbers as numbers,
  timestamps as ISO-8601 + ns).
- **Provenance line** on every result: DB path, row count, filters applied, and `evidence_source`
  spread — so a screenshot in a report is self-describing (the workshop literally asks students to
  screenshot findings).
- All string output is `jsonguard`-sanitized (formula-injection, bidi, control chars) because the
  data is attacker-controlled.

---

## Security considerations

1. **Read-only by construction** — the query layer opens DuckDB with a read-only handle; no code
   path can mutate evidence.
2. **No interpolation** — typed filters bind as parameters; `--path` globs are escaped; the DSL is
   parsed to an AST, never string-concatenated.
3. **`--sql` is fenced** — read-only connection + statement-type allowlist + explicit flag + notice.
4. **Loud on unknown fields** — `--field nope=…` lists valid fields and exits non-zero; never a
   silent empty result.
5. **Empty ≠ absent** — when a filter matches zero rows, the result states whether the field was
   *populated by any ingested source in this case*; a never-populated field is a coverage gap
   (e.g. Registry not yet parsed), reported as such, not as "clean."

---

## Non-goals (YAGNI)

- No general SQL builder UI, no saved-query store, no joins across multiple DBs (one case = one DB).
- No write/annotation path (an "evidence editor" is explicitly out — findings live in the report
  layer, never back in the timeline).
- No new query *language* beyond the small boolean filter DSL; if a need exceeds it, that is a
  signal to add a typed flag or an intent verb, not to grow the DSL.

---

## Phasing & implementation plan (strict TDD)

Each phase: RED commit (failing tests defining behavior) then GREEN commit (minimal impl), per the
fleet TDD standard. Validate against the **real Case 001 DBs** (`g1-rerun/dc01.duckdb`,
`desktop.duckdb`) — the same numbers the deck quotes — not synthetic fixtures (Doer-Checker).

1. **Field registry + read-only query core** (`issen-timeline`): the typed-filter → parameterized-
   query compiler, the field registry, the renderer. Unit-tested against the real DBs.
2. **Tier 1 `issen timeline` flags** — filters, projection, aggregation, formats. Acceptance test =
   reproduce all 20 deck numbers via flags (a golden table: query → expected value).
3. **Tier 2 intent verbs** — `logons`, `files`, `persistence`, `hosts`; each defined by the deck
   question it answers, with an E2E test asserting the deck's quoted output.
4. **DuckDB mode for `frequency` / `session`** — add the DB input path; assert parity with EVTX mode.
5. **`issen query` DSL + fenced `--sql`** — parser, allowlist, read-only handle, injection tests.
6. **Deck/quickstart migration** — replace every `duckdb …` line in `gamma-script.md` and
   `szechuan-sauce-quickstart.md` with the new commands; re-validate outputs match.

**Definition of done:** `grep -c 'duckdb ' docs/workshop-3hr/gamma-script.md` → `0`, and the
golden-query table passes on the real images.

---

## Open questions

- **Field registry source of truth** — hand-curated table vs derived from the parser crates'
  emitted-key manifests. Prefer derived (so a new parser's fields appear automatically), with a
  curated display-name/alias overlay.
- **`logon-type` naming** — expose numeric (`2,10,11`) plus named aliases (`interactive`,`remote`,
  `unlock`)? Lean yes (idiotproofing), numerics still accepted.
- **Cross-host queries** — out of scope here (one DB per host); the multi-host story stays in
  `issen correlate`. Confirm that boundary.
