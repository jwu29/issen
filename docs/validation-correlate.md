# Correlation Engine — Validation

This document records how issen's cross-artifact correlation engine
(`issen-correlation`, the disk-leg runner in `crates/issen-correlation/src/runner.rs`)
is validated, following the fleet Doer-Checker discipline: *what* was validated,
*against what oracle*, and *what the tests assert*. The lesson driving this page
is that synthetic fixtures you author yourself inherit your blind spots — green
unit tests passed while the engine was wrong three different ways the first time
it touched a real disk image.

## Summary

The runner is exercised at two tiers:

1. **Synthetic rule-behavior + regression tests** (`runner.rs`, `#[cfg(test)]`):
   each correlation rule fires on a constructed positive case and stays silent on
   a constructed negative, plus two regression guards that lock in fixes found
   only on real data (a false-positive guard and an O(n²) performance guard).
2. **Real-data validation** against the DFIR Madness "Stolen Szechuan Sauce"
   Case-001 Windows 10 DC image — an *independent third-party corpus with a
   published answer key* (Tier-1 evidence: neither the artifact nor the ground
   truth was authored by us).

Synthetic tests are Tier-3 (we wrote both the fixture and the expected answer);
the Case-001 run is Tier-1. The Tier-3 suite is the regression backstop; the
Tier-1 run is what actually establishes correctness.

## What the regression tests assert

Both live in `crates/issen-correlation/src/runner.rs`.

### `bruteforce_fires_for_burst_then_success_same_ip`

A `LogonFailureBurst` event followed by a `LogonSuccess`, both carrying the same
source-IP entity (`EntityRef::Ip`), must raise `CORR-BRUTEFORCE-LOGON`
(MITRE T1110). The test asserts the code fires for the burst→success sequence on
a shared join entity.

This is the positive half of the brute-force precision fix (`66f85bc`): the burst
is seeded only from a genuine run of `LogonFailure` events, and the rule joins on
the entity every burst member shares (the source IP, falling back to the account).
On real data the same logic fires the DC's RDP brute-force — 96 `Administrator`
failures, then success 217 ms later, account-keyed — and *stops* a dense
`LogonSuccess` run from masquerading as a burst (the link-local machine-account
false positive that this join-key discipline removed).

### `scales_to_a_large_disjoint_filecreate_slice_without_quadratic_blowup`

A regression guard for the O(n²) evaluator hang. A real DC timeline carries
~111k `FileCreate` events; the pre-index runner cloned and scanned the entire
candidate slice for every anchor (`run_exfil_stage` cloned all N others per
anchor), turning a single pass into minutes of CPU.

The test builds `N = 30_000` `FileCreate` events that pairwise share **no**
basename/stem and **no** entity ref (so zero disk-leg correlations among them),
plus one genuine `FileCreate → ServiceInstall` persistence pair on a shared stem.
It asserts:

- the fired set is **exactly** `["CORR-MALWARE-PERSIST"]` (only the one real pair
  correlates — the 30k disjoint events produce nothing); and
- the whole pass completes in **under 5 seconds** (with the entity index each
  anchor visits only candidates that share one of its own `EntityRef`s, so a
  structurally disjoint slice is near-instant).

This locks in the entity-index fix (`9824f0f`): `evaluate` already mandates
`shares_entity`, so candidates are bucketed by `EntityRef` and only
entity-sharing ones are evaluated — an identical fired set at linear cost.

## Real-data validation history (Case-001)

The runner passed every synthetic test yet failed three ways the first time it
ran against the real Case-001 DC E01 (`20200918_0347_CDrive.E01`,
~691,649 events, ~35 s correlation). Each was fixed under strict TDD (RED/GREEN
commits on `main`):

| # | Symptom on real data | Root cause | Fix |
|---|---|---|---|
| 1 | 0 artifacts discovered | discovery handed `run_auto` the *directory*; a disk image is only cracked when pointed at the *file* (`run_collection_pipeline`) | discovery recurses for disk-image first-segments (`af6fffd`) |
| 2 | 0 correlations | correlation fetch capped at `DEFAULT_LIMIT = 100_000`; the attack window sat at event ranks 368k–691k and was truncated | `EventQuery::is_unbounded()` (no `LIMIT`), used by `correlation_query()` (`b753b1a`) |
| 3 | Evaluator hang | O(n²): `run_exfil_stage` cloned all candidates per anchor over 111,240 `FileCreate`s | entity index — bucket candidates by `EntityRef`, evaluate only entity-sharing ones; identical fired set (`9824f0f`) |

Brute-force precision was a fourth fix (`66f85bc`): seed `LogonFailureBurst` only
from a run of `LogonFailure` events and join on `burst_join_entity` (source IP,
else account). The real DC RDP brute-force now fires correctly (T1110), and the
machine-account false positive is gone.

### Oracle and reproduction

- **Corpus / oracle:** DFIR Madness "Stolen Szechuan Sauce" Case-001 — a
  third-party DFIR teaching corpus with a published scenario answer key (the C2
  beacon `coreupdater.exe → 203.78.103.109`, the RDP brute-force, the persistence
  chain). Provenance and download in `docs/corpus-catalog.md`.
- **Run:** `issen correlate "<…>/extracted/E01-DC01"` (~4 min ingest →
  ~691,649 events, ~35 s correlation), then inspect `correlate.duckdb` with the
  `duckdb` CLI (`-readonly`).

### Known limitation (current state)

On the DC disk image alone, only `CORR-BRUTEFORCE-LOGON` fires end-to-end. The
full rule union (RELOCATE / PERSIST / COPY-DELETE / LATERAL-MOVE and the memory-leg
Tier-C rules) needs both hosts plus the memory leg in one timeline; those rules
are covered by the synthetic suite but await the same real-data tuning across the
combined corpus. This is a coverage caveat that is *currently true*, not a record
of a superseded approach.
