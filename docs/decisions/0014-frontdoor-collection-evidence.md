# 0014. Restore `EvidenceKind::Collection` to the front door (UAC-collection analysis)

- Status: Proposed
- Date: 2026-07
- Deciders: SecurityRonin

## Context

The front-door CLI redesign (bare `issen <evidence…> -o <db>`, no subcommand)
routes each evidence path through `pipeline::classify`. That enum knows only two
worlds:

```rust
// crates/issen-cli/src/pipeline.rs:189
pub enum EvidenceKind {
    Disk,
    Memory,
}
```

A UAC collection — a directory or `.tar.gz`/`.tgz` of loose forensic artifacts
(`chkrootkit/…`, `live_response/…`, `memory_dump/…`, `Windows/…/winevt/Logs/*.evtx`)
— has no `EvidenceKind`. `classify` maps every archive extension (`gz`/`tgz`/`tar`/…)
to `Disk`, and `classify_evidence` (`crates/issen-cli/src/commands/pipeline_run.rs:54`)
only peeks a zip's members to split Disk vs Memory. A UAC `.tar.gz` therefore lands
on the **disk leg**, where `issen-unpack` looks for a disk image inside and finds
none — the collection is never handed to the collection parser. Verified
empirically: the bare front door reports 0 artifacts from a UAC `.tar.gz`.

The collection parser and its analysis are not missing — they are **orphaned**.
`issen_parser_uac` (`UacProvider`) and `run_auto`
(`crates/issen-fswalker/src/orchestrator.rs:307`) are still called only by the
old `analyse.rs` / `supertimeline.rs` / `pivot.rs` command modules (still declared
in `crates/issen-cli/src/commands/mod.rs`, still building `run_auto` at
`supertimeline.rs:60`), but those verbs were dropped from CLI dispatch. So the
whole UAC-collection capability — rootkit indicators, hidden-process detection,
desktop-masquerade, EVTX session correlation, the temporal super-timeline, and the
forensic-pivot rule pack — is **CLI-unreachable**.

Commit `6d5e19e` removed the ~16 tests that documented this, which hid the gap
behind a green suite. The owner ruled that a **regression to fix**, not an
intentional removal. The tests are restored (re-pointed to the front-door
collection form `issen <collection> -o <db>`) and left **failing** so the gap is
visible; this ADR scopes the product fix that greens them.

## Decision

**Restore `EvidenceKind::Collection` and route UAC collections to `run_auto` from
the front door.** Concretely:

1. **Add the variant.** `EvidenceKind::Collection` in
   `crates/issen-cli/src/pipeline.rs`.
2. **Teach classification to recognize a collection** (by content, not just
   extension — consistent with the existing archive member-peek):
   - a **directory** whose layout looks like a UAC collection (`uac.log`,
     `live_response/`, `chkrootkit/`, `memory_dump/`, …), and
   - a **`.tar.gz`/`.tgz`/`.tar`** whose members look like a collection rather
     than a disk image — extend `classify_evidence` /
     `archive_member_kinds` in `pipeline_run.rs` to peek tar members the way it
     already peeks zip members, and return `Collection` when the tree matches.
   A collection classification must win over the current default-to-Disk so the
   archive stops being fed to `issen-unpack` as a disk image.
3. **Add a Collection branch in the front-door pipeline** that runs `run_auto`
   over the collection (extract → `issen_parser_uac` → events) and feeds the
   existing analyse / supertimeline / pivot logic. That logic already lives in
   `analyse.rs` / `supertimeline.rs` / `pivot.rs` — **re-wire it into the
   front-door stage, do not rewrite it**; the orphaned command modules become the
   library the front door calls.

## Constraint — sequence with the ingestion-pipeline rework

`crates/issen-cli/src/commands/pipeline_run.rs` is the front-door driver and is
under heavy concurrent rework (the two-level parallel ingestion pipeline). The
Collection branch touches `classify_evidence` and the stage dispatch in exactly
that file, so this change must be **coordinated and sequenced with the ingestion
work — not dropped in mid-flight.** Land it as a distinct step once the pipeline
driver is stable, to avoid a merge collision on the hot path.

## Consequences

- **The gap is visible, not hidden.** The 16 restored tests fail red until the
  branch lands; this PR therefore does **not** green the Test gate — that is
  blocked on this product fix.
- **No rewrite.** The analyse/supertimeline/pivot analysis is preserved as-is and
  reached through the front door; the folded verbs' modules become internal
  library code.
- **One classification concept.** Disk / Memory / Collection are decided in one
  place, by content where extension is ambiguous.

### Tests that go green once this lands

Restored in `crates/issen-cli/tests/cli_tests.rs`, all re-pointed to
`issen <collection> -o <db>`:

- **analyse (7):** `analyse_synthetic_fixture_emits_expected_sections`,
  `analyse_synthetic_fixture_shows_rootkit_evidence`,
  `analyse_synthetic_fixture_shows_hidden_pid`,
  `analyse_shows_unix_socket_paths_for_hidden_process`,
  `analyse_shows_desktop_masquerade_indicator`, `analyse_color_always_emits_ansi`,
  `analyse_shows_evtx_session_section_when_evtx_present`.
- **supertimeline (4):** `supertimeline_command_exists_with_collection_arg`,
  `supertimeline_jsonl_output_is_valid`, `supertimeline_csv_output_has_correct_headers`,
  `supertimeline_temporal_findings_appear_in_output`.
- **pivot (5):** `pivot_help_exits_success`, `pivot_sync_help_exits_success`,
  `pivot_rules_shows_bundled_rules`, `pivot_eval_empty_evidence_no_findings`,
  `pivot_eval_matching_evidence_emits_finding`.

(The forensic-pivot pack running automatically over a collection is part of this
fix; the pivot tests assert the bundled `pivot.miner.xmrig-process` rule fires on
a rootkit-concealed-miner collection.)
