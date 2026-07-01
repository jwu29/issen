# Monday Morning Plan — consolidated forward plan for `issen`

**Status:** ACTIVE — single source of truth. Supersedes the five plans listed under
[Superseded](#superseded-plans). · **Date:** 2026-06-22 · **Author:** consolidation pass.

## Executive Summary

Most of the standing backlog is **already built**. A verification pass — four read-only
agents plus direct inspection, each item checked against current source rather than trusted
from plan text (the "SRUM lesson": that depth build was fully implemented while still listed
as TODO) — found the Saturday mega-plan's value-first phases (L1/L2/L3, Phase 2 extraction,
Phase 5 integrity) shipped, and three of the four "depth builds" (SRUM, Biome integrity, LNK
JumpLists) done. What remains is a **small, well-scoped open set**, plus one large item
(Epic K) deliberately parked on a go/no-go because it is the least-reversible and
lowest-marginal-capability change in the plan.

**Do-now (low-risk, high-value):** de-specialize the over-fit `/tmp/silly.txt` correlation
rule (a No-Special-Cases violation), and green CI (fix the one pre-existing fmt drift; add the
fleet-standard `fuzz.yml`). **Next:** wire the registry-driven selector's Stage 2/3
consumption (its scaffolding is declared but unread), and surface deep `$LogFile`
per-transaction replay. **Parked on your decision:** Epic K (relocate the semantic
`ArtifactType` taxonomy into forensicnomicon), with a regression-safe, rollback-able migration
design recorded below.

## Verification method

Status was established by reading the code, not the plans: `git log`, `grep`, test-name
existence, and targeted test runs. Each verdict carries file:line / commit / test-name
evidence. A Codex pass independently critiqued the verdicts and the Epic K migration design.
Verdicts: **DONE** (built + tested) · **OPEN** (genuinely unbuilt) · **SUPERSEDED**
(subsumed by other work).

## Verified status — DONE

| Item | Evidence |
|---|---|
| Epic L1 — thin-shim main | `issen-cli/src/main.rs` 6-line shim → `run()`; full `Cli` in `lib.rs` |
| Epic L2/L3 — aggregators + drift gate | `issen-parsers`/`issen-providers` build.rs anchor codegen; `link_completeness.rs` counts registrations; unit gates pass |
| Phase 2 — extraction value slice | `issen-disk` extraction caps + `$I`/LNK/ADS (`extract_named_streams`) |
| Phase 5 — $MFT/$MFTMirr/$Boot integrity | `issen-mft-tree/mirror.rs`; `issen-disk` `read_boot_geometry`/`boot_backup_integrity_events`/`NTFS-BOOT-BACKUP-MISMATCH` |
| Phase 5 — shimcache + timestomp $FN | `issen-parser-shimcache`; `issen-correlation/timestomp.rs:87` (graded **below High** — Medium/Low/Info by signal strength, never High) |
| correlate FP regression tests | `issen-correlation/src/runner.rs`: `bruteforce_fires_for_burst_then_success_same_ip`, `scales_to_a_large_disjoint_filecreate_slice_without_quadratic_blowup` |
| SRUM depth (four-depth §A) | `issen-parser-srum`: 7 tables wired, app_id→app_name enrich, aggregate-by-default tiering, CADET tags |
| Biome integrity (four-depth §C) | `issen-parser-biome/src/lib.rs:82` `segb_forensic::audit`; CRC-mismatch test |
| LNK JumpLists (four-depth §D) | `issen-parser-lnk/src/lib.rs` two `ForensicParser` impls (`LnkParser`, `JumpListParser`); `jumplist.rs` OLE/CFB automatic+custom destinations |
| $LogFile clearing-integrity (four-depth §B1) | `issen-parser-logfile` wraps `ntfs-forensic::audit_logfile` → Integrity events |
| Selector Stage 1 (declare) | `issen-core/src/plugin/selector.rs` `ArtifactSelector` attached to `ParserRegistration` |
| #110 P4 deterministic ordering · ewf provenance | per-unit ordering + ewf stored-hash provenance wired |
| ntfs-core capped-read seam | `read_file_capped` merged in `ntfs-forensic` (alloc-bomb defense) |
| svc/ServiceDll masquerade · APFS P5 · LOLDrivers denylist · reg4n6 release · udf/hfsplus/ext4fs FS-findings | merged in prior sessions |

## Verified status — OPEN (the forward backlog)

Priority order. Each item is a strict-TDD unit (RED → GREEN, signed commits).

### P0 — do now (low-risk, high-value)

1. **#112 — de-specialize the `/tmp/silly.txt` correlation rule.**
   `issen-correlation/src/temporal_rule.rs:240-248` hardcodes a rule keyed on the literal
   filename `/tmp/silly.txt`. This is a No-Special-Cases violation: it fires only on one
   sample and misses every sibling PAM-hook artifact. Generalize to the structural signal
   (a file *created in a world-writable path* in tight temporal proximity to a logon event),
   keep the real-data test, add a test for a *different* filename in the same class.
   *Effort: S–M.*

2. **#109 — green CI.** The fmt drift in `issen-parser-srum/tests/real_srudb_category.rs`
   **is real at committed HEAD** (`cargo fmt --check -p issen-parser-srum` → rc 1; a worktree
   fix is prepared and brings it to rc 0) — commit it as a standalone fmt fix. Then add the
   fleet-standard `fuzz.yml` (cargo-fuzz targets per parsed structure + a full-pipeline
   target). *Effort: S.*

3. **Fix the actively-misleading selector doc.** `issen-core/src/plugin/selector.rs:7` still
   says *"Stage 1 only declares selectors — nothing reads them yet"* — **false**: production
   already consumes them (`detect_from_registry` registry.rs:45, `triage_ntfs_sources` :58,
   fswalker classifier orchestrator.rs:231, disk triage issen-disk:193). A stale doc that
   reads "not wired" invites someone to rebuild wired code. Correct the comment to describe
   what actually consumes the selector. *Effort: XS.* (Codex catch.)

4. **Complete the `from_debug_str` round-trip test — it is the Epic K regression oracle.**
   `artifacts/types.rs` `artifact_type_from_debug_str_roundtrips_all_variants` loops only
   through `DeviceInstall` (:180), **omitting `Pe` and `RecycleBin`** though both have
   `from_debug_str` arms (:137-138). Since DuckDB persists the type as `format!("{:?}", …)`
   and rebuilds it via `from_debug_str`, an un-tested variant silently round-trips to the
   wrong type. Extend the loop to all **28** variants. This must land **before** Epic K — it
   is the test that proves no artifact-type token drifts. *Effort: XS.* (Codex catch.)

### P1 — substantial value

3. **Selector — close the consumption gaps (it is already half-wired, not unbuilt).** Codex
   verified production *does* consume selectors (`detect_from_registry` registry.rs:45 →
   `discover_artifacts` orchestrator.rs:129; disk triage issen-disk:193). So this is **not** a
   from-scratch Stage 2/3 build. Remaining: (a) audit which classification / disk-collection
   paths still bypass the registry and route them through it; (b) add the differential
   ("same events out") harness so a routing change can't alter emitted events; (c) a
   per-parser `supported_artifacts()` audit (see Epic K Risk 3). Detailed design preserved in
   `archive/2026-06-20-registry-driven-artifact-selector-design.md`. *Effort: M (was over-scoped
   as L).*

4. **four-depth §B2 — deep `$LogFile` transaction replay.** Today only journal-clearing
   integrity is surfaced. Surface per-transaction replay (the validated slot+terminal model in
   `ntfs-forensic`) as timeline events, so undo/redo operations on a record become evidence,
   not just a "log was cleared" flag. *Effort: M.*

### P2 — medium

5. **#114 — `CoverageManifest` runtime completeness report.** No such type exists. Emit a
   per-run report of which artifact classes were searched, found, parsed, and skipped — so an
   empty result is distinguishable from "not looked for" (the bootstrap-vs-miss discipline).
   *Effort: M.*

6. **SRUM full-row opt-in flag → a general `ParseOptions` seam.** SRUM's high-volume tables
   (Energy/Push) are aggregate-only; the design's full-row opt-in needs a flag, but the
   `ForensicParser` trait's `parse()` takes only input+emitter — there is no per-parser config.
   Build the *general* `ParseOptions` seam (one structural change, all parsers benefit), not a
   SRUM-local hack. The aggregate-by-default path is already the safe default. *Effort: M.*

7. **#110 P3 — remote-URI ingest — PARKED (deferred by user, 2026-06-22).**
   `issen-cli/src/commands/ingest.rs:52-79` remote-fetch paths (gdrive + generic operator) are
   stubs that early-return; the URI/operator scaffolding exists. When resumed: byte-streaming →
   temp file → existing ingest path, validated against a *controlled* oracle (a localhost
   HTTP/file source we mint), not a self-authored round-trip. *Effort: M.*

### Szechuan-validation backlog (surfaced 2026-06-22 — issen scored 16/17 on the case)

End-to-end validation against DFIR Madness "Stolen Szechuan Sauce" (both hosts, disk + memory)
measured **16 of 17 core questions** answered and key-matched (DC 9/9, workstation 7/8; two
answers beat the Volatility/Rekall baseline — e.g. WS-memory `ps` recovered the malware process
structurally where both failed). Full verbatim record:
`docs/profiling/szechuan-sauce-issen-profiling.md`. Two genuine **capability** items it surfaced
(distinct from the PCAP-only scope boundary, which is not a gap):

1. **build-19041 symbol-free memory overlay** — *M, `memory-forensic` / memf-windows.* The
   symbol-free `TcpE`/SAM pool-scan (which recovered the DC's C2 endpoint + Administrator hash)
   has only a **build-9600** (Server 2012 R2) overlay; on the Win10-2004 **build-19041**
   workstation dump `netstat`/`creds`/`scan` return empty (fails loud-but-clean — "symbols
   unavailable", no fabrication). Wiring a build-19041 overlay closes the workstation-memory
   C2/creds leg. **Higher value of the two** (the only thing between issen and 17/17 from
   host artifacts).
2. **`Lnk` artifact-path / timestamp bug** — *S, `issen-parser-lnk`.* The Lnk source mislocates
   `artifact_path` to the ingest tempdir and emits empty timestamps (the case answers survived
   via MFT/UsnJournal, so low-severity — but a real defect).

### P3 — ~~Epic K~~ DISSOLVED → done as a contained rename

8. **~~Epic K (relocate the taxonomy into forensicnomicon)~~ — resolved without a fleet
   republish.** A three-way review (user intuition + first-hand verification + Codex) found the
   two `ArtifactType` enums are *orthogonal axes that only collided by name*: issen's is the
   genuine artifact-**family** taxonomy (correctly named), forensicnomicon's catalog one is the
   **location** axis (the misnomer). Fixed by renaming the misnamed one —
   `forensicnomicon::catalog::ArtifactType → ArtifactLocation` (commit **`f08f35c`**, fn
   `0.8.0 → 0.9.0`; 6914 mechanical word-boundary renames across 27 files, `artifact_type` field
   and serde wire format unchanged, **2680 tests green**). No fleet crate imports
   `catalog::ArtifactType`, so the relocation/version-unify/~10-crate-republish wave is **moot**,
   and the Debug-token/skew risks are gone. **One step remains and is held for your explicit
   go:** publish forensicnomicon `0.9.0` to crates.io (the only irreversible action).

### Blocked / minor

- **regcatalog `scan_users` multi-profile** (`issen-parser-regcatalog/src/lib.rs:19`) — a
  documented follow-up, blocked on Issen passing a profile-tagged hive. *Blocked upstream.*
- **correlate validation doc** — the capstone's FP tests exist; only a real-data (Case-001)
  validation write-up remains. *Minor.*
- **#114 nested archive/VHD/VSS expansion** — large; coordinates with the `[H]` history layer.
  Keep as its own roadmap, not folded here.
- **#70 fleet hierarchy reorg — DEFERRED, gated on fleet remediation ("after backup").** The
  physical regrouping of the fleet into a layered tree. **Gate:** it must come *after* fleet
  remediation (commit/push everything, create missing remotes) — that is the "back up first"
  step, because the move touches ~68 cross-repo path deps + CI flat-sibling checkouts.
  **Lower-risk path preferred** (per the sub-plan): Option A — a generated `FLEET.md` index
  (zero change), and/or Option B — a `~/src/fleet/<layer>/<repo>` *symlink view* over unmoved
  flat repos (browsable tree, zero dep/ref breakage), rather than a physical move. Coupled with
  the fleet `forensicnomicon` version unification. Full detail + blast-radius in
  `archive/2026-06-09-fleet-hierarchy-reorg.md` (and `archive/2026-06-09-issen-grand-plan.md`
  §P4). *Effort: L (physical move) / S (index+symlink view).* This was dropped in the
  2026-06-22 consolidation and is restored here.

## Epic K — SUPERSEDED by the `ArtifactLocation` rename (kept for reference)

> The relocation migration below is **no longer the plan** — the name collision that motivated
> it was resolved by renaming forensicnomicon's location enum (P3 #8, commit `f08f35c`). This
> section is retained only as the design that *would* apply if a genuine cross-repo taxonomy
> move is ever needed (e.g. a second orchestrator wants the family taxonomy). It is not active
> work.

### (archived) regression-safe, rollback-able migration

`ArtifactType` lives in two places on **genuinely different axes** (a self-critique finding,
verified against source): forensicnomicon's catalog `ArtifactType` is documented as *"the kind
of forensic artifact **location**"* — RegistryKey, RegistryValue, File, Directory, EventLog,
MemoryRegion (9 variants; a *where*), whereas `issen-core`'s `ArtifactType` is the **artifact
family** — Mft, Prefetch, JumpLists, Srum… (**28** variants; a *what*). They answer different
questions **and share the name** `ArtifactType` (a collision).

**Design decision that gates Epic K (resolve before Phase 1):** the two enums must **not** be
merged — relocate issen's family taxonomy into forensicnomicon as a **distinctly-named** enum
on its own axis (e.g. `forensicnomicon::artifact::ArtifactKind`), sitting *alongside* the
catalog `ArtifactType`, never collapsed into it. (My earlier "reconcile to a contract-identical
superset of the catalog enum" was wrong — it conflated two axes.)

There is also a **live version skew** to collapse: 11 crates use workspace
`forensicnomicon = "0.5"`, while `issen-parser-registry` pins `"0.7"`.

**Core principle:** separate the reversible part (the code change — all git) from the
irreversible part (the crates.io publish); do 100% of validation before any publish; make the
publish last and purely additive.

**Phases (each above the line is pure git, fully revertible):**

```
Phase 0  golden + real-.duckdb read-back regression tests (issen)   ← the regression oracle
Phase 1  reconcile fn's ArtifactType to a contract-identical superset
Phase 2  version-unify fn fleet-wide via [patch.crates-io]          ← also kills the 0.5/0.7 skew
Phase 3  flip issen-core ArtifactType to a re-export; delete duplicate body (call-sites unchanged)
Phase 4  differential read-back: NEW binary vs an OLD .duckdb       ← cross-version compat proof
──────────────────────────── irreversible boundary ────────────────────────────
Phase 5  publish fn first (verify 408/exclude + crate:needs-release), then ~10 dependents,
         each verified live; drop the patch as each moves to the registry version
```

**No-regression mechanism:** the regression oracle is the real `.duckdb` read-back (an
independent artifact written by the *old* code — a tier-2 oracle, not a self-authored
snapshot); the `pub use` re-export keeps every `issen_core::artifacts::ArtifactType` path
resolving so the 27 parsers need zero call-site edits; a skew gate (`cargo tree -d -i
forensicnomicon` shows exactly one version) catches any half-migrated trait-skew.

**Three migration risks the design must defend against (Codex review):**

1. **Silent semantic remap in the DuckDB read-back.** Timeline rows persist the artifact type
   as `format!("{:?}", event.source)` (`issen-timeline/src/ingest.rs:169`) and rebuild it via
   `from_debug_str`. If *any* relocated variant's `Debug` token differs — even capitalization
   or an underscore — old rows deserialize to the wrong type or `None` with **no error**,
   silently corrupting historical analysis. So Phase 0/4 must assert **token-level string
   identity** of every variant's `Debug` output (all 28), not just type identity — which is
   exactly why the completed `from_debug_str` round-trip test (P0 #4) is a hard prerequisite.
2. **Dual-version type islands survive compilation.** The lockfile already carries `fn 0.5.8`
   *and* `0.7.0`; because the two enums share the name `ArtifactType`, a `[patch.crates-io]`
   unification can compile green while `issen-parser-registry` (the intentional 0.7 pin) still
   binds an old API/feature surface — a partially-migrated *runtime* with no compile error. The
   skew gate must therefore verify a single version **and** unified feature flags, and Phase 2
   must move the 0.7 pin onto the patch explicitly.
3. **A name-compatible re-export is not enough across differing axes.** Every
   `supported_artifacts()` match arm, every selector classifier arm, and every persisted string
   must be **differentially tested against real `.duckdb` data** — without a per-parser
   `supported_artifacts()` audit the re-export compiles but the classifier can silently stop
   matching artifacts it used to handle (a real investigation returning zero results is how
   you'd find out). This per-parser audit is a named deliverable of Phase 3.

**Rollback:** pre-publish → git (`git revert` / restore the committed `Cargo.lock`; tag
`pre-epic-k`). During the wave → remove the `[patch.crates-io]` lever. Post-publish →
crates.io is immutable+additive, so pin dependents back to the last-good version and `cargo
yank` the bad one (yank is reversible). The last-good state is always recoverable because it
is an immutable published version + a committed lock.

## Superseded plans

Their live items are folded into the backlog above; the durable "why" decisions are
captured as ADRs in `docs/decisions/`. The detailed superseded designs
(saturday-morning-mega-plan, four-depth-builds, registry-driven-artifact-selector,
stage1-selector-implementation, parallel-ingest-design) live in git history —
`git log --follow -- docs/plans/<name>.md` — per the plan-lifecycle standard (git is
the archive; the working tree holds only the conclusion).

## Working-tree note

Three pre-existing dirty files (`issen-cli/tests/cli_tests.rs`,
`issen-cli/tests/integration_test.rs`, `docs/corpus-catalog.md`) and the prepared SRUM fmt-fix
sit uncommitted; they belong to in-flight work and are intentionally not swept into this pass.
