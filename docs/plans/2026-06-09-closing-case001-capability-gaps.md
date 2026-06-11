# Plan — Closing the Issen Capability Gaps (Case 001 yardstick)

**Status:** DRAFT for the Issen tool-dev session to execute. This session (workshop) authored it;
**all code changes are performed by the tool-dev Claude**, strict TDD, per the handover below.
**Critic pass:** reviewed by Codex against the live codebase (see §Critic notes).

---

## Executive Summary

Empirical measurement on the **real Case 001 artifacts, both hosts**
([`../workshop-3hr/issen-measured-coverage.md`](../workshop-3hr/issen-measured-coverage.md))
scored **11 WORKS / 3 PARTIAL / 5 GAP** of 18 questions (Desktop added lateral movement, USN moves,
and Desktop persistence/users). **A Codex pass against the live code (2026-06-09) overturned the
original symptom reading** — the gaps are *wiring + stubs + one insert bug*, NOT missing capability.
Corrected diagnosis:

1. **The ingest hang is a DuckDB insert bug, not a parser loop.** `issen-timeline/src/ingest.rs:39-47`
   does a per-event `SELECT … WHERE record_hash=? ` + single-row `INSERT`, unbatched, no
   transaction → ~738K sequential round-trips for 369K events. This is why events appear in the DB
   yet the run never finishes. **Fix this first — it blocks all measurement.**
2. **The narrow MFT+EVTX breadth is broken wiring, not missing parsers.** `issen-disk` already
   *extracts* registry hives, `SRUDB.dat`, `Amcache.hve`, `.pf`, and USN `$J` (lib.rs:121-163;
   orchestrator.rs:77-123). But `issen-cli/main.rs:11-14` only links `issen_parser_evtx`/`_uac`/
   `_velociraptor`; `issen-parser-registry` and `issen-parser-srum` `parse()` are **stubs returning
   empty**; USN *is* linked yet yields zero events (a correctness bug, not absence).
3. **`issen memf` for raw Windows is unwired, not unimplemented.** The Windows `ps` EPROCESS walker
   exists (`memf-windows/src/process.rs:13-35`) and VAD malfind exists (`vad.rs:102-142`), but the
   CLI requires `--profile`+CR3, routes Raw→Linux best-effort (`cmd_memf.rs:155-156`), never calls
   malfind from `scan`, and never invokes the existing auto-profile/PDB resolver (`memf-symbols`).

**Goal:** on the Case 001 hosts, `issen` answers every disk+RAM-answerable question, ingest
**terminates and is broad**, the memory path works, findings carry **ATT&CK**, and `issen report`
narrates the attack chain. **Target: lift measured WORKS from 11 → ≥16 of 18**, then unify under one
`issen correlate` command (makes the flyer's central claim true).

**Validate everything against the real artifacts** (ground-truth answers known) — never synthetic
fixtures alone (Doer-Checker). **All file:line targets below are Codex-verified against the live
code.**

---

## Validation targets (the regression gate)

Staged real data: `/tmp/case001/` — **both hosts measured**: DC01 (`citadeldc01.mem` +
`…CDrive.E01/.E02`) and Desktop (`/tmp/case001/desktop/…DESKTOP-SDN1RPT.E01-.E04` +
`DESKTOP-SDN1RPT.mem`); re-stage from `tests/data/DFIR Madness …/{DC01,DESKTOP}-*.zip` if `/tmp` is
cleared (Desktop E01 needs an **absolute path** until F1 is fixed). Known answers each fix must
reproduce:

| Closes | Assertion on real data |
|---|---|
| memf ps | process list contains `coreupdater` (and `spoolsv` host of the injection) |
| memf netstat | `203.78.103.109:443` ESTABLISHED, tied to the malware PID |
| memf malfind | injected MEM_PRIVATE + EXECUTE_READWRITE region in `spoolsv` |
| ingest registry | OS = `Windows 2012`, TZ = `UTC-6` (mis-set −7), interfaces `10.42.85.10` |
| ingest USN | _already passing on Desktop (39K events)_ — assert `coreupdater.exe` RENAME `…\Downloads\`→`…\System32\` once DC01 ingest completes |
| ingest SRUM | non-zero bytes-sent in the exfil window |
| ingest MFT (F2) | DC01 `$MFT` → 348K records ✓; **Desktop `$MFT` → only 31** ✗ — assert full record count on Desktop |
| timestomp | `Beth_Secret.txt` flagged ($SI vs $FN, matched to `PortalGunsPlans.txt`) |
| ATT&CK | findings include T1110, T1021.001, T1543.003, T1070.006 (no Sigma) |
| lateral movement | _already passing on Desktop_: 4624 type 10 from `10.42.85.10`, Administrator, `03:36:24` |
| ingest completion | DC01 (369K events) finishes in < target minutes; `source` ∈ {Mft, EventLog, Registry, UsnJournal, Srum} |
| EWF relative path (F1) | `issen ingest <bare.E01>` from the evidence dir succeeds |

A single **re-runnable assertion script** (extending the queries in `issen-measured-coverage.md`)
re-scores WORKS/PARTIAL/GAP after each workstream.

---

## Principles (binding)

- **Strict TDD** — RED commit (failing test on the real artifact) then GREEN commit, separately.
- **Real-artifact gate** — each task's acceptance is proven against `/tmp/case001`, not just synthetic.
- **Per-artifact isolation + fail-loud** — one parser hanging/failing must be logged as a finding
  and skipped, **never** abort or hang the whole pipeline, **never** silently drop an artifact.
- **Layer boundaries** (CLAUDE.md) — parser logic lives in `*-core`/`*-forensic` repos; `issen-*`
  crates only wrap; orchestration in `issen-cli`/`issen-correlation`.
- **Paranoid gatekeeper** — untrusted image input: panic-free, bounds-checked, fuzzed.

---

## Workstream A — Ingest: completion, robustness, breadth (P0)

**A00 · EWF relative-path bug (finding F1) — trivial, do alongside A0.** `issen ingest <bare.E01>`
(no directory component, run from the evidence dir) fails *"no segment files found matching"* though
libewf reads the set. Root cause: `ewf/reader.rs:35` `first.parent().unwrap_or_else(|| Path::new("."))`
— `parent()` of a bare filename returns `Some("")` not `None`, so the segment glob is rooted at `/`.
**Fix:** map an empty parent to `.`. **RED:** ingest a bare-filename E01 from its own dir. (Workshop
trap — students hit this.)

**A0 · Fix the DuckDB insert (the hang) — DO THIS FIRST, it blocks all measurement.** Confirmed the
"hang" is **linear-slow inserts, not an infinite loop**: the 84K-event Desktop image *completed*
(~5 min) while the 369K-event DC01 did not (killed at 23 min). Replace the per-event `SELECT
record_hash` + single-row `INSERT` loop in `issen-timeline/src/ingest.rs:39-47` with a `UNIQUE` index
on `record_hash` + a **transaction-wrapped batch / appender** insert (dedup via `INSERT … ON CONFLICT
DO NOTHING`). **RED:** ingest the DC E01 (369K events) and assert completion under a bounded
wall-clock. **GREEN:** batched insert; same count, no dedup regression.

**A1 · Per-artifact isolation harness.** Wrap each extractor/parser in a bounded unit (per-unit
timeout + error capture); a unit that fails/loops → a `scan_findings` finding + skip; the pipeline
always terminates. Defensive backstop so one bad real-world artifact can't reintroduce a hang.

**A2 · Registry — implement `issen-parser-registry` + link it. ✅ DONE (2026-06-10).**
**CORRECTION:** the original "Issen already vendors `notatin`; do not create a registry repo" guidance
was wrong — **`~/src/winreg-forensic` is ours** (the registry equivalent of `ntfs-forensic`:
`winreg-core` reader + `winreg-artifacts`/`-carve`/`-recover`/`-diff`). Per the prefer-our-own-crates
rule it replaces notatin. Delivered: (a) `parse()` wired to `winreg-core::Hive::from_bytes` +
`winreg-artifacts::registry_keys::walk_keys` → RegistryModify TimelineEvents (notatin dropped);
(b) **linked** via `extern crate issen_parser_registry` in issen-cli lib+main (`all_parsers()`
registration test). **Still TODO (extend INTO winreg-forensic, not issen):** the richer fact events —
OS version, timezone, computer name, `Services\…`, Run keys, user list, SAM NTLM hashes — via
`winreg_artifacts::{run_keys, svc_diff, sam}`. Unblocks **Q1, Q3, Q9, B4/B5**, the Run-key half of
**6.9**, hashes for **B6**.

**A3 · USN ($J) — already works; just needs ingest to complete.** _Downgraded after the two-host
measurement:_ USN is linked **and functional** — the **Desktop** ingest captured **39,072
UsnJournal events**. DC01's "0 USN" was because ingest was *killed mid-run* (A0/A1), not a USN bug.
**No fix needed** beyond A0 completion; add a regression assertion (DC E01 → `coreupdater.exe`
RENAME `…\Downloads\`→`…\System32\` appears once ingest completes). Unblocks **6.6**.

**A2b · MFT under-parse (finding F2).** On the *completed* Desktop ingest, `$MFT` yielded only **31
records** (vs DC01's 348K). Investigate the MFT extraction/parse on the Desktop image — a real
correctness bug, separate from the insert hang. **RED:** assert the Desktop `$MFT` yields a
full-disk record count.

**A4 · SRUM — link + implement ESE parse.** Two sub-tasks: (a) link `issen-parser-srum` in
`issen-cli/Cargo.toml:28-32`/main.rs (currently unlinked); (b) replace the stub `parse()`
(`issen-parser-srum/src/lib.rs:116-120`) / DataSource with a real ESE B-tree leaf traversal so
app-exec + network-usage rows parse. Unblocks the **bytes-exfiltrated** ledger (Module 4). Coordinate
with the `srum-forensic` ESE reader (don't duplicate).

**A5 · Amcache + Prefetch (optional).** Both are *already extracted* by `issen-disk`; needs parser
link/impl like A2/A4. Strengthens **6.5** + execution evidence. Defer if A0–A4 slip.

**Acceptance:** ingest on the DC E01 **completes** under target; `source` includes Mft, EventLog,
Registry, UsnJournal, Srum; the §Validation assertions for registry/USN/SRUM pass.

---

## Workstream B — Memory: wire the existing raw-Windows walker (P0, long pole)

Codex confirmed the walkers **exist** — this is wiring + symbol plumbing + CR3, **not** a
from-scratch Volatility build. Scope accordingly.

**B1 · CR3/DTB discovery + AutoProfile integration into `build_reader`.** The auto-profile/PDB
resolver already exists (`memf-symbols`: `auto_profile.rs`, `pdb_resolver.rs`, `pe_debug.rs`) but is
**never called by the CLI**, and `issen-mem/dispatch.rs:27-56` hard-requires `--profile`+explicit
CR3. Wire `build_reader` to: (a) discover the kernel DTB/CR3 from the raw dump (low_stub at PA
`0x1000` / KPCR self-ref); (b) extract the kernel RSDS GUID+age (`ntkrnlmp.pdb`) and call the
existing AutoProfile resolver (fetch prebuilt ISF by GUID / convert PDB); `--profile` stays as
fallback. Validate the resolver on the **SecurityNik** dump too (its sidecar JSON has
`pdbGuid`/`regCr3`/`ntosBase` for ground truth across builds).

**B2 · Route Raw→Windows + connect `ps`.** `cmd_memf.rs:155-156` currently routes Raw/Unknown to
Linux best-effort. Route a Windows-profiled Raw dump to the **existing**
`memf_windows::process::walk_processes` (`ActiveProcessLinks` walk, `process.rs:13-35`). Unblocks
**6.1** (coreupdater) and the memory half of **4**.

**B3 · netscan → `netstat`.** Needs the `TcpPortPool`/`TcpNumTablePartitions` symbols
(`dispatch.rs:704-722`) which B1 now resolves; complete the **stubbed pool scan**
(`pool_scan.rs:137-151`) for `TcpE`/`UdpA` endpoints. Unblocks **6.3** (C2 `203.78.103.109:443`) and
**9**.

**B4 · Wire malfind into `scan`.** The VAD malfind detector exists
(`memf_windows::vad::walk_malfind`, `vad.rs:102-142`) but `scan` **never calls it**. Connect it
(MEM_PRIVATE + PAGE_EXECUTE_READWRITE + `MZ`). Unblocks the **spoolsv injection** (6.1).

**Acceptance (on `citadeldc01.mem`):** ps lists coreupdater(+spoolsv); netstat shows
`203.78.103.109:443` tied to the malware PID; malfind flags the injected region. Cross-validate on
the SecurityNik dump.

---

## Workstream C+D — Findings: ATT&CK classifier + timestomp (P1)

**Codex flagged C and D as coupled** — both write `scan_findings` with tactic tags, and today
there is **no** native event→ATT&CK classifier and the findings schema carries only free tags
(`findings.rs:13-21`), not MITRE refs. So **land D's findings path first, then C's detector emits
into it.** Treat as one workstream.

**D1 · Findings schema + native event→ATT&CK classifier.** Extend the findings storage to carry
MITRE refs (or tactic tags the report already reads). Add a data-driven classifier in
`issen-signatures` (the scan phase is Sigma/YARA/hash/IOC only today, `scanning.rs:78-155`) mapping
event signatures → `Finding`s with `ExternalRef::mitre_attack(...)`, **no Sigma required**:
4625-burst→**T1110**, 4624 type10→**T1021.001**, 4672→privileged-logon, 7045→**T1543.003**,
Run-key→**T1547.001**, Meterpreter-on-disk→threat. Persist as `scan_findings` rows.

**D2 · Report attack-chain from raw findings.** `attack_chain.rs:15-47` reads tactic tags only —
ensure D1's findings carry them so the chain populates without Sigma.

**C1 · Surface `$FN` quads (prerequisite for the detector).** Both `$SI` (`mft/src/attribute/x10.rs`)
and `$FN` (`x30.rs`) are decoded and the CSV wrapper carries both, but the MFT→TimelineEvent
conversion **drops `$FN` when `$SI` exists** — in **two** places that must both change:
`issen-parser-mft/src/lib.rs:287-311` **and** the duplicate `issen-cli/src/parsers/mft.rs:219-243`.
Surface `$FN` timestamps (event metadata or side channel) so a detector can compare. *(Consider
de-duplicating the two MFT converters while here.)*

**C2 · Timestomp detector → `Finding`.** Using C1's `$FN`, emit a finding via D1's path (code
`NTFS-TIMESTOMP-SI-FN-MISMATCH`, ATT&CK **T1070.006**, severity High, "consistent with" language)
when `$SI.modify < $FN.creation` / sub-second-zeroed `$SI`.

**Acceptance:** `issen report` renders InitialAccess(T1110/T1021.001) → Execution → Persistence
(T1543.003) → DefenseEvasion(T1070.006) from raw events, no Sigma; ingest flags `Beth_Secret.txt`
(matched to `PortalGunsPlans.txt`), visible in `issen timeline --flagged`.

---

## Workstream E — `issen correlate` capstone (P2)

After A–D: a single `issen correlate <case-dir>` orchestrating disk-extract → broad ingest →
`memf` → timestomp+ATT&CK findings → temporal correlation → one DuckDB → one `issen report`, with
per-event `source=` attribution across both hosts. Makes the flyer's "five-source correlation"
claim real.

**Acceptance:** one command on the Case 001 case dir yields a unified, source-attributed timeline +
ATT&CK report spanning DC01 and Desktop.

---

## Sequencing & parallelization

```
A0 (DuckDB insert fix) ─── GATE: do first, alone. Unblocks all measurement.
        │
        ├─ Track 1 (disk):     A1 → { A2 link+impl ∥ A3 diagnose-USN ∥ A4 link+impl } → A5
        ├─ Track 2 (memory):   B1 (CR3+AutoProfile) → B2 ps → { B3 netstat ∥ B4 malfind }
        └─ Track 3 (findings): D1 (schema+classifier) → D2 report  →  C1 ($FN) → C2 timestomp
Capstone:                      E  (after Tracks 1–3)
```

**A0 is a hard gate** — until ingest terminates, nothing downstream is measurable; do it first and
alone. Then Tracks 1/2/3 touch different repos → run as **parallel tool-dev sub-agents**. Within
Track 3, C depends on D's findings path (Codex: they share `scan_findings`), so D1→C, not parallel.
Start the gitsign credential cache before dispatch (per CLAUDE.personal). Each task = RED commit +
GREEN commit.

---

## Risks & mitigations

- **Memory is still the long pole, but de-risked** — Codex confirmed the walkers exist, so it's
  wiring + symbol resolution, not a Volatility rebuild. Residual risk is B1 (CR3 discovery +
  AutoProfile across real Windows builds); validate on **two** dumps (citadeldc01 + SecurityNik).
- **SRUM ESE B-tree is non-trivial.** Mitigate: if A4 slips, Module 4's exfil leans on USN+MFT;
  bytes-sent is the only SRUM-unique answer.
- **Ingest hang is now understood** (A0 = batched insert), so it's low-risk; A1 isolation remains a
  defensive backstop against a *different* real-world artifact looping.
- **Real-image robustness** — real NTFS/registry/ESE violate the spec; paranoid parsing + fuzz +
  fail-loud (the disciplines exist for exactly this).
- **B6 passwords** end in an offline crack (semi-external); count B6 as PARTIAL (hashes recovered),
  not a target WORKS.
- **Two duplicate MFT converters** (`issen-parser-mft` and `issen-cli/src/parsers/mft.rs`) — C1 must
  patch both or de-duplicate; missing one silently leaves $FN dropped on that path.

---

## Out of scope

PCAP/network capture (excluded by design); full Volatility plugin parity (only ps/netscan/malfind);
cross-host pivoting beyond the unified timeline; the deleted-file **contents** carving for B7 (name
is recoverable; contents are carving-dependent → stays PARTIAL).

---

## Critic notes (Codex, 2026-06-09 — codebase-verified)

The draft's symptom reading was wrong in three expensive ways; the plan above is corrected. Verbatim
findings (each `ASSUMPTION → VERDICT`, file:line):

1. **Ingest breadth — WRONG: not missing parsers.** `issen-disk` extracts registry/SRUDB/Amcache/
   prefetch/USN (`lib.rs:121-163`, `orchestrator.rs:77-123`), but `issen-cli/main.rs:11-14` links
   only evtx/uac/velociraptor; `issen-parser-registry/src/lib.rs:61-68` and `issen-parser-srum/src/
   lib.rs:116-120` `parse()` are **stubs returning empty**. → A is "link + implement stubs", not
   "write new parsers."
2. **Ingest hang — CONFIRMED + root-caused.** `issen-timeline/src/ingest.rs:39-47`: per-event
   `SELECT … record_hash` + single-row `INSERT`, no transaction → ~738K round-trips for 369K events.
   → A0 (batched insert) first.
3. **memf — partially confirmed, more incomplete than drafted.** Windows `ps` walker exists
   (`memf-windows/src/process.rs:13-35`); VAD malfind exists (`vad.rs:102-142`) but `scan` never
   calls it; pool scan is a **stub** (`pool_scan.rs:137-151`); Raw routes to Linux
   (`cmd_memf.rs:155-156`); auto-profile/PDB resolver exists (`memf-symbols`) but the CLI never calls
   it. → B = CR3 discovery + AutoProfile wiring + route Raw→Windows + connect malfind + finish pool
   scan.
4. **C/D — $SI & $FN both decoded** (`mft/src/attribute/x10.rs`, `x30.rs`; CSV carries both) but
   the conversion **drops $FN** in *two* places (`issen-parser-mft/src/lib.rs:287-311` **and**
   `issen-cli/src/parsers/mft.rs:219-243`). No event→ATT&CK classifier exists; scan is Sigma/YARA/
   IOC only (`scanning.rs:78-155`); findings schema has no MITRE refs (`findings.rs:13-21`); report
   reads tactic tags (`attack_chain.rs:15-47`). → C depends on D's findings path.
5. **Scope/sequencing fixes:** `registry-forensic` repo **does not exist** — use vendored `notatin`
   via `issen-parser-registry` (A2). **USN is already linked** (`parsers/mod.rs:6-7`,
   `usnjrnl.rs:17-30`, `:173-176`) — zero events is a **correctness bug to diagnose** (A3), not
   missing capability. SRUM needs **both** linking (`Cargo.toml:28-32`) and a parse body (A4).
