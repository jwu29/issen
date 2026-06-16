# Design Memo — `issen correlate` Capstone (Task #37 / WS-E + P3)

**Date:** 2026-06-11 · **Status:** DESIGN v4 (pre-implementation)
**Predecessors:** [`2026-06-09-issen-grand-plan.md`](2026-06-09-issen-grand-plan.md) (P3 capstone),
[`2026-06-09-closing-case001-capability-gaps.md`](2026-06-09-closing-case001-capability-gaps.md) (WS-E),
measured baseline [`../workshop-3hr/issen-measured-coverage.md`](../workshop-3hr/issen-measured-coverage.md).
**v4 change:** the acceptance target is now an external, independently authored oracle — the
walshcat write-up of Case 001 — decomposed into 25 enumerated findings (F1–F25, §1) and mapped
finding-by-finding to issen capabilities (§2). The coverage matrix IS the acceptance test.

## Executive Summary

`issen correlate <case-dir>` is one command that turns a directory of raw evidence
(two E01 disk images, two memory dumps in Case 001) into a single cross-artifact,
cross-host DuckDB super-timeline plus an HTML report whose findings are *correlations* —
joined observations spanning **five evidence sources: MFT, USN journal, EVTX, registry,
and memory** — rather than N independent per-artifact rows.

**The explicit, testable target (new in v4):** the capstone must produce **at least every
in-scope finding** in the walshcat write-up of "The Stolen Szechuan Sauce" (Case 001) —
an external analyst's published solution, fetched and decomposed in §1 into findings
F1–F25. §2 maps each finding to the evidence source(s) that carry it, the issen
capability that produces it (a `CORR-*` correlation rule, or single-artifact surfacing
that needs no correlation), and an honest status: **4 findings are producible today,
13 are covered by this design once its pre-tasks land, 5 are partially covered, and
3 are out of scope/reach** (pure pcap traffic analysis and pure OSINT enrichment —
named, with reasons, in §2.3). For three of the five partials, issen reaches the same
conclusion through a *stronger local-artifact route* than the write-up used (e.g. the C2
address from in-dump netstat instead of a VirusTotal pivot). Notably, the walshcat
write-up performed **no memory analysis at all** — the memory leg is where issen
*exceeds* the oracle, not where it chases it.

**The capstone remains gated on upstream plumbing.** v3's four pre-tasks are re-confirmed
against the codebase as of 2026-06-11 (§4): memory results never reach the timeline store
(PRE-1), `entity_refs` is populated by almost nothing and persisted by nothing (PRE-2,
PRE-4), and the registry parser emits key-level metadata only — and zero events at all on
the measured Case 001 baseline (PRE-3). The walshcat oracle forces **two new pre-tasks**:
PRE-5 — four parser crates that already exist (amcache, lnk, shimcache, prefetch) are
**dead code in the `issen` binary** because `main.rs` never force-links them, and the
artifact-discovery heuristic has no `.lnk` arm at all; PRE-6 — a flagged-executable
extract-and-hash pass so the malware-hash finding (F9) has a local, non-pcap route.
PRE-3 is widened from two named keys to a declarative named-value extraction table
(OS version, timezone, computer name, interfaces, service keys) because four oracle
findings are plain registry values.

**The rule set grows from 8 to 10**: `CORR-PERSIST-REGCONFIRM` (7045 service install
↔ registry `Services\<name>` key — the EVTX↔registry join the oracle's F17 demands) and
`CORR-COPY-DELETE` (near-name file created while the original is deleted — F24's
`Beth_Secret.txt` shape). `CORR-EXFIL-STAGE` must now fire on **both** hosts
(`loot.zip` on Desktop AND `secret.zip` on DC — F21 corrects v3's single-host chain).

**Validation:** fast synthetic fixtures gate CI; the real Case 001 corpus is the
`#[ignore]`-gated oracle behind a documented release gate. **New in v4: the corpus test
is the coverage matrix made executable** — one assertion per in-scope matrix row (§8.1),
so "produces at least every walshcat finding" is machine-checked, not narrated.

**The honest headline claim stays five evidence sources, not five navigation paths** —
`[Q]` and `[C]` contribute nothing on Case 001. All flyer/README language pins to "five
evidence sources correlated in one case database, source-attributed per event, across
two hosts."

**Architecture in one line (unchanged from v3):** an ordered-window correlation evaluator
in `issen-correlation` (kept DuckDB-free) running over stored-event slices fetched
through a bounded-by-construction `fetch_events` API in `issen-timeline`, persisting
into two new DuckDB tables (`correlations` + `correlation_members`, keyed on the
existing `timeline.id`), rendered by a new report section.

---

## 1 · The oracle — walshcat's Case 001 findings, enumerated (F1–F25)

### 1.1 Provenance

Source: *"Case Write Up: The Stolen Szechuan Sauce"* by walshcat,
<https://walshcat.medium.com/case-write-up-the-stolen-szechuan-sauce-2409344264c3>
(Medium origin returns HTTP 403 to non-browser fetches; retrieved 2026-06-11 via the
Internet Archive capture of 2025-09-11,
<https://web.archive.org/web/20250911141030/https://walshcat.medium.com/case-write-up-the-stolen-szechuan-sauce-2409344264c3>,
content confirmed present — full article, 13 question sections, "Thanks to DFIR Madness"
footer). The write-up answers the 13 official DFIR Madness Case 001 challenge questions.
Artifacts the author used: EVTX, MFT (MFTECmd/Timeline Explorer), USN journal, registry,
pcap (Wireshark), IE webcache, Amcache, LNK files, recycle bin + file content (FTK
Imager), and OSINT (VirusTotal, AlienVault). **No memory analysis appears anywhere in
the write-up** (verified: zero occurrences of volatility/memory/malfind/netscan/spoolsv
in the article text).

### 1.2 Reconciliation notes (read before trusting the oracle's literals)

- **Clock skew, deliberately handled by the author (Q3):** the server's registry says
  Pacific (UTC−8) but the org is in Colorado (Mountain, UTC−7), so EVTX and pcap clocks
  disagree by one hour; the author pinned narrative times to the pcap clock ("~2:31",
  "2:36", "2:57"). issen's measured baseline uses EVTX/MFT UTC (burst 03:21:25, logon
  03:21:48, first coreupdater MFT 03:24:06, Desktop logon 03:36:24). The author's one
  explicit UTC value — first appearance "2020-09-19 03:24:12 (UTC)" (Q6.d) — agrees
  with the measured 03:24:06 MFT creation to within seconds. **The oracle test asserts
  the measured UTC values**, and the report must carry the skew observation (F3).
- **IP typo in the article body:** Q5/Q6.a body text writes `194.64.24[.]102` in three
  places, but the answer lines (Q6.b, Q7) and the case canon say **`194.61.24.102`** —
  the oracle uses the canonical value.
- **Host/IP label swap in Q9:** the article lists "DESKTOP-SDN1RPT (10.42.85.10) /
  CITADEL-DC01 (10.42.85.115)". The corpus canon and issen's measured baseline have it
  the other way (DC01 = `10.42.85.10` — the Desktop 4624 arrives *from* `10.42.85.10`,
  the DC). The oracle asserts the measured assignment; the F22 row notes the source
  discrepancy.

### 1.3 The findings, in article order

Q10 (architecture recommendations) is advice, not a forensic finding, and is excluded.
"(pcap-clock)" marks the author's skew-adjusted display times.

| # | Finding (the author's discrete forensic conclusion) | Author's evidence |
|---|---|---|
| F1 | DC OS is **Windows Server 2012** (Q1) | registry `HKLM\Software\Microsoft\Windows NT\CurrentVersion` (+ `C:\Windows\System32\license.rtf`) |
| F2 | Desktop OS is **Windows 10 Enterprise** (Q2) | registry, same key, Desktop hive |
| F3 | DC local time is **Pacific (UTC−8)** — and is *misconfigured* (org is in Colorado/Mountain), so EVTX and pcap clocks are offset (Q3) | registry ControlSet `TimeZoneInformation`; EVTX 6013; pcap cross-check |
| F4 | **A breach occurred** (Q4) | aggregate of all below |
| F5 | **Brute-force burst of failed remote logons** against `Administrator` on the DC, from a kali host, tightly time-clustered (Q5) | DC EVTX 4625 |
| F6 | **Successful logons (4624) from `194.61.24.102` follow the burst** → initial access = RDP brute force to the DC (~03:21 UTC; "~2:31" pcap-clock) (Q5) | DC EVTX 4624 after the 4625 burst |
| F7 | pcap shows an **initial ping then RDP brute-force traffic** from the suspect IP (Q5) | pcap |
| F8 | The malicious process/file is **`coreupdater.exe`**, fetched via HTTP GET `194.61.24[.]102/coreupdater.exe` served by a Python **SimpleHTTPServer** — first on the DC, soon after on the Desktop (Q6.a) | pcap GET requests + response headers |
| F9 | **SHA256 of the carved binary** (exported from pcap via Wireshark → `Get-FileHash`); VirusTotal flags it as malware (Q6.a; hash value shown only in a screenshot) | pcap HTTP object export + VT |
| F10 | Download corroborated by a **webcache entry matching the GET** and an **Amcache entry** for coreupdater.exe (Q6.a) | IE webcache (WebCacheV01.dat), Amcache.hve |
| F11 | **Payload-delivery IP = `194.61.24.102`** (Q6.b) | pcap |
| F12 | **C2 address = `203.78.103.109`** — VT-relations candidate confirmed by post-download communication in the pcap (Q6.c) | VT pivot + pcap |
| F13 | coreupdater.exe **first appeared on the DC at 2020-09-19 03:24:12 UTC** — MFT creation ("2:24:06" pcap-clock) with **USN agreement** (Q6.d) | MFT + USN |
| F14 | The file was **moved from Administrator's Downloads to System32**, on the DC *and* the Desktop — USN parent-entry analysis (DC parent entry 84880 = Downloads, later parent = System32); webcache response header corroborates the Downloads landing (Q6.e) | USN parent entries + webcache |
| F15 | The malware is **Meterpreter/Metasploit** (Q6.f) | VT community identifications |
| F16 | Metasploit is **open source / easily obtained** (Q6.g) | general knowledge |
| F17 | **Persistence on both machines**: service "coreupdater" installed — EVTX 7045 on the DC at "2:27:49" and Desktop at "2:42:42" (pcap-clock) — **plus a registry key "coreupdater" set to run at startup on both systems** (Q6.h) | EVTX 7045 + registry |
| F18 | OSINT: `194.61.24.102` was exploiting CVE-2015-1635 at the time; `203.78.103.109` was flagged in AlienVault as Meterpreter-associated (Q7) | VT/AlienVault |
| F19 | **Lateral movement: RDP from the DC to the Desktop at ~2:36 (pcap-clock; 03:36:24 UTC measured)** using the compromised `Administrator` account, confirmed in Desktop EVTX 4624 (Q8) | pcap + Desktop EVTX |
| F20 | The Administrator account **accessed all files in the DC file share's "Secret" folder**; a similar pattern on the Desktop (Q8.b) | MFT recent-access timestamps, both hosts |
| F21 | **Staging archives created: `loot.zip` on the Desktop and `secret.zip` on the DC** (USN new-zip search); outlier **`Loot.lnk`/`Secret.lnk`** show Administrator created/accessed them; webcache "Files Accessed" entries corroborate on both systems (Q8.b) | USN + MFT + LNK + webcache |
| F22 | **Network layout: domain C137, CITADEL-DC01 + DESKTOP-SDN1RPT on 10.42.85.0/24** (Q9; the article's host↔IP labels conflict with corpus canon — §1.2) | registry + EVTX |
| F23 | **The Szechuan sauce was stolen** (~"2:32pm" per the author, riding the file-share access/staging findings) (Q11) | aggregate of F20/F21 |
| F24 | **`SECRET_beth.txt` manipulation**: a copy named `Beth_Secret.txt` created ~3:38; the original deleted ~3:32 (USN); MFT byte-counts match (copy, not new file); recycle bin confirms the deletion; the copy's contents were then modified (Q12) | USN + MFT + recycle bin + file content (FTK) |
| F25 | **Last known adversary contact: last user-initiated logoff on the DC at "2:57"** (pcap-clock) (Q13) | DC EVTX logoff events |

---

## 2 · Coverage matrix — every walshcat finding mapped to an issen capability

**Legend.** *Kind*: `CORR` = needs a cross-artifact correlation rule; `single` = a
single-artifact event/finding that needs no correlation — the capstone's job for these
is surfacing them in the unified timeline/report with correct attribution. *Status*:
**TODAY** = produced by code that exists and is wired now; **DESIGN** = produced once
the named pre-task(s)/rule land; **PARTIAL** = the in-scope half is produced, the named
leg is not; **OUT** = out of reach/scope today, with the reason.

### 2.1 The matrix

| F | issen evidence source(s) | Producing capability | Kind | Status → gap detail |
|---|---|---|---|---|
| F1 | registry (DC SOFTWARE hive) | `CurrentVersion\ProductName` value → host-profile surfacing (§6.2) | single | **DESIGN** — PRE-3 named-value table + PRE-3 zero-events root-cause |
| F2 | registry (Desktop SOFTWARE hive) | same | single | **DESIGN** — PRE-3 |
| F3 | registry + EVTX | `TimeZoneInformation` values → host profile; EVTX 6013 already flows as `Other("EventID:6013")` (the mapper's catch-all, `crates/parsers/issen-parser-evtx/src/lib.rs:75`); cross-clock skew note via `detect_time_skew` (`issen-correlation/src/skew.rs:74`) over EVTX-internal sources | single | **PARTIAL** — tz value lands with PRE-3; the EVTX-vs-pcap skew leg is OUT (no pcap parsing) but EVTX-internal skew detection exists |
| F4 | all five | the correlation chain + report (the capstone itself) | CORR | **DESIGN** — the aggregate of F5–F25 |
| F5 | EVTX | 4625→`LogonFailure` (lib.rs:62) + `failed_logon_burst_finding` (`issen-signatures/src/attack_classifier.rs:105`) | single | **TODAY** — measured: burst at 03:21:25 |
| F6 | EVTX | `CORR-BRUTEFORCE-LOGON` (anchor 4625 burst → 4624 type 10, same source IP) | CORR | **DESIGN** — Tier B, needs PRE-2 (`Ip` refs) + PRE-4 |
| F7 | — (pcap) | none | — | **OUT** — issen parses no pcap (only `issen-evtx/src/net_correlation.rs` consumes *Zeek conn logs* if supplied). Compensation: F5/F6 reach the same conclusion from EVTX. Future: zeek-forensic (planned, CLAUDE.md layer map) |
| F8 | MFT + USN + EVTX + memory | the chain `CORR-LOGON-MALWARE-WRITE` → `CORR-MALWARE-RELOCATE` → `CORR-MALWARE-PERSIST` → `CORR-PROC-DISK-MATCH` names coreupdater.exe malicious by convergence | CORR | **DESIGN** — same conclusion via a different (local-artifact) route; the HTTP-GET/SimpleHTTPServer delivery *mechanism* is OUT (pcap) |
| F9 | disk file bytes | PRE-6: extract the flagged executable from the image (`issen-disk::extract_files`, `crates/issen-disk/src/lib.rs:273`), compute SHA256, match against the `--hash-iocs` store the ingest engine already loads (`commands/ingest.rs:214-227`) | single | **DESIGN** — PRE-6. The VT *lookup* is out of scope (no online enrichment promised); local hash + known-bad-list match is the in-scope equivalent |
| F10 | Amcache (+ webcache OUT) | Amcache `ProcessExec` events — parser exists (`crates/parsers/issen-parser-amcache/src/lib.rs:129`) but is dead code in the binary | single | **PARTIAL** — Amcache leg lands with PRE-5 (force-link); the IE webcache (WebCacheV01.dat, ESE) leg is OUT — issen-browser wraps browser-forensic (Chrome/Firefox/Safari, workspace `Cargo.toml:117-120`), no ESE webcache parser. Future: ride srum-forensic's ESE reader |
| F11 | EVTX | the IP surfaces as `CORR-BRUTEFORCE-LOGON`'s source-IP subject and in 4624 metadata | single/CORR | **PARTIAL** — the IOC value is surfaced and attributed; its *delivery-server* role is OUT (pcap) |
| F12 | memory | PRE-1 netstat → `NetworkConnect` event for `203.78.103.109` + `CORR-INJECTED-C2` | CORR | **DESIGN** — a stronger route than the author's OSINT pivot: the C2 address is observed locally in the dump (measured ground truth confirms it is memory-resident) |
| F13 | MFT + USN | `FileCreate` events from both parsers (mft.rs:119, usnjrnl.rs:118) — measured: first coreupdater MFT event 03:24:06; both become members of `CORR-LOGON-MALWARE-WRITE` | single | **TODAY** — surfacing + (DESIGN) chain membership |
| F14 | USN + MFT | `CORR-MALWARE-RELOCATE` (FileCreate in user dir → USN rename/parent-change into System32, same name stem) — **asserted on both hosts** | CORR | **DESIGN** — Tier A; the webcache-response-header corroboration leg is OUT (webcache) |
| F15 | — (OSINT) | family *attribution* (Meterpreter) is out of scope for local analysis; if the user-supplied hash-IOC list (PRE-6/F9) carries family labels, the finding note carries them as "consistent with" | — | **PARTIAL** — honest: no online enrichment; memory injection findings (F12 chain) are *consistent with* this family but do not name it |
| F16 | — | not a forensic finding from evidence (tool availability) | — | **OUT of scope** — excluded from the oracle |
| F17 | EVTX + registry | 7045→`ServiceInstall` (lib.rs:66) on both hosts (measured: 129× 7045 incl. coreupdater) + `CORR-MALWARE-PERSIST`; **new `CORR-PERSIST-REGCONFIRM`** joins the 7045 to the `...\Services\coreupdater` `RegistryModify` key event (key-level suffices; value-level `ImagePath`/`Start` via PRE-3 strengthens) | single + CORR | **DESIGN** — needs PRE-3 (registry events at all) + the new rule |
| F18 | — (OSINT) | none | — | **OUT of scope** — no online enrichment in the capstone. (`issen-correlation/src/zeek_intel.rs:98` can consume a *local* intel file if the analyst supplies one; not promised) |
| F19 | EVTX (+ registry inventory) | Desktop 4624 type 10 single-artifact (TODAY at type level) + `CORR-LATERAL-MOVE` with the §5.2 guards | single + CORR | **DESIGN** — Tier D, needs PRE-2 + PRE-3 |
| F20 | MFT | `FileAccess` events (mft.rs:111) over the Secret-share paths, both hosts; members of `CORR-EXFIL-STAGE` | single | **TODAY** — surfacing (caveat: depends on `$SI` access-time updates being enabled on the host, which the author's own success demonstrates for this corpus) |
| F21 | USN + MFT + LNK (+ webcache OUT) | `CORR-EXFIL-STAGE` **on both hosts** (loot.zip Desktop — measured 5 events; secret.zip DC); `Loot.lnk`/`Secret.lnk` corroboration after PRE-5 (lnk parser exists, `crates/parsers/issen-parser-lnk/src/parser.rs:56`, but is unlinked AND undiscoverable — no `.lnk` arm in `detect_artifact_type`) | CORR + single | **DESIGN** — rule (Tier B) + PRE-5; webcache "Files Accessed" leg OUT |
| F22 | registry + EVTX | hostnames: EVTX `Computer` today (lib.rs:207) + registry `ComputerName` (PRE-3); addresses: `Tcpip\Parameters\Interfaces` (PRE-3) → host-profile section; domain `C137` flows in flattened logon metadata today | single | **DESIGN** — PRE-3; oracle pins the *measured* host↔IP assignment (§1.2 discrepancy noted in the matrix row's assertion) |
| F23 | MFT + USN | the conclusion rides F20 + F21 (access + staging chain); the report's chain narrative states it as "consistent with staging for exfiltration" — observation, not verdict | CORR | **DESIGN** — no separate rule; asserted as: both F20 and F21 members present in one chain |
| F24 | USN + MFT | singles TODAY: `FileDelete` of SECRET_beth.txt + `FileCreate` of Beth_Secret.txt (usnjrnl.rs:118-120); **new `CORR-COPY-DELETE`** joins them (near-name + window guards, §5.4); recycle-bin movement appears as USN rename-into-`$RECYCLE.BIN` events | single + CORR | **PARTIAL** — the copy+delete correlation is DESIGN; the *content-modified* leg (FTK file-content diff) is OUT (no content extraction/diff in the capstone); the `$SI`-only timestomp on this file stays a measured gap, not promised (v3 position unchanged) |
| F25 | EVTX | 4634/4647→`Logoff` (lib.rs:63) TODAY; the report's **session envelope** (§6.2) surfaces the last event of the correlated adversary session — "last observed activity" | single | **TODAY** (events) + **DESIGN** (envelope surfacing) |

### 2.2 Scorecard

- **TODAY (4):** F5, F13, F20, F25 (event level) — already measured on the corpus.
- **DESIGN (13):** F1, F2, F4, F6, F8, F9, F12, F14, F17, F19, F21, F22, F23.
- **PARTIAL (5):** F3 (pcap-skew leg out), F10 (webcache leg out), F11 (delivery role
  out), F15 (online attribution out), F24 (content-diff leg out).
- **OUT (3):** F7 (pcap traffic), F16 (not evidence-derived), F18 (pure OSINT).

**Oracle-asserted rows: 21** — 4 TODAY + 13 DESIGN + the in-scope halves of 4 PARTIALs
(F3, F10, F15, F24); F11's in-scope half is asserted inside F6's assertion block.
F7/F16/F18 are excluded from the acceptance test and documented as exclusions in
`docs/validation.md`.

### 2.3 The honest out-of-reach list (and what would close each)

| Missing leg | Findings affected | Why out of reach | Closure path (future work, named — not promised) |
|---|---|---|---|
| pcap parsing | F7, F8 (delivery mechanism), F9 (pcap-carved binary), F11 (delivery role), F12 (pcap confirmation route), F3 (clock cross-check) | no pcap parser anywhere in `crates/` (verified: only `net_correlation.rs` mentions pcap, and it consumes Zeek conn logs) | zeek-forensic (planned LOG FORMAT crate); Case 001's pcap is in the corpus, unused |
| IE/Edge webcache (WebCacheV01.dat, ESE) | F10, F14 (corroboration), F21 (corroboration) | issen-browser = Chrome/Firefox/Safari via browser-forensic; no ESE-webcache parser | a webcache parser reusing srum-forensic's ESE layer |
| online OSINT enrichment (VT, AlienVault) | F15, F18, F9 (VT half) | deliberate scope cut: the capstone is local-evidence-only; online lookups are not reproducible oracle inputs | optional `enrich` pass (`issen-correlation/src/enrich.rs` exists as a seam) — separate task |
| file-content extraction + diff | F24 (contents-modified leg) | the capstone extracts/hashes flagged executables (PRE-6) but does not diff document contents | future `issen extract`/content-diff work |
| recycle-bin `$I` metadata parsing | F24 (deletion detail) | no `$I` parser; USN rename-into-`$RECYCLE.BIN` events cover the movement observation | small `$I` parser, low priority |

---

## 3 · What exists today (verified 2026-06-11, file:line)

All v3 claims were re-verified this date; paths corrected (parser crates live under
`crates/parsers/`, not `parsers/`). New-in-v4 verifications are marked ★.

### CLI surface (`crates/issen-cli/src/main.rs`, binary `issen`)
`Commands` enum: `Analyse`, `Ingest`, `Timeline`, `Info`, `Feed`, `Scan`,
`RemoteAccess`, `Memf`, `Pivot`, `Report`, `Supertimeline`, `Srum`, `Frequency`,
`Processes`, `Session`. **No `Correlate` variant.** ★ **Force-linked parser crates are
exactly four** (`main.rs:12-15`): `issen_parser_evtx`, `issen_parser_registry`,
`issen_parser_uac`, `issen_parser_velociraptor`. The workspace also contains
**twelve more parser crates** (`crates/parsers/`: amcache, linux, lnk, macos, mft, pe,
prefetch, registry, setupapi, shellbags, shimcache, srum, usnjrnl, velociraptor…) —
amcache/lnk/shimcache/prefetch implement `ForensicParser` + `inventory::submit!` but,
unlinked, their registrations never reach the binary (the PRE-5 gap). Disk-container
providers force-linked at `main.rs:18-24`.

### Artifact discovery (`crates/issen-fswalker/src/orchestrator.rs`)
★ `detect_artifact_type` (:78-127) matches: `$J`/usnjrnl, `$MFT`, `.evtx`, `.pf`,
registry hive basenames (only when the path contains "registry" or "config"),
`amcache.hve`, `srudb.dat` — **and nothing else**. `ArtifactType::Lnk`, `Shellbags`,
`BrowserHistory` exist in the enum (`issen-core/src/artifacts/types.rs:17-25`) but have
**no detection arm**: `.lnk` files are never discovered even if the parser were linked.
The registry zero-events failure (measured baseline :44) is still undiagnosed; the
"registry|config" path guard is a candidate but unproven — PRE-3 step 1 diagnoses,
doesn't guess.

### Timeline store (`crates/issen-timeline/`) — unchanged from v3, re-confirmed
- `store.rs:47-78` — `timeline` table with `id UBIGINT PRIMARY KEY` (:53), epoch column
  (:66), `evidence_sources` table (:70-76). **No correlation tables; no `entity_refs`
  column** — both insert column lists end at `record_hash, evidence_source[, epoch]`
  (`ingest.rs:16`, `:99-103`).
- `ingest.rs` — set-based dedup insert scoped **within the epoch** (:105-110);
  `update_tags` (:118-131) is the model for the PRE-4 backfill.
- `findings.rs` — `FindingRow` (:13-22) exposes no `id`; cannot key a membership table.
- `temporal.rs` — `EntityIndex` (:19), `temporal_join` (:64, symmetric), reused not
  duplicated.
- `query.rs` — `TimelineRow` carries `id` (:6) but no tags/epoch/entity_refs.

### Event model + entity_refs population (PRE-2 gap, re-verified ★)
`EventType` (`issen-core/src/timeline/event.rs:10`), `EntityRef` (:52),
`TimelineEvent.entity_refs` (:112), builder `with_entity_ref` (:206). Workspace grep:
the only **production** call sites remain the three in
`issen-cli/src/commands/supertimeline.rs` (:78, :108, :130) — every other hit is the
builder definition or test code (`temporal.rs:185-225`, `event.rs:365/:371`,
`temporal_rule.rs:379` are `#[cfg(test)]` fixtures). Nothing persists refs.

### EVTX parser (`crates/parsers/issen-parser-evtx/src/lib.rs`) ★ corrected detail
The event-ID map (:61-75) is richer than v3 implied: 4624→`LogonSuccess`,
4625→`LogonFailure`, **4634/4647→`Logoff`** (F25's type exists today),
4688/4689→`ProcessExec`/`Exit`, **7045→`ServiceInstall`**, 4698/4702→scheduled tasks,
6005-6009→boot/shutdown, 5156/5157→`NetworkConnect`, else `Other("EventID:<n>")`
(:75 — F3's 6013 flows through this arm). Hostname from `Computer` (:207); `logon_id`
(:233-234) and `logon_type` (:237-238) promoted to metadata. **Zero `with_entity_ref`
or `with_user` calls** (grep count 0). The separate `issen-evtx` crate adds 27 TTP
detectors (`detections.rs`), a **Prefetch/Amcache↔4688 execution join**
(`exec_join.rs` — reusable for F10's logic), and Zeek-conn↔Sysmon-EID3 correlation
(`net_correlation.rs`).

### Registry parser (`crates/parsers/issen-parser-registry/`) — re-verified
Deps already include **winreg-core AND winreg-artifacts** (Cargo.toml) — the value-level
machinery PRE-3 needs is on hand. `events_from_hive` (`parser.rs:51-80`) emits one
key-level `RegistryModify` per key with metadata `hive`/`key`/`value_count` (:74-76)
only. No value contents, no hostname, no `Tcpip`/`Interfaces`/`CurrentVersion`/
`TimeZoneInformation` handling anywhere in the crate. Measured baseline: **0 events
end-to-end on Case 001** (`issen-measured-coverage.md:44`).

### MFT/USN emitters — re-verified
`issen-cli/src/parsers/mft.rs` emits `FileModify`/`FileAccess`/`FileCreate`/
`Other("MftEntryModified")` (:103/:111/:119/:164); `usnjrnl.rs` emits
`FileCreate`/`FileDelete`/`FileRename`/`FileModify`/`Other("MetadataChange")`
(:118-129). (Note: sibling crates `issen-parser-mft`/`issen-parser-usnjrnl` exist under
`crates/parsers/` — the CLI currently uses its local modules; consolidation is future
work, not capstone scope.) No entity_refs.

### Memory path (PRE-1 gap) — re-verified
`commands/memf.rs` contains no `TimelineStore`/`TimelineEvent` (grep: zero matches; 88
lines). `issen_mem::run_memf_command` prints; dispatch returns string rows
(`(Vec<&'static str>, Vec<Vec<String>>)`). `crates/issen-mem/Cargo.toml` depends on
none of issen-core/issen-timeline/issen-correlation/duckdb. ★ It does depend on
**forensic-hashdb** (`issen-mem/src/hashdb.rs:2` re-exports `KnownBadDb`) — relevant to
PRE-6's known-bad matching.

### Disk extraction (`crates/issen-disk/src/lib.rs`) ★ new verification for PRE-6
`find_ntfs_partitions` (:58), `extract_triage` (:172), **`extract_files` (:273)**,
`extract_dir_suffix` (:310), `extract_named_streams` (:416) — the byte-level extraction
PRE-6 needs already exists; PRE-6 adds hash-and-match, not extraction.

### Findings + ATT&CK, SRUM, correlation library, corpus — unchanged from v3
- `attack_classifier.rs:88/:105`; `scanning.rs:141/:178`; report `collect_findings`
  (`issen-report/src/lib.rs:274`, no `id` selected); attack chain renderer.
- SRUM: `issen srum` works via `parse_path` (`issen-parser-srum/src/lib.rs:44`); the
  generic-ingest `parse` is a stub returning `Ok(ParseStats::new())` (:117-124).
  Exfil-bytes ledger stays deferred (A4).
- `issen-correlation` is DuckDB-free; both existing evaluators are symmetric
  (`temporal_rule.rs:173-186`; `engine.rs:112-124`, which also passes missing
  timestamps); ordered evaluator does not exist (grep: no `EventQuery`/`fetch_events`/
  `correlations` tables anywhere). `skew.rs:74 detect_time_skew`, `enrich.rs:4`,
  `warninglist.rs`, `timestomp.rs:39` available. The bundled YAML pack's verdict tone
  ("confirmed") remains quarantined from CORR-* notes (§6.3).
- Ingest already supports `--hash-iocs` / `--network-iocs` stores layered onto the scan
  engine (`commands/ingest.rs:214-235`) ★ — PRE-6 plugs into this.
- Corpus: `tests/data/DFIR Madness "Stolen Szechuan Sauce" Case 001 — Windows 10/`
  (catalog §A3, MD5s in `docs/corpus-catalog.md`). Measured ground truth as in v3 §1;
  DC01 ingest kill at 23 min (369K events) predates the set-based insert path —
  re-measure (§9).

---

## 4 · Prerequisites — the upstream plumbing (PRE-1..PRE-6)

Each pre-task is independently RED→GREEN-able (two commits: RED tests first, then GREEN)
and must land before the CORR-* rules that depend on it (dependency map in §5.5).
PRE-1/2/4 are unchanged from v3 (gaps re-confirmed §3); PRE-3 is **widened**; PRE-5 and
PRE-6 are **new, forced by the oracle**.

### PRE-1 — Memory → typed `TimelineEvent`s, persisted (unchanged)
Typed results at the dispatch boundary (PID, process name, image path, addresses,
injection classification); converter `memory_events(...) -> Vec<TimelineEvent>` with
`EntityRef::Process`/`Ip`, structured `pid`/`process_name`/`image_path` metadata,
acquisition-timestamp semantics (§5.6); issen-mem gains exactly one new edge
(issen-core); persistence stays in issen-cli. **Oracle rows served:** F12 (and the
memory half of F8).

### PRE-2 — Parsers populate `entity_refs` (unchanged)
EVTX: `Ip(IpAddress)`, `User(TargetUserName)`, `Session(logon_id)` for logon-family
events + the `user` field + `FilePath(ImagePath)` on 7045. MFT/USN: `FilePath` for the
subject path. Memory: via PRE-1. Registry: via PRE-3. Depends on PRE-4.
**Oracle rows served:** F6, F14, F17, F19, F21, F24 (join keys).

### PRE-3 — Registry: root-cause zero events + a named-value extraction table (WIDENED)
**Gap:** key-level only (parser.rs:51-80), zero events on the measured baseline, no
hostname on registry events. The oracle adds four findings that are plain registry
values (F1, F2, F3, F22), so v3's two named keys become a **declarative named-value
table** — one general mechanism, no per-case special cases:

| Key (per relevant hive/ControlSet) | Values | Serves |
|---|---|---|
| `Microsoft\Windows NT\CurrentVersion` | ProductName, CurrentBuild | F1, F2 |
| `Control\TimeZoneInformation` | TimeZoneKeyName, ActiveTimeBias | F3 |
| `Control\ComputerName\ComputerName` | ComputerName → event `hostname` | F22, host attribution for all registry events |
| `Services\Tcpip\Parameters\Interfaces\*` | IPAddress, DhcpIPAddress per interface → `EntityRef::Ip` | F22, `CORR-LATERAL-MOVE` inventory |
| `Services\<name>` (for names seen in 7045 events or any service key) | ImagePath, Start | F17 value-level strengthening |
| `...\CurrentVersion\Run*` | value name + command | F17's "runs at startup" key |

Scope: (1) root-cause and fix zero-events-through-ingest (parser is force-linked, so
the failure is discovery/routing — the `detect_artifact_type` "registry|config" path
guard at orchestrator.rs:103-114 is a candidate, diagnose don't guess); (2) the table
above as targeted value extraction (key-level events remain the default for all other
keys); (3) the host-address inventory helper (host → IPs with provenance); (4) a
**host-profile surfacing** path: the named values feed the report's per-host profile
(§6.2). winreg-artifacts is already a dependency — use it, don't re-implement.
**Oracle rows served:** F1, F2, F3, F17, F19, F22.

### PRE-4 — `entity_refs` schema + explicit backfill (unchanged)
`ALTER TABLE timeline ADD COLUMN IF NOT EXISTS entity_refs VARCHAR`; both insert paths
write it; backfill = NULL-guarded UPDATE-on-reingest modeled on `update_tags`
(`ingest.rs:118-131`); loud NULL-refs preflight in `issen correlate`.

### PRE-5 — Force-link + make discoverable the inert parsers (NEW)
**Gap (verified ★):** `main.rs:12-15` force-links four parser crates; `issen-parser-amcache`,
`-lnk`, `-shimcache`, `-prefetch` implement `ForensicParser` + `inventory::submit!` but
are never linked — their registrations are dead code in the shipped binary. This is the
prime suspect for the measured "Prefetch and Amcache emitted 0 events" (:44). Separately,
`detect_artifact_type` has **no `.lnk` arm** (and none for shellbags), so LNK files are
undiscoverable regardless of linking.

Scope: (1) `extern crate` the four parser crates in `main.rs` (and any other implemented-
but-unlinked parser found by an exhaustive sweep of `crates/parsers/*` vs `main.rs`);
(2) add a `.lnk` detection arm (`ArtifactType::Lnk` already exists, types.rs:19);
(3) RED tests pin: a case dir containing an Amcache.hve / a `.lnk` / a `.pf` fixture
produces non-zero events of the right type through **generic ingest** (the regression
the measured baseline caught). **Oracle rows served:** F10 (amcache leg), F21 (LNK leg).

### PRE-6 — Flagged-executable extract + hash + known-bad match (NEW)
**Why:** F9's malware hash must have a local route (the author's route was pcap export —
out of reach). **What exists:** `issen-disk::extract_files` (:273) extracts file bytes
from NTFS partitions; ingest already loads `--hash-iocs` known-bad stores
(`ingest.rs:214-227`); issen-mem already wraps forensic-hashdb.

Scope: during the correlate run, for every file path that is a member of a CORR-* finding
or a ≥ High scan finding **and still resident in the image**, extract bytes, compute
SHA256, record it as event/finding metadata (`file_sha256`), and match against the
supplied hash-IOC store; a match emits a per-event finding with the store's label as
"consistent with" context. Bounded by construction: only flagged paths, never a
whole-image hash sweep (that is a different product feature). The general mechanism —
hash-what-you-flag — is not Case-001-specific. **Oracle rows served:** F9 (and F15's
label, when the analyst's list carries one).

### Sequencing
PRE-4 → PRE-2 → PRE-5 (independent of 2/4, can run parallel-tracked but lands before
Tier B' rules) → PRE-1 → PRE-3 → PRE-6 (needs the rules to exist to have anything to
flag; lands with §8 step 13). Full ordering folded into the TDD plan (§8).

---

## 5 · `issen correlate <case-dir>` — behavior and rules

### 5.1 The six phases (unchanged from v3)
1. **Case discovery** — content-sniff classification (disk image / memory dump / zip of
   either); unrecognized files listed and skipped loudly.
2. **Disk ingest per image** → ONE shared DuckDB (`<case-dir>/issen-case.duckdb`),
   reusing `run_auto` + `insert_batch_at_epoch(events, "live")` + the PRE-4 backfill;
   `evidence_source` = image stem; host attribution from event `hostname`, never
   filename.
3. **Memory ingest per dump** (PRE-1) — acquisition timestamps + `point_in_time` tags.
4. **Per-event findings pass** — `run_native_attack_phase` + `detect_timestomp` +
   (PRE-6) extract-hash-match → `scan_findings`.
5. **Correlation pass** — the ordered evaluator runs the 10 CORR-* rules; persists into
   `correlations` + `correlation_members`.
6. **Report** — "Correlated Findings" + (new) "Host Profiles" + "Session Envelope"
   sections; console exec summary.

### 5.2 Rule table (10 rules; ★ = new in v4)

| Code | Anchor → consequent (ordered) | Shared subject + scope | Window | ATT&CK | Oracle rows |
|---|---|---|---|---|---|
| `CORR-BRUTEFORCE-LOGON` | 4625 burst (SQL `burst_windows`) → 4624 type 10 | same source `Ip`, `SameHost` | ≤ 30 min from burst end | T1110 → T1021.001 | F6 (F5 anchor, F11 subject) |
| `CORR-LOGON-MALWARE-WRITE` | remote 4624 → `FileCreate` of executable in user-writable path | same host + same account (`User`) | ≤ 60 min | T1105 | F8, F13 |
| `CORR-MALWARE-RELOCATE` | `FileCreate` (user dir) → USN rename of same name into System32 | `FilePath` stem, `SameHost` | ≤ 24 h | T1036.005 | F14 — **asserted on both hosts** |
| `CORR-MALWARE-PERSIST` | executable `FileCreate` → `ServiceInstall` (7045) same image stem | 7045 metadata ↔ `FilePath`, `SameHost` | ≤ 24 h | T1543.003 | F17 |
| ★ `CORR-PERSIST-REGCONFIRM` | `ServiceInstall` (7045) → `RegistryModify` of `...\Services\<same name>` (or `Run*` value naming the image) | service name ↔ registry key tail, `SameHost` | ≤ 24 h (registry LastWrite) | T1543.003 / T1547.001 | F17 (the EVTX↔registry join) |
| `CORR-PROC-DISK-MATCH` | disk events for an image path ↔ memory `ProcessExec` of same image | `FilePath`/process name; case envelope (point-in-time) | — | (binds [M]↔[P]) | F8 |
| `CORR-INJECTED-C2` | malfind injection → netstat `NetworkConnect`, same PID | PID + process name, **`SameDump`** | — | T1055 → T1071 | F12 |
| `CORR-LATERAL-MOVE` | host-A compromise finding → 4624 type 10 on host B | §5.3 guards, `CrossHost` | ≤ 24 h | T1021.001 | F19 |
| `CORR-EXFIL-STAGE` | suspicious-session start → archive `FileCreate` (zip/rar/7z) | host + user/`Session`, `SameHost` | session window | T1074.001 | F21, F23 — **must fire on DC (secret.zip) AND Desktop (loot.zip)** |
| ★ `CORR-COPY-DELETE` | `FileDelete` of file A → `FileCreate` of file B where stems are near-name permutations (token-set match, e.g. `SECRET_beth` ↔ `Beth_Secret`) | same host + same directory subtree; size-equality guard when MFT size metadata is present | ≤ 30 min, either order within the window (copy-then-delete and delete-then-create both occur in the wild; the *pair* inside one window is the observation) | T1070 (consistent with) | F24 |

`CORR-COPY-DELETE` precision guards (this is the second-highest FP-risk rule): token-set
stem match (not substring), same directory subtree, extension equality, and — when both
MFT records are available — byte-size equality (the author's own copy test). Negative
controls: unrelated same-size files; same name, different subtree; reversed tokens that
are dictionary-plausible (`report_final` / `final_report` in two unrelated dirs) must
not fire without the subtree guard.

### 5.3 `CORR-LATERAL-MOVE` precision spec — unchanged from v3
All five guards hold: (1) host-A address inventory from its own registry Interfaces
values (PRE-3; netstat-from-memory secondary; observed-traffic inference last-resort,
provenance recorded); (2) ordered timing (≥ High host-A finding strictly before the
host-B logon, ≤ 24 h); (3) same account as the host-A chain; (4) host-B 4624 source IP ∈
host-A inventory; (5) routine-admin exclusion (+ session-chain linkage where available).
Negative controls as in v3.

### 5.4 Single-artifact surfacing (the non-correlation half of the oracle)
These need no CORR rule — the capstone's obligation is that they appear, attributed, in
the unified timeline/report and (where noted) in a dedicated report element:

| Surfacing | Mechanism | Oracle rows |
|---|---|---|
| 4625 burst finding | existing `failed_logon_burst_finding` → `scan_findings` | F5 |
| Logon/logoff/service/task events | existing EVTX mapping (lib.rs:61-75) | F6 members, F17, F25 |
| coreupdater MFT/USN file events | existing MFT/USN parsers | F13, F14 members, F20, F24 members |
| **Host profile** (per host: OS, build, timezone, computer name, interface IPs) | PRE-3 named values → new report section | F1, F2, F3, F22 |
| **Session envelope** (per correlated adversary session: first/last event, "last observed activity") | report query over chain-member sessions (`logon_id`) | F25 |
| Amcache/LNK/Prefetch/Shimcache execution & access evidence | PRE-5 | F10, F21 corroboration |
| Flagged-file hashes | PRE-6 | F9 |
| EVTX-internal clock-skew observation | `detect_time_skew` over the case DB, surfaced as an Info finding | F3 (in-scope half) |

### 5.5 Staging — what runs on today's data vs. what waits

| Tier | Rules / surfacing | Gated by |
|---|---|---|
| A — after PRE-4 only | `CORR-MALWARE-RELOCATE`, `CORR-MALWARE-PERSIST`, `CORR-COPY-DELETE` (all interim-join on `artifact_path`/metadata that exists today; typed-ref upgrade swaps the key when PRE-2 lands, same code, same tests) | PRE-4 |
| B — after PRE-2 | `CORR-BRUTEFORCE-LOGON`, `CORR-LOGON-MALWARE-WRITE`, `CORR-EXFIL-STAGE` | PRE-2 (+PRE-5 for the LNK corroboration members of EXFIL-STAGE) |
| B' — after PRE-3 | `CORR-PERSIST-REGCONFIRM`, host-profile surfacing | PRE-3 (registry events must exist at all) |
| C — after PRE-1 | `CORR-PROC-DISK-MATCH`, `CORR-INJECTED-C2` | PRE-1 |
| D — after PRE-2+PRE-3 | `CORR-LATERAL-MOVE` | both |

### 5.6 Memory timestamp semantics, zip/workdir policy — unchanged from v3
Acquisition-timestamp events (`--acquired-at` required for the oracle run; fallback
chain `user_supplied`/`dump_metadata`/`file_mtime` with provenance, never silent);
`SameDump` = `evidence_source` equality; PIDs never cross dumps/hosts/disk.
Content-hash-keyed, idempotent, disk-space-preflighted extraction workdir
(`<case-dir>/.issen-work/extracted/<sha256[..16]>/`, `completed` marker written last,
`available >= 1.2 × needed` before any write).

---

## 6 · Architecture, CLI + report surface

### 6.1 Architecture — unchanged from v3 (summary)
SQL for candidates (pushdown filters + SQL-assisted `burst_windows`), Rust for rules.
Crate homes: `EventQuery`/`StoredEvent` in issen-core (leaf); `fetch_events` (bounded by
construction — time envelope + row cap required by the constructor) /
`burst_windows` / DDL + persistence in issen-timeline; `EventSource` trait + ordered
evaluator + `CorrelationFinding` in issen-correlation (stays DuckDB-free); the
`CaseStore` shim + memory persistence in issen-cli; report reads
`correlations ⋈ correlation_members ⋈ timeline` on `timeline.id` (chosen over
`record_hash` because dedup is within-epoch only). Ordered semantics: anchor strictly
before consequent; missing/zero timestamps never satisfy a window; `SameHost`/
`CrossHost`/`SameDump` scopes explicit; warninglist suppression before emission;
negative controls mandatory. Schema DDL exactly as v3 §4.3 (correlations +
correlation_members + `evidence_sources` acquisition columns).

### 6.2 CLI + report
CLI grammar as v3 §6.1 (`--output`, `--report`, `--work-dir`, `--acquired-at`,
`--skip-ingest`, `--rules`, `--format`), plus `--hash-iocs <FILE>` (repeatable —
the existing ingest flag, now honored by the correlate pipeline for PRE-6 matching).

Report sections:
1. **Host Profiles** (new) — per host: hostname, OS/build, timezone, interface IPs —
   each value with its registry-key provenance (F1/F2/F3/F22).
2. **Correlated Findings** — one card per correlation, three explicitly separated
   layers (observed members with roles → "consistent with" inference → the fixed
   tribunal footer).
3. **Attack chain** — existing renderer, merged `correlations.tags`.
4. **Session Envelope** (new) — per adversary session in the chain: first/last
   observed event ("last observed activity: <ts> — logoff", F25).

### 6.3 Epistemics enforcement — unchanged from v3
Unit test over every CORR-* `note_template`: must contain "consistent with", must not
match `(?i)\b(confirm(s|ed)?|prove[sdn]?|proof|undoubtedly|certainly)\b`; render test
asserts the tribunal footer; same regex gate on console output. The bundled
supertimeline YAML pack's "confirmed" tone is explicitly not a precedent.

---

## 7 · MVP cut (YAGNI line)

**The MVP is the smallest build that makes the §2 coverage matrix true:**
PRE-1..PRE-6; case discovery + workdir policy; multi-host ingest into one DB; the
correlation schema; `EventQuery`/`StoredEvent`/`fetch_events`/`burst_windows`;
`EventSource` + ordered evaluator; the **10** CORR-* rules with guards and negative
controls; host-profile + session-envelope report sections; `correlate` CLI; epistemics
tests; the coverage-matrix oracle test.

**Stretch / future (named, deliberately out):** everything in §2.3 (pcap/zeek,
webcache-ESE, online enrichment, content diff, `$I` parsing); `[H]` epoch `at`/`diff`;
SRUM generic ingest + exfil-bytes ledger (A4); MFT/USN local-module → parser-crate
consolidation (§3); pagefile/hiberfil epochs; `[Q]`/`[C]`; YAML rule-authoring UX;
cross-case correlation; GUI; shared narrative renderer; rewording the supertimeline
YAML pack.

---

## 8 · TDD plan (ordered RED→GREEN; two commits per step, RED first)

Fast tests: synthetic `TimelineEvent` fixtures + in-memory `EventSource` impls, gating
CI. Heavy-corpus tests: `#[ignore]`-gated, sequential (`--test-threads=1`). **The corpus
gate is a documented release gate** (docs/validation.md entry + release-checklist item;
a recorded gate run, not `#[ignore]` alone, is the Doer-Checker evidence).

### 8.1 The acceptance oracle (the matrix made executable)
`cargo test -p issen-cli --test correlate_case001 -- --ignored --test-threads=1` runs
`issen correlate` once over the cached corpus workdir and then asserts **one block per
in-scope matrix row** (21 blocks; F7/F16/F18 documented as exclusions). Representative
assertions (each cites its F-row in the test source):

- F1/F2: host profile rows exist for both hosts with `product_name` containing
  "Windows Server 2012" / "Windows 10 Enterprise".
- F3: both a `TimeZoneKeyName` profile value (Pacific) and a skew/Info observation.
- F5: a `scan_findings` row from `failed_logon_burst` whose window covers 03:21:25.
- F6: a `CORR-BRUTEFORCE-LOGON` correlation whose members include a 4624 with metadata
  `IpAddress = 194.61.24.102` and `logon_type = 10` at 03:21:48 (DC01).
- F9: the coreupdater member event carries `file_sha256` metadata, and (when the test's
  IOC list is supplied) a hash-match finding exists.
- F12: a `NetworkConnect` event with remote `203.78.103.109` exists with memory
  evidence_source, and a `CORR-INJECTED-C2` correlation references it.
- F13: first `FileCreate` for `coreupdater.exe` on DC01 at 03:24:06 ± 60 s, from both
  MFT and USN sources.
- F14: `CORR-MALWARE-RELOCATE` findings exist **for both hosts** with a System32
  consequent.
- F17: `CORR-MALWARE-PERSIST` and `CORR-PERSIST-REGCONFIRM` exist on both hosts; the
  7045 member's service name is `coreupdater`.
- F19: `CORR-LATERAL-MOVE` exists; host-B member is the Desktop 4624 type 10 from
  `10.42.85.10` at 03:36:24, account Administrator.
- F21: `CORR-EXFIL-STAGE` exists on the Desktop (`loot.zip`) **and** the DC
  (`secret.zip`).
- F24: `CORR-COPY-DELETE` exists pairing `SECRET_beth.txt` (delete) with
  `Beth_Secret.txt` (create).
- F25: the session envelope's last event is a `Logoff` on DC01; its UTC value is pinned
  when first measured (the author reports "2:57" pcap-clock).
- F4/F8/F23: the report's attack chain spans InitialAccess → Execution → Persistence →
  LateralMovement → C2 (+ Collection), all five evidence sources attributed, both
  hostnames present.

Timestamps asserted in UTC per the measured baseline; tolerance ± 60 s where the
write-up gives minute precision. Any row that cannot be asserted after implementation
moves — loudly, in the same commit — to the §2.3 out-of-reach table with its reason.

### 8.2 Ordered steps

**Pre-tasks (each its own RED commit, then GREEN commit):**
1. **PRE-4 — schema + backfill** (as v3: round-trip, idempotent migration, NULL-guarded
   backfill, pinned failure mode, preflight count).
2. **PRE-2 — entity refs from EVTX + MFT/USN** (4624 fixture → `Ip`/`User`/`Session`
   refs + `user`; 7045 → ImagePath `FilePath` ref; MFT/USN → `FilePath`; persists
   through `fetch_events`).
3. **PRE-5 — force-link + discovery** ★. RED: a synthetic case dir with Amcache.hve /
   `.lnk` / `.pf` fixtures yields non-zero typed events through *generic ingest*; a
   sweep test asserts every `crates/parsers/*` crate with an `inventory::submit!` is
   linked in `main.rs`. GREEN: extern-crate lines + `.lnk` detection arm.
4. **PRE-1 — memory seam** (as v3, incl. the `#[ignore]` RED: `DESKTOP-SDN1RPT-memory`
   → a `NetworkConnect` for `203.78.103.109` in the DB).
5. **PRE-3 — registry root-cause + named-value table** ★ widened. RED: SYSTEM/SOFTWARE
   hive fixtures yield ProductName, TimeZoneKeyName, ComputerName (→ hostname),
   per-interface `Ip` refs, `Services\<name>` values; inventory helper returns
   addresses with provenance; `#[ignore]` RED: DC01 hive → non-empty inventory +
   ProductName "Windows Server 2012"; plus the zero-events root-cause pin once
   diagnosed. GREEN: declarative extraction table + helper.

**Engine (as v3, renumbered):**
6. Correlation schema + model (persist finding → id; members on `timeline.id`;
   cross-epoch regression test).
7. `EventQuery`/`StoredEvent` + `fetch_events` + `burst_windows` (bounds
   non-constructible-unbounded; full-fidelity reconstruction incl. entity_refs).
8. `EventSource` + ordered evaluator (ordered-only matching; reversed/missing-ts/
   cross-host/cross-dump negatives all yield nothing).

**Rule tiers (small, independently revertable):**
9. Tier A: `CORR-MALWARE-RELOCATE` + `CORR-MALWARE-PERSIST` + ★`CORR-COPY-DELETE`
   (synthetic shapes + negatives; `#[ignore]`: DC01 relocate/persist on coreupdater;
   DC01 copy-delete on Beth_Secret).
10. Tier B: `CORR-BRUTEFORCE-LOGON` + `CORR-LOGON-MALWARE-WRITE` + `CORR-EXFIL-STAGE`
    (`#[ignore]`: DC01 burst→logon 194.61.24.102; **Desktop loot.zip AND DC
    secret.zip**).
11. Tier B': ★`CORR-PERSIST-REGCONFIRM` + host-profile surfacing (`#[ignore]`: both
    hosts' 7045↔Services-key joins; profile rows). *(Requires step 5.)*
12. Tier C: `CORR-PROC-DISK-MATCH` + `CORR-INJECTED-C2` (same-dump fixtures; cross-dump
    PID negative). *(Requires step 4.)*
13. **PRE-6 — extract+hash+match** ★. RED: a synthetic image with a flagged file →
    `file_sha256` metadata + an IOC-match finding from a supplied list; absent file →
    loud "not resident" note, no silent skip. GREEN: extraction-hash pass wired into
    phase 4. *(Placed here because it consumes flagged paths from steps 9-12.)*
14. Tier D: `CORR-LATERAL-MOVE` (all five guards + three negatives; real both-host DB).
    *(Requires steps 2+5.)*
15. Workdir policy (hash-keyed reuse, partial-extraction recovery, space preflight).
16. CLI command (synthetic case dir end-to-end; unknown files loudly skipped;
    `--skip-ingest`; NULL-refs preflight warning).
17. Report sections + epistemics tests (three-layer card, host profiles, session
    envelope, forbidden-verdict regex gate).
18. **End-to-end acceptance: the §8.1 coverage-matrix oracle** (`#[ignore]`, the WS-E
    gate). RED: the 21 assertion blocks. GREEN: whatever wiring remains. Record the
    gate run per the release-gate procedure.

---

## 9 · Open questions for Codex to attack

1. **Findings I could not map to an available artifact** — confirm or contest the §2.3
   exclusions: F7 (pcap-only traffic observations), F16 (not evidence-derived), F18
   (pure OSINT), and the named partial legs (webcache corroboration in F10/F14/F21;
   content-diff in F24; online attribution in F15). Is there any local-artifact route I
   missed — e.g. does the Case 001 Desktop image carry browser SQLite history that
   browser-forensic (already a workspace dep) could surface for the F10 download
   evidence, making that leg PARTIAL→DESIGN?
2. **Registry zero-events root cause** — still undiagnosed (measured-coverage :44).
   v4 adds a concrete suspect (the `detect_artifact_type` "registry|config" path-guard,
   orchestrator.rs:103-114, vs. the actual extracted-path layout) — verify against a
   real extraction listing before PRE-3 lands.
3. **`CORR-COPY-DELETE` FP envelope** — is token-set stem matching + subtree + size
   equality tight enough, or does it need a content-hash guard (which would couple it
   to PRE-6's extraction)? Adversarial case: log-rotation patterns (`app.log` /
   `app.log.1`).
4. **F25's "2:57" reconciliation** — the author's pcap-clock logoff time has no
   measured UTC counterpart yet; the oracle assertion is pinned at first measurement.
   Confirm the Logoff event exists in DC01 EVTX at ~03:57 UTC (or determine the skew
   direction) before writing step 18's literal.
5. **Acquisition-time values for the Case 001 dumps** (`--acquired-at`) — still to be
   pinned from the DFIR Madness case documentation (v3 open-Q1, unchanged).
6. **Ingest throughput on DC01** — the 23-minute kill predates the set-based insert
   path; re-measure before step 18 (v3 open-Q3, unchanged).
7. **Tier-A interim joins** — skip the `artifact_path` interim form if PRE-2 lands
   first in practice (v3 open-Q4, unchanged).
8. **`fetch_events_unbounded`** — omit entirely if the case envelope suffices
   everywhere (v3 open-Q5, unchanged; YAGNI-preferred answer is omit).
9. **walshcat Q9 label swap** — F22's oracle assertion pins the measured host↔IP
   assignment (DC01 = 10.42.85.10). Independent confirmation from the corpus registry
   (PRE-3's Interfaces extraction) would settle it from primary evidence — make that
   the F22 assertion's source of truth rather than either write-up.
