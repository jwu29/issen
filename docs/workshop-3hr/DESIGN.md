# DFIR at Machine Speed — Workshop Design

**BSidesHK 2026 · Blue Team Workshop · 3 hours · 30 seats (hands-on lab)**
Instructor: Albert Hui (@Security Ronin) · TA: Josiah Wu

---

## Executive Summary

A 3-hour hands-on workshop that takes junior IR analysts through a **real intrusion
(DFIR Madness Case 001, "The Stolen Szechuan Sauce")** using **only disk images and RAM
dumps** — the evidence you actually have in post-incident IR — and the **Issen** Rust-native
tool suite instead of the traditional FTK/Volatility/Zimmerman/KAPE stack.

**The thesis we are selling (and teaching):** knowing *which tool* and *where the artifact
lives* is a **fake moat** — it is mechanical, and in the age of AI it is being unified,
normalized, and integrated away. The **real moat is investigative mindset**: reading what the
output *means*, building the attack narrative, and presenting it to a board. The workshop
spends its mechanical time in *one* cross-platform tool so the cognitive time can go to the
thing that matters.

**The climax** (a hard requirement from the flyer review): students produce an **ATT&CK
attack-narrative timeline** corroborated across five evidence sources, and learn to present it
with the **three-layer epistemic discipline** — observed fact vs. forensic inference vs. the
legal conclusion that belongs to the tribunal, not the analyst.

> **Honesty gate (binding):** every module below is annotated **WORKS / PARTIAL / GAP**
> against the *current* Issen codebase (audited 2026-06-09). Where Issen cannot yet produce the
> complete answer, it is a **TOOL-DEV TODO** (see backlog) — not a slide we fake. The 6 days
> before the workshop are a sprint to convert GAP → WORKS.

---

## The Scenario (what students are handed)

A Windows estate breached on **19 Sep 2020**: an attacker brute-forced RDP into a domain
controller, dropped Meterpreter, moved laterally to a Win10 desktop, staged and exfiltrated
secrets, time-stomped a decoy, and was still interactive at the moment of capture.

**Evidence (disk + RAM only — deliberately no PCAP, no pre-extracted autoruns/protected files):**

| Host | Disk (E01) | Memory | Pagefile |
|---|---|---|---|
| CitadelDC01 — Win Server 2012 R2 — 10.42.85.10 | `DC01-E01.zip` | `DC01-memory.zip` | `DC01-pagefile.zip` |
| DESKTOP-SDN1RPT — Win10 — 10.42.85.115 | `DESKTOP-E01.zip` | `DESKTOP-SDN1RPT-memory.zip` | `Desktop-SDN1RPT-pagefile.zip` |

Excluded on purpose (briefed as a teaching point): `case001-pcap.zip`, both `*-autorunsc.zip`,
both `*-ProtectedFiles.zip`. Students **extract** the hives and protected files from the E01
themselves — that *is* the exercise.

**The UTC-7 clock trap:** the VMs were mis-set to UTC-7; the (excluded) PCAP router was UTC-6.
Disk/EVTX/memory timestamps are skewed ~1h. Brief students to normalize — and let Issen's
`ClockProvenance` surface it.

---

## Run of Show (180 min)

| Time | Module | Source(s) | What students DO | Issen surface | Status |
|---|---|---|---|---|---|
| 0:00–0:20 | **0 · The Frame** | — | Cold-open: traditional 4-tool path vs one `issen` workflow. Verify install. | — | demo |
| 0:20–0:45 | **1 · Crack the container** | [P] disk | Open E01 → find NTFS partitions → extract Security.evtx, System.evtx, SRUDB.dat, $MFT, SYSTEM/SOFTWARE/SAM hives **by path** | `issen ingest`, `issen-disk` extract | **WORKS** |
| 0:45–1:15 | **2 · The entry story** | [L] logs | Reconstruct RDP brute force (4625 flood → 4624 success) → pinpoint compromise; map T1110/T1021/T1078 | `issen processes`, `session`, `frequency`, `ingest` | **WORKS** |
| 1:15–1:45 | **3 · The live truth** | [M] memory | Walk DC RAM: find `coreupdater.exe`, injection into `spoolsv.exe`, C2 `203.78.103.109:443`, session dwell; T1055/T1071/T1573 | `issen memf` ps/netstat/scan | **PARTIAL** |
| 1:45–1:55 | **Break** | — | — | — | — |
| 1:55–2:25 | **4 · What survives cleanup** | [Q] SRUM + [P] residue | SRUM exec/bytes ledger; MFT `$SI`/`$FN` timestomp on `Beth_Secret.txt`; USN for `secret.zip`/`loot.zip`; T1070.006/T1560/T1041 | `issen srum`, MFT tree, `supertimeline` | **PARTIAL/GAP** |
| 2:25–2:55 | **5 · The narrative (CLIMAX)** | [C] + report | One unified timeline w/ per-event source attribution → ATT&CK attack-chain report → **how to brief a board** (3-layer epistemic discipline) | `issen correlate` (NEW) → `issen report` | **GAP→build** |
| 2:55–3:00 | **Wrap** | — | Install on your own cases; takeaways; the moat is the mindset | — | — |

Single-host (DC) is the spine; the Desktop (lateral movement, `loot.zip`) ships as a **take-home
challenge** with the same toolchain — protects the 3-hour budget for juniors.

---

## The Yardstick: CTF question → Issen command → gap

This is the table Josiah fills by running **both** the traditional baseline (ground truth) and
Issen, per question. Any row where Issen ≠ ground truth becomes a TOOL-DEV TODO.

| CTF item | Ground-truth answer | Artifact | Issen command (today) | Verdict |
|---|---|---|---|---|
| Entry vector | RDP brute force, CITADEL\Administrator | Security.evtx 4625→4624 | `issen processes --evtx-file Security.evtx`, `session` | verify |
| Compromise time | 02:21 UTC 19-Sep-2020 | 4624 type 10 | `session` / `timeline` | verify |
| Malware proc | coreupdater.exe → spoolsv inject | memory pslist/malfind | `issen memf --command scan` | PARTIAL |
| C2 IP | 203.78.103.109:443 | memory netscan | `issen memf --command netstat` | verify |
| Malware on disk | C:\Windows\System32\coreupdater.exe | MFT | `issen ingest` (MFT) | verify |
| Persistence | service "coreupdater" + Run key | System.evtx 7045 + hives | extract hives → 7045/Run parse | RE-ROUTE |
| Lateral movement | DC→Desktop RDP 02:35:54 | Desktop 4624 type 10 | `issen processes` (Desktop evtx) | verify |
| Timestomp | Beth_Secret.txt ~02:38 | MFT $SI vs $FN | MFT tree / temporal rule | verify |
| Exfil staging | secret.zip / loot.zip create+delete | USN journal | `issen ingest` (USN) | verify |
| Passwords | SAM+SYSTEM → NTLM → crack | SAM hive / lsass | extract hives or memf creds | RE-ROUTE |

Full official question set + answers + sources: see `ctf-yardstick.md`.

---

## Tool-Dev Backlog (sprint to make the flyer true)

Prioritized for the 6-day window; ordered by workshop leverage.

1. **`issen correlate <case-dir>` — unified five-source command** *(makes the flyer's central
   claim real)*. Thin orchestration over existing pieces: disk-extract → EVTX ingest → memf →
   SRUM → temporal rules → one DuckDB → one `issen report`. Per-event `source=` attribution.
2. **ATT&CK tagging on raw events** (4625→T1110, 4624/type10→T1021.001, 7045→T1543.003,
   timestomp→T1070.006) so the narrative report populates without requiring Sigma.
3. **SRUM ESE B-tree extraction** (currently stub) — needed for the "bytes exfiltrated" ledger.
4. **Memory C2/injection as first-class findings** — `memf` surfaces coreupdater→203.78.103.109
   and the spoolsv migration as graded findings; validate against the real DC01 dump.
5. **MFT `$SI`/`$FN` timestomp finding** — confirm it fires on `Beth_Secret.txt` (mostly works).
6. **Hive extraction + 7045/Run persistence parse** (re-route question).
7. **SAM/SYSTEM cred extraction or lsass-from-RAM** (re-route; advanced/optional).

Each item is **strict TDD**, validated against the **real Case 001 artifacts** (Doer-Checker),
not synthetic fixtures.

---

## Josiah's TA Workstream (baseline + yardstick)

**Goal:** finish Case 001 *by hand* with the traditional stack to produce the **known-working
ground-truth answer key**, then run Issen against the same questions to expose gaps.

- **Deadline:** Mon **15 Jun 2026, 09:00 HKT**.
- **Tools (baseline only — not taught in the workshop, used as a frame of reference):**
  FTK Imager (mount E01) · Volatility 3 (RAM) · Eric Zimmerman tools (Windows artifacts) · KAPE.
- **Constraint:** disk + RAM only. No PCAP. No pre-extracted autoruns/protected files —
  extract hives/protected files from the E01.
- **If blocked on Linux:** Win10 Docker container, host-mapped artifact path, drive EZ tools CLI.
- **Reporting cadence:** daily kanban update (this repo, `KANBAN.md`) — done / doing / next /
  blockers. Ping instructor immediately on any bottleneck.
- **Deliverable:** the filled `ctf-yardstick.md` (ground truth vs Issen, per question), which
  directly drives the backlog above.

---

## Cross-platform / logistics

- Issen ships native Mac/Win/Linux binaries (Rust; build model = SecurityRonin/blazehash).
- Min 8 GB RAM, 10 GB free disk. Dataset pre-shared 1 week out; Issen pre-installed (prereq).
- Module 0 includes a 5-min install-verification checkpoint with a tiny canned sample.
