# What Issen Can Answer — measured on real Case 001 data

**This is an empirical measurement, not a prediction.** Every verdict below comes from running the
`issen` release binary against the **real DFIR Madness Case 001 DC01 artifacts** on 2026-06-09 and
inspecting the actual output. The CTF answers are the ground truth (official key); the question here
is strictly *what the tool produced*.

**Scope of this run:** **both hosts** — CitadelDC01 (`…CDrive.E01/.E02` + `citadeldc01.mem`) and
DESKTOP-SDN1RPT (`…DESKTOP-SDN1RPT.E01-.E04` + `DESKTOP-SDN1RPT.mem`, both 2 GB raw). DC01 = §"DC01"
column; Desktop adds the lateral-movement and Desktop-only answers (§"Desktop measurement").

**Legend:** **✓ WORKS** = Issen surfaced the correct answer directly · **◑ PARTIAL** = the
supporting data is present but the answer is incomplete or needs manual digging · **✗ GAP** =
Issen did not/could not produce it · **N/M** = not measured this run.

---

## Two cross-cutting findings (these gate everything)

### 1. Memory path (`issen memf`) — ✗ GAP for raw Windows dumps
Every memory sub-command failed identically on `citadeldc01.mem`:
```
$ issen memf /tmp/case001/citadeldc01.mem --command ps   # also netstat, scan, check
[rt-mem] walker unavailable: --profile <isf.json> is required
(no data — walker for Raw/ps not yet wired)
```
→ **No process list, no netstat, no malfind, no OS check** from a raw Windows memory image today.
This single gap removes the C2 IP, the live malicious process, and the `spoolsv` injection.

### 2. Disk ingest (`issen ingest`) — completes only on small images; **never emits Registry/SRUM**
Two-host comparison sharpens this:

| host | events generated | completed? | sources captured |
|---|---|---|---|
| **DC01** (369K events) | 369,492 | **✗ killed at 23 min** (CPU-bound, plateaued) | `Mft` 348,512 · `EventLog` 20,980 |
| **Desktop** (84K events) | 84,138 | **✓ ~5 min** | `EventLog` 40,917 · `UsnJournal` 39,072 · `Mft` **124** |

Three measured facts:
- **The "hang" is linear-slow inserts, not an infinite loop.** Desktop (84K) finished; DC01 (369K)
  did not in 23 min. Per-event un-batched DuckDB insert (~2 round-trips/event) makes large images
  impractical. (Root cause confirmed by Codex: `issen-timeline/src/ingest.rs:39-47`.)
- **USN actually works** — Desktop captured **39,072 UsnJournal events**. DC01's "0 USN" was the
  *kill*, not a USN bug.
- **Registry, SRUM, Prefetch, Amcache emit 0 events even on the *completed* Desktop run** — these
  are genuinely unlinked/stubbed, independent of completion.
- **Desktop `$MFT` severely under-parsed: only 31 records** (×4 = 124 events) from a full Win10
  disk, vs DC01's 348K. A real anomaly (new finding F2).

EVTX `metadata` carries fully-flattened EventData (`IpAddress`, `LogonType`, …), which powers the
logon answers below.

### 3. EWF relative-path bug (new finding F1) — `issen ingest <bare.E01>` fails to find segments
`issen ingest 20200918_0417_DESKTOP-SDN1RPT.E01` (run from inside the evidence dir) → *"no segment
files found matching"*, **even though libewf reads the set fine**. Absolute path works. Root cause:
`ewf/reader.rs:35` uses `first.parent().unwrap_or_else(|| Path::new("."))`, but `parent()` of a bare
filename returns `Some("")` not `None`, so the segment glob becomes `/stem.[Ee][0-9][0-9]` rooted at
`/`. A workshop-grade trap (students invoking from the evidence folder hit it). One-line fix.

---

## Per-question measurement (DC01)

| # | Question | What Issen produced (evidence) | Verdict |
|---|---|---|---|
| 1 | Server OS | ingest surfaced no registry/SOFTWARE hive → OS version not emitted | **✗ GAP** |
| 3 | Server local time | no registry `TimeZoneInformation` parsed | **✗ GAP** |
| 4 | Was there a breach? | `LogonSuccess` 2,540 + `LogonFailure` burst @ `03:21:25` | **✓ WORKS** |
| 5 | Initial vector (RDP brute force) | 4625 failure burst, then **4624 LogonType 10, Administrator, from `194.61.24.102` @ 03:21:48** | **✓ WORKS** (compromise pinpointed) |
| 6.1 | Malicious process (coreupdater→spoolsv) | binary on disk ✓ (below); running process + `spoolsv` injection need memory → unwired | **◑ PARTIAL** |
| 6.2 | Delivery IP `194.61.24.102` | present in the 4624 `IpAddress` metadata | **✓ WORKS** |
| 6.3 | C2 IP `203.78.103.109` | 0 rows in the disk timeline; `memf netstat` unwired | **✗ GAP** |
| 6.4 | Malware path on disk | `coreupdater` in MFT timeline (4 events) | **✓ WORKS** |
| 6.5 | When it first appeared | first `coreupdater` MFT event **`03:24:06`** (= key's 02:24:06 + UTC-7 skew) | **✓ WORKS** |
| 6.6 | Was it moved? (Downloads→System32) | MFT `$SI` only; no USN `RENAME` records in the run | **◑ PARTIAL** |
| 6.9 | Persistence (service install) | **129 × EventID 7045** parsed (coreupdater service among them) | **✓ WORKS** (needs filtering to the row) |
| 7 | Malicious IPs involved | `194.61.24.102` ✓ (EVTX); `203.78.103.109` ✗ (memory) | **◑ PARTIAL** |
| 8 | Lateral movement to Desktop | **measured on Desktop:** 4624 LogonType 10 from `10.42.85.10` (DC), Administrator, `03:36:24` (= key 02:35:54 + skew) | **✓ WORKS** |
| 9 | Network layout | no registry interfaces, no `memf netstat` | **✗ GAP** |
| 11 | Szechuan Sauce.txt access | 8 MFT events for the file → access time recoverable | **✓ WORKS** |
| 12 | Other sensitive files / times | `Beth_Secret` 8 MFT events (create/access/modify) | **✓ WORKS** |
| 13 | Last contact | `Logoff` events present (4634/4647) | **✓ WORKS** |
| B4 | Users logged onto DC | host/domain in event metadata; `C:\Users\` enumeration not surfaced as such | **◑ PARTIAL** |
| B6 | Domain passwords | no SAM/registry/lsass parsing | **✗ GAP** |
| B7 | Recover Beth's deleted file | MFT has the **name**; deleted `$DATA` carving / contents not in ingest | **◑ PARTIAL** (name only) |
| B8 | Timestomped file (`Beth_Secret.txt`) | MFT timeline is `$SI`-only (no `$FN`); **0 scan_findings** → timestomp **not flagged** | **✗ GAP** |

### Desktop measurement (the lateral-movement host)

The Desktop ingest **completed**, and (because USN parsed there) adds clean answers:

| # | Question | What Issen produced on Desktop | Verdict |
|---|---|---|---|
| 8 | Lateral movement | 4624 type 10 from DC `10.42.85.10`, Administrator, `03:36:24` | **✓ WORKS** |
| 8.3 | Exfil staging (`loot.zip`) | 5 timeline events for `loot.zip` (USN+MFT) | **✓ WORKS** |
| 6.5 | Malware lands on Desktop | first `coreupdater` event `03:39:57` (= key 02:40 + skew) | **✓ WORKS** |
| 6.9 | Desktop persistence | 21 × EventID 7045 | **✓ WORKS** |
| B5 | Users logged onto Desktop | logon list includes **Administrator + ricksanchez** (key's answer) — plus service accounts (noisier than the "profile folders" method) | **✓ WORKS** |
| 6.6 | Was malware moved? | USN parsed on Desktop (39,072 events) → rename records present | **✓ WORKS** (USN works when ingest completes) |

→ Desktop **proves USN ingestion works** when the run completes — DC01's gaps on 6.6/8 were the
*kill*, not missing capability.

---

## Tally (18 core questions; "best across both hosts" where a host-specific answer exists)

- **✓ WORKS — 11:** breach (4), entry vector + compromise (5), delivery IP (6.2), malware on disk
  (6.4), first-appearance (6.5), moved/USN (6.6, Desktop), persistence (6.9), **lateral movement (8,
  Desktop)**, Szechuan access (11), other sensitive files (12), last contact (13). Plus bonus **B5**
  (users, Desktop).
- **◑ PARTIAL — 3:** malicious process (6.1 — disk yes, live process/injection need memory),
  malicious IPs (7 — delivery yes, C2 no), recover-deleted name (B7 — name yes, contents carving).
- **✗ GAP — 5:** server OS (1), local time (3), C2 IP (6.3), network layout (9), passwords (B6),
  timestomp detection (B8). Plus B4 (DC user-folder enumeration). *(All gated by the memory path,
  the Registry parser, or the `$SI`/`$FN` timestomp finding.)*

**Headline:** across both hosts, Issen answers the **EVTX + USN + MFT-timeline** questions well —
the RDP brute-force compromise, lateral movement, the malware on disk and when it landed,
persistence, file moves, and access/modification times (**11/18 WORKS**). It **cannot yet** answer
anything that needs **memory** (live process, C2, injection), **registry** (OS, timezone, network,
passwords), **SRUM** (bytes exfiltrated), or **`$SI`-vs-`$FN` timestomp detection** — and `ingest`
does not complete on a large image (DC01, 369K events, killed at 23 min) though it does on a smaller
one (Desktop, 84K, ~5 min).

---

## Reproduction (commands run)

```bash
issen memf citadeldc01.mem --command ps|netstat|scan|check          # all → "walker not wired"
issen ingest 20200918_0347_CDrive.E01 --output dc01.duckdb          # 23 min, stalled, killed
issen info dc01.duckdb                                              # 369,492 events: Mft + EventLog
# evidence queried directly:
duckdb dc01.duckdb -c "SELECT timestamp_display, json_extract_string(metadata,'\$.LogonType')
  FROM timeline WHERE event_type='LogonSuccess' AND metadata LIKE '%194.61.24.102%';"  # → type 10, 03:21:48
duckdb dc01.duckdb -c "SELECT min(timestamp_display) FROM timeline
  WHERE lower(artifact_path) LIKE '%coreupdater%';"                                     # → 03:24:06
```

---

## What this feeds (tool-dev backlog, → handover plans)

Ordered by workshop leverage; each becomes a separate strict-TDD handover plan for the tool-dev
session (this session does not write tool code):

0. **EWF relative-path bug (F1)** — one-line fix (`ewf/reader.rs:35`, map empty parent → `.`).
   Cheap, and a workshop trap (students invoking `issen ingest image.E01` from the evidence dir).
1. **`ingest` completion** — batched DuckDB insert so a 369K-event image finishes (DC01 killed at
   23 min; Desktop's 84K finished). Gates everything.
2. **`ingest` breadth** — Registry (OS/timezone/network/SAM → Q1/3/9/B6) and **SRUM** (bytes) emit
   0 events even on a *completed* run → link + implement the stubbed parsers. (USN already works —
   Desktop got 39K — so it just needs completion, not a parser.)
3. **MFT under-parse (F2)** — Desktop `$MFT` yielded only **31 records** on a completed ingest
   (DC01 got 348K). Investigate the MFT extraction/parse on the Desktop image.
4. **`memf` raw-Windows walker** — wire CR3 discovery + the existing AutoProfile/PDB resolver +
   route Raw→Windows + connect the existing `walk_processes`/`walk_malfind` + finish the pool-scan
   stub. Unblocks C2 IP (6.3), live process + `spoolsv` injection (6.1), network (9).
5. **`$SI`-vs-`$FN` timestomp finding** — surface `$FN` (dropped today) + emit a flagged finding
   when `$SI.modify < $FN.creation` (B8).
6. **ATT&CK tagging on raw events** — 4625→T1110, 4624/type10→T1021.001, 7045→T1543.003 so the
   report narrates without Sigma (today `scan_findings` was empty).

> All of the above are detailed, Codex-verified, in the gap-closing plan:
> [`../../plans/2026-06-09-closing-case001-capability-gaps.md`](../../plans/2026-06-09-closing-case001-capability-gaps.md).
> Next: propagate these empirical verdicts into the `Issen verdict` column of
> [`ctf-yardstick.md`](./ctf-yardstick.md) (currently `_tbd_`).
