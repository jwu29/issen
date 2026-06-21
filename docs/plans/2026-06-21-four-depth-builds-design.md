# Design: Four remaining depth-track builds (post-registry-catalog)

Status: DESIGN v2 (Codex-critiqued, facts re-verified). Author: depth-track.
Context: registry catalog (#1) + depth gate are done. Investigation reframes three
of the four "remaining larger items" as **capability-built-not-surfaced wiring
jobs** (the exact systemic pattern the depth track fixes); only `$LogFile`
transaction replay is a genuine new build.

Verified facts (Doer-Checker, 2026-06-21 — incl. Codex's corrections, each
re-checked against source):
- `srum_parser` exposes all 7 table parse fns (2 wired). App-id/user-id/profile-id
  → name resolution is in `srum-analysis::{enrich, enrich_connectivity, load_id_map}`
  (best-effort), NOT the raw `parse_*` fns → the 2 wired tables emit RAW numeric ids.
  Connectivity resolves `profile_id`→`profile_name` (NOT "interface LUID").
- `segb-forensic::audit(records) -> Vec<Anomaly>` emits `SEGB-CRC-MISMATCH`
  (Severity::High, with `offset` + record `index`) and timestamp-order anomalies.
- `ntfs-core::logfile::parse_logfile` only scans RSTR/RCRD pages + detects gaps/
  clearing (+ a `usn_extractor`); it does NOT decode redo/undo transaction records.
- `lnk-core` exposes `parse_automatic_destinations`/`parse_custom_destinations` +
  `JumpList`/`JumpListEntry`/`DestListEntry`/`JumpListKind`.
- `ArtifactType::JumpLists` ALREADY EXISTS (`artifacts/types.rs`, mapped to
  `EventSource::Disk`) — it is a dark artifact type with no parser, not a new type.
- `forensicnomicon::jumplist::appid_name(appid)` ALREADY EXISTS (resolves
  `5d696d521de238c3`→"Chrome", etc.) — AppID resolution is not future work.
- `ActivityCategory::Integrity` exists.

---

## A. SRUM — enrich + wire the 5 remaining tables (issen-wrapper job)

**Reframe:** not "wire 5 tables." Two gaps: (1) the 2 wired tables emit raw app_ids
(an analyst sees `app_id=42`, not `chrome.exe`); (2) 5 tables dark.

**Tables** (srum_parser): wired = NetworkUsage, AppResourceUsage; dark =
NetworkConnectivity, EnergyUsage, EnergyUsageLT, PushNotifications, AppTimeline.

**Volume tiering (Codex):** SRUM tables emit tens of thousands of interval rows/day.
Do NOT treat all five as equal event sources.
- **Default-on (high-signal):** AppTimeline (foreground app usage — highest value),
  NetworkConnectivity (connected intervals), plus the existing NetworkUsage /
  AppResourceUsage. One TimelineEvent per row.
- **Opt-in / aggregated (low-signal, high-volume):** EnergyUsage, EnergyUsageLT,
  PushNotifications — emit an aggregate-per-app summary by default (count + first/last
  seen), full rows only behind an explicit flag. (Resolves the flood risk.)

**Enrichment:** load the SruDbIdMap once per database (`load_id_map`); enrich every
table via `enrich` / `enrich_connectivity` (profile_id→profile_name for connectivity).
Apply to the 2 EXISTING tables too (fixes the latent shallowness).
- **best-effort, NOT a gate (Codex):** `load_id_map` can miss; an unresolved id is
  VALID output. Events carry raw `app_id` always + `app_name` when resolved. The
  depth gate requires the `app_id` key (always present), and asserts `app_name`
  surfaces for a KNOWN-resolvable row on the real corpus — never "app_name on every
  event."

**CADET:** NetworkConnectivity→NetworkActivity; AppTimeline→Execution; Push→
NetworkActivity; Energy→Execution (corroboration). Keyed on the row timestamp.

**Oracle:** Szechuan SRUDB.dat. Per-table RED asserts a known enriched row.
**Q2 (must check):** confirm the corpus has rows per table; skip-document any table
the corpus can't exercise (a server may have empty Energy/Push).

**Layer note:** parsers live in srum-forensic (done); the issen→TimelineEvent mapping
+ tiering is issen work. The "SRUM changes go in srum-forensic" rule covers
parser/record/CLI, not the mapping.

**Effort:** S–M (wrapper-only; parsers + enrich exist; tiering adds the aggregate path).

---

## B. $LogFile — split a wire-only B1 from a spike-first B2 (Codex)

**B1 — anti-forensic findings (S, wire-only, ship independently):**
`audit_logfile` (LogFileCleared/gaps) + `audit_mft_mirror` ($MFTMirr ≠ $MFT) already
exist. Wire them as `Integrity` findings ("consistent with journal clearing" — never
a tamper *verdict*; the tribunal concludes). Reuses existing audits over the existing
`parse_logfile` scan. NOT conflated with B2.

**B2 — transaction replay (L, SPIKE-FIRST, separate milestone):**
Decode RCRD pages → LFS records → `NTFS_LOG_RECORD` redo/undo ops → reconstruct file
operations. **Explicit deliverables the v1 doc hand-waved (Codex):**
- USA (update-sequence-array) fixup per RCRD page; multi-page record reassembly
  (records span pages; PageCount/PagePosition).
- LFS transaction headers; the Open-Attribute Table (OAT) and Dirty-Page Table
  (these are how an op's target attribute/file is resolved).
- Opcode interpretation: InitializeFileRecordSegment, Deallocate…, CreateAttribute,
  UpdateFileNameInRoot/Allocation, etc.

**Honest scope (Codex — corrects a v1 overclaim):** `$FILE_NAME` is NOT recoverable
for every op. `CreateAttribute` carries no name; the name is a *reconstructed join*
through the OAT + $MFT, and **MFT-record reuse makes attribution ambiguous**. v1
deliverable = **confidence-graded partial operations** (op + LSN + target ref +
name-if-resolved + a confidence/ambiguity flag), NOT "every op named."

**Oracle is a platform BLOCKER, decide before scheduling B2 (Codex):** the reference
decoders — Schicht's **LogFileParser** (AutoIt-compiled Windows `.exe` + bundled
`sqlite3.exe`) and NTFS Log Tracker (Windows) — are **not macOS-native**. B2 MUST NOT
be scheduled until a validated oracle harness exists: a Windows VM / Wine /
container plan + a fixture-parity format + a fallback corpus. Without it, differential
validation gets skipped and the correctness guarantee dissolves (the LZNT1 trap).

**ORACLE GATE RESOLVED (2026-06-21, research-first):**
- **`dissect.ntfs` (Fox-IT) does NOT decode `$LogFile`** — verified by install +
  inspection: modules are `mft`/`usnjrnl`/`attr`/`secure`, the only logfile mention
  is `FILE_NUMBER_LOGFILE = 2` (a constant). No RCRD/redo/undo parser. The native-
  oracle hope is dead.
- **No pip-installable `$LogFile` transaction parser exists** (ntfs-logfile-parser /
  logfileparser / ntfs-logtracker all 404 on PyPI; `analyzemft` is `$MFT`-only).
- ⇒ The independent oracle for the SEMANTIC decode is Windows-only (LogFileParser /
  NTFS Log Tracker). **BUT Wine WORKS — proven, not assumed (corrects an earlier
  unverified "Wine is flaky" dismissal):** LogFileParser has a documented headless
  CLI mode (`/LogFileFile /OutputPath /SkipSqlite3:1 /SectorsPerCluster /MftRecordSize`,
  exit codes, CSV output — `/SkipSqlite3:1` drops the bundled `sqlite3.exe`), and the
  shipped binary is a PE32 **console** app. On Apple Silicon: `brew install --cask
  wine-stable` (Wine 11, x86_64 via Rosetta) → **must `xattr -dr com.apple.quarantine
  "/Applications/Wine Stable.app"`** (Gatekeeper kills it otherwise: SIGKILL/RC 137,
  "Apple could not verify…" — non-notarization, not malware). Then:
  `WINEPREFIX=~/.wine-lfp WINEDEBUG=-all wine LogFileParser64.exe /LogFileFile:Z:\path\$LogFile
  /OutputPath:Z:\out /SkipSqlite3:1 /SectorsPerCluster:8 /MftRecordSize:1024`.
  **Validated end-to-end on the real 17.5 MB DC01 `$LogFile`: 77,452 transactions
  decoded** + `LogFile_OpenAttributeTable.csv` (the OAT for the name join),
  `LogFile_FileNames.csv`, `LogFile_Mft_StandardInformation.csv`, dirty-page table.
  ⇒ **No QEMU VM required.** Caveat (user-accepted): Wine's reimplemented Windows
  DLLs (`win32u.dll`, `vssapi.dll`) + the AutoIt-compiled `.exe` are common AV
  false-positives — host-level noise (an isolated VM would contain it, but Wine is
  kept). LogFileParser binary + `SampleTinyNtfsVolume.zip` test volume in
  `~/src/disk-forensic/tests/data` (provenance README; verify redistribution license).
- **Real `$LogFile` data IS available** (no need to mint): from the Szechuan
  **DC01 `…/E01-DC01/20200918_0347_CDrive.E01`**, partition `0x15f00000` →
  **18,317,312-byte `$LogFile`** (starts `RSTR`, 4470 RCRD pages, USA count 9 =
  8×512 B sectors/4096 B page). MD5 `a8e8582498464b4fbc15f83db8782516`.
  **INDEPENDENTLY CROSS-VALIDATED (NOT circular):** extracting with issen's own
  stack (`issen_ewf::EwfDataSource::open` + `issen_disk::extract_ntfs_sources`,
  `NtfsLoc::FixedPath(\$LogFile)`) AND with **The Sleuth Kit** (`icat -o 718848
  <E01> 2`, a separate libewf+NTFS codebase) yields **byte-identical** output
  (same MD5, `cmp` clean) — so issen's reader is not the sole authority for the
  input bytes. **Use TSK `icat` as the independent extractor for `$LogFile`
  fixtures** (the input oracle), distinct from LogFileParser (the decode oracle).
  Reproducible; gitignored (17.5 MB) — provenance in corpus-catalog.

**B2 SPLITS AT THE ORACLE LINE:**
- **B2a — RCRD page reader + USA fixup + LFS-record enumeration (ntfs-core).**
  **Structurally self-validating, NO Windows oracle needed:** the update-sequence-array
  check is the format's own integrity mechanism (USN at each sector tail must match
  USA[0]); page count cross-checks a raw `RCRD` signature scan; record boundaries are
  structural. Validate against the real 17.5 MB DC01 `$LogFile`. This is responsibly
  buildable now.
- **B2b — redo/undo opcode → file-op semantics (+ `$FILE_NAME` join, confidence grade).**
  This is B2's *value* and is exactly the part that needs LogFileParser differential
  validation — **do NOT build semantics on synthetic-only data (the LZNT1 trap).**
  Gated on the QEMU+LogFileParser harness decision.

**Layering:** RCRD reader → ntfs-core; transaction-anomaly audits (e.g. a
UpdateFileName redo that rewinds a timestamp = timestomp evidence) → ntfs-forensic;
`ArtifactType::LogFile` (NEW — does not exist) + `issen-parser-logfile` wrapper +
collection ($LogFile = MFT record 2, pulled as a metadata file) → issen.
**Cross-artifact payoff** ($LogFile × $MFT × $UsnJrnl × $MFTMirr = TriForce) lives in
issen-correlation, consuming the parser output.

**Effort:** B1 = S; B2 = L (gated on the oracle-harness decision).

---

## C. Biome SEGB integrity — wire segb-forensic's audit, attribute when exact (Codex)

**Reframe:** the "architecturally awkward" framing was about threading per-record
`crc_ok` THROUGH useract-forensic's lossy normalization. The fix doesn't touch that
layer. `segb-forensic::audit(&records)` already emits `SEGB-CRC-MISMATCH` (High,
offset+index) over the raw records the wrapper already has (`read_segb`) BEFORE
normalization.

**Design — standalone Integrity events (per-event attribution REJECTED after
code-level verification, overriding Codex's design-level suggestion):**
Codex suggested attaching `crc_ok` to the matching menu event when the record index
maps cleanly. Verifying the actual pipeline killed that: there are **two** order-
dropping `filter_map` stages between SEGB records and menu events — the wrapper's
`filter(Written).filter_map(decode.ok())`, then `useract::from_biome_menu_items`'s
`filter_map(menu_item.is_some())`. Positional record→event attribution across two
content-dependent filters is exactly the fragile coupling to avoid; reconstructing it
would hard-couple the wrapper to useract's internal filter predicate. CRC validity is
a property of the record/stream, not the selection, so:
1. In `BiomeParser::parse_bytes`, after `read_segb` → records, call
   `segb_forensic::audit(&records)`.
2. Map each `CrcMismatch` (and timestamp-order) `Anomaly` → a STANDALONE
   `Integrity`-category TimelineEvent: code `SEGB-CRC-MISMATCH`, record `index`,
   `data_offset`, `stored` vs `computed` CRC. Emitted alongside the menu events.
3. Reuses the published analyzer (DRY); no useract-forensic change; no fragile zip.
   (An analyst correlates an integrity event to a menu event by offset/timestamp if
   needed — the evidence is fully present, just not pre-joined.)

**Oracle:** the existing synthetic SEGB builder sets stored crc=0 over a real payload,
so its Written record already fails CRC — RED asserts no integrity event today, GREEN
asserts a `SEGB-CRC-MISMATCH` Integrity event surfaces. A correct-CRC fixture (compute
crc32 over the payload) asserts the benign path emits none. josh-hickman iOS biome
corpus for the real-data benign path.

**Effort:** S.

---

## D. LNK JumpLists — a 2nd registration in issen-parser-lnk (Codex; NOT a new crate)

**Reframe:** a DISTINCT artifact, but `ArtifactType::JumpLists` ALREADY EXISTS (dark —
no parser) and `lnk-core`'s readers + `forensicnomicon::jumplist::appid_name` are
done. This is **un-darkening an existing artifact type**, not new infrastructure.

**Design:**
1. Reuse `ArtifactType::JumpLists` (do NOT add a type).
2. Add a SECOND `inventory::submit!{ ParserRegistration … }` inside `issen-parser-lnk`
   (lnk-core owns both readers; issen-parser-lnk owns LNK→timeline — a new crate isn't
   justified). A `JumpListParser` impl alongside `LnkParser`.
3. Each `DestListEntry` → a `FileSystemActivity` event: target path (from the embedded
   LNK sub-stream — reuse `parse_shell_link`, DRY), access time, MRU position, pin
   state, raw AppID + `appid_name(appid)` resolution (existing fn), and
   automatic-vs-custom kind (`JumpListKind`).
4. Selector: `*.automaticDestinations-ms` + `*.customDestinations-ms` under
   `\Users\*\AppData\Roaming\Microsoft\Windows\Recent\{Automatic,Custom}Destinations\`.
5. Collection: add those two dirs to issen-disk's per-user sweep (same mechanism as
   the `.lnk` Recent/Desktop sweep already added).
6. CFB: AutomaticDestinations is OLE/CFB — lnk-core uses the `cfb` crate (documented
   third-party exception); inherited transitively.

**Oracle:** lnk-forensic's committed fixtures
(`pinned_removable.automaticDestinations-ms`, `tasks.customDestinations-ms`). Copy in,
RED/GREEN, ratchet the gate.

**Effort:** M (registration + selector + collection sweep; reader + type + appid map exist).

---

## Cross-cutting

**Headline reframe (holds after critique):** A (SRUM), C (Biome), D (JumpList) are
capability-built-not-surfaced WIRING jobs — fast, low-risk, each ratchets the depth
gate. `$LogFile` splits into a wire-only **B1** (ship now) and a large **B2** that is
a separate spike, gated on an oracle-harness decision, and must NOT block the others.

**Riskiest single assumption (Codex):** that B2's redo/undo→named-file reconstruction
is tractable+validatable on this host. It is the only item with a hard external
dependency (a Windows oracle) and irreducible ambiguity (MFT reuse). Treat it as
research, not delivery.

**Build order (Codex-revised):**
1. **C — Biome integrity** (S; thin bridge over existing `audit()`).
2. **B1 — $LogFile clearing/gap findings** (S; wire existing audits).
3. **A — SRUM** (S–M; high-signal tables default-on, Energy/Push aggregated, enrich
   ids, fix the app_name-as-gate mistake).
4. **D — JumpLists** (M; reuse existing type + appid_name, 2nd registration in lnk).
5. **B2 — $LogFile transaction replay** (L; spike, own oracle harness, separate milestone).

**Open questions:** Q1 SRUM Energy/Push aggregate shape. Q2 SRUM corpus per-table
coverage. Q3 B2 oracle-harness (Windows VM/Wine/container) — the go/no-go gate for B2.
