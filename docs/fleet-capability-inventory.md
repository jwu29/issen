# Fleet Capability Inventory — *wire, don't reinvent*

*Generated 2026-06-12 by a 6-way parallel scan of the SecurityRonin forensic fleet,
cross-referenced against what `issen` actually calls. Purpose: stop rebuilding things
that already exist (we nearly rebuilt amcache/shimcache decoders that were already in
`winreg-artifacts`; the in-issen prefetch/amcache/shimcache parsers were "dark" because
their decoders existed but the trait `parse()` was a stub).*

## Executive summary

The fleet has a **large** amount of implemented-but-unsurfaced capability. The single
biggest lever for the Case-001 capstone is **wiring**, not building:

- **In `issen` itself:** parsers whose decoders work but whose ingest `ForensicParser::parse()`
  was a stub. **Fixed this session: prefetch, amcache, shimcache, shellbags.** Still dark:
  **MFT / USN-journal** (real impls, but not force-linked in `main.rs`), **SRUM** (command-only,
  ingest path stubbed), **LNK / PE / SetupAPI** (stub + no discovery).
- **`winreg-artifacts`** ships **14 hive decoders**; issen used 3 (amcache/shimcache/shellbags,
  now wired). **11 unwired**: run_keys, sam, userassist, typed_urls, lsadump, com_hijacking,
  svc_diff, lxss, catalog_scan, path_expansion — plus `winreg-carve` (deleted-key recovery),
  `winreg-diff`, `winreg-discover`.
- **`memory-forensic`** has **~40 Windows + ~50 Linux walkers**. Many wired, but high-value
  ones are **dark**: SAM hashdump, LSA secrets, cachedump (domain cached creds), in-memory
  shimcache/amcache/prefetch, SSDT/IAT hooks, kernel callbacks, APC injection, process
  hollowing, handles.
- **Container/partition analyzers** (`vmdk/vhdx/qcow2/mbr/gpt/apm/ntfs-forensic`) emit **40+
  graded `Finding` codes** (VHDX-DIRTY-LOG, VMDK-RGD-MISMATCH, MBR-GAP-WIPED, the **NTFS USN
  rule engine**: USN-SUSPICIOUS-EXECUTABLES / USN-RANSOMWARE / USN-SECURE-DELETE / USN-CREDENTIAL-ACCESS).
  issen surfaces almost none.
- **App-artifact crates** are mostly **UNWIRED**: `browser-forensic` (history + deleted-record
  carving + history-clearing detection), `sqlite-forensic` (WAL/free-page deleted-row carving),
  `srum-forensic` (per-app user-presence + network bytes).
- **`forensicnomicon`** exposes correlation knowledge issen **does not use**: `playbooks`
  (directed investigation chains), `attack_flow` (campaign graphs), `eventids`
  (EventID→ATT&CK + logon-type), `temporal` (timestamp-relation/timestomp), `persistence`
  (run-key/IFEO/AppInit paths), `mitre`, `sigma`, `yara`.

**Bottom line: dozens of Case-001-relevant capabilities are a wiring task away, already
written, tested, and (mostly) published.**

---

## 1 · issen internal wiring audit (turn these on)

| Parser / stage | trait `parse()` real? | force-linked? | discovery classifies? | ingest status |
|---|---|---|---|---|
| evtx | ✅ | ✅ | EventLog | 🟢 wired |
| registry | ✅ | ✅ | Registry | 🟢 wired |
| prefetch | ✅ (fixed) | ✅ | Prefetch | 🟢 **wired this session** (636 events) |
| amcache | ✅ (fixed) | ✅ | Amcache | 🟢 **wired this session** |
| shimcache | ✅ (fixed) | ✅ | Registry (SYSTEM) | 🟢 **wired this session** |
| shellbags | ✅ (fixed) | ❌ | ❌ no discovery | 🟡 parse wired; **needs force-link + NTUSER/UsrClass discovery** |
| mft | ✅ | ❌ | Mft | 🟡 real impl, **not force-linked** (note: MFT still emits via issen-disk path) |
| usnjrnl | ✅ | ❌ | UsnJournal | 🔴 real impl, **not force-linked** |
| srum | ❌ stub (free `parse_path` exists) | ❌ | Srum | 🔴 **command-only** (`issen srum`); ingest path stubbed |
| lnk | ❌ stub | ❌ | ❌ | ⚫ dark (no discovery/link/impl) |
| pe / setupapi / linux / macos | ❌ stub | ❌ | ❌ | ⚫ dark |

`issen-correlation` is a post-hoc enricher (tags evidence, fires bundled rules) — it does
not ingest; it needs the streams above populated to fire.

**Lowest-effort, highest-value:** (1) force-link + discover shellbags/usnjrnl; (2) wire
SRUM into the ingest pipeline (today it only runs via the `issen srum` subcommand).

## 2 · winreg-forensic (`winreg-artifacts` 14 decoders + carve/diff/recover)

| Capability | Location | Extracts | issen |
|---|---|---|---|
| amcache / shimcache / shellbags | `winreg_artifacts::{amcache,shimcache,shellbags}::parse` | execution + folder-access evidence | 🟢 wired |
| registry_keys::walk_keys | `winreg_artifacts::registry_keys` | all keys + metadata | 🟢 wired |
| **run_keys** | `winreg_artifacts::run_keys::parse` | Run/RunOnce autostart (persistence) | 🔴 unwired |
| **userassist** | `winreg_artifacts::userassist::parse` | per-user GUI execution, run/focus counts, last run | 🔴 unwired |
| **sam** | `winreg_artifacts::sam::parse` | local accounts, last-logon, RIDs | 🔴 unwired |
| **lsadump** | `winreg_artifacts::lsadump::parse_secrets` | LSA cached domain creds | 🔴 unwired |
| **com_hijacking** | `winreg_artifacts::com_hijacking::parse_pair` | COM hijack (T1546.015) | 🔴 unwired |
| **svc_diff** | `winreg_artifacts::svc_diff::parse` | services (name/state/binary) | 🔴 unwired |
| **typed_urls** | `winreg_artifacts::typed_urls::parse` | address-bar URL history | 🔴 unwired |
| **catalog_scan** | `winreg_artifacts::catalog_scan::scan` | keys/values vs forensicnomicon catalog (analyzer) | 🔴 unwired |
| **recover_deleted** | `winreg_carve::recover_deleted` | deleted keys/values from slack (confidence-graded) | 🔴 unwired |
| **diff_hives / discover_hives** | `winreg_diff` / `winreg_discover` | hive snapshot diff; hive-source provenance (RegBack/VSC/txlog) | 🔴 unwired |

**Top 3 for Case-001:** run_keys+sam+userassist (persistence + identity + execution
timeline); `winreg-carve` deleted-key recovery (anti-forensics); `winreg-diff`+`discover`
(when persistence was installed, across RegBack/VSC).

## 3 · memory-forensic (`memf-windows` ~40, `memf-linux` ~50 walkers)

Most core walkers are **wired** (psscan, psxview, VAD/malfind, netscan, drivers, DSE/ETW/AMSI
patches, COM-hijack, message hooks, token impersonation, bitlocker, Linux rootkit suite).
High-value **dark** Windows walkers:

| Capability | Location | Surfaces | issen |
|---|---|---|---|
| **SAM hashdump** | `memf_windows::hashdump::dump_sam_hashes` | NT/LM hashes via bootkey | 🔴 unwired |
| **LSA secrets** | `memf_windows::lsadump::walk_lsa_secrets` | service passwords, autologon, DPAPI_SYSTEM | 🔴 unwired |
| **cachedump (DCC2)** | `memf_windows::cachedump::walk_cached_credentials` | domain cached creds NL$1..10 | 🔴 unwired |
| **credman** | `memf_windows::credman::walk_credman` | stored web/app creds (LSASS vault) | 🔴 unwired (stub) |
| **in-memory shimcache** | `memf_windows::shimcache::walk_shimcache_entries` | execution from kernel g_ShimCache | 🔴 unwired |
| **in-memory amcache / prefetch** | `memf_windows::{amcache,prefetch}` | execution evidence from RAM | 🔴 unwired |
| SSDT/IAT hooks, kernel callbacks, APC injection, process hollowing, TLS callbacks, handles, mutants | `memf_windows::{ssdt,iat_hooks,callbacks,apc_injection,hollowing,tls_callbacks,handles,mutant}` | injection/rootkit/persistence | 🔴 unwired |
| DPAPI master keys | `memf_windows::dpapi_keys` | DPAPI keys (RED stub; needs lsasrv symbols) | 🔴 unwired |

**Top 3 for Case-001:** SAM hashdump + LSA secrets (credentialed lateral-movement
attribution); in-memory shimcache/prefetch (hiding-immune execution timeline, DC+Desktop);
cachedump + credman (which domain users / C2 URLs).

## 4 · disk / container / filesystem (graded `Finding` analyzers, almost all unwired)

| Analyzer | Repo | Finding codes (sample) | issen |
|---|---|---|---|
| VHDX integrity | `vhdx-forensic::forensic` | VHDX-DIRTY-LOG, VHDX-LOG-ENTRY-CRC-MISMATCH, VHDX-BAT-ENTRIES-OVERLAP, VHDX-GHOST-DATA-IN-ABSENT-BLOCK (18) | 🔴 unwired |
| VMDK integrity | `vmdk-forensic::forensic` | VMDK-RGD-MISMATCH, VMDK-PRIMARY-GD-RECOVERABLE, VMDK-DANGLING-GRAIN, VMDK-UNCLEAN-SHUTDOWN (7) | 🔴 unwired |
| QCOW2 integrity | `qcow2-forensic::forensic` | QCOW2-ORPHAN-CLUSTERS, QCOW2-CORRUPT, QCOW2-BACKING-FILE, QCOW2-ENCRYPTED (9) | 🔴 unwired |
| MBR analyzer | `mbr-partition-forensic` | MBR-PART-OVERLAP, MBR-BOOT-MALWARE, MBR-GAP-WIPED, MBR-CARVE-ARTIFACT, MBR-GPT-HYBRID (25) | 🟡 partial (overlap/OOB only) |
| GPT analyzer | `gpt-partition-forensic` | GPT-HDR-CRC, GPT-PART-OVERLAP, GPT-MBR-HYBRID-HIDDEN (12) | 🟡 partial |
| **NTFS USN rule engine** | `ntfs-forensic::rules::RuleSet::with_builtins` | USN-SUSPICIOUS-EXECUTABLES, USN-RANSOMWARE-EXTENSIONS, USN-SECURE-DELETE-PATTERN, USN-CREDENTIAL-ACCESS | 🔴 unwired |
| NTFS timestomp / ADS / slack | `ntfs-forensic::forensic` | NTFS-TIMESTOMP (T1070.006), NTFS-ADS, NTFS-SLACK-RESIDUE, NTFS-LOGFILE-CLEARED | 🟡 timestomp only |

**Top 3 for Case-001:** the **NTFS USN rule engine** (instant attacker-tooling timeline
filter — Mimikatz/ProcDump/RDP/SDelete); container integrity (VHDX/VMDK dirty-log /
GD-mismatch — evidence-chain + unclean-shutdown); MBR/GPT wipe + hidden-volume carving.

## 5 · application artifacts (mostly unwired)

| Capability | Repo | Evidence | issen |
|---|---|---|---|
| Browser history/downloads/cookies + **deleted-record carving** + history-clearing detection | `browser-forensic` | BrowserEvent; HistoryCleared, AutoIncrementGap Findings | 🔴 unwired |
| **SQLite deleted-row carving** (free-page + WAL frames + overflow chains, severity-graded) | `sqlite-forensic` | recovered deleted rows w/ confidence + LSN snapshot | 🔴 unwired |
| SRUM per-app **user-presence** (InFocus/UserInput) + CPU/network bytes | `srum-forensic` | timeline w/ `user_present`, exfil sizing | 🟡 command-only |
| USN journal full-path rewind | `usnjrnl-forensic` | create/modify/delete/rename w/ 100 ns precision | 🟡 partial |
| EVTX + carving from unallocated (`ElfChnk` scan) | `winevt-forensic` | EventRecord + integrity Findings | 🟡 partial |
| Prefetch (MAM+SCCA) | `prefetch-forensic` | execution evidence + graded findings | 🟢 wired |
| **Apple Biome SEGB reader + anomaly analyzer** (macOS/iOS user-activity streams) | `segb-core` / `segb-forensic` | v1/v2 records (state/timestamp/CRC/protobuf) + CRC-mismatch / timestamp-order Findings | 🟢 published, 🔴 unwired |
| **per-user activity timeline merge** (shell-history + peripherals + Biome) | `useract-forensic` | one per-user activity timeline (consumes segb-core) | 🟢 published, 🔴 unwired |

**Top 3 for Case-001:** browser carving + history-clearing (delivery-mechanism timeline);
SQLite deleted-row carving (chat/cache/credential rows issen's shallow parse misses);
SRUM user-presence (human engagement vs. silent C2 beacon) wired into ingest.

## 6 · forensicnomicon (correlation knowledge issen under-uses)

| Capability | Location | Enables | issen |
|---|---|---|---|
| **playbooks** | `playbooks::{INVESTIGATION_PATHS, paths_for_trigger}` | directed artifact chains (RDP→creds→logon→exec) | 🔴 unused |
| **attack_flow** | `attack_flow::{flow_by_id, artifacts_in_flow, FlowAction}` | campaign graph → evidence artifacts | 🔴 unused |
| **eventids** | `eventids::{event_entry, events_for_artifact, high_value_events}` | EventID→description, logon-type-aware triage | 🔴 unused |
| **temporal** | `temporal::{filetime_to_unix_secs, TemporalRelation}` | timestomp / before-after-overlap | 🔴 unused |
| **persistence** | `persistence::{WINDOWS_RUN_KEYS, IFEO_PATHS, APPINIT_PATHS}` | persistence-path triage | 🔴 unused |
| mitre / sigma / yara | `mitre`, `sigma`, `yara` | technique enrichment, rule cross-ref, YARA templates | 🔴 unused |
| attack_events / lolbins / commands / ports | (various) | native event→ATT&CK, LOLBin, reverse-shell, C2 ports | 🟢 used |

**Top 3 for Case-001:** `playbooks` + `attack_flow` (artifact-driven chain reconstruction —
issen's correlation engine is hand-rolled); `eventids` (logon-type-aware 4624/4648/4672
enrichment); `persistence` paths (post-execution persistence triage).

## 7 · fleet utilities (cross-cutting, not artifact analyzers)

| Capability | Repo | Enables | issen |
|---|---|---|---|
| **fleet output-sanitization** (CSV/JSON injection + bidi guard) | `jsonguard` | RFC-4180 CSV / formula-injection guard, bidi/control stripping, serde `JsonSafe<'_>` for safe CLI/report output | 🟢 published (memf uses it; available fleet-wide) |

---

## Prioritized "wire, don't build" backlog for the Case-001 capstone

Ranked by (Case-001 leverage ÷ effort). All are EXISTING code.

1. **Force-link + discover the dark issen parsers** (usnjrnl, shellbags) and **wire SRUM
   into ingest** — pure wiring; unlocks change-journal timeline, folder-access, and
   per-app exfil sizing. (issen-only)
2. **NTFS USN rule engine** (`ntfs-forensic::rules`) on the $UsnJrnl stream — attacker-tooling
   timeline filter, zero new parsing.
3. **winreg-artifacts run_keys + userassist + sam** → 3 new ingest event streams (persistence,
   per-user execution, identity).
4. **memory: SAM hashdump + LSA secrets + cachedump** → credentialed-lateral-movement attribution.
5. **memory in-memory shimcache/prefetch/amcache** → hiding-immune execution timeline (DC + Desktop).
6. **browser-forensic + sqlite-forensic carving** → deleted browsing/chat/credential rows.
7. **forensicnomicon playbooks + attack_flow + eventids** → upgrade `issen-correlation` from
   hand-rolled rules to the shared campaign-graph / investigation-path knowledge.
8. **Container integrity analyzers** (vhdx/vmdk/qcow2 `forensic::audit`) + **winreg-carve** /
   **winreg-diff** → evidence-chain integrity + anti-forensics recovery.

*Methodology: 6 parallel read-only scans (winreg-forensic, memory-forensic, disk/container/fs,
app-artifacts, forensicnomicon, issen-internal), each cross-referencing the fleet repo's public
API against `issen`'s actual usage. Re-run when fleet crates change.*
