# NTFS Timestomping Detection and Its False-Positive Problem

*Research memo — 2026-06-09. Author: DFIR research. Drives the redesign of `detect_timestomp`.*

---

## Executive Summary

**BLUF — our current rule is not sound as a finding generator. `$SI.created < $FN.created` (minus a tolerance) is the single noisiest, lowest-precision timestomp heuristic in the literature, and on its own it should be downgraded from "finding" to "weak signal."** The single biggest benign cause is **ordinary file copy**: copying a file preserves the source's `$SI` creation/modification time onto the destination, while the destination's `$FN.created` is stamped at copy time — producing exactly `$SI.created < $FN.created` with no tampering whatever. Archive extraction (7-Zip, cab, MSI, installers, `tar`/`unzip`), `robocopy /COPY:T`, backup/restore, and NTFS file-system *tunnelling* all reproduce the same signature.

What the field actually does:

- **No serious tool treats `$SI < $FN` as proof.** Magnet, Velociraptor and Mandiant all frame it as a *lead/starting point* requiring corroboration. Velociraptor's own docs state plainly that "timestomping detections are not very reliable" because "a lot of programs set file timestamps … into the past by design."
- The **more robust ordering test** practitioners cite is `$SI.modified < $FN.created` (a file modified *before its own name record was created* is hard to produce benignly), but it is **not immune** to copy/archive cases either.
- **Sub-second (100 ns) zeroing** of `$SI` is a useful *corroborating* signal against naive tools (Metasploit/`timestomp.exe`/Cobalt Strike write whole-second values), but it is **defeated by nTimestomp/SetMACE** (which write 100 ns precision) and can be produced benignly. It is a booster, never a sole trigger.
- The heuristic rests on **two documented fallacies** (Lina Lau / inversecos): that `$FN` cannot be stomped (it can — rename/move copies `$SI`→`$FN`; SetMACE writes `$FN` directly), and that tools cannot fake nanoseconds (they can).
- The **highest-confidence corroboration is cross-artifact**: the `$LogFile`, `$UsnJrnl:$J`, `$I30` slack, PE compile time, ShimCache/Amcache. Issen already parses `$UsnJrnl`/`$LogFile` (usnjrnl-forensic) — that is the correct place to raise confidence.

**Recommendation:** replace the single-comparison boolean with a **layered, confidence-graded detector**. Require an ordering anomaly **AND** at least one independent corroborator (sub-second zeroing, USN/LogFile contradiction, or PE/ShimCache contradiction) before emitting a Medium+ finding; emit ordering-only hits as `Info`/`Low` leads. Exclude the documented benign signatures (copy pattern, tunnelling window, known system/installer paths). To implement this we must surface several fields we currently drop (all four `$SI` MACE values on one event, both `$FN` attributes, the raw 100 ns sub-second component, and a USN/LogFile cross-check). Details in *Recommended algorithm*.

> **Update — adversarial review (Codex critic, §6).** This memo was critiqued; several claims below are corrected or softened there and §6 takes precedence on conflict. The load-bearing corrections: (1) the file-copy mechanism is **modified-time**, not necessarily creation-time, so the robust benign pattern is `$SI.modified < $FN.created` (not `$SI.created < $FN.created`); (2) the §5.2 "suppress entirely" **gates are dangerous as hard filters** (`\Windows\Temp\`/`$Recycle.Bin` are evasion locations; an attacker can set `$SI.modified < $SI.created` to trip the "copy" gate) — they must become **confidence *modifiers*** that never override strong USN/`$LogFile` corroboration; (3) **never fully discard** a hit — emit it as a lead; (4) PE-compile-time and USN are softened from "High/foolproof" to corroborators requiring identity correlation (MFT ref **+ sequence number**). Read §6 with §2 and §5.

---

## 1. The canonical $SI vs $FN heuristics

NTFS stores two timestamp sets per MFT record: `$STANDARD_INFORMATION` (`$SI`, attribute type `0x10`) and `$FILE_NAME` (`$FN`, type `0x30`), each holding four MACE/MACB values (Modified, Accessed, MFT-Changed, Born/Created). Records with both a long and short name carry **two** `$FN` attributes, i.e. up to 8 `$FN` timestamps; the parent directory's `$I30` index also caches 4 more. `$SI` is writable from user mode via `SetFileTime`/`NtSetInformationFile`; `$FN` is normally written only by the kernel on **create / rename / move / hardlink**, and (critically) **not on ordinary content modification**. (Confirmed — Velociraptor NTFS docs; inversecos; MS *File Times*.)

### 1.1 `$SI.created < $FN.created` — our current rule

The textbook rule. Rationale: a naive `SetFileTime` stomp rewinds `$SI` but leaves `$FN` at the true creation time, so `$SI.created` lands before `$FN.created`. (Confirmed — Velociraptor NTFS docs: *"find files which have `$STANDARD_INFORMATION` times earlier than the `$FILENAME` times … if the API is used to send the timestamps backwards the `$STANDARD_INFORMATION` timestamps will appear earlier"*.)

**Reliability: low in isolation.** Velociraptor's documentation, immediately after describing the rule, warns it is "not very reliable" (§4). The DFRWS study by Palmbach & Breitinger ("Artifacts for Detecting Timestamp Manipulation in NTFS on Windows and Their Reliability", *FSI:DI* 32 (2020) 300920) is the academic anchor: comparing `$SI`/`$FN` detects naive stomping but is bypassable and noisy, and the `$LogFile`/`$UsnJrnl` are the more reliable artifacts. **Verdict: keep as a *trigger candidate*, not a finding.** (Confirmed.)

### 1.2 `$SI.modified < $FN.created` — the more-robust ordering test

Semantically stronger: a file whose **content was last modified before its own name record was even created** is anomalous, because in normal life a file is named at/after creation and modified at/after that. (Inferred from inversecos + Palmbach/Breitinger reasoning; the comparison is standard practitioner lore but I did not find a single canonical primary source asserting it is *impossible* benignly — treat as "more robust, not immune.") **Contested/inferred.** Note the important benign counterexample: **copy inherits `$SI.modified` from an older source**, so a freshly-copied old file routinely has `$SI.modified` far earlier than its new `$FN.created`. This test narrows but does **not** eliminate the copy false positive.

### 1.3 Sub-second / 100 ns precision zeroing in `$SI`

NTFS stores time as 100 ns ticks since 1601-01-01 UTC. Many stomp tools (Metasploit `timestomp`, `timestomp.exe`, Cobalt Strike, PowerShell `SetCreationTime`) write **whole-second** values, zeroing the sub-second field; `$FN` retains true 100 ns granularity. Analysts are "taught to spot 0s in the millisecond/nanosecond position." (Confirmed — nTimetools README; inversecos; Magnet.)

**Reliability: moderate as a corroborator, poor as a sole trigger.**
- **Defeated by precision-aware tooling:** nTimestomp and SetMACE write full 100 ns `$SI` (and SetMACE `$FN`) values. nTimetools explicitly markets "blend in on cursory inspection." (Confirmed — nTimetools README; inversecos "Myth 2".)
- **False positives:** legitimate timestamps *can* land on a whole second (e.g. some API/format round-trips, archive-stored times). Whole-second `$SI` is "a *potential* indicator," per Magnet/Velociraptor, never dispositive.

### 1.4 Attribute-pair (like-with-like) comparisons

Compare same-named values across attributes: `$SI.created` vs `$FN.created`, `$SI.modified` vs `$FN.modified`, etc., plus intra-`$SI` ordering. AnalyzeMFT's accepted FP fixes (PRs surfaced in SIFT issue #241) added exactly such like-with-like and intra-`$SI` tests:
- file-copy flag: `$SI.created > $SI.modified` (born after last-modified — a copy tell),
- volume-move flag: `$SI.accessed > $SI.created && $SI.accessed > $SI.modified`,
- narrowed the `$SI`/`$FN` shift to fire **only** when `$SI.created < $FN.created` (previously also fired when the first `$FN` was absent — "resulted in a few false positives"),
- fixed the nanosecond check to read `$SI.created` not `$FN.created`.

(Confirmed — teamdfir/sift issue #241, quoting accepted analyzeMFT PRs by `mpilking`.) **Takeaway:** the canonical practitioner suite is a *panel* of comparisons, several of which exist specifically to *recognise and suppress* benign copy/move patterns.

### 1.5 Can `$FN` itself be stomped? (does the heuristic break?)

Yes, two ways (inversecos "Myth 1"):
- **Method 1 — direct `$FN` write** on pre-PatchGuard OSes (or via SetMACE writing `$FN` values directly). SetMACE is cited by inversecos as *an* example of a tool that can alter `$FN` (the "only tool" phrasing is **not** in the source — see §7.5 — and is time-sensitive; do not encode it).
- **Method 2 — rename/move abuse on any OS:** Windows **copies `$SI`→`$FN` when a file is renamed or moved.** So an attacker stomps `$SI`, then renames the file (and optionally back) — Windows propagates the forged `$SI` into `$FN`, and `$SI`/`$FN` now *agree* on the fake time, defeating the comparison. (Confirmed — inversecos; Velociraptor docs.)

This cuts both ways: it is an **evasion** (false negatives) *and* the mechanism behind several **false positives** (any legitimate rename/move propagates `$SI` into `$FN`). It is the core reason `$FN` is **not** ground truth and why USN/`$LogFile` corroboration is needed.

---

## 2. False-positive taxonomy (the centerpiece)

Every entry below produces `$SI` older than `$FN` (or a related "anomaly") with **no tampering**. Each is documented.

### 2.1 File copy — the dominant FP

Copying preserves the source file's `$SI` **created and modified** times onto the destination, while the destination's `$FN.created` is set to the **copy time**. Result: `$SI.created < $FN.created` *and* `$SI.modified < $FN.created` — the exact stomp signature, entirely benign. AnalyzeMFT added an explicit "possible file copy" flag (`$SI.created > $SI.modified`) precisely to label this. (Confirmed — SIFT issue #241; cyberengage; community demonstrations.) **This is the headline cause and must be excluded.**

### 2.2 Archive / zip extraction, installers, MSI, package managers

Archivers restore the **archive-stored** modification time onto extracted files; the new `$FN.created` is extraction time → `$SI` older than `$FN`. Velociraptor's docs name this directly: *"a lot of programs set file timestamps after creating them into the past **by design** — mostly archiving utilities like 7zip or cab will reset the file time to the times stored in the archive."* Applies to 7-Zip, cab/MSI, `tar`/`unzip`, many installers and package managers. (Confirmed — Velociraptor NTFS docs.) MITRE notes Stuxnet "extracts and writes driver files that match the times of other legitimate files" — same mechanism, weaponised, but the benign version is ubiquitous. (Confirmed — MITRE T1070.006.)

### 2.3 NTFS file-system tunnelling (the 15-second cache)

When a name is removed from a directory (delete/rename) its creation time + short/long name pair are cached, keyed by name, for a default **15 seconds**; if a file with the same name is recreated in the same directory within that window, the **old creation time is resurrected**. Designed to preserve creation time across the "safe save" pattern (write temp, delete original, rename temp→original) used by editors. A recreated file thus shows an *old* `$SI`/`$FN.created` against newer modification — and intra-record ordering can look anomalous. Tunnelling applies to **FAT and NTFS** (KB172190 names only these two; **not** exFAT — see §7.6). Config: `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem` → `MaximumTunnelEntries`, `MaximumTunnelEntryAgeInSeconds` (default 15; absence of these values = defaults). (Confirmed — Microsoft KB172190 [archived]; Raymond Chen, *The apocryphal history of file system tunnelling*.)

### 2.4 Legitimate `SetFileTime` callers

Many benign tools call the same API attackers use:
- **`robocopy /COPY:T`, `xcopy /K`, `rsync -t`, `cp --preserve=timestamps`** — explicitly replicate source mtimes.
- **Backup/restore** (Windows Backup, third-party) restores original timestamps.
- **Git** does **not** preserve mtimes on checkout (sets to checkout time), but **build tools, CI, and `tar`-based deployments** do.
- **Browsers / downloaders** may set the "Last-Modified" HTTP header time on downloaded files.
- **Cloud sync clients** (OneDrive, Dropbox, etc.) replicate server timestamps.

(Confirmed for the existence of legitimate `SetFileTime` use — cyberengage; MITRE notes "legitimate reasons"; tool flags are documented in their respective man pages. Specific per-tool timestamp effects are *inferred* from documented behaviour and should be baselined empirically per environment.)

### 2.5 `$FN` update semantics — the structural FP source

`$FN` timestamps update **only on create / rename / move / hardlink — never on ordinary content modification.** Therefore for **any normally-edited file**, `$SI.modified` (and often `$SI.accessed`, `$SI.mft_changed`) legitimately diverge from the frozen `$FN` values; `$FN.created` stays at true birth while `$SI` advances. A rule that flags *any* `$SI`≠`$FN` divergence (rather than the specific `<` ordering) fires on essentially every active file. (Confirmed — Velociraptor docs; inversecos; MS File Times.) **Implication:** never flag on `created_mismatch` (`$SI.created != $FN.created`) alone — inequality is the normal state after any copy/restore; only a specific *ordering* anomaly is even a candidate.

### 2.6 System/OS files, Windows Update, in-place upgrades, VSS

OS servicing stages files with vendor-set timestamps: Windows Update/WinSxS components, in-place upgrades, and volume restores commonly land files whose `$SI` predates their on-disk `$FN.created`. Volume Shadow Copy restores and image deployments reintroduce old `$SI` onto freshly-created records. (Inferred from the same copy/restore mechanism §2.1/§2.4; widely reported in practitioner discussion. Treat `C:\Windows\WinSxS`, `\Windows\servicing`, `\Windows\Installer`, `\$Recycle.Bin` as high-FP paths.)

---

## 3. What real tools/detections do to suppress FPs

| Tool / source | Core logic | FP suppression / framing |
|---|---|---|
| **Eric Zimmerman MFTECmd** | Parses `$MFT`; emits both `$SI` and `$FN` MACE columns + an `SI<FN` style boolean so the analyst eyeballs the comparison. | Surfaces data, **does not auto-verdict**; the analyst corroborates. (Confirmed — MFTECmd README/usage.) |
| **AnalyzeMFT** (dkovar / rowingdude) | Panel of checks incl. `$SI<$FN` shift, nanosecond-zero, intra-`$SI` ordering. | Accepted PRs (SIFT #241) **narrowed** the `$SI`/`$FN` shift to fire only on `$SI.created<$FN.created`, fixed the nanosecond check to read `$SI`, and **added explicit benign labels** for file copy (`$SI.created>$SI.modified`) and volume move (`$SI.accessed>created&modified`). (Confirmed.) |
| **Velociraptor** `Windows.NTFS.Timestomp` (Matt Green / @mgreen27) | `$SI."B"<$FN."B"` **AND** `$SI."B"/"M"` sub-second component is **zero** (`USecZeros` — verified against the Go source, §7.2; this *agrees with* our S3 zeroing design); **plus** PE compile-time < any `$SI`; **optional** `$SI."M"`<ShimCache, `$SI`<`$I30`-slack "B"/"M". Uses `Created0x10/0x30` etc. | **Conjunction of independent signals**, not a single comparison. Docs explicitly warn detections are "not very reliable" because archivers reset times "by design." (Confirmed — Velociraptor exchange artifact + NTFS docs.) |
| **Magnet AXIOM** "NTFS Timestamp Mismatch" | `$SI` earlier than `$FN` (the blog states **no** precision threshold — the earlier "whole-millisecond" wording is unverified, §7.4). | Framed as a **"starting point," not proof**; docs explicitly state "there could be legitimate reasons from normal system behavior" and link MITRE on circumvention. (Confirmed — Magnet blog.) |
| **Mandiant / SANS** | Include `$FN` (`MACB`) times in the **super-timeline**; corroborate `$SI` anomalies against other events. | The classic SANS 2010 case (Dave Hull) shows the **timeline as a whole**, not a single mismatch, establishes manipulation. (Confirmed — SANS DFIR blog.) |
| **inversecos (Lina Lau)** | Demonstrates both heuristics are "trivial to bypass." | Recommends `$UsnJrnl:$J` + `$LogFile` as the **"more foolproof"** corroboration (FILE_CREATE/RENAME_OLD/RENAME_NEW records contradict forged MFT times). (Confirmed.) Lau's NTFS/timestomp work is the most-cited primary write-up and is the technique the team recalled as "CyberCX-pioneered." |
| **Attacker side: SetMACE / nTimestomp / EvilClippy** | SetMACE writes `$FN` directly and via rename; nTimestomp writes 100 ns `$SI`. | Establish that **both** naive heuristics are defeatable → detection must not rely on them alone. (Confirmed — nTimetools; inversecos; DFRWS keyword set.) |

**Common pattern:** every mature detector either (a) presents raw `$SI`/`$FN` for human judgement, or (b) **requires a conjunction** (ordering + nanosecond + an independent artifact such as PE/ShimCache/`$I30`/USN), and (c) **labels benign copy/move patterns explicitly**. None ships `$SI.created < $FN.created` alone as a finding.

---

## 4. Practitioner commentary about false alerts

- **Velociraptor docs (Velocidex):** "Although it might appear to be a solid detection of timestomping, generally timestomping detections are not very reliable. It turns out that a lot of programs set file timestamps after creating them into the past by design — mostly archiving utilities like 7zip or cab will reset the file time to the times stored in the archive." (Confirmed — primary, the bluntest statement in the corpus.)
- **AnalyzeMFT / SIFT issue #241:** the `stf-fn-shift` logic "also alerted [when] the first `$FN` entry is not present. This resulted in a few false-positives" — fixed by narrowing to `$SI.created < $FN.created`; new flags added to *recognise* copies and volume moves rather than mis-call them stomps. (Confirmed — primary maintainer/PR commentary.)
- **Magnet Forensics:** "there could be legitimate reasons from normal system behavior that could cause this mismatch" — artifact is a "starting point," not proof. (Confirmed.)
- **inversecos (Lina Lau):** the two taught methods rest on "two fallacies"; "it's almost trivial to bypass these two detection mechanisms." (Confirmed.)
- **cyberengage:** "There might be false positives while analyzing the `$MFT` for timestomping — this must be understood by analysts." (Confirmed.)

(Forum/Reddit/X threads echo the same "copies and archives make `$SI<$FN` noisy" complaint; the primary-source statements above are stronger and are cited in preference, consistent with our discipline of preferring primary sources over forum SEO.)

---

## 5. Recommended algorithm for OUR detector

Replace the single boolean with a **layered, confidence-graded** evaluation. The output is a confidence grade, not a boolean.

### 5.1 Inputs (what we must surface — see §5.4)

Per FileCreate/MFT event for one record: all four `$SI` MACE (`si_created, si_modified, si_accessed, si_mft_changed`), all four `$FN` MACE for **each** `$FN` attribute (long + short), the **raw 100 ns ticks** (not truncated to seconds), the full path, and — where Issen has it — the USN/`$LogFile` create/rename events for the same MFT reference.

### 5.2 Stage A — gate (cheap exclusions; suppress before scoring)

Suppress entirely (do **not** emit) when:
1. **Copy pattern:** `si_created > si_modified` (born-after-modified ⇒ copy/restore). *(AnalyzeMFT-style benign label.)*
2. **Volume-move pattern:** `si_accessed > si_created && si_accessed > si_modified`.
3. **Known high-FP path** (allow-list, case-insensitive): `\Windows\WinSxS\`, `\Windows\servicing\`, `\Windows\Installer\`, `\Windows\SoftwareDistribution\`, `\$Recycle.Bin\`, `\Windows\Temp\`, package-manager caches.
4. **Tunnelling window:** if USN/`$LogFile` shows a delete+recreate of the same name in the same directory within ~15 s (or `MaximumTunnelEntryAgeInSeconds` if surfaced from the registry), suppress.

### 5.3 Stage B — score (only records that pass the gate)

Compute independent signals; combine for confidence. **Never** emit on a single ordering signal.

- **S1 ordering (weak):** `si_created < fn_created - tolerance`. *(our current rule)*
- **S2 ordering (stronger):** `si_modified < fn_created - tolerance` (content modified before its name record existed).
- **S3 sub-second zeroing:** `si_created` and/or `si_modified` have **zero** 100 ns sub-second component **while** the corresponding `$FN` value does not. *(corroborator only.)*
- **S4 PE contradiction (if PE):** PE compile timestamp **>** any `$SI` time (file claims to predate its own code). *(Velociraptor's strongest single add-on.)*
- **S5 cross-artifact contradiction (strongest):** USN/`$LogFile` FILE_CREATE/RENAME for this MFT ref disagrees with `$SI` by more than tolerance. *(inversecos' "more foolproof" method; we already parse these.)*
- **S6 `$I30`/ShimCache/Amcache contradiction:** `$SI` earlier than `$I30`-slack born/modified, or `$SI.modified` < ShimCache time. *(optional, if available.)*

**Confidence grading (maps to `forensicnomicon::report::Severity`):**

| Condition | Grade |
|---|---|
| Passed gate **and** S5 fires (USN/LogFile contradiction), or S4 fires | **High** (`Severity::High`) — "strongly consistent with timestomping" |
| (S1 or S2) **AND** S3 (ordering + nanosecond zeroing) | **Medium** — "consistent with timestomping by a whole-second tool" |
| S2 alone (modified-before-name) | **Low** — lead; "anomalous ordering, benign causes not excluded" |
| S1 alone (`$SI.created < $FN.created`) | **Info** lead, **or suppress** in noisy contexts — explicitly *not* a Medium+ finding |

All findings carry `ExternalRef::mitre_attack("T1070.006")` and **"consistent with," never "confirms."** Note in the `note` which benign causes were *not* excludable (e.g. "copy pattern not present, but archive extraction cannot be ruled out without USN corroboration").

### 5.4 Extra fields we must surface (gap analysis vs. current state)

Today we surface only `$SI.created` on the FileCreate event plus `fn_created/fn_modified/fn_accessed/fn_mft_modified`; the other three `$SI` values live as *separate* timeline events. That is insufficient for the algorithm above. We need, **on the same event object**:

1. **All four `$SI` MACE values together** (`si_modified, si_accessed, si_mft_changed` alongside `si_created`) — required for the copy/volume-move gates (S-A1/A2) and S2. *(Highest priority — without this we cannot even run the FP gate.)*
2. **Raw 100 ns sub-second component** of each `$SI` and `$FN` value (don't truncate to seconds) — required for S3.
3. **Both `$FN` attributes** (long *and* short name), each with its four MACE — short-name `$FN` is sometimes the only un-propagated copy after a rename.
4. **Full path** on the event — required for the path allow-list gate (A3).
5. **USN/`$LogFile` cross-reference** for the MFT entry (create/rename records + timestamps) — required for the tunnelling gate (A4) and the High-confidence corroborator (S5). Issen already parses these via usnjrnl-forensic; the work is *wiring the correlation*, not new parsing.
6. *(Optional, later)* PE compile time (S4) and ShimCache/Amcache/`$I30`-slack (S6) for the strongest tiers.

### 5.5 One-paragraph summary of the new logic

Gate out copies (`SI.created>SI.modified`), volume moves (`SI.accessed` newest), known servicing/installer paths, and the 15 s tunnelling window. Then score the surviving records on independent signals — `SI.created<FN.created` (weak), `SI.modified<FN.created` (stronger), nanosecond-zeroing, PE-compile contradiction, and USN/`$LogFile` contradiction — and **only** emit Medium+ when an ordering anomaly is joined by an independent corroborator; ordering-alone becomes an Info/Low lead. Grade confidence accordingly and always phrase findings as "consistent with T1070.006," never as proof.

---

## References (hotlinked; confidence-marked)

**Primary — Microsoft / format authority**
- Microsoft, *File Times* (Win32 SysInfo). https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times — *Confirmed.*
- Microsoft KB172190, *Windows NT Contains File System Tunneling Capabilities* (archived). https://web.archive.org/web/20160410012540/https://support.microsoft.com/en-us/kb/172190 — *Confirmed (via archive; live MS URL 404s).*
- Raymond Chen, *The apocryphal history of file system tunnelling*, The Old New Thing. https://devblogs.microsoft.com/oldnewthing/20050715-14/?p=34923 — *Confirmed.*

**Primary — tools (detection)**
- Velociraptor, *NTFS Analysis* (incl. the "not very reliable / 7zip / cab" caveat). https://docs.velociraptor.app/docs/forensic/filesystem/ntfs/ — *Confirmed.*
- Velociraptor Exchange, *Windows.NTFS.Timestomp* (Matt Green / @mgreen27). https://docs.velociraptor.app/exchange/artifacts/pages/timestomp/ — *Confirmed.*
- Velociraptor `Timestomp.yaml` source. https://github.com/Velocidex/velociraptor-docs/blob/master/content/exchange/artifacts/Timestomp.yaml — *Confirmed (artifact present; full VQL on page).*
- Eric Zimmerman, *MFTECmd*. https://github.com/EricZimmerman/MFTECmd — *Confirmed.*
- AnalyzeMFT (dkovar; active fork rowingdude). https://github.com/dkovar/analyzeMFT and https://github.com/rowingdude/analyzeMFT — *Confirmed.*
- teamdfir/SIFT issue #241 (analyzeMFT FP fixes: copy/volume-move flags, narrowed `$SI<$FN`, nanosecond fix). https://github.com/teamdfir/sift/issues/241 — *Confirmed (primary maintainer/PR commentary).*

**Primary — attacker tooling**
- Benjamin Lim, *nTimetools / nTimestomp* (100 ns `$SI` stomping; "blend in"). https://github.com/limbenjamin/nTimetools — *Confirmed.*

**Primary — vendor / research**
- Magnet Forensics, *Expose Evidence of Timestomping with the NTFS Timestamp Mismatch Artifact* ("starting point," "legitimate reasons"). https://www.magnetforensics.com/blog/expose-evidence-of-timestomping-with-the-ntfs-timestamp-mismatch-artifact-in-magnet-axiom-4-4/ — *Confirmed.*
- Lina Lau (inversecos), *Defence Evasion Technique: Timestomping Detection – NTFS Forensics* (the two "myths"; rename `$SI`→`$FN`; USN/`$LogFile` corroboration). https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html — *Confirmed. (The "CyberCX-pioneered" technique the team recalled.)*
- Palmbach & Breitinger, *Artifacts for Detecting Timestamp Manipulation in NTFS on Windows and Their Reliability*, FSI:DI 32 (2020) 300920 (DFRWS). https://dfrws.org/wp-content/uploads/2020/05/Artifacts-for-Detecting-Timestamp-Manipulati_2020_Forensic-Science-Internati.pdf · DOI 10.1016/j.fsidi.2020.300920 — *Confirmed (metadata + abstract verified; treat detailed experimental tables as the authoritative academic reliability source).*
- SANS DFIR, Dave Hull, *Digital Forensics: Detecting time stamp manipulation* (2010; `$FN` in super-timeline). https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation — *Confirmed.*
- MITRE ATT&CK T1070.006 *Indicator Removal: Timestomp* (procedure examples incl. Stuxnet matching legit file times). https://attack.mitre.org/techniques/T1070/006/ — *Confirmed.*
- cyberengage, *The Truth About Changing File Timestamps: Legitimate Uses and Anti-Forensics* ("there might be false positives … this must be understood"). https://www.cyberengage.org/post/anti-forensics-timestomping — *Confirmed.*

**Secondary / corroborating (tunnelling explainers)**
- Senturean/Forensixchange, *File System Tunneling in Windows* (registry keys, 15 s default). https://www.senturean.com/posts/19_04_13_windows-file-system-tunneling/ — *Inferred (mirror; cert/spam issues on one host — content corroborates KB172190).*

*Confidence key: **Confirmed** = verified against primary source this session; **Inferred** = consistent with primary sources but not directly asserted by one; **Contested** = sources disagree or claim is practitioner lore without a single authoritative anchor.*

---

## 6. Codex adversarial critique & reconciled design

An adversarial critic (Codex) reviewed §1–§5. Its findings correct real errors and harden the algorithm. **On any conflict, this section governs.**

### 6.1 Corrections to the body (errors / overstatements)

1. **File-copy mechanism (corrects §2.1 / Exec-Summary).** Ordinary Windows copy commonly preserves the source **modified** time, not necessarily **creation** time — and it conflicts with the AnalyzeMFT copy heuristic (`$SI.created > $SI.modified`). The robust benign signature is **`$SI.modified < $FN.created`**, while `$SI.created < $FN.created` depends on the tool/API restoring creation time. *Net: our current rule keys on the weaker of the two copy tells.*
2. **`$FN` update semantics (corrects §1, §2.5).** Drop "never": say *"normally not updated by ordinary content writes; updated by name/namespace operations (create/rename/move/hardlink)."* Behaviour varies by attribute, namespace, and operation.
3. **Rename → `$FN` propagation (corrects §1.5).** Not categorical. **Cross-volume "move" is a copy-delete, not a rename**; same-volume rename *can* refresh `$FN` from `$SI` in documented cases; multiple `$FN` attributes can diverge. Avoid "any/always."
4. **PE compile-time (corrects §5.3 S4).** Linker-controlled — routinely zeroed, reproducible-build-normalised, packed, or timezone-misread. **S4 is Medium alone**, High only with S1/S2 + S3 or USN.
5. **USN/`$LogFile` "foolproof" (corrects §1, §5.3 S5).** Can roll over, be disabled, sparse, or ambiguous under **MFT reference reuse**. High **only** when correlated to the same MFT reference **and sequence number** and path — absence/scope gaps handled explicitly.
6. **Sub-second zeroing (corrects §1.3 / S3).** Medium may be too high in archive/installer contexts (ZIP/cab store coarse times; many APIs round to the second). Score higher only when **multiple `$SI` MACE are all exact-second while the corresponding `$FN` retain 100 ns precision**.

### 6.2 The decisive design change — gates → modifiers, never discard

The §5.2 "suppress entirely" gates are **attacker-controllable blind spots**: `\Windows\Temp\` and `$Recycle.Bin` are common staging/evasion locations, and an attacker can set `$SI.modified < $SI.created` to trip the "copy" suppression. Reconciled rules:

- **Every gate becomes a confidence *modifier*, not a hard filter.** Copy-pattern, volume-move, high-FP path, and tunnelling-window *lower* confidence — they never suppress a hit that has strong independent corroboration (S5 USN/`$LogFile`, or S4+others).
- **Never fully discard a hit — emit it as a lead.** Losing the record loses the forensic chain. The invariant the redesign must hold (and TDD must assert):
  - `S1` alone → **Info** lead.
  - `S1` **+** copy-pattern/path modifier → still **emitted** (Info, "benign-context"), *not dropped*.
  - `S1` **+** `S5` (USN/`$LogFile` contradiction) → **High** *regardless* of any benign modifier or path.
- **`S2` (`$SI.modified < $FN.created`) is Low by default** — copy/archive/extraction produce it trivially; raise only when copy/archive context is excluded *and* another signal fires.
- **Path = weight, not allow-list.** Downweight only when paired with benign provenance (trusted signer, servicing transaction, package metadata, matching USN install activity). Unsigned executables/scripts in writable/staging paths get **no** path suppression.
- **USN reason-code correlation** beats bare timestamp compare: use `FILE_CREATE`, `RENAME_OLD_NAME`, `RENAME_NEW_NAME`, `BASIC_INFO_CHANGE`, `DATA_EXTEND`. A `$SI` change shortly after `BASIC_INFO_CHANGE` is more suspicious than an MFT-only comparison.
- **Both `$FN` attributes (long + short) compared separately** — divergence between them after a rename is itself a signal; don't collapse to the first `$FN`.

### 6.3 Claims to web-verify before encoding tool-specific logic

Do **not** hard-code these until confirmed against the live source:
- AnalyzeMFT PR history in SIFT #241 (copy/volume-move flags, narrowed `$SI<$FN`, nanosecond fix) — specific implementation history.
- Velociraptor `Windows.NTFS.Timestomp` exact VQL — **Codex flags its "has nanosecond precision" condition may read *opposite* to our S3 "zeroing"; confirm the comparison direction.**
- Magnet "whole-millisecond" (possible paraphrase of sub-second/nanosecond).
- MFTECmd's exact `SI<FN` column name/semantics.
- inversecos "SetMACE is currently the only tool offering `$FN` modification" — time-sensitive, likely stale by 2026.
- KB172190 specifics (exFAT coverage; `MaximumTunnelEntries`/`MaximumTunnelEntryAgeInSeconds`, 15 s default).
- "CyberCX-pioneered" — attribution-by-memory; the verifiable primary write-up is inversecos. Do not assert CyberCX without a citation.

### 6.4 Reconciled implementation sequence (strict TDD)

1. **Now — downgrade the current single-event detector** from `High` to a `Low`/`Info` lead with a "benign causes (copy/archive/tunnelling) not excluded — corroboration required" note. This is all our present single-event data (`$SI.created` + `$FN` MACE) supports, and it stops the false **High** alerts immediately. *(Grounded; no must-verify dependency.)*
2. **Surface the missing fields** (extend C1): all four `$SI` MACE + raw 100 ns sub-second components + full path + both `$FN` attributes, on the same `FileCreate` event.
3. **Layered scorer** with copy/volume-move/path as **modifiers** (not gates), `S2` Low, `S3` sub-second (multi-value), graded per §6.2.
4. **USN reason-code correlation** (S5) keyed on MFT ref **+ sequence number** for the High tier — wiring `usnjrnl-forensic`, not new parsing.
5. Web-verify §6.3 before encoding any tool-specific comparison.

---

## 7. Source verification (claim-by-claim)

*Web-verification pass — 2026-06-09. Every verdict clicked through to the live primary source and confirmed against the actual content (no fake 200s). Where the source is code, the ground-truth expression is quoted, not paraphrased.*

### Summary table

| # | Claim | Verdict | Correction (if any) |
|---|---|---|---|
| 1 | AnalyzeMFT FP fixes (SIFT #241, `mpilking`) | **CONFIRMED** | — |
| 2 | Velociraptor `Windows.NTFS.Timestomp` VQL logic/direction | **PARTLY** | Prose "has nanosecond precision" is the **inverse** of the code: the flag (`USecZeros`) fires on **ZEROED** sub-seconds, not on present precision. Direction of `$SI<$FN` confirmed. |
| 3 | Velociraptor "not very reliable" caveat | **CONFIRMED** | — |
| 4 | Magnet "whole-millisecond" + framing | **PARTLY** | Framing CONFIRMED verbatim; the **"whole-millisecond" precision wording is UNVERIFIABLE** — the blog never states a millisecond/sub-second threshold. |
| 5 | inversecos "SetMACE only tool for `$FN`" + two myths | **PARTLY** | Two myths + rename `$SI`→`$FN` CONFIRMED. The exact phrase **"currently the only tool offering `$FN` modification" is NOT in the article** — inversecos names SetMace as *a* tool, not *the only* one; treat as unsupported/time-sensitive. |
| 6 | MS file-system tunnelling (KB172190) | **PARTLY** | 15 s default, both registry value names, `Control\FileSystem` path all CONFIRMED. **exFAT is REFUTED** — KB172190 scopes tunnelling to **FAT and NTFS only**; exFAT is not mentioned. |
| 7 | "CyberCX-pioneered" attribution | **PARTLY / REFUTED-as-stated** | A real CyberCX primary source exists, but it is **USN Journal *Rewind* (path reconstruction)**, *not* a timestomp `$SI/$FN` technique. The canonical timestomp write-up remains inversecos. |

> **Loud callout — claim #2 changes detector logic.** The Velociraptor signal our memo cites as "`$SI` has nanosecond precision" is, in the actual code, the **opposite**: the `USecZeros` column is `True` when `$SI` sub-seconds are **zeroed**. This *agrees with* our S3 "sub-second zeroing" design — but the §3 table's wording ("`$SI."B"/"M"` has nanosecond precision") must be corrected to "`$SI` 'B'/'M' sub-second component is **zero**," or it inverts the signal. See claim #2 below for the quoted Go source.

---

**Claim 1 — AnalyzeMFT FP fixes (SIFT #241). Verdict: CONFIRMED.**
Source: [github.com/teamdfir/sift/issues/241](https://github.com/teamdfir/sift/issues/241) (opened by `mpilking`, 19 Mar 2018).
The issue body lists exactly the four fixes the memo attributes to it, verbatim: *"1. Fixed nanosecond anomaly check so it looks at the $SI create time instead of $FN create time. 2. Added new checks to flag possible file copies ($SI create time > $SI modify time) & volume moves ($SI access time > $SI create time & $SI modify time). 3. Narrowed stf-fn-shift logic so it only flags when $SI create time < $FN create time (previously it also alerted with … the first $FN entry is not present). This resulted in a few false-positives."* (The PRs themselves were merged into the AnalyzeMFT repo; the issue is the maintainer-facing record of them.)

**Claim 2 — Velociraptor `Windows.NTFS.Timestomp` VQL. Verdict: PARTLY (one inversion).**
Sources: [artifact page](https://docs.velociraptor.app/exchange/artifacts/pages/timestomp/) · [Timestomp.yaml](https://github.com/Velocidex/velociraptor-docs/blob/master/content/exchange/artifacts/Timestomp.yaml) · ground-truth column definitions in [go-ntfs `parser/mft.go`](https://github.com/Velocidex/go-ntfs/blob/master/parser/mft.go).
The artifact's three core checks (description): *"$STANDARD_INFORMATION 'B' time prior to $FILE_NAME 'B' time; $STANDARD_INFORMATION 'B' or 'M' time has nanosecond precision; PE compile time prior to any $STANDARD_INFORMATION time stamp."* The YAML surfaces these via columns `SI_Lt_FN` (aliased `SI<FN`) and `USecZeros`, which are **computed in the `parse_mft` plugin**, not the YAML. The Go ground truth:
- **(a) `$SI`-vs-`$FN` direction — CONFIRMED:** `row.SI_Lt_FN = row.Created0x10.Before(row.Created0x30)` — i.e. fires when `$SI.created` is **earlier than** `$FN.created` (`0x10` = `$SI`, `0x30` = `$FN`). Matches our S1.
- **(b) precision/zeroing test — INVERTED in our prose:** `row.USecZeros = row.Created0x10.Unix()*1000000000 == row.Created0x10.UnixNano() || row.LastModified0x10.Unix()*1000000000 == row.LastModified0x10.UnixNano()`. `Unix()*1e9` (whole seconds in ns) equals `UnixNano()` (full precision) **only when the sub-second component is zero**. So the flag is `True` ⇔ **`$SI` created or last-modified sub-seconds are ZEROED** — the artifact flags the *absence* of sub-second precision, in **`$SI`** (`0x10`), not `$FN`. The memo's phrase "has nanosecond precision" describes the human-readable *check name* but reads opposite to what the column computes. This **agrees with** our S3 zeroing design; the §3 wording must be corrected (see callout).
- **(c) PE compile-time test — CONFIRMED:** `SuspiciousCompileTime` fires when any `$SI` stamp is **earlier than** `PE.FileHeader.TimeDateStamp`: `LastModified0x10 < PE.FileHeader.TimeDateStamp OR LastAccess0x10 < … OR LastRecordChange0x10 < … OR Created0x10 < PE.FileHeader.TimeDateStamp`. (The memo's "PE compile-time < `$SI`" phrasing is loose; the code tests `$SI < PE.compile_time` — file claims to predate its own code. Same semantic, stated as the inequality the code uses.)

**Claim 3 — Velociraptor "not very reliable" caveat. Verdict: CONFIRMED.**
Source: [docs.velociraptor.app/docs/forensic/filesystem/ntfs](https://docs.velociraptor.app/docs/forensic/filesystem/ntfs/).
Verbatim: *"Although it might appear to be a solid detection of timestomping, generally timestomping detections are not very reliable. It turns out that a lot of programs set file timestamps after creating them into the past by design — mostly archiving utilities like 7zip or cab will reset the file time to the times stored in the archive."* (Wording in memo §4 matches.)

**Claim 4 — Magnet AXIOM precision + framing. Verdict: PARTLY.**
Source: [magnetforensics.com/blog/…ntfs-timestamp-mismatch…](https://www.magnetforensics.com/blog/expose-evidence-of-timestomping-with-the-ntfs-timestamp-mismatch-artifact-in-magnet-axiom-4-4/).
- **Framing — CONFIRMED verbatim:** the artifact *"gives you a starting point in the incident response investigations in which you suspect timestomping may have occurred,"* and *"there could be legitimate reasons from normal system behavior that could cause this mismatch, as well as ways that malicious activity can circumvent this timestamp difference"* (links MITRE).
- **"Whole-millisecond" precision — UNVERIFIABLE:** the blog describes the artifact only as flagging *"when the $SI timestamp is earlier than the $FN timestamp."* It states **no** millisecond/sub-second/nanosecond precision threshold anywhere. The memo's "whole-millisecond check" attribution to Magnet is **not supported by this source** and should be dropped or re-sourced.

**Claim 5 — inversecos "only tool" + two myths. Verdict: PARTLY.**
Source: [inversecos.com/2022/04/defence-evasion-technique-timestomping.html](https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html) (Lina Lau).
- **Two myths — CONFIRMED verbatim:** *"Myth 1: $FILE_NAME timestamps cannot be timestomped"* and *"Myth 2: Attacker tools cannot alter nanoseconds in a timestamp,"* and *"it's almost trivial to bypass these two detection mechanisms."*
- **Rename copies `$SI`→`$FN` — CONFIRMED:** *"If a threat actor timestomps the $SI attribute, and then moves or renames the file — Windows will copy the timestomped $SI times into the $FN attributes."*
- **USN/`$LogFile` "more foolproof" — CONFIRMED:** *"this is a more foolproof way of detecting timestomping versus looking for nanosecond precision / comparing $FN to $SI."*
- **"SetMACE is currently the only tool offering `$FN` modification" — NOT FOUND / REFUTED-as-quoted:** the article uses SetMace as *an example* (*"you can use SetMace to alter the $FN timestamps"*) but never claims it is the *only* such tool. Treat the "only tool" assertion as unsupported by this primary source and inherently time-sensitive — do not encode it.

**Claim 6 — MS file-system tunnelling (KB172190). Verdict: PARTLY (exFAT REFUTED).**
Sources: [KB172190 (archived)](https://web.archive.org/web/20160410012540/https://support.microsoft.com/en-us/kb/172190) · [Raymond Chen, *The apocryphal history of file system tunnelling*](https://devblogs.microsoft.com/oldnewthing/20050715-14/?p=34923).
- **15 s default — CONFIRMED verbatim:** *"Tunneling cache time can be adjusted from the default time of 15 seconds."*
- **Registry value names + path — CONFIRMED verbatim:** under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`, the KB documents creating DWORD `MaximumTunnelEntryAgeInSeconds` (cache age) and `MaximumTunnelEntries` (set to `0` to disable).
- **Keyed-by-name creation-time cache — CONFIRMED:** Raymond Chen: *"the creation timestamp and short/long names of a file are taken from a file that existed in the directory previously … if you delete some file 'File with long name.txt' and then create a new file with the same name, that new file will have the same short name and the same creation time as the original file."*
- **exFAT scope — REFUTED:** KB172190 states *"Windows performs tunneling on both FAT and NTFS file systems."* It names **only FAT and NTFS**; exFAT is **not** mentioned. The memo's "applies to FAT/NTFS/exFAT" overstates the primary source — drop exFAT (or cite a separate source) in §2.3.

**Claim 7 — "CyberCX-pioneered" attribution. Verdict: PARTLY (mis-attributed technique).**
Sources: [CyberCX, *NTFS USN Journal Rewind*](https://cybercx.com.au/blog/ntfs-usnjrnl-rewind/) (Yogesh Khatri, Apr 2024) · PoC [CyberCX-DFIR/usnjrnl_rewind](https://github.com/CyberCX-DFIR/usnjrnl_rewind) · canonical timestomp write-up [inversecos](https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html).
A genuine CyberCX primary source **does** exist, but it is the **USN Journal "Rewind"** algorithm — full-path reconstruction by walking `$UsnJrnl:$J` backwards to rebuild the directory tree at each historical point — **not** an `$SI`/`$FN` timestomp-detection technique. The team's recollection conflates two different NTFS contributions: CyberCX → *path reconstruction* (Rewind); inversecos (Lina Lau) → the *timestomp `$SI`/`$FN` + USN/`$LogFile`* detection write-up this memo relies on. **For timestomp detection, cite inversecos; do not attribute the `$SI`/`$FN` heuristic to CyberCX.** (CyberCX Rewind is correctly relevant to our S5 USN corroboration path-building, via `usnjrnl-forensic`, which already implements it.)
