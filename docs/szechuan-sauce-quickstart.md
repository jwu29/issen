# Quickstart — Solving "The Stolen Szechuan Sauce" (Case 001) with issen

A command-by-command walkthrough of [DFIR Madness Case 001](https://dfirmadness.com/the-stolen-szechuan-sauce/)
using the `issen` CLI. Every question below shows the **exact command line** to run.

The case has two victim hosts on domain **C137** (`10.42.85.0/24`):

| Host | Role | Memory dump | Disk image (E01) |
|---|---|---|---|
| **CITADEL-DC01** (`10.42.85.10`) | Domain Controller, Win Server 2012 R2 (9600) | `citadeldc01.mem` | `20200918_0347_CDrive.E01` |
| **DESKTOP-SDN1RPT** (`10.42.85.115`) | Workstation, Win 10 Enterprise (19041) | `DESKTOP-SDN1RPT.mem` | `20200918_0417_DESKTOP-SDN1RPT.E01` |

> **Honesty note.** issen does **not** solve this case end-to-end, and this guide does not pretend
> otherwise. Each answer is tagged:
> **✅ measured** (issen produces it directly), **◐ partial** (issen surfaces the member evidence;
> the clean answer needs correlation or a parser not yet wired — cross-check a write-up), or
> **○ out of reach** (PCAP / OSINT / advisory — answer from the write-ups). Ground truth is the
> union finding set in `tests/data/dfirmadness-szechuan-sauce/szechuan-sauce-writeups/szechuan-sauce-union-answers.md`.

---

## 0. Setup

**Build / install issen** (any one):

```bash
# from the repo
cargo build --release -p issen-cli && export PATH="$PWD/target/release:$PATH"
# or a downloaded release binary
issen --version          # issen 0.1.0
```

**Stage the evidence.** The corpus ships as zips under
`~/src/issen/tests/data/dfirmadness-szechuan-sauce/`. Extract the four artifacts this guide uses to
`/tmp` (never under `~/src` — extracted multi-GB copies are ephemeral):

```bash
SZ=/tmp/szechuan ; mkdir -p "$SZ"
cd ~/src/issen/tests/data/dfirmadness-szechuan-sauce
unzip -o DC01-memory.zip            -d "$SZ"   # → $SZ/citadeldc01.mem
unzip -o 'DESKTOP-SDN1RPT-memory.zip' -d "$SZ" # → $SZ/DESKTOP-SDN1RPT.mem
unzip -o DC01-E01.zip               -d "$SZ"   # → $SZ/E01-DC01/20200918_0347_CDrive.E01 (+ .E02)
unzip -o DESKTOP-E01.zip            -d "$SZ"   # → $SZ/20200918_0417_DESKTOP-SDN1RPT.E01 (+ .E02..E04)

export SZ
export DC_MEM="$SZ/citadeldc01.mem"
export WS_MEM="$SZ/DESKTOP-SDN1RPT.mem"
export DC_E01="$SZ/E01-DC01/20200918_0347_CDrive.E01"
export WS_E01="$SZ/20200918_0417_DESKTOP-SDN1RPT.E01"
```

> **Clock-skew caveat (read before trusting any timestamp).** The victims' clocks were misconfigured
> (effective UTC−7) while the PCAP router was correct (UTC−6). issen's **host-derived** times
> (EVTX/MFT/USN) therefore read **one hour ahead** of the network-clock times the official answer key
> narrates. e.g. the key's `02:24:06` download is issen's `03:24:06Z` — same instant.

---

## Fastest path (three commands answer most of it)

```bash
# 1. Memory: malicious process, C2 channel, and credential material on the DC
issen memory "$DC_MEM" --command all

# 2. Disk: parse the DC image into a timeline DB, then a narrative HTML report
issen "$DC_E01" -o /tmp/dc01.duckdb
issen report /tmp/dc01.duckdb -o /tmp/dc01-report.html --case-id "case001-dc01"
```

Everything below breaks that down per question.

---

## The questions

### 1. What is the OS of the Server?  ◐
`Windows Server 2012 R2 (build 9600).` issen auto-detects the symbol profile from RAM:

```bash
issen memory "$DC_MEM" --command check
```
Look for the resolved profile (`Win2012R2x64…`). *Partial:* issen names the build via the memory
profile; clean registry `ProductName` extraction is pending (PRE-3).

### 2. What is the OS of the Desktop?  ◐
`Windows 10 Enterprise (build 19041).`
```bash
issen memory "$WS_MEM" --command check
```

### 3. What was the local time of the Server?  ○
The trick question — the DC's registry `TimeZoneInformation` is set to **Pacific**, producing the
one-hour skew (the *lesson* is the skew, not a zone name). The skew shows up as the offset between
issen's host-derived timeline and the PCAP clock; the registry-value read and PCAP cross-check are
not yet wired. Answer from the write-ups.

### 4. Was there a breach?  ✅
`Yes.` Parse the DC disk and surface cross-artifact findings:
```bash
issen "$DC_E01" -o /tmp/dc01.duckdb
issen correlate "$SZ/E01-DC01"
```
issen measures the members: a 4625 failed-logon burst, thousands of `LogonSuccess` events incl. the
attacker logon, and service-install events.

### 5. What was the initial entry vector?  ✅
`RDP brute force against Administrator, then a successful interactive logon from 194.61.24.102.`
The logon evidence lives in the DC's EVTX (carried in the ingested timeline):
```bash
issen "$DC_E01" -o /tmp/dc01.duckdb
issen timeline /tmp/dc01.duckdb --event-type LogonSuccess
issen timeline /tmp/dc01.duckdb --event-type LogonFailure
```
issen measured the 4625 burst at host-derived `03:21:25Z`, then **4624 LogonType 10, Administrator,
from `194.61.24.102` at `03:21:48Z`**. (The tool name *Hydra* is the key's knowledge, not artifact-derived.)

If you have the EVTX extracted from the image, the dedicated logon/process views also work:
```bash
issen session   --evtx-dir "$SZ/dc01-evtx"
issen processes --evtx-dir "$SZ/dc01-evtx" --link-sessions
```

### 6. Was malware used?  ✅ / ◐
`Yes — coreupdater.exe, consistent with a Meterpreter payload.` Sub-answers, each with its command:

**Malicious process on the DC** — ✅
```bash
issen memory "$DC_MEM" --command ps
```
`coreupdater.exe` (PID 3644, dead — 0 threads) and `spoolsv.exe` (PID 3724, hosting the migrated
session). The conjunction is *consistent with* Meterpreter process migration.

**C2 the malware is calling** — ✅ *(now measured — fixed in memf 0.2.2)*
```bash
issen memory "$DC_MEM" --command netstat
```
Recovers the ESTABLISHED TCP connection to **`203.78.103.109:443`** tied to the malware. *(Validated
this session byte-for-byte against Volatility `windows.netscan`.)*

**Where the malware is on disk** — ✅
```bash
issen "$WS_E01" -o /tmp/ws.duckdb
issen timeline /tmp/ws.duckdb --event-type FileCreate
```
`C:\Windows\System32\coreupdater.exe`; the Desktop `FileCreate` is host-derived `03:40:00Z`.

**In-memory scan / injected region** — ◐
```bash
issen memory "$DC_MEM" --command scan
```
Surfaces suspicious regions (the `PAGE_EXECUTE_READWRITE` `MZ` region in `spoolsv.exe`). Family naming
(Metasploit) ships only as "consistent with"; VirusTotal/ClamScan/FLOSS are external.

**Persistence** — ✅ (service) / ◐ (Run key)
```bash
issen timeline /tmp/dc01.duckdb --event-type ServiceInstall
```
The 7045 `coreupdater` LocalSystem service install (DC network-clock `02:27:49`). The Run-key/Services
registry leg needs registry-value extraction (PRE-3) — cross-check a write-up.

### 7. Which IP addresses were malicious / known adversary infra?  ✅ / ○
`194.61.24.102` (delivery + brute source) and `203.78.103.109` (C2).
```bash
issen memory "$DC_MEM" --command netstat      # 203.78.103.109:443
issen timeline /tmp/dc01.duckdb --event-type LogonSuccess   # 194.61.24.102 as logon source
```
*Caution:* the write-up's original APT/`happydoghappycat-th.com` attribution for `203.78.103.109` was
**retracted by the author** — do **not** assert APT attribution. All OSINT/whois is **out of reach**.

### 8. Were other systems accessed? How and when?  ✅
`Yes — DESKTOP-SDN1RPT, by RDP from inside the DC, reusing the stolen Administrator credential.`
Ingest both hosts into **one** timeline for cross-host correlation:
```bash
issen "$DC_E01" "$WS_E01" -o /tmp/case001.duckdb -s case001
issen timeline /tmp/case001.duckdb --event-type LogonSuccess
```
issen measured the Desktop **4624 LogonType 10 from `10.42.85.10` (the DC), Administrator, host-derived
`03:36:24Z`**.

### 9. Was any data stolen or accessed? When?  ✅
`secret.zip` staged/exfiltrated/deleted on the DC (~02:31 network clock), `loot.zip` on the Desktop
(~02:48). The MFT/USN staging trail:
```bash
issen "$WS_E01" -o /tmp/ws.duckdb
issen timeline /tmp/ws.duckdb --event-type FileCreate
issen timeline /tmp/ws.duckdb --event-type FileDelete
```
issen measures the staging members; byte-level transfer evidence is PCAP territory (**out of reach**).

### 10. What was the network layout?  ◐
`Domain C137, single subnet 10.42.85.0/24; DC 10.42.85.10, Desktop 10.42.85.115.` Hostnames/IPs flow
through the measured EVTX events (visible in the ingested timeline); the clean registry interface
extraction is pending (PRE-3). Cross-check a write-up.

### 11. What architecture changes should be made?  ○
Advisory, not an artifact: remove internet-facing RDP (especially to a DC), VPN-gate remote access,
add a firewall/IPS, kill credential reuse, deploy EDR. No command — analyst recommendation.

### 12. If the Szechuan sauce was stolen, what time?  ◐
`~02:30 UTC network clock (host-derived ~03:30Z)` — the recipe rode the `secret.zip` window;
`Szechuan Sauce.txt` was accessed at network-clock `02:32:21`.
```bash
issen "$DC_E01" -o /tmp/dc01.duckdb
issen timeline /tmp/dc01.duckdb | grep -i "Szechuan Sauce"
```
issen surfaces the file-access members; the woven chain is a correlation target.

### 13. Were other sensitive files stolen/accessed? Times?  ✅
`Yes — SECRET_beth.txt deleted and a different Beth_Secret.txt created (then timestomped ~02:38).`
```bash
issen "$DC_E01" -o /tmp/dc01.duckdb
issen timeline /tmp/dc01.duckdb | grep -i "Beth_Secret"
```
issen measured the **8 `Beth_Secret` MFT events** (create/access/delete). The timestomp shows up as the
`$SI`/`$FN` discrepancy (an Info-level lead). Content comparison is out of reach.

### 14. When was the last known contact with the adversary?  ◐
`Last interactive logoff ~03:00 network clock; attacker tooling still resident at capture time.`
```bash
issen timeline /tmp/dc01.duckdb --event-type Logoff
issen memory "$DC_MEM" --command ps     # spoolsv.exe (3724) session still resident
```
issen has the Logoff events and the resident migrated session; the per-session "last adversary logoff"
envelope is a designed correlation.

### Credentials (bonus — what are the account hashes/passwords?)  ✅
The DC SAM yields the local/DSRM Administrator NT hash:
```bash
issen memory "$DC_MEM" --command creds
```
Recovers Administrator (RID 500) = `f56a8399599f1be040128b1dd9623c29` and Guest = the empty-password
constant `31d6cfe0d16ae931b73c59d7e0c089c0`. *(Validated this session byte-for-byte against Volatility
`windows.hashdump`.)* **Note:** this is the **local/DSRM** Administrator — the *domain* admin password
`)&Denver89` (NT hash `10e63d3f2c9924bae49241cff847e405`) lives in NTDS.dit, not the SAM, so it is
correctly absent here.

---

## Whole-case sweeps

```bash
# Narrative supertimeline across the extracted evidence directory
issen supertimeline "$SZ" --format narrative

# Cross-artifact correlated findings for a host's evidence directory
issen correlate "$SZ/E01-DC01"

# Remote-access infrastructure (RDP/RMM) scan over a mounted image or evidence dir
issen remote-access "$SZ/E01-DC01"

# Full memory triage on either host (ps + modules + netstat + creds + scan + check)
issen memory "$DC_MEM" --command all
issen memory "$WS_MEM" --command all
```

## What issen does NOT answer here (be honest with the analyst)

Several official answers genuinely require parsers that are **present in the fleet but not yet wired
into the binary** (`PRE-5`): **Prefetch, Shimcache (AppCompatCache), Amcache, LNK/Jump Lists**. So the
**evidence-of-execution** answers ("was `coreupdater.exe` *run*, how many times, its hash") and the
staging `Loot.lnk`/`Secret.lnk` targets come from the write-ups, not issen — issen currently only
*infers* execution indirectly (the `.pf` file's MFT creation time + the 7045 service start). PCAP
byte-transfer, OSINT/whois, and content carving are also out of issen's current reach. Treat those as
**◐/○** above and cite the published analysis.
