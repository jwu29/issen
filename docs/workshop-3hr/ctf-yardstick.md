# CTF Yardstick — DFIR Madness Case 001

Official question set, ground-truth answers, evidence source, disk+RAM answerability, and the
**Issen verdict** column Josiah fills (run Issen per row; mismatch → TOOL-DEV TODO).

Sources: official case https://dfirmadness.com/the-stolen-szechuan-sauce/ · answer key
https://dfirmadness.com/answers-to-szechuan-case-001/ · walshcat write-up
https://walshcat.medium.com/case-write-up-the-stolen-szechuan-sauce-2409344264c3 · iblue.team
(memory detail). **All times UTC, 19 Sep 2020.** VM artifacts run ~1h off (UTC-7 misconfig).

> Flags: **D+R** = answerable from disk+RAM+pagefile · **RE-ROUTE** = extraction is now part of
> the exercise (hives / protected files) · **PCAP-only** = footnote, not assessable.

## Core questions

| # | Question | Ground truth | Artifact | Flag | Issen verdict |
|---|---|---|---|---|---|
| 1 | Server OS | Win Server 2012 R2 (CitadelDC01) | SOFTWARE hive / mem KDBG | D+R | _tbd_ |
| 2 | Desktop OS | Win 10 (DESKTOP-SDN1RPT) | SOFTWARE hive | D+R | _tbd_ |
| 3 | Server local time | MST (UTC-6); VM mis-set UTC-7 | SYSTEM TimeZoneInformation | D+R | _tbd_ |
| 4 | Breach? | Yes | Security.evtx 4625/4624; mem pslist | D+R | _tbd_ |
| 5 | Initial vector | RDP brute force → CITADEL\Administrator | Security.evtx 4625 flood→4624 | D+R | _tbd_ |
| 6.a | Malicious process | coreupdater.exe → migrated to spoolsv.exe | mem pslist/pstree/malfind | D+R | _tbd_ |
| 6.b | Delivery IP | 194.61.24.102 | WebCacheV01.dat/Amcache; mem strings | D+R | _tbd_ |
| 6.c | C2 IP | 203.78.103.109:443 (Thailand) | **mem netscan**; pagefile strings | D+R | _tbd_ |
| 6.d | Malware path | C:\Windows\System32\coreupdater.exe | MFT; mem | D+R | _tbd_ |
| 6.e | First appeared | ~02:24:06 download to DC | MFT $SI, Amcache, USN | D+R | _tbd_ |
| 6.f | Moved? | Yes: Downloads → System32 | MFT $FN parent / USN RENAME | D+R | _tbd_ |
| 6.i | Persistence | service "coreupdater" (02:27:49) + Run key; both hosts | System.evtx **7045** + SYSTEM hive | RE-ROUTE | _tbd_ |
| 7 | Malicious IPs | 194.61.24.102 (delivery), 203.78.103.109 (C2) | EVTX src IP + mem netscan | D+R | _tbd_ |
| 8 | Other systems | DESKTOP via RDP from DC, 02:35:54 | Desktop 4624 type 10 from DC | D+R | _tbd_ |
| 8.c | Data stolen | secret.zip (DC ~02:31), loot.zip (Desktop ~02:48) | USN, MFT, LNK | D+R | _tbd_ |
| 9 | Network layout | 10.42.85.0/24; DC .10, Desktop .115 | registry interfaces / mem netscan | D+R | _tbd_ |
| 11 | Szechuan Sauce stolen? | Accessed 02:32:21 (Szechuan Sauce.txt) | MFT $SI access, LNK/RecentDocs | D+R | _tbd_ |
| 12 | Other sensitive files | Beth's secret manipulated ~02:34; Morty's thoughts ~02:34 | MFT/USN | D+R | _tbd_ |
| 13 | Last adversary contact | last logoff ~03:00; still interactive at capture | 4634/4647; live mem sessions | D+R | _tbd_ |

## Advanced / bonus

| # | Question | Ground truth | Artifact | Flag | Issen verdict |
|---|---|---|---|---|---|
| B4 | Users logged onto DC | Administrator | DC C:\Users\ + NTUSER.DAT; 4624 | D+R | _tbd_ |
| B5 | Users logged onto Desktop | Administrator, Rick Sanchez | Desktop C:\Users\; 4624 | D+R | _tbd_ |
| B6 | Domain passwords | admin `)&Denver89`; +6 users (see key) | SAM+SYSTEM→NTLM→crack; or lsass | RE-ROUTE | _tbd_ |
| B7 | Recover Beth's original | name `Secret_Beth.txt`, "Earth Beth is the real Beth." | carve deleted file (MFT/$DATA, USN) | D+R | _tbd_ |
| B8 | Time-stomped file | `Beth_Secret.txt` (matched to PortalGunsPlans.txt) | **MFT $SI vs $FN mismatch** | D+R | _tbd_ |

## Write-up traps to brief students on
1. **Delivery IP:** correct is **194.61.24.102** (walshcat's `194.64.24.102` is a typo).
2. **Subnet:** canonical **10.42.85.0/24** from the key (PCAP screenshots show `10.45.85.x` — different vantage).
3. **Numbering:** walshcat uses its own Q-numbers; map back to the official set above.
4. **PCAP-only footnotes (not assessable):** the 02:19 NMAP 3389 probe; packet-level brute-force
   visual. The *outcome* (brute force) is conclusive in Security.evtx 4625/4624 — question stays in.

## Evidence download
All under `https://dfirmadness.com/case001/`. In scope: `DC01-E01.zip`, `DC01-memory.zip`,
`DC01-pagefile.zip`, `DESKTOP-E01.zip`, `DESKTOP-SDN1RPT-memory.zip`,
`Desktop-SDN1RPT-pagefile.zip`. **Drop:** `case001-pcap.zip`, both `*-autorunsc.zip`, both
`*-ProtectedFiles.zip`. (Case-page tiers: this workshop ≈ "Ultra-Violence + pagefiles".)
