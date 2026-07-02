# Test Data — Issen

Forensic disk images, memory dumps, and UAC/Velociraptor collections, plus other test artifacts.
These files are large and not tracked in git — download them manually.

Files are organized into per-challenge or per-source subfolders. For the **fleet-wide** corpus
inventory (every repo, real vs synthetic, provenance + licenses) see
[`docs/corpus-catalog.md`](../../docs/corpus-catalog.md).

## Directory Layout

```
tests/data/
├── CyberDefenders/
│   └── 78-DeepDive.zip                              (537 MB)
├── cyberspace-ctf-2024/
│   └── csctf-2024_forensics_memory.zip             (671 MB)
├── defcon-dfir-ctf-2018/
│   └── MaxPowersCDrive.E01                          (29 GB)
├── dfirmadness-szechuan-sauce/   (full case, both hosts)
│   ├── DC01-E01.zip / DC01-memory.zip / DC01-pagefile.zip          (Server 2012 R2)
│   ├── DESKTOP-E01.zip / DESKTOP-SDN1RPT-memory.zip / …-pagefile.zip  (Windows 10)
│   ├── {DC01,DESKTOP-SDN1RPT}-autorunsc.zip + *Protected*Files*.zip ×2
│   └── case001-pcap.zip
├── hal-linux-dfir-challenge/
│   ├── uac-vbox-linux-20260324193807.tar.gz        (143 MB — no memory dump)
│   └── uac-vbox-linux-20260324234043.tar.gz        (5.9 GB — includes avml.lime)
├── magnet-summit-2023-ctf/
│   └── PC-MUS-001.E01                               (49 GB)
├── SecurityNik/
│   └── TOTAL_RECALL_memory_forensics_CHALLENGE.zip (1.2 GB)
├── Volatility/
│   └── cridex_memdump.zip                           (38 MB)
└── Collection-A380_localdomain-2025-08-10T03_41_20Z.zip   (2.2 GB — Velociraptor, root)
```

## Files

### defcon-dfir-ctf-2018/

#### MaxPowersCDrive.E01

- **Source:** DEFCON DFIR CTF 2018, organized by David Cowen
- **Identity:** Image 3 (Desktop) — C: drive of user `mpowers` (Max Powers)
- **EWF metadata:** Case "MaxPowers-1", examiner "Professor Frink", linen 5 format, acquired May 5, 2018 with f-response
- **Blog:** <https://www.hecfblog.com/2018/08/daily-blog-451-defcon-dfir-ctf-2018.html>
- **Writeup:** <https://or10nlabs.tech/defcon-dfir-ctf-2018/>
- **Original download:** <https://www.dropbox.com/s/jvaqb4rfi3jojbk/Image3.7z> (may be expired)
- **MD5:** `10c1fbc9c01d969789ada1c67211b89f`
- **Notable contents:** Has `pagefile.sys` and `swapfile.sys` but NO `hiberfil.sys` (hibernation was disabled)

### dfirmadness-szechuan-sauce/

**Full case present — both hosts** (the folder name predates the DC host): CitadelDC01
(Server 2012 R2) and DESKTOP-SDN1RPT (Windows 10), each with disk E01 + memory + pagefile, plus
the PCAP, autoruns, and protected-files bundles.

- **Source:** DFIR Madness — "The Case of the Stolen Szechuan Sauce" (Case 001)
- **Created by:** James Smith (DFIR Madness)
- **Site:** <https://dfirmadness.com/the-stolen-szechuan-sauce/> (may be down)
- **Mirror:** <https://mimircyber.com/the-case-of-the-stolen-szechuan-sauce/>
- **DESKTOP-E01.zip MD5:** `71C5C3509331F472ABCDF81EB6EFFF07` (DC01 hashes not published on the
  case page — DC01 files verified by byte-length vs server `content-length`)
- **Used by:** BSidesHK 3hr workshop (`docs/workshop-3hr/`, disk + RAM only — pcap/autoruns/
  protected-files downloaded for completeness but excluded from the lab) and `usnjrnl-forensic`
  integration tests (desktop E01).

### hal-linux-dfir-challenge/

Used by automated tests in `rt-parser-uac` and `rt-navigator`. The small archive runs in CI; the large one is `#[ignore]`d unless explicitly requested.

#### uac-vbox-linux-20260324193807.tar.gz (143 MB)

- **Source:** Self-collected using UAC on a Linux VirtualBox VM, March 24, 2026
- **Tool:** [UAC — Unix-like Artifacts Collector](https://github.com/tclahr/uac)
- **Contents:** Filesystem artifacts only (no memory dump) — bodyfile, network, processes, system info, etc.
- **Use case:** UAC parser integration tests (`rt-parser-uac`, `rt-navigator`)

#### uac-vbox-linux-20260324234043.tar.gz (5.9 GB)

- **Source:** Self-collected using UAC on a Linux VirtualBox VM, March 24, 2026
- **Tool:** [UAC](https://github.com/tclahr/uac) with AVML memory acquisition
- **Contents:** Full UAC collection including `memory_dump/avml.lime` (~5.5 GB AVML-format memory dump)
- **Use case:** End-to-end UAC pipeline tests including memory dump detection, AVML format provider, Linux process/module/network walking

### magnet-summit-2023-ctf/

#### PC-MUS-001.E01 (50 GB)

- **Source:** magnet-summit-2023-ctf challenge
- **Created by:** Jessica Hyde and Champlain College Digital Forensic Association (DFA) for Magnet Forensics
- **EWF metadata:** Case "1", evidence "PhysicalDrive0", EnCase 6 format, acquired Jan 7, 2023
- **Writeups:**
  - <https://www.stark4n6.com/2023/03/magnet-virtual-summit-2023-ctf-windows.html>
  - <https://download.getdata.com/support/documents/ctf/Magnet%20Virtual%20Summit%202023%20CTF%20-%20Windows%2011.pdf>
  - <https://getdataforensics.com/capture-the-flag/>
- **MD5:** `522df9db8289f4f8132cf47b14d20fb8`
- **Notable contents:** Contains `hiberfil.sys` (MFT entry 54, 3.37 GB allocated) — usable as real test data for `memf-format` hiberfil provider

### magnet-summit-2025-ctf/

- **Source:** **2025 Magnet Virtual Summit CTF** — authored by the **Hexordia** team (Kevin Pagano
  authored the harder questions) with Champlain College DFA interns (Yehuda Bollen, Fatima Omorevic,
  Adam Hachem, James Cangelosi, Cece Ehgotz, Nathan Kreit), for Magnet Forensics.
- **Scenario:** two personas "Ruth" and "Mary"; activity across mobile + computer + web, Nov–Dec 2024.
- **Devices/images:** iOS 18 full-file-system, Android 14, **Windows 11**, and a **Chromebook**.
- **Catalog page:** NIST **CFReDS** — <https://cfreds.nist.gov/all/Hexordia/2025MVSCTF>
  (the public index). **Note:** CFReDS *hosts this dataset on Google Drive* — its download API resolves
  files by Drive `fileIds` (`POST /api/google-drive/files`), so CFReDS and the folder below are the
  **same Google Drive files**, subject to the same per-file quota.
- **Writeup:** <https://www.magnetforensics.com/blog/announcing-the-winners-of-the-2025-magnet-virtual-summit-ctf/>
- **Google Drive folder:** <https://drive.google.com/drive/folders/1qLwXFZTZidkx1tWpG8uenVQnX6zWF-Oa>.
  Contains `userbss.ad1` (AccessData **AD1** logical image; Drive id `1ImeVi8BzHcuLDOV7LhAle9kRnZOMFb64`)
  among others.
- **Download status (2026-07-01):** **acquired** — `userbss.ad1` obtained via a logged-in
  browser (bypasses the public Drive quota). It lives in the AD1 repo, not here:
  `ad1-forensic/tests/data/userbss.ad1` (gitignored), with full provenance in
  `ad1-forensic/tests/data/README.md`.
  - Size: 51,678,663,221 bytes (≈ 48.1 GiB)
  - MD5: `0b6b53e3475b97ae8b3bd3c1e7cec2d9`
  - SHA256: `743e1e89e1d4fa9d6f75d91e820f6dd02d2d906e1bab70eb4731a2fdb4458e7c`
- **Used by (planned):** Windows 11 leg → NTFS/registry/EVTX triage; `userbss.ad1` exercises a future
  **AD1 (AccessData logical image) container** reader (issen does not yet parse AD1); the iOS 18 /
  Android / Chromebook legs are mobile/cross-platform corpora for later parsers.

### CyberDefenders/

#### 78-DeepDive.zip (537 MB)

- **Source:** CyberDefenders Blue-Team lab **#78 "DeepDive"** (<https://cyberdefenders.org/blueteam-ctf-challenges/deepdive/>)
- **Contents:** `banking-malware.vmem` (2.0 GB) — Win7 SP1 x64 memory image of an **Emotet** banking-trojan infection (DKOM-hidden process `vds_ps.exe`). *Confirmed by inspecting the archive (2026-06-09).*
- **Redistribution:** CyberDefenders educational license — verify before redistribution.

### cyberspace-ctf-2024/

#### csctf-2024_forensics_memory.zip (671 MB)

- **Source:** **cyberspace-ctf-2024**, "Memory" forensics challenge (30 Aug–01 Sep 2024; CTFtime event #2428)
- **Contents:** `mem.dmp` (2.0 GB) — MS Windows 64-bit crash dump; recover-deleted-`flag.jpg` via PowerShell/AES/environment-variables. *Confirmed by inspecting the archive + write-ups (2026-06-09).*
- **Redistribution:** Verify CyberSpace CTF terms.

### SecurityNik/

#### TOTAL_RECALL_memory_forensics_CHALLENGE.zip (1.2 GB)

- **Source:** SecurityNik **TOTAL RECALL 2024** memory-forensics challenge by Nik Alleyne (write-up <https://www.securitynik.com/2024/03/total-recall-2024-memory-forensics-self.html>, files <https://github.com/SecurityNik/CTF>)
- **Contents:** `SECURITYNIK-WIN-20231116-235706.dmp` (4.29 GB) + sidecar `.json` — Windows 11 (build 22621) x64 crash dump, acquired with **DumpIt 3.0**, host `SECURITYNIK-WIN` / user `securitynik`. **SHA256** `cabe2fd543eac1cd2eab9ccd0a840d83481a3f00e16015287323b2cb44fe0686`. *Confirmed from embedded metadata (2026-06-09).*
- **Redistribution:** SecurityNik public challenge — attribution.

### Volatility/

#### cridex_memdump.zip (38 MB)

- **Source:** Volatility Foundation public sample — Cridex banking-trojan memory image (<https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples>)
- **Contents:** `cridex.vmem` (512 MB) — the canonical Windows XP Cridex memory sample (2012-08-02) from the Volatility tutorials. *Confirmed by inspecting the archive (2026-06-09).*
- **Redistribution:** Volatility Foundation public sample.

### josh-hickman-ios17-biome-segb/

Real iOS 17 device data — the DFIR community's standard public test image. Used by
**`sqlite-forensic`** as a real-world SQLite + **WAL** validation source (env-gated robustness
test; CI skips when absent — these files are gitignored and downloaded manually).

- **Source:** Josh Hickman (The Binary Hick), iOS 17 public research image. Blog/index:
  <https://thebinaryhick.blog/2023/12/05/ios-17-image-now-available-with-a-twist/> (series index
  <https://thebinaryhick.blog/images/>). Documented + hashed on the source post; download via the
  Mega link there (manual — Mega is not curl-fetchable).
- **Contents:**
  - `iOS_17_Public_Image.tar.gz` (21 GB) — the full file-system image (unextracted here). Holds the
    full set of real app SQLite (e.g. `knowledgeC.db`, `sms.db`, Safari `History.db`, CallHistory) —
    extract it to broaden the SQLite corpus.
  - `biome_ffs/filesystem1/` — a Biome-focused partial extract. **3 genuine iOS app SQLite databases,
    each with a live `-wal` + `-shm` sidecar** (real Write-Ahead Log, captured uncheckpointed):
    `private/var/mobile/Library/Biome/sync/sync.db`,
    `…/Biome/databases/ApplePay.Security.Features/ApplePay.Security.Features.sqlite3`, and
    `…/Caches/CloudKit/com.apple.biomesyncd/…/MMCS/.cs/ChunkStoreDatabase`.
  - `biome_extract/` — decoded Biome SEGB streams (Apple's `SEGB` event format).
  - `iOS17-ImageCreation.pdf` (3 MB) — Josh Hickman's image-creation documentation.
- **Use case (`sqlite-forensic`):** real iOS app SQLite + real WAL for the panic-free robustness suite
  and WAL version-history validation — genuine on-device structures, not synthetic. Point the test at
  this folder via `SQLITE_FORENSIC_IOS_CORPUS=<this path>` (or extract the full image and point there).
- **Redistribution:** Josh Hickman's public research images — free for research/testing, attribution.
  Belongs to **issen** (large, gitignored); `sqlite-forensic` reads it in place via the env var.

### Root (self-collected, no challenge affiliation)

#### Collection-A380_localdomain-2025-08-10T03_41_20Z.zip (2.2 GB)

- **Source:** Self-collected from host `A380` (Windows 11 Pro 24H2, standalone workstation), August 10, 2025
- **Tool:** Velociraptor offline collector v0.74.5 — artifact `Windows.KapeFiles.Targets` (`_SANS_Triage` target set). **Not UAC** — the earlier "UAC" label was incorrect (verified by inspecting the archive: `client_info.json` / `collection_context.json`, 2026-06-09).
- **Contents:** Disk-artifact triage only — registry hives, EVTX, prefetch, `$MFT`, browser artifacts (2,952 files). **No memory dump.** Benign baseline (real daily-driver host), not an intrusion scenario.
- **Use case:** Velociraptor parser integration tests (`rt-parser-velociraptor`, `rt-navigator`)
- **Note:** Contains real personal artifacts — sanitize before any external sharing.

## Examining E01 Images

These tools are useful for inspecting E01 contents (install via Homebrew: `brew install libewf sleuthkit`):

```bash
# Image metadata
ewfinfo MaxPowersCDrive.E01

# Partition table
mmls -i ewf MaxPowersCDrive.E01

# List root directory (use partition offset from mmls)
fls -i ewf -o 1026048 MaxPowersCDrive.E01

# Search for a specific file
fls -i ewf -o 1026048 MaxPowersCDrive.E01 | grep -i hiberfil

# Extract a file by inode (e.g., hiberfil.sys from PC-MUS-001)
icat -i ewf -o 239616 PC-MUS-001.E01 54-128-1 > hiberfil.sys
```

#### josh-hickman-ios17-biome-segb/iOS_17_Public_Image.tar.gz (22 GB)

- **Source:** Joshua Hickman ("The Binary Hick"), hosted by DigitalCorpora — public iOS forensic
  reference image, freely licensed for training/education/testing/research.
- **Identity:** iPhone 11 (A2111), iOS 17.3 build 21D50, Cellebrite UFED full file-system extraction;
  synthetic persona `thisisdfir@gmail.com`.
- **Writeup:** <https://thebinaryhick.blog/2024/09/14/triple-trouble-ios-16-android-14-and-ios-17-images-now-available/>
- **Original download:** <https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS_17_Public_Image.tar.gz>
  (image-creation doc with hashes: <https://digitalcorpora.s3.amazonaws.com/corpora/mobile/iOS17/iOS17-ImageCreation.pdf>)
- **MD5:** `e115f051d15178fa1334489e24c9f0fd` (22,132,295,131 bytes).
- **Structure:** Cellebrite UFED package — the full file system is the nested
  `iOS_17/Cellebrite_Extraction/.../EXTRACTION_FFS 01/EXTRACTION_FFS.zip`; biome streams are inside it
  at `private/var/db/biome/streams/restricted/*/local` and `private/var/mobile/.../Library/Biome/`
  (same SEGB v1/v2 container macOS uses). Extract the biome subset from the nested zip; only that
  subset is kept on disk.
- **Used by:** `segb-core` — **public/reproducible validation**: across all **401** real iOS 17 Biome
  SEGB files (139 v1 + 262 v2), segb-core's record counts match the ccl-segb reference exactly —
  **401 PASS / 0 MISMATCH** (2026-06-14). The stream dirs unzip with restrictive Apple modes (0700);
  `chmod -R u+rwX` before scanning. `App.MenuItem` is macOS-Tahoe-26-only and absent here (this is the
  container validation; the App.MenuItem protobuf field mapping still awaits a Tahoe 26 image).

#### josh-hickman-mac-bigsur/macOS - BigSur.zip (32 GiB zip → 80 GB image)

- **Source:** Joshua Hickman ("The Binary Hick") — public macOS Big Sur forensic reference image,
  freely licensed for training / education / testing / research (attribution).
- **Identity:** macOS Big Sur install on **APFS**; 80 GB virtual disk (167,772,160 × 512-byte sectors);
  acquired Sat 2021-02-20 with AccessData FTK Imager 4.5.0.3 from an Arsenal-mounted VM disk
  ("Arsenal Virtual SCSI Disk Device", serial `{77ed1df2-737f-11eb-999e-f01898863f52}`).
- **Writeup:** <https://thebinaryhick.blog/2021/02/20/ios-14-macos-big-sur-lots-of-images/>
  (series index <https://thebinaryhick.blog/images/>) — documented + hashed on the source post.
- **Zip MD5:** `1047921dcc695be98fa648ad54a111d6` (34,408,655,935 bytes).
- **Image hashes** (from the embedded `macOS-BigSur.E01.txt`, computed by FTK Imager at acquisition):
  MD5 `768785635426d008df76200fbc421063`, SHA1 `e3a73cd1b750a851c12c7b608e95edbef1606504`.
- **Structure:** split EWF/E01 — `macOS/macOS-BigSur.E01`–`.E22` (~1.57 GB segments, **Deflated** zip
  entries) + `macOS-BigSur.E01.txt` (acquisition metadata). Pass the first segment (`.E01`) to `ewf`;
  it follows `.E02…` automatically.
- **Used by:** macOS / APFS forensic testing (apfs-forensic, planned), and a real **multi-segment
  E01-inside-a-zip** that exercises issen's EWF zip-direct path + the `DeflateSeekReader` (zran)
  seekable-DEFLATE backing — the segments are Deflated, so this is the live regression for that wiring.

#### loghub-openssh/OpenSSH_2k.log (220 KB)

- **Source:** loghub (logpai), the LogPAI OpenSSH dataset — real, unsanitized SSH server auth events
  from a `LabSZ` host (genuine attacker IPs, brute-force `Failed password` floods, invalid users).
  Pre-journald **text** `auth.log` syslog format. Cite: Zhu et al., *Loghub*, ISSRE 2023.
- **Identity:** the 2k-line sample slice (1999 lines) of the OpenSSH dataset.
- **Original download:** <https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log>
  (dataset: <https://github.com/logpai/loghub/tree/master/OpenSSH>)
- **MD5:** `72efdaaf373b8d6c8a809cc86b2a951f` (225,216 bytes).
- **Used by:** `issen-parser-linux` to validate `parse_auth_log` against **real** evidence — the Hal
  Linux UAC corpus is journald-only (no text `auth.log`), so this fills that gap. Copy/rename to
  `auth.log` and ingest → **519 LoginHistory events** (1 Accepted + 518 Failed), exact match to an
  independent grep oracle. See catalog §A8.

## Test path references

Tests reference these files relative to the crate root (e.g., `../../tests/data/...`).
If you add a new file or subfolder, update the corresponding integration test and this README.

| Test file | Archive referenced |
|-----------|-------------------|
| `crates/parsers/rt-parser-uac/tests/integration_test.rs` | `hal-linux-dfir-challenge/uac-vbox-linux-20260324193807.tar.gz` |
| `crates/parsers/rt-parser-velociraptor/tests/integration_test.rs` | `Collection-A380_localdomain-2025-08-10T03_41_20Z.zip` |
| `crates/rt-navigator/tests/collection_loading.rs` | Both of the above |
