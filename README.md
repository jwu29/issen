# RapidTriage

[![Stars](https://img.shields.io/github/stars/SecurityRonin/rapidtriage?style=for-the-badge)](https://github.com/SecurityRonin/rapidtriage/stargazers) [![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](LICENSE) [![Build](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)]() [![Rust](https://img.shields.io/badge/rust-1.80+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org) [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=for-the-badge)]() [![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ff69b4?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**One command. One output. The full attack narrative.**

---

```
$ rt analyse collection.tar.gz

[CRITICAL] Rootkit concealed miner activity
  Rule    : correlation.miner.rootkit-concealment
  Evidence: ld_preload /lib/x86_64-linux-gnu/libymv.so.3
            PID 977 "top" [thread: libuv-worker] → XMRig
            127.0.0.1:59182 → 127.0.0.1:3333 [Stratum tunnel]
```

A rootkit hiding a crypto miner behind an SSH tunnel. Found automatically. Zero manual grep.

---

## How it works

- **Ingests** UAC live response collections, Volatility sockstat output, EVTX logs, and memory dumps — simultaneously.
- **Correlates** evidence across sources using the Pivot engine: a network connection isn't a finding on its own; combined with a hidden PID and a loaded rootkit library, it is.
- **Outputs** a structured Finding with severity, rule name, and the full evidence chain — ready for your report.

No Python env. No dependency hell. One static binary.

---

## Install

```bash
# Requires Rust 1.80+
cargo install --git https://github.com/SecurityRonin/rapidtriage rt-cli

# Verify
rt --version
```

## First command

```bash
rt analyse collection.tar.gz
```

That's it. Everything else is optional.

---

## Quick reference

```bash
# Parse artifacts into a DuckDB timeline and scan for IOCs
rt ingest evidence/ --output case.duckdb --scan

# Query the timeline
rt timeline case.duckdb --flagged --min-severity high

# Analyse a physical memory dump (LiME, AVML, crash dump)
rt memf dump.lime --command all

# Detect remote access tools (LOLRMM-based)
rt remote-access evidence/

# Scan files against YARA/Sigma/hash/STIX signatures
rt scan evidence/ --auto-feeds

# Update threat intel feeds (YARA, Sigma, STIX, Zeek)
rt feed update

# Generate HTML report from a timeline database
rt report case.duckdb --output report.html
```

---

## What it covers

| Category | Formats / Sources |
|---|---|
| **Collection formats** | UAC `.tar.gz`, Velociraptor, KAPE triage zip |
| **Memory formats** | LiME, AVML, WinPMEM, crash dump (DMP), Hibernation (hiberfil.sys) |
| **Detection types** | YARA rules, Sigma rules, STIX indicators, hash IOCs |
| **Artifact sources** | EVTX, registry hives, MFT, USN Journal, prefetch, $LogFile |
| **Network analysis** | Volatility sockstat, pcap, Zeek logs |
| **Remote evidence** | 48 URI schemes — object storage, cloud drives, databases, SFTP, HDFS, IPFS, and more (see [Remote Sources](#remote-sources)) |
| **Output formats** | Terminal (colour-coded), JSON, HTML report, DuckDB timeline, bodyfile |
| **RAT detection** | LOLRMM rule set (400+ tools) |

---

## Architecture

<details>
<summary>Crate layout</summary>

```
rt-cli                      # The rt binary — commands and arg parsing
rt-core                     # Shared types, plugin traits, error types
rt-plugin-sdk               # Compile-time parser registration via inventory
rt-timeline                 # DuckDB (primary) + SQLite export timeline store
rt-fswalker                 # Parallel filesystem walk via rayon, SHA-256 integrity
rt-unpack                   # Collection format detection (UAC tar.gz, Velociraptor, KAPE)
rt-remote-io                # Remote storage I/O — 48 URI schemes via OpenDAL (S3, GCS, Azure, SFTP, HDFS, GDrive, …)
rt-signatures               # YARA-X, Tau-Engine, Hash/Network/STIX IOCs, feed sync
rt-correlation              # Pivot engine: YAML rules, zeek-intel
rt-remote-access            # LOLRMM 400+ tool definitions, RMM/RAT detection
rt-mem                      # Memory forensics bridge (memf-* sibling workspace)
rt-report                   # Self-contained HTML report with Mermaid attack chains
rt-mft-tree                 # MFT heuristic analysis
rt-navigator                # Interactive TUI navigation
rt-shrinkpath               # Path abbreviation utilities
rt-ewf                      # EWF/E01 forensic image support
rt-parser-mft               # NTFS MFT + USN Journal parser
rt-parser-evtx              # Windows Event Log parser
rt-parser-uac               # UAC collection format parser
rt-parser-velociraptor      # Velociraptor collection parser
xtask                       # Build automation
```

Each crate is independently testable and versioned. The CLI wires them together; you can also use the crates as a library in your own tooling.

</details>

---

## Correlation Rules

Most tools find indicators. RapidTriage finds **attack patterns** by joining evidence across sources automatically.

A Correlation Rule looks like this:

```yaml
id: correlation.miner.rootkit-concealment
severity: critical
description: Rootkit concealing cryptominer activity via LD_PRELOAD
clauses:
  - source: uac.ld_preload
    field: library_path
    match: "lib*.so.*"
  - source: memory.process_threads
    field: thread_name
    match: "libuv-worker"
  - source: network.connections
    field: dest_port
    match: 3333            # Stratum mining protocol
logic: all
emit:
  finding: "Rootkit concealed miner activity"
  evidence: [library_path, pid, thread_name, src_addr, dest_addr]
```

Rules are YAML files in `~/.config/rapidtriage/rules/`. Ship your own. Share with your team.

<details>
<summary>Why YAML rules and not hard-coded detections?</summary>

Hard-coded detections age badly. Threat actors change port numbers, rename binaries, and swap libraries. YAML rules are versionable, shareable, and reviewable in a pull request. The correlation engine is stable; the rules are data.

The built-in rule set covers the most common patterns (miners, rootkits, SSH tunnels, LOLRMM RATs). Your custom rules compose with the built-ins — one `rt analyse` call evaluates all of them.

</details>

---

## Demo

```
$ rt analyse collection-WIN10-CORP-20260401.zip

╔══════════════════════════════════════════════════════════╗
║  RapidTriage — Collection Analysis                       ║
╚══════════════════════════════════════════════════════════╝

  Collection : collection-WIN10-CORP-20260401.zip
  Host       : WIN10-CORP
  OS         : Windows 10 Enterprise 22H2 (19045.4291)
  Collected  : 2026-04-01T14:32:07Z
  Artifacts  : MFT, EVTX, Registry, Prefetch, Amcache

  Parsed 1,247,831 MFT entries in 3.2s
  Parsed 48 EVTX logs (312,406 events) in 1.8s
  Parsed 4 registry hives in 0.4s

┌─ PERSISTENCE ───────────────────────────────────────────
│
│  [SERVICE] AnyDeskMaint
│    Binary  : C:\ProgramData\Temp\Support\anydesk.exe --service
│    Start   : Auto (SERVICE_AUTO_START)
│    Account : LocalSystem
│    Created : 2026-03-28T09:14:22Z
│
│  [REG RUN KEY] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│    Name    : AnyDeskUpdate
│    Value   : "C:\ProgramData\Temp\Support\anydesk.exe" --start-with-win
│    Modified: 2026-03-28T09:14:38Z

┌─ REMOTE ACCESS ─────────────────────────────────────────
│
│  [LOLRMM] AnyDesk (relocated binary)
│    Path    : C:\ProgramData\Temp\Support\anydesk.exe
│    SHA256  : a1b2c3d4e5f60718293a4b5c6d7e8f90aabbccdd11223344556677889900eeff
│    Size    : 5,389,312 bytes
│    Signed  : philandro Software GmbH (valid, not revoked)
│    Config  : ad.router.custom_id = "corp-maint-04"
│
│  [C2 CONNECTION]
│    Dest IP : 194.36.28.117:7070
│    First   : 2026-03-28T09:17:03Z
│    Last    : 2026-04-01T13:58:41Z
│    Note    : IP not in AnyDesk relay network (AS 208323 / BL Networks, RU)

┌─ TIMELINE ──────────────────────────────────────────────
│
│  2026-03-28T09:12:55Z  [EVTX Security 4624]  Logon Type 3 — CORP\svc_backup
│                         from 10.20.5.44 (WIN-RUNBOOK)
│  2026-03-28T09:14:18Z  [MFT]  File created: C:\ProgramData\Temp\Support\anydesk.exe
│                         Parent created at same time — directory is new
│  2026-03-28T09:14:22Z  [EVTX System 7045]   Service installed: AnyDeskMaint
│                         ImagePath: C:\ProgramData\Temp\Support\anydesk.exe --service
│                         Account: LocalSystem | Type: user mode (0x10)
│  2026-03-28T09:17:03Z  [EVTX Security 5156] Outbound TCP — anydesk.exe (PID 6284)
│                         → 194.36.28.117:7070

┌─ CORRELATION FINDINGS ──────────────────────────────────
│
│  [CRITICAL] LOLRMM with non-vendor C2 infrastructure
│    Rule    : remote-access.lolrmm.custom-c2
│    Evidence: AnyDesk outside vendor path (C:\ProgramData\Temp\Support\)
│              Outbound → 194.36.28.117 (AS 208323, not AnyDesk relay ASN)
│              MFT entry + EVTX 7045 + EVTX 5156 + Registry Run key
│    MITRE   : T1219, T1543.003
│
│  [HIGH] Lateral movement via service account
│    Rule    : lateral-movement.service-account.file-drop
│    Evidence: Type 3 logon CORP\svc_backup from 10.20.5.44 (WIN-RUNBOOK)
│              File drop + service install within 120s of logon
│    MITRE   : T1021.002

  2 findings | 1 critical, 1 high | 4 artifact sources correlated
```

The correlation engine flagged AnyDesk installed under `C:\ProgramData\Temp\Support\` — not its standard `Program Files` path — with outbound connections to a Russian ASN outside AnyDesk's relay infrastructure. The timeline shows a service account logon from an internal host, followed by file drop, service install, and first C2 callback within a four-minute window: the attacker pivoted from `WIN-RUNBOOK` using `svc_backup` credentials to deploy the RAT on `WIN10-CORP`.

---

## Remote Sources

RapidTriage can ingest evidence directly from any of these URI schemes:

```bash
rt ingest --source s3://my-bucket/case/collection.tar.gz
rt ingest --source sftp://analyst@10.0.1.5/evidence/
rt ingest --source gdrive://1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms
```

| Scheme | Backend | Auth env vars |
|--------|---------|---------------|
| **Cloud object storage** | | |
| `s3://bucket/key` | AWS S3, MinIO, R2, Wasabi | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION` |
| `gcs://bucket/object` | Google Cloud Storage | `GOOGLE_APPLICATION_CREDENTIALS` |
| `azblob://container/blob` | Azure Blob Storage | `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_ACCESS_KEY` |
| `azdls://filesystem/path` | Azure Data Lake Gen2 | `AZURE_STORAGE_ACCOUNT`, `AZDLS_ENDPOINT` |
| `azfile://share/path` | Azure Files | `AZURE_STORAGE_ACCOUNT`, `AZFILE_ENDPOINT` |
| `b2://bucket/key` | Backblaze B2 | `BACKBLAZE_APPLICATION_KEY_ID`, `BACKBLAZE_APPLICATION_KEY` |
| `cos://bucket/key` | Tencent Cloud COS | `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`, `TENCENTCLOUD_REGION` |
| `obs://bucket/key` | Huawei Cloud OBS | `HUAWEI_ACCESS_KEY_ID`, `HUAWEI_SECRET_ACCESS_KEY`, `HUAWEI_REGION` |
| `oss://bucket/key` | Alibaba Cloud OSS | `ALIBABA_CLOUD_ACCESS_KEY_ID`, `ALIBABA_CLOUD_ACCESS_KEY_SECRET` |
| `swift://container/path` | OpenStack Swift | `SWIFT_ENDPOINT`, `SWIFT_TOKEN` |
| `upyun://bucket/key` | Upyun CDN storage | `UPYUN_OPERATOR`, `UPYUN_PASSWORD` |
| **Cloud drives** | | |
| `gdrive://file-id` | Google Drive | OAuth2 / service account (interactive or `GOOGLE_APPLICATION_CREDENTIALS`) |
| `onedrive://path` | Microsoft OneDrive | `ONEDRIVE_ACCESS_TOKEN` |
| `dropbox://path` | Dropbox | `DROPBOX_ACCESS_TOKEN` |
| `aliyun-drive://path` | Aliyun Drive | `ALIYUN_DRIVE_ACCESS_TOKEN` |
| `yandex-disk://path` | Yandex Disk | `YANDEX_DISK_ACCESS_TOKEN` |
| `pcloud://path` | pCloud | `PCLOUD_USERNAME`, `PCLOUD_PASSWORD` |
| `koofr://path` | Koofr | `KOOFR_EMAIL`, `KOOFR_PASSWORD` |
| `seafile://server/repo/path` | Seafile | `SEAFILE_USERNAME`, `SEAFILE_PASSWORD` |
| **Developer / ML / infra** | | |
| `github://owner/repo/path` | GitHub (code forensics) | `GITHUB_TOKEN` |
| `huggingface://owner/repo/path` | HuggingFace datasets | `HUGGINGFACE_TOKEN` |
| `vercel-blob://key` | Vercel Blob | `BLOB_READ_WRITE_TOKEN` |
| `vercel-artifacts://key` | Vercel build cache | `VERCEL_ARTIFACTS_TOKEN` |
| `ghac://key` | GitHub Actions Cache | auto (CI environment) |
| `dbfs://path` | Databricks DBFS | `DATABRICKS_HOST`, `DATABRICKS_TOKEN` |
| **Distributed / big data** | | |
| `alluxio://host:port/path` | Alluxio data orchestration | — |
| `webhdfs://namenode:port/path` | WebHDFS REST API | `WEBHDFS_USER` |
| `hdfs://namenode:port/path` | HDFS native (pure Rust, no JVM) | — |
| `lakefs://repo/branch/path` | LakeFS data versioning | `LAKEFS_ACCESS_KEY_ID`, `LAKEFS_SECRET_ACCESS_KEY`, `LAKEFS_ENDPOINT` |
| **Decentralized** | | |
| `ipfs://CID/path` | IPFS (read-only, content-addressed) | `IPFS_GATEWAY` |
| `ipmfs:///path` | IPFS Mutable File System | `IPFS_ENDPOINT` |
| **Network KV / databases** | | |
| `redis://host:port/key` | Redis | endpoint in URI |
| `rediss://host:port/key` | Redis over TLS | endpoint in URI |
| `memcached://host:port/key` | Memcached | — |
| `etcd://host:port/key` | etcd | — |
| `tikv://pd-host:port/key` | TiKV distributed KV | — |
| `mongodb://host/db/collection/key` | MongoDB | credentials in URI |
| `gridfs://host/db/bucket/key` | MongoDB GridFS | credentials in URI |
| `mysql://host/db/key` | MySQL / MariaDB | credentials in URI |
| `postgresql://host/db/key` | PostgreSQL | credentials in URI |
| `sqlite:///path/to/db.sqlite/key` | SQLite | — |
| `cloudflare-kv://namespace/key` | Cloudflare KV | `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` |
| `d1://database-id/key` | Cloudflare D1 | `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` |
| **Filesystem / network protocols** | | |
| `file:///abs/path` | Local filesystem | — |
| `http://host/path` | HTTP (read-only) | — |
| `https://host/path` | HTTPS (read-only) | — |
| `webdav://host/path` | WebDAV | — |
| `sftp://user@host/path` | SFTP | SSH agent / `RT_SFTP_KEY_PATH`, `RT_SFTP_KNOWN_HOSTS_STRATEGY` |
| `ftp://user:pass@host/path` | FTP | credentials in URI |
| `ftps://user:pass@host/path` | FTPS (FTP over TLS) | credentials in URI |
| `mem://path` | In-process memory (testing) | — |

All backends use [OpenDAL](https://opendal.apache.org/) — the same operator interface regardless of where evidence lives. Read and write are both supported except where noted (HTTP/HTTPS and IPFS are read-only).

---

## Contributing

PRs welcome. The most valuable contributions right now:

- New Correlation Rules (add to `crates/rt-correlation/rules/`)
- Additional artifact parsers (implement the `rt-plugin-sdk` trait)
- Platform-specific memory analysis improvements

Please open an issue before large changes so we can align on approach.

```bash
git clone https://github.com/SecurityRonin/rapidtriage
cd rapidtriage
cargo test --workspace
```

All crates follow strict TDD — write failing tests first, then the implementation.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

**Found this useful?** [Sponsor development](https://github.com/sponsors/h4x0r) to keep the threat intel feeds updated and new parsers shipping.
