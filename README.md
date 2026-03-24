# RapidTriage

Fast forensic triage for incident responders. Ingest evidence collections, build timelines, scan for threats, detect remote access infrastructure, and generate reports — from the command line.

RapidTriage takes output from collection tools (KAPE, Velociraptor, ACQUIRE, or raw disk images) and turns it into a queryable DuckDB timeline enriched with signature matches and remote access findings. Designed for practitioners who need answers fast and reports that non-technical stakeholders can act on.

## Who This Is For

**Incident Response Firms** — Triage multiple cases in parallel. Ingest a KAPE collection, scan against YARA/Sigma/STIX threat intelligence, detect 260+ remote access tools via LOLRMM, and have a structured timeline with flagged findings before your first call with the client.

**Digital Forensics Practitioners** — Parse Windows artifacts (USN Journal, MFT, Event Logs, Prefetch, Registry, Amcache, LNK, Jump Lists) into a unified DuckDB timeline. Export to SQLite for portable case files. Generate self-contained HTML reports with case metadata.

**Law Firms and Liquidators** — Run initial triage to gauge the scale and severity of a matter before engaging specialist firms. RapidTriage surfaces remote access tools, lateral movement indicators, C2 frameworks, and web shells across evidence images. Results come with caveats (false positives and negatives are inherent to automated triage), but provide an informed basis for resourcing decisions and scoping forensic engagements.

## What It Does

```
Evidence Collection         RapidTriage                    Output
 (KAPE, Velociraptor,       ┌──────────────────────┐
  ACQUIRE, raw image)  ───> │ Parse artifacts       │ ──> DuckDB timeline
                            │ Build timeline        │ ──> Signature findings
                            │ Scan signatures       │ ──> Remote access assessment
                            │ Detect remote access  │ ──> HTML report
                            │ Generate report       │ ──> SQLite export
                            └──────────────────────┘
```

### Artifact Parsing

| Artifact | Source | What It Extracts |
|----------|--------|-----------------|
| USN Journal | `$UsnJrnl:$J` | File create/delete/rename/close events with timestamps |
| MFT | `$MFT` | File metadata, timestamps (MACE), path reconstruction |
| Event Logs | `.evtx` files | Security, System, Application events with structured data |
| Prefetch | `.pf` files | Program execution history with run counts and timestamps |
| Registry | Hive files | Configuration, installed software, user activity |
| Amcache | `Amcache.hve` | Program execution evidence with SHA-1 hashes |
| LNK | `.lnk` files | Shortcut targets, access timestamps, volume info |
| Jump Lists | `AutomaticDestinations` | Recent/frequent application file access |

### Signature Scanning

Six detection engines scan files and timeline events against threat intelligence:

- **YARA** — Pattern matching against file content (yara-x)
- **Sigma** — Detection rules against timeline events (tau-engine)
- **Hash IOCs** — MD5/SHA-1/SHA-256 indicator matching
- **Network IOCs** — IP, domain, and CIDR indicator matching against event metadata
- **STIX 2.1** — Structured threat intelligence bundles (indicators, malware, attack patterns)
- **Suricata** — Network IOC extraction from ET Open / Suricata rules

### Remote Access Detection

Scans evidence for every category of remote access capability:

| Category | Detection Method | Examples |
|----------|-----------------|----------|
| Commercial RMM | 294 LOLRMM YAML rules | AnyDesk, TeamViewer, ConnectWise, Splashtop, ... |
| Built-in Remote | Configuration assessment | RDP, SSH, WinRM, VNC |
| VPN/ZTNA | Custom YAML rules | Tailscale, WireGuard, OpenVPN |
| Tunneling | Behavioral detection | ngrok, cloudflared, netsh portproxy |
| Lateral Movement | Event log correlation | PsExec (7045), WMI (5857), Kerberoasting (4769) |
| C2 Frameworks | Service + named pipe patterns | Cobalt Strike, Sliver, Metasploit, ... |
| Web Shells | Filesystem scanning | IIS/Apache/nginx web root anomalies |
| Firewall Config | Registry assessment | Profile enable/disable, rule modifications |
| Hardware Remote | Indicator detection | iLO, iDRAC, IPMI, Intel AMT |

### Feed Management

Download and cache threat intelligence feeds. Built-in feed registry with conditional HTTP requests (ETag/If-None-Match) for efficient updates.

```bash
rt feed update    # Download all enabled feeds
rt feed list      # Show feed status and cache freshness
rt feed info kev  # Details for a specific feed
```

## Quick Start

### Build

```bash
git clone https://github.com/SecurityRonin/rapidtriage.git
cd rapidtriage
cargo build --release
```

Requires Rust 1.80+ and a C compiler (for bundled DuckDB).

### Ingest Evidence

```bash
# Parse a KAPE collection into a DuckDB timeline
rt ingest /path/to/kape/output -o case001.duckdb

# Ingest with signature scanning
rt ingest /path/to/evidence -o case001.duckdb \
  --yara-rules ./rules/yara/ \
  --sigma-rules ./rules/sigma/ \
  --hash-iocs ./iocs/hashes.txt

# Ingest with case metadata
rt ingest /path/to/evidence -o case001.duckdb \
  -s "CASE-2026-0042 / WORKSTATION-PC"
```

### Query the Timeline

```bash
# View latest events
rt timeline case001.duckdb -n 100 --descending

# Filter by artifact type
rt timeline case001.duckdb --source EventLog -n 50

# View flagged findings from signature scans
rt timeline case001.duckdb --flagged

# Export to SQLite for portability
rt timeline case001.duckdb --export-sqlite case001.sqlite
```

### Scan for Threats

```bash
# Scan files against threat intelligence
rt scan /path/to/files --yara-rules ./rules/ --sigma-rules ./sigma/

# Scan with auto-loaded cached feeds
rt scan /path/to/files --auto-feeds

# Scan with STIX bundle
rt scan /path/to/files --stix-bundle ./stix/apt28.json
```

### Detect Remote Access

```bash
# Scan evidence for remote access infrastructure
rt remote-access /path/to/evidence

# Use vendored LOLRMM rules (294 RMM tools)
rt remote-access /path/to/evidence --rules-dir ./data/lolrmm/

# JSON output for integration with other tools
rt remote-access /path/to/evidence --format json

# Persist findings to DuckDB
rt remote-access /path/to/evidence --db case001.duckdb
```

### Generate Reports

```bash
# Self-contained HTML report
rt report case001.duckdb -o report.html

# With case metadata
rt report case001.duckdb -o report.html \
  --case-id "CASE-2026-0042" \
  --examiner "J. Smith"
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture guide with diagrams.

RapidTriage is a Rust workspace with 14 crates:

| Crate | Purpose |
|-------|---------|
| `rt-core` | Shared types, plugin traits, timeline schema |
| `rt-pipeline` | Evidence ingestion orchestration (Layer 0-4) |
| `rt-timeline` | DuckDB timeline store, queries, SQLite export |
| `rt-signatures` | YARA, Sigma, STIX, IOC, Suricata engines + feed infrastructure |
| `rt-remote-access` | Remote access detection (LOLRMM, category scanners, findings store) |
| `rt-report` | HTML report generation |
| `rt-cli` | Command-line interface (`rt`) |
| `rt-ewf` | Expert Witness Format (E01) image support |
| `rt-shrinkpath` | Windows path normalization |
| `rt-plugin-sdk` | Plugin registration (inventory crate) |
| `rt-parser-usnjrnl` | USN Journal parser |
| `rt-parser-mft` | MFT parser |
| `rt-parser-evtx` | Event Log parser |
| `xtask` | Build automation |

## Development

```bash
# Run all tests (495 tests)
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Run lints
cargo clippy --workspace --lib --bins

# Build in release mode
cargo build --release
```

Workspace enforces `unsafe_code = "deny"` and `clippy::unwrap_used = "deny"`.

## License

Apache-2.0

## Limitations

RapidTriage is automated triage tooling. It is not a substitute for expert forensic analysis.

- **False positives** — Signature matches and remote access detections can produce false positives, particularly in environments with legitimate RMM deployments or overlapping service names.
- **False negatives** — Absence of findings does not prove absence of compromise. Anti-forensic techniques, log clearing, and artifacts outside the parsed set will not be detected.
- **Not a collection tool** — RapidTriage processes evidence already collected by tools like KAPE, Velociraptor, or ACQUIRE. It does not perform live acquisition.
- **Windows-focused** — Current artifact parsers target Windows forensic artifacts. Linux/macOS support is planned.

Results should be reviewed by qualified practitioners and corroborated with additional analysis before being relied upon in legal proceedings or remediation decisions.
