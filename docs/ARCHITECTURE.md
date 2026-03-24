# Architecture

This document describes RapidTriage's architecture using progressive disclosure. Start with the overview, then drill into subsystems as needed.

## Overview

RapidTriage transforms forensic evidence collections into structured timelines and assessment findings. Evidence goes in, a DuckDB database with parsed events, signature matches, and remote access detections comes out.

```mermaid
flowchart LR
    Evidence["Evidence Collection\n(KAPE, Velociraptor,\nraw image)"]
    Pipeline["rt-pipeline\nIngestion"]
    Timeline["rt-timeline\nDuckDB Store"]
    Sigs["rt-signatures\nThreat Intel"]
    RA["rt-remote-access\nRemote Access"]
    Report["rt-report\nHTML Output"]
    CLI["rt-cli"]

    CLI --> Pipeline
    CLI --> Sigs
    CLI --> RA
    CLI --> Report
    Evidence --> Pipeline
    Pipeline --> Timeline
    Sigs --> Timeline
    RA --> Timeline
    Timeline --> Report
```

The CLI (`rt`) is the entry point. It dispatches to four subsystems: the ingestion pipeline, signature scanning, remote access detection, and report generation. All subsystems write to or read from a shared DuckDB timeline database.

## Workspace Structure

14 crates in a Cargo workspace, organized by responsibility:

```mermaid
graph TD
    subgraph CLI["CLI Layer"]
        rt-cli
    end

    subgraph Assessment["Assessment Layer"]
        rt-signatures
        rt-remote-access
    end

    subgraph Pipeline["Pipeline Layer"]
        rt-pipeline
        rt-report
    end

    subgraph Storage["Storage Layer"]
        rt-timeline
    end

    subgraph Parsers["Parser Plugins"]
        rt-parser-usnjrnl
        rt-parser-mft
        rt-parser-evtx
    end

    subgraph Foundation["Foundation"]
        rt-core
        rt-plugin-sdk
        rt-ewf
        rt-shrinkpath
    end

    rt-cli --> rt-pipeline
    rt-cli --> rt-signatures
    rt-cli --> rt-remote-access
    rt-cli --> rt-report
    rt-pipeline --> rt-timeline
    rt-pipeline --> rt-core
    rt-pipeline --> rt-plugin-sdk
    rt-signatures --> rt-core
    rt-remote-access --> rt-core
    rt-remote-access --> rt-timeline
    rt-report --> rt-timeline
    rt-report --> rt-core
    rt-timeline --> rt-core
    rt-parser-usnjrnl --> rt-core
    rt-parser-usnjrnl --> rt-plugin-sdk
    rt-parser-mft --> rt-core
    rt-parser-mft --> rt-plugin-sdk
    rt-parser-evtx --> rt-core
    rt-parser-evtx --> rt-plugin-sdk
    rt-pipeline --> rt-ewf
```

**Dependency rule:** Arrows point downward. Higher layers depend on lower layers, never the reverse. `rt-core` has no internal dependencies.

### Crate Responsibilities

| Crate | Layer | Responsibility |
|-------|-------|---------------|
| `rt-core` | Foundation | Shared types (`TimelineEvent`, `ArtifactType`, `EventType`), plugin traits, error types, configuration |
| `rt-plugin-sdk` | Foundation | Parser plugin registration via `inventory` crate. Parsers register themselves at compile time |
| `rt-ewf` | Foundation | Expert Witness Format (E01) forensic image reading |
| `rt-shrinkpath` | Foundation | Windows path normalization and shortening |
| `rt-timeline` | Storage | DuckDB columnar timeline store. Insert events, query by time/type/source, export to SQLite |
| `rt-pipeline` | Pipeline | Evidence ingestion orchestration. Discovers parseable files, dispatches parsers via rayon, writes events to timeline |
| `rt-report` | Pipeline | Self-contained HTML report generation from timeline data |
| `rt-signatures` | Assessment | Six detection engines (YARA, Sigma, Hash IOC, Network IOC, STIX, Suricata) + feed infrastructure |
| `rt-remote-access` | Assessment | Remote access detection: LOLRMM rule engine + 7 category scanners + DuckDB findings store |
| `rt-parser-*` | Parsers | Individual artifact parsers (USN Journal, MFT, Event Logs). Each registers via `inventory::submit!` |
| `rt-cli` | CLI | Command-line interface. Parses args, dispatches to subsystems, formats output |
| `xtask` | Build | Build automation tasks |

---

## Ingestion Pipeline

The pipeline ingests an evidence collection and produces a DuckDB timeline. It uses a layered architecture where each layer handles one level of abstraction.

```mermaid
flowchart TD
    Input["Evidence Path\n/path/to/collection/"]
    L4["Layer 4: Artifact Parsing\n(rayon parallel dispatch)"]
    USN["USN Journal\nParser"]
    MFT["MFT\nParser"]
    EVTX["Event Log\nParser"]
    Future["Future\nParsers..."]
    TL["rt-timeline\nDuckDB Insert"]

    Input --> L4
    L4 --> USN
    L4 --> MFT
    L4 --> EVTX
    L4 --> Future
    USN --> TL
    MFT --> TL
    EVTX --> TL
    Future --> TL
```

### Plugin System

Parsers register themselves at compile time using the `inventory` crate. The pipeline discovers registered parsers at runtime without hardcoded dispatch:

```rust
// In rt-parser-usnjrnl:
inventory::submit! {
    ParserPlugin::new("usnjrnl", &["$UsnJrnl:$J"], parse_usnjrnl)
}

// In rt-pipeline:
for plugin in inventory::iter::<ParserPlugin> {
    if plugin.can_parse(file_path) {
        plugin.parse(file_path, &timeline)?;
    }
}
```

Adding a new parser means creating a new crate, implementing the trait, and linking it — no changes to the pipeline.

### Timeline Schema

All parsed events become `TimelineEvent` records in DuckDB:

| Column | Type | Description |
|--------|------|-------------|
| `timestamp` | `TIMESTAMP_NS` | Event time (nanosecond precision) |
| `event_type` | `VARCHAR` | `FileCreate`, `FileDelete`, `ProcessExec`, `LogonEvent`, ... |
| `source` | `VARCHAR` | Artifact type: `UsnJournal`, `MFT`, `EventLog`, ... |
| `path` | `VARCHAR` | File path or event identifier |
| `description` | `VARCHAR` | Human-readable event summary |
| `evidence_source` | `VARCHAR` | Case/host identifier |
| `metadata` | `VARCHAR` (JSON) | Artifact-specific structured data |

DuckDB's columnar storage makes time-range and type-filtered queries fast, even with millions of events.

---

## Signature Scanning

`rt-signatures` provides six detection engines behind a unified `ScanEngine` interface.

```mermaid
flowchart TD
    ScanEngine["ScanEngine\n(unified orchestrator)"]
    YARA["YARA Engine\n(yara-x)"]
    Sigma["Sigma Engine\n(tau-engine)"]
    Hash["Hash IOC\nEngine"]
    Net["Network IOC\nEngine"]
    STIX["STIX 2.1\nEngine"]
    Suri["Suricata\nIOC Extractor"]
    Feeds["Feed Registry\n+ Cache"]
    Findings["ScanFinding"]

    ScanEngine --> YARA
    ScanEngine --> Sigma
    ScanEngine --> Hash
    ScanEngine --> Net
    ScanEngine --> STIX
    ScanEngine --> Suri
    Feeds --> ScanEngine
    YARA --> Findings
    Sigma --> Findings
    Hash --> Findings
    Net --> Findings
    STIX --> Findings
    Suri --> Findings
```

### Engine Details

| Engine | Input | Matching Strategy |
|--------|-------|-------------------|
| YARA | File bytes | Pattern matching via yara-x. Compiles rules once, scans files in parallel |
| Sigma | Timeline events | Converts events to field maps, evaluates detection logic via tau-engine |
| Hash IOC | File hashes | MD5/SHA-1/SHA-256 lookup in HashSet. Hashes computed on-the-fly |
| Network IOC | Event metadata | IP, domain, CIDR matching against string fields in event metadata |
| STIX 2.1 | Files + events | Extracts indicators from STIX bundles, dispatches to hash/network engines |
| Suricata | Rule files | Parses Suricata syntax to extract IPs, domains, ports as network IOCs |

### Feed Infrastructure

Threat intelligence feeds are downloaded, cached locally, and loaded into engines automatically:

```mermaid
flowchart LR
    Registry["Feed Registry\n(built-in configs)"]
    HTTP["HTTP Downloader\n(reqwest, ETag caching)"]
    Cache["Local Feed Cache\n(~/.rapidtriage/feeds/)"]
    Parsers["Feed Parsers\n(plaintext, CSV, JSON, STIX)"]
    Loader["Feed-to-Engine\nLoader"]
    ScanEngine["ScanEngine"]

    Registry --> HTTP
    HTTP --> Cache
    Cache --> Parsers
    Parsers --> Loader
    Loader --> ScanEngine
```

Conditional HTTP requests (ETag / If-None-Match) avoid re-downloading unchanged feeds. Each feed has a format parser that extracts indicators into the appropriate engine.

---

## Remote Access Detection

`rt-remote-access` uses a hybrid detection engine to find every category of remote access capability in forensic evidence.

```mermaid
flowchart TD
    scan["scan(provider, config)"]

    subgraph Phase1["Phase 1: Rule Engine"]
        LOLRMM["LOLRMM YAML\n(294 RMM tools)"]
        Custom["Custom YAML\n(VPN/ZTNA/Hardware)"]
        Compile["Compile to\nDetectionRule"]
        Eval["Evaluate against\nArtifactProvider"]
    end

    subgraph Phase2["Phase 2: Category Scanners"]
        Builtin["Built-in Remote\n(RDP/SSH)"]
        Lateral["Lateral Movement\n(PsExec/WMI)"]
        Tunnel["Tunneling\n(ngrok/cloudflared)"]
        C2["C2 Frameworks"]
        WebShell["Web Shells"]
        Firewall["Firewall Config"]
        Hardware["Hardware Remote\n(iLO/iDRAC)"]
    end

    Phase3["Phase 3: Merge\n(deduplicate by tool + category)"]
    Result["ScanResult\n{findings, capabilities, categories}"]

    scan --> Phase1
    LOLRMM --> Compile
    Custom --> Compile
    Compile --> Eval
    scan --> Phase2
    Eval --> Phase3
    Builtin --> Phase3
    Lateral --> Phase3
    Tunnel --> Phase3
    C2 --> Phase3
    WebShell --> Phase3
    Firewall --> Phase3
    Hardware --> Phase3
    Phase3 --> Result
```

### ArtifactProvider Trait

The scanner doesn't read forensic artifacts directly. Instead, it queries an `ArtifactProvider` trait that abstracts over available data sources:

```rust
pub trait ArtifactProvider: Send + Sync {
    fn capabilities(&self) -> Vec<ProviderCapability>;
    fn registry_values(&self, path: &str) -> Result<Vec<RegistryEntry>>;
    fn event_log_entries(&self, log_name: &str) -> Result<Vec<EventLogEntry>>;
    fn prefetch_entries(&self) -> Result<Vec<PrefetchEntry>>;
    fn file_exists(&self, path: &str) -> Result<bool>;
    // ... 12 methods total, all with default empty implementations
}
```

**Graceful degradation:** Every method has a default implementation returning empty results. If the evidence lacks Event Logs, event-based scanners silently skip rather than error. The `capabilities()` method reports what data is available, and the evaluator checks capabilities before attempting queries.

**CompositeArtifactProvider** aggregates specialized sub-providers (registry, filesystem, event log) into a single provider, delegating calls based on capability.

### Detection Flow

**Rule engine** (Phase 1): LOLRMM YAML definitions describe what artifacts each RMM tool leaves behind (registry keys, file paths, services, event log entries). These are compiled into `DetectionRule` structs with `DetectionCondition` variants:

```
LOLRMM YAML ──> compile_lolrmm() ──> DetectionRule {
    conditions: [
        RegistryKeyExists("HKLM\\SOFTWARE\\AnyDesk"),
        FilePathExists("C:\\Program Files\\AnyDesk\\*"),
        ServiceName("AnyDesk"),
        EventLogSource("AnyDesk"),
    ]
}
```

The evaluator tests each condition against the provider, producing a `Finding` with raw artifact hits when any condition matches.

**Category scanners** (Phase 2): For detection that requires correlation or behavioral analysis (e.g., "RDP is enabled AND NLA is disabled AND firewall allows 3389"), dedicated scanner modules implement the `CategoryScanner` trait.

### Findings Storage

Findings are stored in a DuckDB `findings` table and cross-referenced into the timeline as `Assessment` events:

```mermaid
flowchart LR
    Finding["Finding\n{tool, category, artifacts}"]
    FTable["findings table\n(DuckDB)"]
    XRef["Cross-reference\nevent"]
    Timeline["Timeline\n(chronological view)"]

    Finding --> FTable
    Finding --> XRef
    XRef --> Timeline
```

This gives analysts two views: the findings table for assessment-oriented queries ("what remote access tools were found?") and the timeline for chronological context ("when did AnyDesk first appear relative to the intrusion?").

---

## Report Generation

`rt-report` generates self-contained HTML reports from a DuckDB timeline database. Reports include:

- Case metadata (case ID, examiner, generation timestamp)
- Event timeline with filtering and sorting
- Signature findings summary
- Evidence source breakdown

Reports are single HTML files with embedded CSS — no external dependencies, suitable for email attachment or upload to case management systems.

---

## Data Flow

End-to-end flow for a typical incident response engagement:

```mermaid
sequenceDiagram
    participant User as Practitioner
    participant CLI as rt (CLI)
    participant Pipeline as rt-pipeline
    participant Timeline as rt-timeline (DuckDB)
    participant Sigs as rt-signatures
    participant RA as rt-remote-access
    participant Report as rt-report

    User->>CLI: rt ingest /evidence -o case.duckdb --scan
    CLI->>Pipeline: ingest(path, db)
    Pipeline->>Pipeline: Discover parseable files
    Pipeline->>Pipeline: Parse artifacts (parallel via rayon)
    Pipeline->>Timeline: Insert TimelineEvents
    CLI->>Sigs: scan(timeline_events, engines)
    Sigs->>Timeline: Insert ScanFindings
    CLI-->>User: Ingestion complete (N events, M findings)

    User->>CLI: rt remote-access /evidence --db case.duckdb
    CLI->>RA: scan(provider, config)
    RA->>RA: Rule engine (LOLRMM + custom YAML)
    RA->>RA: Category scanners (7 modules)
    RA->>RA: Merge findings
    RA->>Timeline: Insert findings + cross-ref events
    CLI-->>User: Remote access findings (table/JSON)

    User->>CLI: rt timeline case.duckdb --flagged
    CLI->>Timeline: Query flagged events
    CLI-->>User: Findings with severity and context

    User->>CLI: rt report case.duckdb -o report.html
    CLI->>Report: generate(db, config)
    Report->>Timeline: Read events + findings
    Report-->>User: Self-contained HTML report
```

---

## Design Principles

**Correctness over speed.** Forensic accuracy is non-negotiable. Rust's type system and `unsafe_code = "deny"` enforce memory safety. `clippy::unwrap_used = "deny"` prevents silent panics. When speed and correctness conflict, correctness wins.

**Graceful degradation.** Missing artifacts produce coverage gaps, not crashes. Every parser failure is caught and logged. The pipeline continues with whatever data is available. Partial results with explicit warnings are more valuable than no results.

**Evidence integrity.** RapidTriage never modifies source evidence. All data flows from evidence into new DuckDB databases. Read-only access to evidence is enforced by design.

**Plugin extensibility.** New artifact parsers are added by creating a crate, implementing the plugin trait, and linking it. No changes to the pipeline, timeline, or CLI are required.

**Progressive analysis.** Each command produces useful output independently. `rt ingest` creates a timeline. `rt scan` adds threat intel. `rt remote-access` adds infrastructure assessment. `rt report` generates deliverables. Run them all or run them individually.

---

## Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `duckdb` | 1.x (bundled) | Columnar timeline storage, analytical queries |
| `yara-x` | 0.12 | YARA rule compilation and file scanning |
| `tau-engine` | 1.x | Sigma rule evaluation |
| `notatin` | 1.0 | Windows registry hive parsing |
| `evtx` | 0.11 | Windows Event Log parsing |
| `mft` | 0.6 | NTFS Master File Table parsing |
| `usnjrnl-forensic` | 0.6 | USN Change Journal parsing |
| `ewf` | 0.1 | Expert Witness Format (E01) image support |
| `clap` | 4.x | CLI argument parsing |
| `rayon` | 1.x | Parallel parser dispatch |
| `reqwest` | 0.12 | HTTP feed downloads (rustls-tls) |
| `serde` / `serde_yaml` | 1.x / 0.9 | LOLRMM YAML deserialization |
| `tracing` | 0.1 | Structured logging and diagnostics |

---

## Build and Test

```bash
# Full build
cargo build --workspace --release

# Full test suite
cargo test --workspace

# Single crate
cargo test -p rt-remote-access
cargo test -p rt-signatures

# Lints
cargo clippy --workspace --lib --bins
```

Minimum Rust version: 1.80. C compiler required for bundled DuckDB.
