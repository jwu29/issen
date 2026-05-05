# Signature Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the rt-signatures crate into the forensic pipeline so files are scanned during ingest, findings are stored in the timeline, feeds can be downloaded from the internet, and Suricata rules are supported.

**Architecture:** Five features that build on each other: (1) Suricata engine adds network detection rules, (2) Feed-to-Engine loader wires cached feeds into ScanEngine, (3) Feed downloading enables HTTP fetch + cache, (4) Pipeline integration runs scans during ingest and tags events, (5) Timeline enrichment stores findings in DuckDB and exposes them via CLI queries.

**Tech Stack:** Rust, yara-x, tau-engine, reqwest (new), DuckDB, clap, serde

---

### Task 1: Suricata Rule Parser

**Files:**
- Create: `crates/rt-signatures/src/engines/suricata.rs`
- Modify: `crates/rt-signatures/src/engines/mod.rs`

Suricata rules contain network IOCs (IPs, ports, domains) embedded in rule syntax. We parse these to extract indicators and feed them into `NetworkIocStore`. We do NOT execute Suricata rules against PCAP — we mine them for IOCs.

- [ ] **Step 1: Add module declaration**

In `crates/rt-signatures/src/engines/mod.rs`, add:
```rust
pub mod suricata;
```

- [ ] **Step 2: Write failing tests for rule parsing**

Create `crates/rt-signatures/src/engines/suricata.rs` with test module first:

```rust
// Suricata/ET Open rule parser for network IOC extraction.
//
// Parses Suricata rule syntax to extract source/destination IPs,
// domains (from content matches), and ports. Does NOT execute rules
// against traffic — only mines them for threat intelligence.

use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SuricataError {
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A network indicator extracted from a Suricata rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuricataIoc {
    Ip(String),
    Network(String),     // CIDR
    Domain(String),      // from content/dns.query
    Port(u16),
}

/// Metadata from a parsed Suricata rule.
#[derive(Debug, Clone)]
pub struct SuricataRule {
    pub sid: u64,
    pub msg: String,
    pub iocs: Vec<SuricataIoc>,
    pub classtype: Option<String>,
    pub reference: Vec<String>,
}

/// Parse Suricata rules and extract network IOCs.
pub struct SuricataParser;

impl SuricataParser {
    /// Parse a single Suricata rule line.
    pub fn parse_rule(line: &str) -> Result<Option<SuricataRule>, SuricataError> {
        todo!()
    }

    /// Parse a rules file (one rule per line). Returns successfully parsed rules.
    pub fn parse_file(path: &Path) -> Result<Vec<SuricataRule>, SuricataError> {
        todo!()
    }

    /// Parse rules from a string (one rule per line).
    pub fn parse_rules(data: &str) -> Vec<SuricataRule> {
        todo!()
    }

    /// Extract all IOCs from parsed rules into a NetworkIocStore.
    pub fn extract_to_network_store(
        rules: &[SuricataRule],
        store: &mut crate::engines::ioc_network::NetworkIocStore,
    ) -> usize {
        todo!()
    }
}
```

Write tests covering:
1. Parse basic alert rule with src/dst IPs
2. Parse rule with `$HOME_NET` / `$EXTERNAL_NET` variables (skip)
3. Parse rule with content match containing domain
4. Parse rule with CIDR network
5. Parse rule with sid and msg extraction
6. Parse rule with classtype and reference
7. Skip comment lines (starting with #)
8. Skip empty lines
9. Parse multiple rules from string
10. Parse rules file from disk
11. Extract IOCs into NetworkIocStore
12. Rule with `any` IP/port (skip, no IOC value)
13. Parse rule with dns.query content

- [ ] **Step 3: Run tests — verify RED**

```bash
cargo test -p rt-signatures --lib engines::suricata
```
Expected: FAIL — `todo!()` panics

- [ ] **Step 4: Implement SuricataParser**

Parsing approach:
- Split rule into header (`alert tcp ...`) and options (`(msg:"..."; sid:123; ...)`)
- Header: `action protocol src_ip src_port -> dst_ip dst_port`
- Extract IPs/CIDRs from src/dst (skip variables like `$HOME_NET`, `any`)
- Extract domains from `content:"..."` patterns in options
- Extract `dns.query` content matches as domains
- Extract sid, msg, classtype, reference from options

- [ ] **Step 5: Run tests — verify GREEN**

```bash
cargo test -p rt-signatures --lib engines::suricata
```
Expected: All PASS

- [ ] **Step 6: Commit**

---

### Task 2: Feed-to-Engine Loader

**Files:**
- Create: `crates/rt-signatures/src/feeds/loader.rs`
- Modify: `crates/rt-signatures/src/feeds/mod.rs`

This module bridges the gap between cached feed data and the ScanEngine. Given a FeedRegistry and FeedCache, it reads cached feeds, parses them using the appropriate parser, and populates IOC stores or loads YARA/Sigma rules.

- [ ] **Step 1: Add module declaration**

In `crates/rt-signatures/src/feeds/mod.rs`, add:
```rust
pub mod loader;
```

- [ ] **Step 2: Write failing tests**

Create `crates/rt-signatures/src/feeds/loader.rs` with:

```rust
// Feed-to-engine loader.
//
// Bridges cached feed data and the ScanEngine by reading cached feeds,
// parsing them with the appropriate parser, and building a configured
// ScanEngine with all available threat intelligence.

use std::path::Path;
use thiserror::Error;

use crate::engines::ioc_hash::HashIocStore;
use crate::engines::ioc_network::NetworkIocStore;
use crate::feeds::config::{FeedFormat, FeedIndicatorType, FeedRegistry};
use crate::feeds::fetcher::FeedCache;
use crate::matching::engine::ScanEngine;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("Feed error: {0}")]
    Feed(#[from] crate::feeds::fetcher::FeedError),
    #[error("Parse error: {0}")]
    Parse(#[from] crate::feeds::parsers::FeedParseError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Summary of what was loaded from feeds.
#[derive(Debug, Clone, Default)]
pub struct LoadSummary {
    pub feeds_loaded: usize,
    pub feeds_skipped: usize,
    pub hash_indicators: usize,
    pub network_indicators: usize,
    pub kev_vulnerabilities: usize,
}

/// Load all cached feeds from a registry into a ScanEngine.
pub fn load_cached_feeds(
    registry: &FeedRegistry,
    cache: &FeedCache,
) -> Result<(ScanEngine, LoadSummary), LoaderError> {
    todo!()
}
```

Tests:
1. Empty registry returns empty engine and zero summary
2. Registry with uncached feeds returns zero loads, all skipped
3. Load plaintext hash feed from cache
4. Load plaintext network feed from cache
5. Load ThreatFox CSV feed from cache
6. Load CISA KEV feed from cache
7. Mixed feeds — some cached, some not
8. Summary counts are correct
9. Disabled feeds are skipped

- [ ] **Step 3: Run tests — verify RED**

- [ ] **Step 4: Implement load_cached_feeds**

Logic:
- Iterate enabled feeds in registry
- For each: check if cached, skip if not
- Match on FeedFormat + FeedIndicatorType to pick parser
- PlainText + Hash → parse_plaintext_hashes into HashIocStore
- PlainText + Ip/Domain → parse_plaintext_network into NetworkIocStore
- CsvAbuseCh → parse_threatfox_csv
- JsonCisaKev → parse_cisa_kev
- Accumulate stores, build ScanEngine

- [ ] **Step 5: Run tests — verify GREEN**

- [ ] **Step 6: Commit**

---

### Task 3: Feed Downloading (HTTP Fetcher)

**Files:**
- Modify: `Cargo.toml` (root — add `reqwest = { version = "0.12", features = ["blocking"] }`)
- Modify: `crates/rt-signatures/Cargo.toml` (add reqwest dep)
- Create: `crates/rt-signatures/src/feeds/downloader.rs`
- Modify: `crates/rt-signatures/src/feeds/mod.rs`
- Create: `crates/rt-cli/src/commands/feed.rs`
- Modify: `crates/rt-cli/src/commands/mod.rs`
- Modify: `crates/rt-cli/src/main.rs` (add Feed subcommand)

Two parts: (A) the downloader module in rt-signatures, (B) the CLI `rt feed` subcommand.

- [ ] **Step 1: Add reqwest to workspace**

In root `Cargo.toml` under `[workspace.dependencies]`:
```toml
reqwest = { version = "0.12", default-features = false, features = ["blocking", "rustls-tls"] }
```
In `crates/rt-signatures/Cargo.toml`:
```toml
reqwest = { workspace = true }
```

- [ ] **Step 2: Write failing tests for downloader**

Create `crates/rt-signatures/src/feeds/downloader.rs`:

```rust
// HTTP feed downloader.
//
// Downloads threat intelligence feeds from configured URLs and stores
// them in the local feed cache. Supports conditional requests via ETag.

use thiserror::Error;

use super::config::FeedConfig;
use super::fetcher::{FeedCache, FeedMetadata};

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Feed has no URL configured")]
    NoUrl,
    #[error("Cache error: {0}")]
    Cache(#[from] super::fetcher::FeedError),
}

/// Result of a single feed download attempt.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub feed_id: String,
    pub status: DownloadStatus,
    pub bytes_downloaded: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadStatus {
    Downloaded,
    NotModified,
    Skipped(String),
    Failed(String),
}

/// Download a single feed and store in cache.
pub fn download_feed(
    config: &FeedConfig,
    cache: &FeedCache,
) -> DownloadResult {
    todo!()
}

/// Download all enabled feeds with URLs from a registry.
pub fn download_all_feeds(
    registry: &super::config::FeedRegistry,
    cache: &FeedCache,
) -> Vec<DownloadResult> {
    todo!()
}
```

Tests (unit tests only — mock HTTP responses are complex, so test the logic paths):
1. Feed with no URL returns Skipped
2. Feed that is disabled returns Skipped
3. Download result struct construction
4. DownloadStatus equality checks

Integration tests (require network, mark `#[ignore]`):
5. `#[ignore]` Download a real feed (CISA KEV — small JSON)

- [ ] **Step 3: Run tests — verify RED**

- [ ] **Step 4: Implement download_feed and download_all_feeds**

Use `reqwest::blocking::Client` for synchronous HTTP. Handle:
- No URL → Skipped
- Disabled → Skipped
- HTTP GET with optional If-None-Match (ETag)
- 200 → store in cache, return Downloaded
- 304 → return NotModified
- Error → return Failed

- [ ] **Step 5: Run tests — verify GREEN**

- [ ] **Step 6: Write CLI feed subcommand**

Create `crates/rt-cli/src/commands/feed.rs` with subcommands:
- `rt feed update` — download all enabled feeds
- `rt feed list` — show configured feeds and cache status
- `rt feed info <feed-id>` — show details for one feed

Add `Feed` variant to CLI enum in main.rs.

- [ ] **Step 7: Write CLI feed tests**

In `crates/rt-cli/tests/cli_tests.rs`, add:
1. `test_feed_help` — shows subcommands
2. `test_feed_list` — lists configured feeds
3. `test_feed_info_unknown` — error for unknown feed

- [ ] **Step 8: Run tests — verify GREEN**

- [ ] **Step 9: Commit**

---

### Task 4: Pipeline Integration

**Files:**
- Modify: `crates/rt-pipeline/Cargo.toml` (add rt-signatures dep)
- Create: `crates/rt-pipeline/src/scanner.rs`
- Modify: `crates/rt-pipeline/src/lib.rs`
- Modify: `crates/rt-cli/src/commands/ingest.rs`
- Modify: `crates/rt-cli/src/main.rs` (add scan flags to Ingest)

The scanner module runs after artifact parsing. It takes the evidence path and parsed events, scans files with YARA + hash IOC, and enriches events with tags like `sig:yara:rule_name` and metadata.

- [ ] **Step 1: Add rt-signatures to rt-pipeline**

In `crates/rt-pipeline/Cargo.toml`:
```toml
rt-signatures = { workspace = true }
```

- [ ] **Step 2: Write failing tests for pipeline scanner**

Create `crates/rt-pipeline/src/scanner.rs`:

```rust
// Post-ingest signature scanning.
//
// Runs after artifact parsing to scan evidence files against loaded
// signatures and enrich TimelineEvents with findings.

use std::path::Path;
use rt_core::timeline::event::TimelineEvent;
use rt_signatures::matching::engine::ScanEngine;
use rt_signatures::matching::results::ScanReport;

/// Scan all evidence files under a path and return reports.
pub fn scan_evidence_files(
    evidence_path: &Path,
    engine: &ScanEngine,
) -> Vec<ScanReport> {
    todo!()
}

/// Enrich timeline events with scan findings.
///
/// For each file that had findings, tag matching events (same artifact_path)
/// with `sig:<source>:<rule_name>` tags and add finding details to metadata.
pub fn enrich_events(
    events: &mut [TimelineEvent],
    reports: &[ScanReport],
) {
    todo!()
}
```

Tests:
1. scan_evidence_files with no engines returns empty reports
2. scan_evidence_files with YARA finds match in file
3. scan_evidence_files with hash IOC finds match
4. scan_evidence_files recurses directories
5. enrich_events tags matching events with sig: prefix
6. enrich_events adds scan_findings metadata
7. enrich_events skips events with non-matching paths
8. enrich_events with no reports leaves events unchanged

- [ ] **Step 3: Run tests — verify RED**

- [ ] **Step 4: Implement scan_evidence_files and enrich_events**

scan_evidence_files:
- Walk evidence_path recursively
- For each file, call engine.scan_file()
- Collect non-empty reports

enrich_events:
- Build a HashMap<path, Vec<ScanFinding>> from reports
- For each event, check if artifact_path matches any report target
- If match: add tags like `sig:yara:rule_name`, `sig:hash_ioc:sha256_match`
- Add metadata key `scan_findings` with JSON array of finding summaries

- [ ] **Step 5: Run tests — verify GREEN**

- [ ] **Step 6: Add --scan flags to CLI ingest**

In main.rs, add optional scan flags to Ingest command:
```rust
/// Path to YARA rules for post-ingest scanning.
#[arg(long)]
yara_rules: Option<PathBuf>,

/// Path to hash IOC file for post-ingest scanning.
#[arg(long)]
hash_iocs: Option<Vec<PathBuf>>,

/// Use cached threat intel feeds for scanning.
#[arg(long)]
auto_feeds: bool,
```

In ingest.rs, after run_pipeline:
- Build ScanEngine from flags (reuse scan.rs engine-building logic)
- Call scan_evidence_files
- Call enrich_events on the parsed events
- Then insert_batch (enriched events go into DuckDB)

- [ ] **Step 7: Write integration tests**

1. Ingest with --yara-rules tags events
2. Ingest with --auto-feeds loads cached feeds
3. Ingest without scan flags works as before (regression)

- [ ] **Step 8: Run tests — verify GREEN**

- [ ] **Step 9: Commit**

---

### Task 5: Timeline Enrichment & Querying

**Files:**
- Create: `crates/rt-timeline/src/findings.rs`
- Modify: `crates/rt-timeline/src/lib.rs`
- Modify: `crates/rt-timeline/src/store.rs`
- Modify: `crates/rt-cli/src/commands/timeline.rs`
- Modify: `crates/rt-cli/src/main.rs` (add --flagged to Timeline)

This adds a `scan_findings` table to DuckDB for structured storage of scan results, and a `--flagged` filter to the timeline command to show only events that matched signatures.

- [ ] **Step 1: Write failing tests for findings storage**

Create `crates/rt-timeline/src/findings.rs`:

```rust
// Scan findings storage in DuckDB.
//
// Stores structured scan findings alongside the timeline, linked
// by evidence_source_id and artifact_path.

use duckdb::Connection;

/// A scan finding row for DuckDB storage.
#[derive(Debug, Clone)]
pub struct FindingRow {
    pub evidence_source_id: String,
    pub artifact_path: String,
    pub engine: String,
    pub severity: String,
    pub rule_name: String,
    pub description: String,
    pub matched_indicator: Option<String>,
    pub tags: Vec<String>,
}

/// Create the scan_findings table if it doesn't exist.
pub fn create_findings_table(conn: &Connection) -> Result<(), duckdb::Error> {
    todo!()
}

/// Insert a batch of findings.
pub fn insert_findings(
    conn: &Connection,
    findings: &[FindingRow],
) -> Result<usize, duckdb::Error> {
    todo!()
}

/// Query findings, optionally filtered by severity.
pub fn query_findings(
    conn: &Connection,
    min_severity: Option<&str>,
) -> Result<Vec<FindingRow>, duckdb::Error> {
    todo!()
}

/// Count findings by severity.
pub fn count_by_severity(
    conn: &Connection,
) -> Result<Vec<(String, usize)>, duckdb::Error> {
    todo!()
}
```

Tests:
1. Create table succeeds on fresh connection
2. Create table is idempotent
3. Insert and query findings roundtrip
4. Query with severity filter
5. Count by severity
6. Empty table returns empty results

- [ ] **Step 2: Run tests — verify RED**

- [ ] **Step 3: Implement findings storage**

SQL schema:
```sql
CREATE TABLE IF NOT EXISTS scan_findings (
    evidence_source_id VARCHAR,
    artifact_path VARCHAR,
    engine VARCHAR,
    severity VARCHAR,
    rule_name VARCHAR,
    description VARCHAR,
    matched_indicator VARCHAR,
    tags VARCHAR
)
```

- [ ] **Step 4: Run tests — verify GREEN**

- [ ] **Step 5: Add --flagged to timeline CLI**

In main.rs, add to Timeline command:
```rust
/// Show only events that matched signatures.
#[arg(long)]
flagged: bool,
```

In timeline.rs, when `flagged` is true:
- Query tags containing `sig:` prefix
- Add WHERE clause: `tags LIKE '%sig:%'`

- [ ] **Step 6: Add scan findings to info command**

In info.rs, after showing timeline stats:
- Call count_by_severity
- Print findings summary if any exist

- [ ] **Step 7: Write CLI tests**

1. `rt timeline --flagged` with no flagged events shows empty
2. `rt info` shows scan findings count when present

- [ ] **Step 8: Run tests — verify GREEN**

- [ ] **Step 9: Commit**

---

### Task 6: Wire --auto-feeds into rt scan

**Files:**
- Modify: `crates/rt-cli/src/commands/scan.rs`

Add `--auto-feeds` flag to the existing scan command that loads all cached feeds via the loader.

- [ ] **Step 1: Add --auto-feeds flag**

In main.rs Scan variant, add:
```rust
/// Load all cached threat intel feeds automatically.
#[arg(long)]
auto_feeds: bool,
```

- [ ] **Step 2: Wire loader into scan command**

In scan.rs, after building the engine from explicit flags:
- If `auto_feeds`, call `load_cached_feeds(registry, cache)`
- Merge the loaded engine's stores into the main engine

- [ ] **Step 3: Write tests**

1. `rt scan --auto-feeds` with empty cache works (0 extra indicators)
2. `rt scan --help` shows auto-feeds option

- [ ] **Step 4: Run tests — verify GREEN**

- [ ] **Step 5: Commit**

---

### Task 7: Full Integration Test

**Files:**
- Create: `crates/rt-cli/tests/scan_integration_test.rs`

End-to-end test: create evidence with known bad content, load YARA rules + hash IOCs, ingest with --yara-rules, verify timeline events are tagged, query with --flagged.

- [ ] **Step 1: Write integration test**

```rust
// Full pipeline integration test:
// 1. Create evidence directory with files
// 2. Create YARA rule that matches one file
// 3. Run `rt ingest --yara-rules` on evidence
// 4. Run `rt timeline --flagged` to see tagged events
// 5. Run `rt info` to see findings summary
```

- [ ] **Step 2: Run test — verify GREEN**

- [ ] **Step 3: Run full workspace tests**

```bash
cargo test --workspace
```

Expected: All tests pass (should be 300+ total)

- [ ] **Step 4: Final commit**
