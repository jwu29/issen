# MFT Tree Extraction & Forensic Heuristics Engine

## Overview

Extract `FileTree`/`FileNode` from rt-navigator into a shared `rt-mft-tree` crate and expand `rt-signatures` with a forensic heuristics engine behind feature flags. The heuristics engine provides two tiers of automated anomaly detection for NTFS artifacts: metadata-only checks (always available) and content-aware checks (conditional on file access).

## Goals

- **Shared MFT tree** — any crate can build and traverse an in-memory NTFS file tree without depending on the TUI
- **Unified detection** — all analysis (rule-based signatures and forensic heuristics) lives in rt-signatures, with a single `Severity` type and consistent output format
- **Streaming + tree modes** — per-entry heuristics run during pipeline ingest (streaming); tree-level and content-aware checks run when full context is available
- **Parsers parse, heuristics analyze** — parser crates produce structured data; all detection logic lives in rt-signatures

## Non-Goals

- Full $LogFile parsing (future work)
- $MFTMirr validation beyond basic integrity check (future work)
- EWF-based file reading (future work — `FileReader` trait is designed for it)
- Real-time monitoring or live filesystem watching

---

## Architecture

### Crate Structure

```
rt-mft-tree (NEW)
├── node.rs         — FileNode, NtfsTimestamps
├── tree.rs         — FileTree (arena, children, entry_map, cached path index)
├── enrich.rs       — USN enrichment (enrich_usn)
├── parse.rs        — from_mft() with indicatif progress bar
└── lib.rs

rt-signatures (EXPANDED — new "heuristics" feature)
├── src/
│   ├── heuristics/
│   │   ├── mod.rs           — public API: run_tier1(), run_tier2()
│   │   ├── anomaly.rs       — Anomaly, AnomalyCategory, AnomalyIndex
│   │   ├── entry_checks.rs  — per-entry streaming checks (Tier 1)
│   │   ├── tree_checks.rs   — tree-level checks (Tier 1)
│   │   ├── content_checks.rs— content-aware checks (Tier 2)
│   │   ├── usn_analysis.rs  — USN stream pattern detection (moved from rt-parser-usnjrnl)
│   │   ├── magic_table.rs   — static file signature table
│   │   └── file_reader.rs   — FileReader trait + FsFileReader, NoFileReader
│   ├── engines/             — existing: yara, sigma, ioc, stix, suricata
│   ├── matching/            — existing: Severity, ScanFinding, ScanResult
│   └── ...
└── Cargo.toml

rt-navigator (MODIFIED — depends on rt-mft-tree instead of owning FileTree)
├── src/
│   ├── app.rs       — gains AnomalyIndex, FileReader
│   ├── ui.rs        — gains anomaly markers, detail panel
│   ├── sources.rs   — unchanged
│   └── main.rs      — wires heuristic passes after tree construction
└── Cargo.toml

rt-parser-usnjrnl (MODIFIED — analysis module removed)
├── src/
│   ├── lib.rs       — UsnRecordV2 struct, parse(), timeline conversion
│   └── ...          — analysis/ module deleted
└── Cargo.toml
```

### Feature Flags (rt-signatures)

```toml
[features]
default = ["heuristics"]
heuristics = ["dep:rt-mft-tree"]    # lightweight, pure Rust
yara = ["dep:yara"]                  # C bindings
sigma = []                           # Sigma rule engine
feeds = ["dep:reqwest"]              # HTTP feed downloading
full = ["heuristics", "yara", "sigma", "feeds"]
```

Consumers:
- `rt-navigator` depends on `rt-signatures = { features = ["heuristics"] }` — lightweight
- `rt-pipeline` depends on `rt-signatures = { features = ["full"] }` — everything

### Dependency Graph

```
rt-mft-tree ← rt-signatures[heuristics] ← rt-navigator
                                         ← rt-pipeline
rt-parser-usnjrnl (no analysis, just parsing)
rt-core (Severity lives here or in rt-signatures — existing location)
```

---

## Data Model

### NtfsTimestamps

```rust
/// Four NTFS timestamps from a single attribute ($SI or $FN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsTimestamps {
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub entry_modified: DateTime<Utc>,
}
```

### FileNode (expanded)

```rust
pub struct FileNode {
    pub name: String,
    pub mft_entry: u64,
    pub parent_entry: u64,
    pub is_dir: bool,
    pub size: u64,
    /// $STANDARD_INFORMATION timestamps (user-visible, modifiable by tools).
    pub si_timestamps: NtfsTimestamps,
    /// $FILE_NAME timestamps (kernel-managed, harder to tamper).
    /// None if identical to si_timestamps (saves memory for the common case).
    pub fn_timestamps: Option<NtfsTimestamps>,
    /// Number of USN journal change records referencing this entry.
    pub usn_change_count: u32,
}
```

### Anomaly

```rust
/// A single heuristic finding for a file or directory.
pub struct Anomaly {
    /// Severity level (reuses existing rt-signatures Severity).
    pub severity: Severity,
    /// What category of anomaly this represents.
    pub category: AnomalyCategory,
    /// Stable identifier for the heuristic rule (e.g., "HEUR-TS-001").
    pub rule_id: &'static str,
    /// Human-readable description of what was detected.
    pub description: String,
    /// Specific values or evidence that triggered the detection.
    pub evidence: String,
}

pub enum AnomalyCategory {
    Timestomping,
    SuspiciousLocation,
    ExtensionMismatch,
    HighEntropy,
    SecureDeletion,
    RansomwarePattern,
    JournalTampering,
    GhostFile,
    SuspiciousSize,
    MftIntegrity,
}
```

### AnomalyIndex

Separate from FileTree to keep the tree as a pure data structure.

```rust
/// Lookup structure for anomalies by arena index.
pub struct AnomalyIndex {
    entries: HashMap<usize, Vec<Anomaly>>,
}

impl AnomalyIndex {
    /// All anomalies for a node, empty slice if none.
    pub fn for_node(&self, idx: usize) -> &[Anomaly];

    /// Highest severity anomaly for a node, if any.
    pub fn max_severity(&self, idx: usize) -> Option<Severity>;

    /// Total number of flagged nodes.
    pub fn flagged_count(&self) -> usize;

    /// All flagged node indices, ordered by severity (highest first).
    pub fn flagged_entries(&self) -> Vec<usize>;

    /// Merge another index into this one (e.g., after Tier 2 results arrive).
    pub fn merge(&mut self, other: AnomalyIndex);
}
```

### FileReader Trait

```rust
/// Abstract access to file content for Tier 2 checks.
pub trait FileReader {
    /// Read the first `n` bytes of the file at arena index `idx`.
    /// Returns None if the file is inaccessible.
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>>;

    /// Whether this reader has access to file content at all.
    fn is_available(&self) -> bool;
}
```

Implementations:

```rust
/// Reads files from a volume root directory via std::fs.
pub struct FsFileReader<'a> {
    volume_root: PathBuf,
    tree: &'a FileTree,
}

/// No-op reader for standalone $MFT mode.
pub struct NoFileReader;
```

Future: `EwfFileReader` for reading through rt-ewf image layer.

---

## Tier 1: Metadata-Only Checks

### Entry-Level Checks (Streaming-Compatible)

These operate on a single `FileNode`. Usable in both streaming (pipeline) and batch (navigator) modes.

| Rule ID | Name | Severity | Logic |
|---------|------|----------|-------|
| HEUR-TS-001 | SI created after modified | High | `si.created > si.modified` — logically impossible without manipulation |
| HEUR-TS-002 | SI/FN timestamp divergence | Medium | `abs(si.created - fn.created) > 24 hours` — timestomping tools modify $SI but cannot touch $FN |
| HEUR-TS-003 | Zeroed subseconds in SI | Low | $SI timestamps have zero nanosecond component while $FN retains sub-second precision |
| HEUR-TS-004 | SI predates volume creation | Medium | $SI created timestamp is before a configurable volume creation date |
| HEUR-SZ-001 | Suspicious size for extension | Low | `.txt` > 10MB, `.dll`/`.exe` = 0 bytes, `.jpg` < 100 bytes |
| HEUR-AT-001 | Hidden+system on non-system file | Low | Hidden and system attributes set on files in user directories |
| HEUR-MG-003 | Double extension | Medium | Filename contains two extensions where the final one is executable: `report.pdf.exe`, `image.jpg.scr`. Pure metadata check — no file content needed. |

```rust
/// Optional configuration for heuristic checks.
pub struct HeuristicsConfig {
    /// Volume creation timestamp. If set, HEUR-TS-004 checks for $SI timestamps
    /// predating this date. If None, HEUR-TS-004 is skipped.
    pub volume_created: Option<DateTime<Utc>>,
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        Self { volume_created: None }
    }
}

/// Run all entry-level checks on a single node.
pub fn check_entry(node: &FileNode, config: &HeuristicsConfig) -> Vec<Anomaly>;
```

### Tree-Level Checks

Require the full `FileTree` with resolved paths.

| Rule ID | Name | Severity | Logic |
|---------|------|----------|-------|
| HEUR-LOC-001 | Executable in temp path | Medium | `.exe`/`.dll`/`.scr`/`.bat`/`.ps1`/`.vbs` in paths containing `Temp`, `$Recycle.Bin`, `AppData\Local\Temp` |
| HEUR-LOC-002 | High MFT entry in system path | Medium | File under `\Windows\System32` with MFT entry number in top 10% of allocated range — recently created in an old location |
| HEUR-LOC-003 | Known-suspicious filename | High | Filename matches built-in list: `mimikatz`, `pwdump`, `procdump`, `lazagne`, `rubeus`, `sharphound`, `psexec`, `wce`, `gsecdump`, etc. Case-insensitive substring match. |

```rust
/// Run all tree-level checks, returns a complete AnomalyIndex.
pub fn check_tree(tree: &FileTree) -> AnomalyIndex;
```

### USN Stream Analysis

Operates on ordered `Vec<UsnRecordV2>`. Moved from rt-parser-usnjrnl.

| Rule ID | Name | Severity | Logic |
|---------|------|----------|-------|
| HEUR-USN-001 | Secure deletion pattern | High | SDelete-style: file renamed to `AAA...` or sequential characters, then deleted. CCleaner variant: renamed to `ZZZ...`. Pattern: rename → rename → ... → delete within short window, applied to same MFT entry. |
| HEUR-USN-002 | Rapid mass rename | High | >50 rename operations on distinct files within 60 seconds. Common ransomware indicator (encrypting and renaming files). |
| HEUR-USN-003 | Journal gap/truncation | Medium | Expected USN sequence numbers have discontinuities beyond what normal journal wrapping explains. Possible anti-forensic journal clearing. |
| HEUR-USN-004 | Ghost file | Medium | USN record references an MFT entry number that has no corresponding node in the tree — file was deleted and entry reallocated. Cross-references with FileTree entry_map. |

```rust
/// Run USN stream analysis. Ghost file detection requires the tree.
pub fn check_usn_stream(
    records: &[(UsnRecordV2, u64)],  // record + offset
    tree: Option<&FileTree>,
) -> AnomalyIndex;
```

### Public API: run_tier1()

```rust
/// Run all Tier 1 checks (entry-level + tree-level + USN if available).
pub fn run_tier1(
    tree: &FileTree,
    usn_records: Option<&[(UsnRecordV2, u64)]>,
    config: &HeuristicsConfig,
) -> AnomalyIndex;
```

---

## Tier 2: Content-Aware Checks (Conditional)

Only execute when `FileReader::is_available()` returns true. Each check reads at most 4KB per file.

| Rule ID | Name | Severity | Logic |
|---------|------|----------|-------|
| HEUR-MG-001 | Magic bytes vs extension mismatch | Medium | First 8-16 bytes compared against ~50-entry static magic table. Flag when extension claims one format but magic bytes indicate another. |
| HEUR-MG-002 | Executable disguised as document | High | File has `MZ` (PE) or `ELF` header but extension is `.docx`, `.pdf`, `.txt`, `.jpg`, `.png`, or other document/media type. |
| HEUR-EN-001 | High entropy non-archive | Medium | Shannon entropy > 7.5 on first 4KB in files with extensions that should be low-entropy (`.txt`, `.csv`, `.log`, `.ini`, `.xml`, `.html`). Suggests encrypted container or obfuscated payload. |
| HEUR-EN-002 | Crypto container signature | High | TrueCrypt/VeraCrypt volume header patterns, LUKS magic (`LUKS\xba\xbe`), BitLocker metadata signature. Also flag files with exact 512-byte size multiple + high entropy + no recognized header. |

Note: HEUR-MG-003 (double extension) is in Tier 1 entry checks since it requires no file content. ADS analysis is deferred until the `FileReader` trait gains an `fn read_ads()` method (future work).

### Magic Table

Static array compiled into the binary. No config files.

```rust
struct MagicEntry {
    extensions: &'static [&'static str],
    magic: &'static [u8],
    offset: usize,
    description: &'static str,
}

static MAGIC_TABLE: &[MagicEntry] = &[
    // Images
    MagicEntry { extensions: &["jpg", "jpeg"], magic: b"\xFF\xD8\xFF", offset: 0, description: "JPEG" },
    MagicEntry { extensions: &["png"], magic: b"\x89PNG\r\n\x1a\n", offset: 0, description: "PNG" },
    MagicEntry { extensions: &["gif"], magic: b"GIF8", offset: 0, description: "GIF" },
    MagicEntry { extensions: &["bmp"], magic: b"BM", offset: 0, description: "BMP" },
    // Documents
    MagicEntry { extensions: &["pdf"], magic: b"%PDF", offset: 0, description: "PDF" },
    MagicEntry { extensions: &["docx","xlsx","pptx","zip"], magic: b"PK\x03\x04", offset: 0, description: "ZIP/OOXML" },
    // Executables
    MagicEntry { extensions: &["exe","dll","scr","sys"], magic: b"MZ", offset: 0, description: "PE executable" },
    // ~50 entries total covering forensic-relevant formats
];
```

### Entropy Calculation

```rust
fn shannon_entropy(data: &[u8]) -> f64 {
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| { let p = f as f64 / len; -p * p.log2() })
        .sum()
}
```

### Execution Model

```rust
/// Run Tier 2 checks on specific entries (typically the visible entries in a directory).
pub fn run_tier2(
    tree: &FileTree,
    entries: &[usize],
    reader: &dyn FileReader,
    index: &mut AnomalyIndex,  // results merged into existing index
);
```

In rt-navigator:
- Tier 2 fires lazily when user browses into a directory
- Results cached in AnomalyIndex via `merge()` — re-visiting doesn't re-read
- Background pre-scan of adjacent directories is a future optimization, not V1

---

## Integration

### rt-navigator Changes

```rust
pub struct App {
    pub tree: FileTree,           // from rt-mft-tree
    pub anomaly_index: AnomalyIndex,  // from rt-signatures[heuristics]
    pub file_reader: Box<dyn FileReader>,
    // ... existing fields unchanged
}
```

Main startup sequence:
1. `FileTree::from_mft(&sources.mft)` — build tree
2. `enrich_usn()` — if USN journal available
3. `run_tier1(&tree, usn_records.as_deref(), &config)` — returns `AnomalyIndex`
4. Construct `FsFileReader` or `NoFileReader` based on `sources` input type
5. `App::new(tree, anomaly_index, file_reader)`

TUI rendering additions:
- Severity marker in name column: `!!` red (High/Critical), `!` yellow (Medium), `·` dim (Low)
- `f` key toggles "flagged only" filter (like search, but for anomalies)
- `d` key shows anomaly detail panel for selected entry
- Footer shows flagged count: `12 flagged`

### rt-pipeline Changes (Streaming)

During MFT ingest, each parsed entry passes through `check_entry()`:
```rust
let config = HeuristicsConfig::default(); // or populated from evidence metadata
let node = parse_mft_entry(&entry);
let anomalies = heuristics::check_entry(&node, &config);
for anomaly in &anomalies {
    let finding: FindingRow = (&node, anomaly).into(); // streaming conversion
    emitter.emit_finding(finding);
}
```

### rt-parser-usnjrnl Changes

Remove `analysis/` module. The crate retains:
- `UsnRecordV2` struct and `parse()` function
- Timeline event conversion
- Re-exports of the struct (public API unchanged for parse-only consumers)

Analysis logic moves to `rt-signatures/src/heuristics/usn_analysis.rs`.

### Anomaly → FindingRow Conversion

Two conversion paths: tree mode (full path available) and streaming mode (node only).

```rust
/// Tree mode: full path from cached_path index.
impl From<(usize, &Anomaly, &FileTree)> for FindingRow {
    fn from((idx, anomaly, tree): (usize, &Anomaly, &FileTree)) -> Self {
        FindingRow {
            artifact_path: tree.cached_path(idx).to_string(),
            engine: "heuristics".to_string(),
            severity: anomaly.severity.to_string(),
            rule_name: anomaly.rule_id.to_string(),
            description: anomaly.description.clone(),
            matched_indicator: anomaly.evidence.clone(),
            tags: serde_json::to_string(&[anomaly.category.as_str()]).unwrap_or_default(),
            ..Default::default()
        }
    }
}

/// Streaming mode: no tree available, use node name + MFT entry as identifier.
impl From<(&FileNode, &Anomaly)> for FindingRow {
    fn from((node, anomaly): (&FileNode, &Anomaly)) -> Self {
        FindingRow {
            artifact_path: format!("MFT#{}: {}", node.mft_entry, node.name),
            engine: "heuristics".to_string(),
            severity: anomaly.severity.to_string(),
            rule_name: anomaly.rule_id.to_string(),
            description: anomaly.description.clone(),
            matched_indicator: anomaly.evidence.clone(),
            tags: serde_json::to_string(&[anomaly.category.as_str()]).unwrap_or_default(),
            ..Default::default()
        }
    }
}
```

---

## Testing Strategy

### rt-mft-tree
- Existing 78 tests migrate from rt-navigator (tree.rs tests, sources.rs unaffected)
- Tests use `from_nodes()` with synthetic `FileNode` data — no real MFT files needed
- New tests for `NtfsTimestamps`, `fn_timestamps` field

### rt-signatures[heuristics]

**Entry checks:** Unit test per rule with crafted `FileNode` inputs.
```rust
#[test]
fn heur_ts_001_si_created_after_modified() {
    let config = HeuristicsConfig::default();
    let node = FileNode {
        si_timestamps: NtfsTimestamps {
            created: ts(2024, 6, 1),   // created AFTER modified
            modified: ts(2024, 1, 1),
            ..default_ts()
        },
        ..default_node()
    };
    let anomalies = check_entry(&node, &config);
    assert!(anomalies.iter().any(|a| a.rule_id == "HEUR-TS-001"));
}
```

**Tree checks:** Build synthetic trees with known anomalous patterns.

**USN analysis:** Feed synthetic USN record sequences and assert expected detections.

**Content checks:** Use `FileReader` mock that returns controlled byte sequences.
```rust
struct MockFileReader(HashMap<usize, Vec<u8>>);
impl FileReader for MockFileReader {
    fn read_first_bytes(&self, idx: usize, n: usize) -> Option<Vec<u8>> {
        self.0.get(&idx).map(|d| d[..n.min(d.len())].to_vec())
    }
    fn is_available(&self) -> bool { true }
}
```

**False positive tests:** Ensure normal files don't trigger heuristics.
- Valid timestamps with $SI == $FN → no timestomping flag
- `.exe` in `\Windows\System32` with low MFT entry → no location flag
- `.zip` file with high entropy → no false entropy flag (archives are expected)

### Integration tests
- Build tree from synthetic nodes, run full `run_tier1()`, verify expected anomalies
- Mock `FileReader`, run `run_tier2()`, verify magic/entropy checks
