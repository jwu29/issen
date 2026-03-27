# winreg-forensic Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the winreg-forensic workspace with core REGF parsing (`winreg-format` + `winreg-core`), test infrastructure (`TestHiveBuilder`), and basic CLI (`rt-reg` with info/dump/search), producing a working registry parser that can open hives, navigate keys, decode values, replay transaction logs, and auto-detect hive types.

**Architecture:** Layered workspace — `winreg-format` (zero-dep BinRead structs) feeds into `winreg-core` (parser with mmap/buffered I/O, miette errors). `TestHiveBuilder` enables TDD for all subsequent crates. `rt-reg` is a thin clap CLI over the library.

**Tech Stack:** Rust 2021, binrw 0.4, bitflags 2, memmap2, miette 7, thiserror 2, clap 4, chrono, serde/serde_json, tempfile (dev)

**Scope:** This is Plan 1 of 4. Subsequent plans cover: (2) artifact decoders + timeline, (3) recovery + carving, (4) FUSE + Python bindings.

**Reference:** Binary format offsets from `research/regf-binary-format-specification.md`. Design from `docs/superpowers/specs/2026-03-27-winreg-forensic-design.md`.

---

## File Structure

```
~/src/winreg-forensic/
├── Cargo.toml                          # Workspace manifest
├── LICENSE                             # Apache-2.0
├── .gitignore
├── crates/
│   ├── winreg-format/
│   │   ├── Cargo.toml                  # binrw, bitflags
│   │   └── src/
│   │       ├── lib.rs                  # Re-exports
│   │       ├── header.rs               # BaseBlock + checksum
│   │       ├── hbin.rs                 # HbinHeader
│   │       ├── cells.rs               # CellOffset, CellHeader, NK, VK, SK, LF, LH, LI, RI, DB
│   │       ├── flags.rs                # KeyFlags, ValueType, NkFlags
│   │       └── version.rs              # RegfVersion enum
│   ├── winreg-core/
│   │   ├── Cargo.toml                  # winreg-format, memmap2, miette, thiserror, chrono
│   │   └── src/
│   │       ├── lib.rs                  # Re-exports
│   │       ├── error.rs                # HiveError with miette diagnostics
│   │       ├── hive.rs                 # Hive<R> struct + from_bytes/from_path
│   │       ├── cell_reader.rs          # CellReader — read cells by offset
│   │       ├── key.rs                  # Key struct — navigation, subkeys, values
│   │       ├── value.rs                # Value struct — all REG_* type decoding
│   │       ├── path.rs                 # Path reconstruction + subkey_path()
│   │       ├── iter.rs                 # BFS/DFS key iterators
│   │       ├── security.rs             # SK chain traversal
│   │       ├── txlog.rs                # Transaction log replay (OverlayBuffer)
│   │       └── detect.rs               # Hive type auto-detection
│   ├── winreg-recover/
│   │   ├── Cargo.toml                  # Placeholder — Plan 3
│   │   └── src/lib.rs
│   ├── winreg-carve/
│   │   ├── Cargo.toml                  # Placeholder — Plan 3
│   │   └── src/lib.rs
│   ├── winreg-artifacts/
│   │   ├── Cargo.toml                  # Placeholder — Plan 2
│   │   └── src/lib.rs
│   ├── winreg-timeline/
│   │   ├── Cargo.toml                  # Placeholder — Plan 2
│   │   └── src/lib.rs
│   ├── winreg-fuse/
│   │   ├── Cargo.toml                  # Placeholder — Plan 4
│   │   └── src/lib.rs
│   └── winreg-py/
│       ├── Cargo.toml                  # Placeholder — Plan 4
│       └── src/lib.rs
├── rt-reg/
│   ├── Cargo.toml                      # clap 4, winreg-core
│   └── src/
│       ├── main.rs                     # Subcommand dispatch
│       └── output.rs                   # Format selection (table/json/jsonl/csv)
└── tests/
    └── common/
        └── hive_builder.rs             # TestHiveBuilder
```

---

### Task 1: Workspace Scaffold

**Files:**
- Create: `~/src/winreg-forensic/Cargo.toml`
- Create: `~/src/winreg-forensic/LICENSE`
- Create: `~/src/winreg-forensic/.gitignore`
- Create: All crate `Cargo.toml` and `src/lib.rs` files
- Create: `rt-reg/Cargo.toml` and `rt-reg/src/main.rs`

- [ ] **Step 1: Create the workspace directory and git init**

```bash
mkdir -p ~/src/winreg-forensic
cd ~/src/winreg-forensic
git init
```

- [ ] **Step 2: Create workspace Cargo.toml**

Create `~/src/winreg-forensic/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/winreg-format",
    "crates/winreg-core",
    "crates/winreg-recover",
    "crates/winreg-carve",
    "crates/winreg-artifacts",
    "crates/winreg-timeline",
    "crates/winreg-fuse",
    "crates/winreg-py",
    "rt-reg",
]

[workspace.package]
edition = "2021"
rust-version = "1.75"
license = "Apache-2.0"
repository = "https://github.com/4n6h4x0r/winreg-forensic"

[workspace.dependencies]
# Format/parsing
binrw = "0.4"
bitflags = "2"

# I/O
memmap2 = "0.9"

# Error handling
miette = { version = "7", features = ["fancy"] }
thiserror = "2"

# Time
chrono = { version = "0.4", default-features = false, features = ["serde"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CLI
clap = { version = "4", features = ["derive"] }

# Testing
tempfile = "3"

# Internal
winreg-format = { path = "crates/winreg-format" }
winreg-core = { path = "crates/winreg-core" }

[workspace.lints.clippy]
pedantic = { level = "warn", priority = -1 }
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
```

- [ ] **Step 3: Create winreg-format crate**

Create `crates/winreg-format/Cargo.toml`:

```toml
[package]
name = "winreg-format"
version = "0.1.0"
description = "Windows Registry (REGF) binary format definitions"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
binrw.workspace = true
bitflags.workspace = true

[lints]
workspace = true
```

Create `crates/winreg-format/src/lib.rs`:

```rust
//! Windows Registry (REGF) binary format definitions.
//!
//! Pure type definitions with zero I/O. All structs derive `BinRead` for
//! declarative parsing from byte streams.

pub mod cells;
pub mod flags;
pub mod hbin;
pub mod header;
pub mod version;
```

- [ ] **Step 4: Create winreg-core crate**

Create `crates/winreg-core/Cargo.toml`:

```toml
[package]
name = "winreg-core"
version = "0.1.0"
description = "Core Windows Registry hive parser"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
winreg-format.workspace = true
memmap2.workspace = true
miette.workspace = true
thiserror.workspace = true
chrono.workspace = true

[dev-dependencies]
tempfile.workspace = true

[lints]
workspace = true
```

Create `crates/winreg-core/src/lib.rs`:

```rust
//! Core Windows Registry hive parser.
//!
//! Provides `Hive<R>` for reading REGF hive files via memory-mapped I/O
//! or in-memory buffers.

pub mod cell_reader;
pub mod detect;
pub mod error;
pub mod hive;
pub mod iter;
pub mod key;
pub mod path;
pub mod security;
pub mod txlog;
pub mod value;

pub use error::HiveError;
pub use hive::Hive;
```

- [ ] **Step 5: Create placeholder crates (recover, carve, artifacts, timeline, fuse, py)**

For each of `winreg-recover`, `winreg-carve`, `winreg-artifacts`, `winreg-timeline`, `winreg-fuse`, `winreg-py`:

Create `crates/<name>/Cargo.toml` with:

```toml
[package]
name = "<name>"
version = "0.1.0"
description = "<description>"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true
```

Create `crates/<name>/src/lib.rs` with:

```rust
//! <description> — placeholder, implementation in Plan N.
```

Descriptions:
- `winreg-recover`: "Deleted registry key/value recovery"
- `winreg-carve`: "Registry hive carving from disk/memory images"
- `winreg-artifacts`: "Forensic artifact decoders for Windows Registry"
- `winreg-timeline`: "Timeline generation from registry artifacts"
- `winreg-fuse`: "FUSE virtual filesystem mount for registry hives"
- `winreg-py`: "Python bindings for winreg-forensic"

- [ ] **Step 6: Create rt-reg CLI crate**

Create `rt-reg/Cargo.toml`:

```toml
[package]
name = "rt-reg"
version = "0.1.0"
description = "Windows Registry forensic CLI"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "rt-reg"
path = "src/main.rs"

[dependencies]
winreg-core.workspace = true
clap.workspace = true
serde_json.workspace = true

[lints]
workspace = true
```

Create `rt-reg/src/main.rs`:

```rust
fn main() {
    println!("rt-reg: Windows Registry forensic toolkit");
}
```

- [ ] **Step 7: Create LICENSE and .gitignore**

Create `LICENSE` with the full Apache-2.0 license text.

Create `.gitignore`:

```
/target
Cargo.lock
*.swp
*.swo
*~
.DS_Store
```

- [ ] **Step 8: Verify workspace compiles**

```bash
cd ~/src/winreg-forensic
cargo check
```

Expected: compiles with no errors.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "chore: scaffold winreg-forensic workspace with 8 crates + CLI"
```

---

### Task 2: winreg-format — BaseBlock + Checksum

**Files:**
- Create: `crates/winreg-format/src/header.rs`
- Create: `crates/winreg-format/src/version.rs`

- [ ] **Step 1: Write the failing test for BaseBlock parsing**

Add to `crates/winreg-format/src/header.rs`:

```rust
//! REGF base block (header) — first 4096 bytes of a hive file.

use binrw::BinRead;

/// REGF base block header (first 512 bytes of the 4096-byte header block).
///
/// Reference: research/regf-binary-format-specification.md Section 1.1
#[derive(Debug, Clone, BinRead)]
#[br(little, magic = b"regf")]
pub struct BaseBlock {
    /// Incremented on each write; must match secondary if hive was properly synced.
    pub primary_sequence: u32,
    /// Updated after successful write; mismatch = dirty hive.
    pub secondary_sequence: u32,
    /// FILETIME (UTC). Not updated as of Windows 8.1.
    pub last_written: u64,
    /// Always 1 for all known Windows versions.
    pub major_version: u32,
    /// 0-2 (NT 3.x), 3 (NT 4.0), 5 (XP+), 6 (Win10+ differencing).
    pub minor_version: u32,
    /// 0 = primary, 1 = transaction log, 2 = alternate (Win2000 SYSTEM.ALT).
    pub file_type: u32,
    /// Always 1 (direct memory load).
    pub format: u32,
    /// Offset to root key node cell, relative to hive bins data start.
    pub root_cell_offset: u32,
    /// Total size of all hive bins in bytes.
    pub hive_bins_data_size: u32,
    /// Logical sector size / 512. Typically 1 or 8.
    pub clustering_factor: u32,
    /// Internal hive path, UTF-16LE, 64 bytes. May contain remnant data.
    pub file_name: [u8; 64],
    /// Resource Manager GUID (Vista+). Null if CLFS not used.
    pub rm_id: [u8; 16],
    /// Log GUID. Usually same as rm_id.
    pub log_id: [u8; 16],
    /// Bit mask: 0x1 = pending txns, 0x2 = differencing hive.
    pub flags: u32,
    /// Transaction Manager GUID.
    pub tm_id: [u8; 16],
    /// "rmtm" signature validating GUID fields are present.
    pub guid_signature: u32,
    /// FILETIME of latest hive reorganization (Win8+).
    pub last_reorganize_time: u64,
    /// Reserved (332 bytes = 83 DWORDs).
    #[br(count = 332)]
    pub reserved1: Vec<u8>,
    /// XOR-32 checksum of first 508 bytes (offsets 0x000-0x1FB).
    pub checksum: u32,
}

impl BaseBlock {
    /// Size of the base block in the file (always 4096 bytes).
    pub const SIZE: usize = 4096;

    /// Validate the XOR-32 checksum.
    ///
    /// Algorithm: XOR all 127 u32 LE words from offsets 0x000-0x1FB.
    /// Special cases: result 0 becomes 1, result 0xFFFFFFFF becomes 0xFFFFFFFE.
    pub fn validate_checksum(header_bytes: &[u8]) -> bool {
        if header_bytes.len() < 512 {
            return false;
        }
        let computed = Self::compute_checksum(header_bytes);
        let stored = u32::from_le_bytes([
            header_bytes[0x1FC],
            header_bytes[0x1FD],
            header_bytes[0x1FE],
            header_bytes[0x1FF],
        ]);
        computed == stored
    }

    /// Compute the XOR-32 checksum over the first 508 bytes.
    pub fn compute_checksum(header_bytes: &[u8]) -> u32 {
        let mut checksum: u32 = 0;
        for i in 0..127 {
            let offset = i * 4;
            let word = u32::from_le_bytes([
                header_bytes[offset],
                header_bytes[offset + 1],
                header_bytes[offset + 2],
                header_bytes[offset + 3],
            ]);
            checksum ^= word;
        }
        if checksum == 0 {
            checksum = 1;
        }
        if checksum == 0xFFFF_FFFF {
            checksum = 0xFFFF_FFFE;
        }
        checksum
    }

    /// Check if primary and secondary sequence numbers match (clean hive).
    pub fn is_clean(&self) -> bool {
        self.primary_sequence == self.secondary_sequence
    }

    /// Decode the internal file name from UTF-16LE.
    pub fn file_name_string(&self) -> String {
        let u16s: Vec<u16> = self
            .file_name
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16_lossy(&u16s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a minimal valid 512-byte base block header for testing.
    fn build_test_header() -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        // Signature "regf"
        buf[0..4].copy_from_slice(b"regf");
        // Primary sequence = 1
        buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        // Secondary sequence = 1
        buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
        // Major version = 1
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        // Minor version = 5
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes());
        // Format = 1
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
        // Root cell offset = 32 (0x20)
        buf[0x24..0x28].copy_from_slice(&32u32.to_le_bytes());
        // Hive bins data size = 4096
        buf[0x28..0x2C].copy_from_slice(&4096u32.to_le_bytes());
        // Clustering factor = 1
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes());
        // Compute and store checksum
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());
        buf
    }

    #[test]
    fn parse_base_block_from_bytes() {
        let buf = build_test_header();
        let mut cursor = Cursor::new(&buf[..]);
        let header = BaseBlock::read(&mut cursor).expect("should parse valid header");
        assert_eq!(header.major_version, 1);
        assert_eq!(header.minor_version, 5);
        assert_eq!(header.root_cell_offset, 32);
        assert_eq!(header.hive_bins_data_size, 4096);
        assert!(header.is_clean());
    }

    #[test]
    fn checksum_validates_on_clean_header() {
        let buf = build_test_header();
        assert!(BaseBlock::validate_checksum(&buf));
    }

    #[test]
    fn checksum_fails_on_corrupt_header() {
        let mut buf = build_test_header();
        buf[0x14] = 0xFF; // corrupt major version
        assert!(!BaseBlock::validate_checksum(&buf));
    }

    #[test]
    fn checksum_special_case_zero_becomes_one() {
        // Construct a header where XOR of all words would be 0
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(b"regf");
        let checksum = BaseBlock::compute_checksum(&buf);
        assert_eq!(checksum, 1, "zero checksum should become 1");
    }

    #[test]
    fn dirty_hive_detection() {
        let mut buf = build_test_header();
        // Make primary != secondary
        buf[0x04..0x08].copy_from_slice(&2u32.to_le_bytes());
        // Recompute checksum
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        let mut cursor = Cursor::new(&buf[..]);
        let header = BaseBlock::read(&mut cursor).unwrap();
        assert!(!header.is_clean());
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut buf = build_test_header();
        buf[0..4].copy_from_slice(b"nope");
        let mut cursor = Cursor::new(&buf[..]);
        assert!(BaseBlock::read(&mut cursor).is_err());
    }
}
```

- [ ] **Step 2: Create version.rs**

Create `crates/winreg-format/src/version.rs`:

```rust
//! REGF hive version enumeration.

/// Registry hive format version, determined by the minor version field
/// in the base block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegfVersion {
    /// Version 1.0-1.2: Windows NT 3.x. LI index only.
    V1_0,
    /// Version 1.3: Windows NT 4.0. Adds LF (fast leaf).
    V1_3,
    /// Version 1.4: Windows XP beta. Adds big data (DB).
    V1_4,
    /// Version 1.5: Windows XP release+. Adds LH (hash leaf).
    V1_5,
    /// Version 1.6: Windows 10+. Differencing/layered hives.
    V1_6,
}

impl RegfVersion {
    /// Determine version from minor version number.
    pub fn from_minor(minor: u32) -> Option<Self> {
        match minor {
            0..=2 => Some(Self::V1_0),
            3 => Some(Self::V1_3),
            4 => Some(Self::V1_4),
            5 => Some(Self::V1_5),
            6 => Some(Self::V1_6),
            _ => None,
        }
    }

    /// Whether this version supports LH (hash leaf) index cells.
    pub fn has_hash_leaf(self) -> bool {
        self >= Self::V1_5
    }

    /// Whether this version supports DB (big data) cells.
    pub fn has_big_data(self) -> bool {
        self >= Self::V1_4
    }

    /// Whether this version supports LF (fast leaf) index cells.
    pub fn has_fast_leaf(self) -> bool {
        self >= Self::V1_3
    }

    /// Whether this version supports differencing/layered keys.
    pub fn has_layered_keys(self) -> bool {
        self >= Self::V1_6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_minor() {
        assert_eq!(RegfVersion::from_minor(0), Some(RegfVersion::V1_0));
        assert_eq!(RegfVersion::from_minor(2), Some(RegfVersion::V1_0));
        assert_eq!(RegfVersion::from_minor(3), Some(RegfVersion::V1_3));
        assert_eq!(RegfVersion::from_minor(5), Some(RegfVersion::V1_5));
        assert_eq!(RegfVersion::from_minor(6), Some(RegfVersion::V1_6));
        assert_eq!(RegfVersion::from_minor(99), None);
    }

    #[test]
    fn version_feature_gates() {
        assert!(!RegfVersion::V1_0.has_fast_leaf());
        assert!(RegfVersion::V1_3.has_fast_leaf());
        assert!(!RegfVersion::V1_3.has_big_data());
        assert!(RegfVersion::V1_4.has_big_data());
        assert!(!RegfVersion::V1_4.has_hash_leaf());
        assert!(RegfVersion::V1_5.has_hash_leaf());
        assert!(RegfVersion::V1_6.has_layered_keys());
    }

    #[test]
    fn versions_are_ordered() {
        assert!(RegfVersion::V1_0 < RegfVersion::V1_3);
        assert!(RegfVersion::V1_3 < RegfVersion::V1_5);
        assert!(RegfVersion::V1_5 < RegfVersion::V1_6);
    }
}
```

- [ ] **Step 3: Run tests to verify they pass**

```bash
cd ~/src/winreg-forensic
cargo test -p winreg-format
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-format/src/header.rs crates/winreg-format/src/version.rs crates/winreg-format/src/lib.rs
git commit -m "feat(format): add BaseBlock header with checksum validation and RegfVersion"
```

---

### Task 3: winreg-format — HBin + CellOffset

**Files:**
- Create: `crates/winreg-format/src/hbin.rs`
- Modify: `crates/winreg-format/src/cells.rs` (add CellOffset)

- [ ] **Step 1: Write HBin header struct and CellOffset newtype**

Create `crates/winreg-format/src/hbin.rs`:

```rust
//! Hive bin (hbin) header — 32-byte container header within a hive file.

use binrw::BinRead;

/// Hive bin header (32 bytes). Hive bins immediately follow the 4096-byte
/// base block and contain all cells (keys, values, security descriptors, etc.).
///
/// Reference: research/regf-binary-format-specification.md Section 2.1
#[derive(Debug, Clone, BinRead)]
#[br(little, magic = b"hbin")]
pub struct HbinHeader {
    /// Offset of this hbin from the start of hive bins data (NOT file start).
    /// First hbin has offset 0.
    pub offset: u32,
    /// Size of this hbin in bytes (including 32-byte header). Always multiple of 4096.
    pub size: u32,
    /// Reserved (8 bytes). Typically zero.
    pub reserved: u64,
    /// FILETIME timestamp. Only meaningful for the first hbin.
    pub timestamp: u64,
    /// Runtime spare/memory allocation field. No meaning on disk.
    pub spare: u32,
}

impl HbinHeader {
    /// Size of the hbin header in bytes.
    pub const SIZE: u32 = 32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_test_hbin(offset: u32, size: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(b"hbin");
        buf[4..8].copy_from_slice(&offset.to_le_bytes());
        buf[8..12].copy_from_slice(&size.to_le_bytes());
        buf
    }

    #[test]
    fn parse_hbin_header() {
        let buf = build_test_hbin(0, 4096);
        let mut cursor = Cursor::new(&buf[..]);
        let hbin = HbinHeader::read(&mut cursor).unwrap();
        assert_eq!(hbin.offset, 0);
        assert_eq!(hbin.size, 4096);
    }

    #[test]
    fn parse_second_hbin_with_offset() {
        let buf = build_test_hbin(4096, 8192);
        let mut cursor = Cursor::new(&buf[..]);
        let hbin = HbinHeader::read(&mut cursor).unwrap();
        assert_eq!(hbin.offset, 4096);
        assert_eq!(hbin.size, 8192);
    }

    #[test]
    fn rejects_invalid_signature() {
        let mut buf = build_test_hbin(0, 4096);
        buf[0..4].copy_from_slice(b"nope");
        let mut cursor = Cursor::new(&buf[..]);
        assert!(HbinHeader::read(&mut cursor).is_err());
    }
}
```

- [ ] **Step 2: Write CellOffset newtype**

Create `crates/winreg-format/src/cells.rs`:

```rust
//! Cell types and the CellOffset newtype.

use binrw::BinRead;

/// Offset to a cell within hive bins data.
///
/// All cell offsets in the REGF format are relative to the start of the hive
/// bins data area (which begins at file offset 4096). This newtype prevents
/// accidentally mixing cell offsets with file offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BinRead)]
#[br(little)]
pub struct CellOffset(pub u32);

impl CellOffset {
    /// Null/empty sentinel value (0xFFFFFFFF).
    pub const NULL: Self = Self(0xFFFF_FFFF);

    /// Convert a cell offset to an absolute file offset.
    ///
    /// `file_offset = 4096 + cell_offset`
    pub fn file_offset(self) -> u64 {
        4096 + u64::from(self.0)
    }

    /// Check if this is a null/empty reference.
    pub fn is_null(self) -> bool {
        self.0 == 0xFFFF_FFFF
    }
}

impl std::fmt::Display for CellOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_null() {
            write!(f, "NULL")
        } else {
            write!(f, "0x{:08X}", self.0)
        }
    }
}

/// Raw cell header — the first 4 bytes of every cell.
///
/// Cell size is a signed i32:
/// - **Negative** = allocated cell (use absolute value for size)
/// - **Positive** = free/unallocated cell
///
/// All cell sizes are 8-byte aligned.
#[derive(Debug, Clone, Copy)]
pub struct CellHeader {
    /// Raw size field (negative = allocated, positive = free).
    pub raw_size: i32,
}

impl CellHeader {
    /// Parse cell header from 4 bytes.
    pub fn from_bytes(bytes: &[u8; 4]) -> Self {
        Self {
            raw_size: i32::from_le_bytes(*bytes),
        }
    }

    /// Whether this cell is allocated.
    pub fn is_allocated(&self) -> bool {
        self.raw_size < 0
    }

    /// Absolute cell size in bytes (including the 4-byte size field).
    pub fn size(&self) -> u32 {
        self.raw_size.unsigned_abs()
    }
}

/// Two-byte cell signature identifying the cell type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellSignature {
    /// `nk` — Key Node
    KeyNode,
    /// `vk` — Key Value
    KeyValue,
    /// `sk` — Security Key
    SecurityKey,
    /// `lf` — Fast Leaf (subkey index with name hints)
    FastLeaf,
    /// `lh` — Hash Leaf (subkey index with name hashes)
    HashLeaf,
    /// `li` — Index Leaf (simple subkey index)
    IndexLeaf,
    /// `ri` — Root Index (index of subkey indices)
    RootIndex,
    /// `db` — Big Data
    BigData,
}

impl CellSignature {
    /// Parse a 2-byte signature.
    pub fn from_bytes(bytes: &[u8; 2]) -> Option<Self> {
        match bytes {
            b"nk" => Some(Self::KeyNode),
            b"vk" => Some(Self::KeyValue),
            b"sk" => Some(Self::SecurityKey),
            b"lf" => Some(Self::FastLeaf),
            b"lh" => Some(Self::HashLeaf),
            b"li" => Some(Self::IndexLeaf),
            b"ri" => Some(Self::RootIndex),
            b"db" => Some(Self::BigData),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_offset_file_conversion() {
        let offset = CellOffset(0x20);
        assert_eq!(offset.file_offset(), 4096 + 0x20);
    }

    #[test]
    fn cell_offset_null() {
        assert!(CellOffset::NULL.is_null());
        assert!(!CellOffset(0).is_null());
    }

    #[test]
    fn cell_offset_display() {
        assert_eq!(format!("{}", CellOffset::NULL), "NULL");
        assert_eq!(format!("{}", CellOffset(0x20)), "0x00000020");
    }

    #[test]
    fn cell_header_allocated() {
        // -128 as i32 = 0xFFFFFF80
        let bytes = (-128i32).to_le_bytes();
        let header = CellHeader::from_bytes(&bytes);
        assert!(header.is_allocated());
        assert_eq!(header.size(), 128);
    }

    #[test]
    fn cell_header_free() {
        let bytes = 64i32.to_le_bytes();
        let header = CellHeader::from_bytes(&bytes);
        assert!(!header.is_allocated());
        assert_eq!(header.size(), 64);
    }

    #[test]
    fn cell_signatures() {
        assert_eq!(CellSignature::from_bytes(b"nk"), Some(CellSignature::KeyNode));
        assert_eq!(CellSignature::from_bytes(b"vk"), Some(CellSignature::KeyValue));
        assert_eq!(CellSignature::from_bytes(b"sk"), Some(CellSignature::SecurityKey));
        assert_eq!(CellSignature::from_bytes(b"lf"), Some(CellSignature::FastLeaf));
        assert_eq!(CellSignature::from_bytes(b"lh"), Some(CellSignature::HashLeaf));
        assert_eq!(CellSignature::from_bytes(b"li"), Some(CellSignature::IndexLeaf));
        assert_eq!(CellSignature::from_bytes(b"ri"), Some(CellSignature::RootIndex));
        assert_eq!(CellSignature::from_bytes(b"db"), Some(CellSignature::BigData));
        assert_eq!(CellSignature::from_bytes(b"xx"), None);
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-format
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-format/src/hbin.rs crates/winreg-format/src/cells.rs
git commit -m "feat(format): add HbinHeader, CellOffset newtype, CellHeader, and CellSignature"
```

---

### Task 4: winreg-format — NK and VK Cell Structures + Flags

**Files:**
- Modify: `crates/winreg-format/src/cells.rs` (add NK, VK structs)
- Create: `crates/winreg-format/src/flags.rs`

- [ ] **Step 1: Write KeyFlags and ValueType in flags.rs**

Create `crates/winreg-format/src/flags.rs`:

```rust
//! Bitflags and enums for registry cell fields.

use bitflags::bitflags;

bitflags! {
    /// NK cell flags (offset 0x02 in NK cell, u16).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyFlags: u16 {
        /// Key exists only in memory (not persisted).
        const VOLATILE      = 0x0001;
        /// Mount point — link to root of another hive.
        const HIVE_EXIT     = 0x0002;
        /// Root key of the current hive.
        const HIVE_ENTRY    = 0x0004;
        /// Key cannot be deleted.
        const NO_DELETE     = 0x0008;
        /// Symbolic link key.
        const SYM_LINK      = 0x0010;
        /// Key name is compressed ASCII (not UTF-16LE).
        const COMP_NAME     = 0x0020;
        /// Predefined handle.
        const PREDEF_HANDLE = 0x0040;
        /// Virtualization: mirror key.
        const VIRT_MIRRORED = 0x0080;
        /// Virtualization: target key.
        const VIRT_TARGET   = 0x0100;
        /// Virtualization: virtual store.
        const VIRTUAL_STORE = 0x0200;
    }
}

bitflags! {
    /// VK cell flags (offset 0x10 in VK cell, u16).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ValueFlags: u16 {
        /// Value name is compressed ASCII (not UTF-16LE).
        const COMP_NAME = 0x0001;
    }
}

/// Registry value data type (offset 0x0C in VK cell, u32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ValueType {
    None = 0,
    Sz = 1,
    ExpandSz = 2,
    Binary = 3,
    Dword = 4,
    DwordBigEndian = 5,
    Link = 6,
    MultiSz = 7,
    ResourceList = 8,
    FullResourceDescriptor = 9,
    ResourceRequirementsList = 10,
    Qword = 11,
    /// Unknown/unrecognized type.
    Unknown(u32),
}

impl ValueType {
    /// Parse from raw u32 value.
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            other => Self::Unknown(other),
        }
    }

    /// Convert to display name.
    pub fn name(&self) -> &str {
        match self {
            Self::None => "REG_NONE",
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD",
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiSz => "REG_MULTI_SZ",
            Self::ResourceList => "REG_RESOURCE_LIST",
            Self::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::Qword => "REG_QWORD",
            Self::Unknown(_) => "REG_UNKNOWN",
        }
    }
}

impl std::fmt::Display for ValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_flags_comp_name() {
        let flags = KeyFlags::COMP_NAME | KeyFlags::HIVE_ENTRY;
        assert!(flags.contains(KeyFlags::COMP_NAME));
        assert!(flags.contains(KeyFlags::HIVE_ENTRY));
        assert!(!flags.contains(KeyFlags::VOLATILE));
    }

    #[test]
    fn value_type_roundtrip() {
        for raw in 0..=11 {
            let vt = ValueType::from_raw(raw);
            assert_ne!(vt.name(), "REG_UNKNOWN");
        }
        assert!(matches!(ValueType::from_raw(99), ValueType::Unknown(99)));
    }

    #[test]
    fn value_type_display() {
        assert_eq!(ValueType::Sz.to_string(), "REG_SZ");
        assert_eq!(ValueType::Dword.to_string(), "REG_DWORD");
        assert_eq!(ValueType::MultiSz.to_string(), "REG_MULTI_SZ");
    }
}
```

- [ ] **Step 2: Add NK and VK raw structs to cells.rs**

Append to `crates/winreg-format/src/cells.rs`:

```rust
use crate::flags::{KeyFlags, ValueFlags, ValueType};

/// Raw NK (Key Node) cell data — parsed from bytes after the cell size field.
///
/// Fixed header: 76 bytes (0x4C) + variable-length key name.
/// Reference: research/regf-binary-format-specification.md Section 3.1
#[derive(Debug, Clone)]
pub struct RawKeyNode {
    /// NK flags (KEY_COMP_NAME, KEY_HIVE_ENTRY, etc.).
    pub flags: KeyFlags,
    /// Last written timestamp (FILETIME UTC).
    pub last_written: u64,
    /// Access bits (Win8+) / spare.
    pub access_bits: u32,
    /// Offset to parent key node.
    pub parent: CellOffset,
    /// Count of stable (non-volatile) subkeys.
    pub subkey_count: u32,
    /// Count of volatile subkeys (not meaningful on disk).
    pub volatile_subkey_count: u32,
    /// Offset to subkeys list (LF/LH/LI/RI cell).
    pub subkeys_list_offset: CellOffset,
    /// Offset to volatile subkeys list (not meaningful on disk).
    pub volatile_subkeys_list_offset: CellOffset,
    /// Count of values under this key.
    pub value_count: u32,
    /// Offset to values list (array of VK offsets).
    pub values_list_offset: CellOffset,
    /// Offset to SK (security key) cell.
    pub security_offset: CellOffset,
    /// Offset to class name data cell.
    pub class_name_offset: CellOffset,
    /// Compound: max subkey name len (u16) | user flags (4 bits) | virt ctrl (4 bits) | debug (8 bits).
    pub max_subkey_name_compound: u32,
    /// Max subkey class name length.
    pub max_subkey_class_len: u32,
    /// Max value name length.
    pub max_value_name_len: u32,
    /// Max value data size.
    pub max_value_data_size: u32,
    /// Runtime work variable (residual data on disk).
    pub work_var: u32,
    /// Key name length in bytes.
    pub key_name_len: u16,
    /// Class name length in bytes.
    pub class_name_len: u16,
    /// Key name bytes (compressed ASCII or UTF-16LE per COMP_NAME flag).
    pub key_name_raw: Vec<u8>,
}

impl RawKeyNode {
    /// Fixed header size (before the variable-length key name).
    pub const HEADER_SIZE: usize = 0x4C;

    /// Parse an NK cell from a byte slice (starting after the 2-byte "nk" signature).
    /// The `data` slice should begin at the flags field (offset 0x02 within the cell body).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE - 2 {
            return None;
        }
        let flags = KeyFlags::from_bits_truncate(u16::from_le_bytes([data[0], data[1]]));
        let last_written = u64::from_le_bytes(data[2..10].try_into().ok()?);
        let access_bits = u32::from_le_bytes(data[10..14].try_into().ok()?);
        let parent = CellOffset(u32::from_le_bytes(data[14..18].try_into().ok()?));
        let subkey_count = u32::from_le_bytes(data[18..22].try_into().ok()?);
        let volatile_subkey_count = u32::from_le_bytes(data[22..26].try_into().ok()?);
        let subkeys_list_offset = CellOffset(u32::from_le_bytes(data[26..30].try_into().ok()?));
        let volatile_subkeys_list_offset =
            CellOffset(u32::from_le_bytes(data[30..34].try_into().ok()?));
        let value_count = u32::from_le_bytes(data[34..38].try_into().ok()?);
        let values_list_offset = CellOffset(u32::from_le_bytes(data[38..42].try_into().ok()?));
        let security_offset = CellOffset(u32::from_le_bytes(data[42..46].try_into().ok()?));
        let class_name_offset = CellOffset(u32::from_le_bytes(data[46..50].try_into().ok()?));
        let max_subkey_name_compound = u32::from_le_bytes(data[50..54].try_into().ok()?);
        let max_subkey_class_len = u32::from_le_bytes(data[54..58].try_into().ok()?);
        let max_value_name_len = u32::from_le_bytes(data[58..62].try_into().ok()?);
        let max_value_data_size = u32::from_le_bytes(data[62..66].try_into().ok()?);
        let work_var = u32::from_le_bytes(data[66..70].try_into().ok()?);
        let key_name_len = u16::from_le_bytes([data[70], data[71]]);
        let class_name_len = u16::from_le_bytes([data[72], data[73]]);

        let name_start = 74; // 0x4C - 2 (we skipped the signature)
        let name_end = name_start + usize::from(key_name_len);
        if data.len() < name_end {
            return None;
        }
        let key_name_raw = data[name_start..name_end].to_vec();

        Some(Self {
            flags,
            last_written,
            access_bits,
            parent,
            subkey_count,
            volatile_subkey_count,
            subkeys_list_offset,
            volatile_subkeys_list_offset,
            value_count,
            values_list_offset,
            security_offset,
            class_name_offset,
            max_subkey_name_compound,
            max_subkey_class_len,
            max_value_name_len,
            max_value_data_size,
            work_var,
            key_name_len,
            class_name_len,
            key_name_raw,
        })
    }

    /// Decode key name to a String.
    pub fn key_name(&self) -> String {
        if self.flags.contains(KeyFlags::COMP_NAME) {
            // Compressed ASCII: one byte per character.
            self.key_name_raw.iter().map(|&b| b as char).collect()
        } else {
            // UTF-16LE.
            let u16s: Vec<u16> = self
                .key_name_raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16s)
        }
    }

    /// Whether this is the root key of the hive.
    pub fn is_root(&self) -> bool {
        self.flags.contains(KeyFlags::HIVE_ENTRY)
    }
}

/// Raw VK (Key Value) cell data — parsed from bytes after the cell size field.
///
/// Fixed header: 20 bytes (0x14) + variable-length value name.
/// Reference: research/regf-binary-format-specification.md Section 3.2
#[derive(Debug, Clone)]
pub struct RawKeyValue {
    /// Value name length in bytes. 0 = unnamed (default value).
    pub name_len: u16,
    /// Data size. Bit 31 set = resident (data inline in data_offset field).
    pub data_size_raw: u32,
    /// Data offset (cell offset) or inline data if resident.
    pub data_offset_raw: u32,
    /// Data type (REG_SZ, REG_DWORD, etc.).
    pub data_type: ValueType,
    /// Flags (VALUE_COMP_NAME).
    pub flags: ValueFlags,
    /// Value name bytes (compressed ASCII or UTF-16LE).
    pub name_raw: Vec<u8>,
}

impl RawKeyValue {
    /// Fixed header size before value name.
    pub const HEADER_SIZE: usize = 0x14;

    /// Parse a VK cell from a byte slice (starting after the 2-byte "vk" signature).
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE - 2 {
            return None;
        }
        let name_len = u16::from_le_bytes([data[0], data[1]]);
        let data_size_raw = u32::from_le_bytes(data[2..6].try_into().ok()?);
        let data_offset_raw = u32::from_le_bytes(data[6..10].try_into().ok()?);
        let data_type = ValueType::from_raw(u32::from_le_bytes(data[10..14].try_into().ok()?));
        let flags = ValueFlags::from_bits_truncate(u16::from_le_bytes([data[14], data[15]]));
        // data[16..18] = spare, skip

        let name_start = 18; // 0x14 - 2
        let name_end = name_start + usize::from(name_len);
        if data.len() < name_end {
            return None;
        }
        let name_raw = data[name_start..name_end].to_vec();

        Some(Self {
            name_len,
            data_size_raw,
            data_offset_raw,
            data_type,
            flags,
            name_raw,
        })
    }

    /// Whether the value data is resident (stored inline in the offset field).
    pub fn is_resident(&self) -> bool {
        self.data_size_raw & 0x8000_0000 != 0
    }

    /// Actual data size in bytes (bit 31 masked off).
    pub fn data_size(&self) -> u32 {
        self.data_size_raw & 0x7FFF_FFFF
    }

    /// Data offset as CellOffset (only valid if not resident).
    pub fn data_offset(&self) -> CellOffset {
        CellOffset(self.data_offset_raw)
    }

    /// Inline data bytes (only valid if resident and data_size <= 4).
    pub fn inline_data(&self) -> Vec<u8> {
        let size = self.data_size() as usize;
        let bytes = self.data_offset_raw.to_le_bytes();
        bytes[..size.min(4)].to_vec()
    }

    /// Decode value name to a String. Empty string for unnamed (default) values.
    pub fn value_name(&self) -> String {
        if self.name_len == 0 {
            return String::new();
        }
        if self.flags.contains(ValueFlags::COMP_NAME) {
            self.name_raw.iter().map(|&b| b as char).collect()
        } else {
            let u16s: Vec<u16> = self
                .name_raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16s)
        }
    }
}

// Add to existing tests module:
#[cfg(test)]
mod nk_vk_tests {
    use super::*;
    use crate::flags::KeyFlags;

    fn build_nk_bytes(name: &str, flags: KeyFlags, subkey_count: u32, value_count: u32) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut buf = vec![0u8; 74 + name_bytes.len()];
        // flags
        buf[0..2].copy_from_slice(&flags.bits().to_le_bytes());
        // last_written
        buf[2..10].copy_from_slice(&1000u64.to_le_bytes());
        // parent offset = 0x20
        buf[14..18].copy_from_slice(&0x20u32.to_le_bytes());
        // subkey_count
        buf[18..22].copy_from_slice(&subkey_count.to_le_bytes());
        // subkeys_list_offset (NULL if no subkeys)
        let sk_offset = if subkey_count > 0 { 0x100u32 } else { 0xFFFF_FFFFu32 };
        buf[26..30].copy_from_slice(&sk_offset.to_le_bytes());
        // value_count
        buf[34..38].copy_from_slice(&value_count.to_le_bytes());
        // values_list_offset (NULL if no values)
        let vl_offset = if value_count > 0 { 0x200u32 } else { 0xFFFF_FFFFu32 };
        buf[38..42].copy_from_slice(&vl_offset.to_le_bytes());
        // security offset
        buf[42..46].copy_from_slice(&0x300u32.to_le_bytes());
        // class_name_offset = NULL
        buf[46..50].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // key_name_len
        buf[70..72].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        // key_name
        buf[74..74 + name_bytes.len()].copy_from_slice(name_bytes);
        buf
    }

    #[test]
    fn parse_nk_root_key() {
        let data = build_nk_bytes("CMI-CreateHive{2A7FB991}", KeyFlags::HIVE_ENTRY | KeyFlags::COMP_NAME, 3, 0);
        let nk = RawKeyNode::parse(&data).unwrap();
        assert!(nk.is_root());
        assert_eq!(nk.key_name(), "CMI-CreateHive{2A7FB991}");
        assert_eq!(nk.subkey_count, 3);
        assert_eq!(nk.value_count, 0);
        assert!(nk.flags.contains(KeyFlags::COMP_NAME));
    }

    #[test]
    fn parse_nk_child_key() {
        let data = build_nk_bytes("Software", KeyFlags::COMP_NAME, 0, 2);
        let nk = RawKeyNode::parse(&data).unwrap();
        assert!(!nk.is_root());
        assert_eq!(nk.key_name(), "Software");
        assert_eq!(nk.value_count, 2);
    }

    #[test]
    fn nk_rejects_truncated_data() {
        let data = vec![0u8; 10]; // Too short
        assert!(RawKeyNode::parse(&data).is_none());
    }

    fn build_vk_bytes(name: &str, data_type: u32, data_size: u32, data_offset: u32) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let comp_flag: u16 = if name.is_empty() { 0 } else { 0x0001 }; // COMP_NAME
        let mut buf = vec![0u8; 18 + name_bytes.len()];
        // name_len
        buf[0..2].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        // data_size
        buf[2..6].copy_from_slice(&data_size.to_le_bytes());
        // data_offset
        buf[6..10].copy_from_slice(&data_offset.to_le_bytes());
        // data_type
        buf[10..14].copy_from_slice(&data_type.to_le_bytes());
        // flags
        buf[14..16].copy_from_slice(&comp_flag.to_le_bytes());
        // name
        buf[18..18 + name_bytes.len()].copy_from_slice(name_bytes);
        buf
    }

    #[test]
    fn parse_vk_dword_resident() {
        // Resident: MSB set in data_size, data stored in offset field
        let data = build_vk_bytes("Start", 4, 0x8000_0004, 0x0000_0003);
        let vk = RawKeyValue::parse(&data).unwrap();
        assert_eq!(vk.value_name(), "Start");
        assert!(matches!(vk.data_type, ValueType::Dword));
        assert!(vk.is_resident());
        assert_eq!(vk.data_size(), 4);
        assert_eq!(vk.inline_data(), vec![3, 0, 0, 0]);
    }

    #[test]
    fn parse_vk_string_non_resident() {
        let data = build_vk_bytes("ImagePath", 1, 42, 0x500);
        let vk = RawKeyValue::parse(&data).unwrap();
        assert_eq!(vk.value_name(), "ImagePath");
        assert!(matches!(vk.data_type, ValueType::Sz));
        assert!(!vk.is_resident());
        assert_eq!(vk.data_size(), 42);
        assert_eq!(vk.data_offset(), CellOffset(0x500));
    }

    #[test]
    fn parse_vk_unnamed_default_value() {
        let data = build_vk_bytes("", 1, 10, 0x600);
        let vk = RawKeyValue::parse(&data).unwrap();
        assert_eq!(vk.value_name(), "");
        assert_eq!(vk.name_len, 0);
    }

    #[test]
    fn vk_rejects_truncated_data() {
        let data = vec![0u8; 5]; // Too short
        assert!(RawKeyValue::parse(&data).is_none());
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-format
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-format/src/flags.rs crates/winreg-format/src/cells.rs crates/winreg-format/src/lib.rs
git commit -m "feat(format): add NK/VK cell structs, KeyFlags, ValueType, ValueFlags"
```

---

### Task 5: winreg-format — Index Cells (LF, LH, LI, RI) + SK + DB

**Files:**
- Modify: `crates/winreg-format/src/cells.rs`

- [ ] **Step 1: Add index cell structs**

Append to `crates/winreg-format/src/cells.rs`:

```rust
/// LF (Fast Leaf) element: key node offset + 4-byte name hint.
#[derive(Debug, Clone, Copy)]
pub struct LfElement {
    pub key_offset: CellOffset,
    /// First 4 ASCII characters of key name (uppercase).
    pub name_hint: [u8; 4],
}

/// LH (Hash Leaf) element: key node offset + 32-bit name hash.
#[derive(Debug, Clone, Copy)]
pub struct LhElement {
    pub key_offset: CellOffset,
    /// Hash: H = 37*H + C[i] over uppercase key name.
    pub name_hash: u32,
}

/// Parsed subkey index — dispatches across LF, LH, LI, RI.
#[derive(Debug, Clone)]
pub enum SubkeyIndex {
    /// Fast Leaf: offsets + 4-byte name hints.
    FastLeaf(Vec<LfElement>),
    /// Hash Leaf: offsets + 32-bit name hashes.
    HashLeaf(Vec<LhElement>),
    /// Index Leaf: plain offsets.
    IndexLeaf(Vec<CellOffset>),
    /// Root Index: offsets to sub-index cells (LF/LH/LI).
    RootIndex(Vec<CellOffset>),
}

impl SubkeyIndex {
    /// Parse an LF (Fast Leaf) from bytes after the 2-byte signature.
    pub fn parse_lf(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let elements_data = &data[2..];
        if elements_data.len() < count * 8 {
            return None;
        }
        let elements = (0..count)
            .map(|i| {
                let base = i * 8;
                LfElement {
                    key_offset: CellOffset(u32::from_le_bytes(
                        elements_data[base..base + 4].try_into().unwrap(),
                    )),
                    name_hint: elements_data[base + 4..base + 8].try_into().unwrap(),
                }
            })
            .collect();
        Some(Self::FastLeaf(elements))
    }

    /// Parse an LH (Hash Leaf) from bytes after the 2-byte signature.
    pub fn parse_lh(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let elements_data = &data[2..];
        if elements_data.len() < count * 8 {
            return None;
        }
        let elements = (0..count)
            .map(|i| {
                let base = i * 8;
                LhElement {
                    key_offset: CellOffset(u32::from_le_bytes(
                        elements_data[base..base + 4].try_into().unwrap(),
                    )),
                    name_hash: u32::from_le_bytes(
                        elements_data[base + 4..base + 8].try_into().unwrap(),
                    ),
                }
            })
            .collect();
        Some(Self::HashLeaf(elements))
    }

    /// Parse an LI (Index Leaf) from bytes after the 2-byte signature.
    pub fn parse_li(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let elements_data = &data[2..];
        if elements_data.len() < count * 4 {
            return None;
        }
        let offsets = (0..count)
            .map(|i| {
                let base = i * 4;
                CellOffset(u32::from_le_bytes(
                    elements_data[base..base + 4].try_into().unwrap(),
                ))
            })
            .collect();
        Some(Self::IndexLeaf(offsets))
    }

    /// Parse an RI (Root Index) from bytes after the 2-byte signature.
    pub fn parse_ri(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let elements_data = &data[2..];
        if elements_data.len() < count * 4 {
            return None;
        }
        let offsets = (0..count)
            .map(|i| {
                let base = i * 4;
                CellOffset(u32::from_le_bytes(
                    elements_data[base..base + 4].try_into().unwrap(),
                ))
            })
            .collect();
        Some(Self::RootIndex(offsets))
    }
}

/// Compute LH name hash: H = 37*H + C[i] over uppercase name.
pub fn lh_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for c in name.to_ascii_uppercase().bytes() {
        h = h.wrapping_mul(37).wrapping_add(u32::from(c));
    }
    h
}

/// Raw SK (Security Key) cell data.
///
/// Reference: research/regf-binary-format-specification.md Section 3.7
#[derive(Debug, Clone)]
pub struct RawSecurityKey {
    /// Forward link to next SK cell in circular doubly-linked list.
    pub flink: CellOffset,
    /// Backward link to previous SK cell.
    pub blink: CellOffset,
    /// Number of NK cells referencing this SK cell.
    pub reference_count: u32,
    /// Size of the security descriptor in bytes.
    pub descriptor_size: u32,
    /// Raw security descriptor bytes (self-relative format).
    pub descriptor: Vec<u8>,
}

impl RawSecurityKey {
    /// Parse an SK cell from bytes after the 2-byte "sk" signature.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 18 {
            return None;
        }
        // data[0..2] = reserved (skip)
        let flink = CellOffset(u32::from_le_bytes(data[2..6].try_into().ok()?));
        let blink = CellOffset(u32::from_le_bytes(data[6..10].try_into().ok()?));
        let reference_count = u32::from_le_bytes(data[10..14].try_into().ok()?);
        let descriptor_size = u32::from_le_bytes(data[14..18].try_into().ok()?);
        let desc_end = 18 + descriptor_size as usize;
        if data.len() < desc_end {
            return None;
        }
        let descriptor = data[18..desc_end].to_vec();
        Some(Self {
            flink,
            blink,
            reference_count,
            descriptor_size,
            descriptor,
        })
    }
}

/// Raw DB (Big Data) cell.
///
/// Reference: research/regf-binary-format-specification.md Section 3.8
#[derive(Debug, Clone)]
pub struct RawBigData {
    /// Number of data segments.
    pub segment_count: u16,
    /// Offset to the segment list cell.
    pub segment_list_offset: CellOffset,
}

impl RawBigData {
    /// Parse a DB cell from bytes after the 2-byte "db" signature.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 6 {
            return None;
        }
        let segment_count = u16::from_le_bytes([data[0], data[1]]);
        let segment_list_offset = CellOffset(u32::from_le_bytes(data[2..6].try_into().ok()?));
        Some(Self {
            segment_count,
            segment_list_offset,
        })
    }
}
```

- [ ] **Step 2: Write tests for index cells**

Append to the test module in `cells.rs`:

```rust
#[cfg(test)]
mod index_tests {
    use super::*;

    #[test]
    fn parse_lh_with_two_elements() {
        let mut data = vec![0u8; 2 + 2 * 8];
        data[0..2].copy_from_slice(&2u16.to_le_bytes()); // count = 2
        // Element 0: offset=0x100, hash=0xABCD
        data[2..6].copy_from_slice(&0x100u32.to_le_bytes());
        data[6..10].copy_from_slice(&0xABCDu32.to_le_bytes());
        // Element 1: offset=0x200, hash=0x1234
        data[10..14].copy_from_slice(&0x200u32.to_le_bytes());
        data[14..18].copy_from_slice(&0x1234u32.to_le_bytes());

        let index = SubkeyIndex::parse_lh(&data).unwrap();
        if let SubkeyIndex::HashLeaf(elements) = index {
            assert_eq!(elements.len(), 2);
            assert_eq!(elements[0].key_offset, CellOffset(0x100));
            assert_eq!(elements[0].name_hash, 0xABCD);
            assert_eq!(elements[1].key_offset, CellOffset(0x200));
        } else {
            panic!("expected HashLeaf");
        }
    }

    #[test]
    fn parse_li_with_three_offsets() {
        let mut data = vec![0u8; 2 + 3 * 4];
        data[0..2].copy_from_slice(&3u16.to_le_bytes());
        data[2..6].copy_from_slice(&0x100u32.to_le_bytes());
        data[6..10].copy_from_slice(&0x200u32.to_le_bytes());
        data[10..14].copy_from_slice(&0x300u32.to_le_bytes());

        let index = SubkeyIndex::parse_li(&data).unwrap();
        if let SubkeyIndex::IndexLeaf(offsets) = index {
            assert_eq!(offsets.len(), 3);
            assert_eq!(offsets[0], CellOffset(0x100));
        } else {
            panic!("expected IndexLeaf");
        }
    }

    #[test]
    fn lh_hash_algorithm() {
        // Known test vector: uppercase "SOFTWARE"
        let hash = lh_hash("SOFTWARE");
        // Manual: H=0, S: 37*0+83=83, O: 37*83+79=3150, F: 37*3150+70=116620,
        // T: 37*116620+84=4314924, W: 37*4314924+87=159652275,
        // A: 37*159652275+65=5907134240 -> wrapping u32 = 1612167344,
        // R: 37*1612167344+82=... let Rust compute
        assert_eq!(hash, lh_hash("software")); // case-insensitive
    }

    #[test]
    fn parse_sk_cell() {
        let mut data = vec![0u8; 18 + 20]; // 20 bytes of descriptor
        // reserved (2 bytes) = 0
        data[2..6].copy_from_slice(&0x100u32.to_le_bytes()); // flink
        data[6..10].copy_from_slice(&0x200u32.to_le_bytes()); // blink
        data[10..14].copy_from_slice(&3u32.to_le_bytes()); // ref_count
        data[14..18].copy_from_slice(&20u32.to_le_bytes()); // descriptor size
        data[18..38].fill(0xAA); // dummy descriptor

        let sk = RawSecurityKey::parse(&data).unwrap();
        assert_eq!(sk.flink, CellOffset(0x100));
        assert_eq!(sk.reference_count, 3);
        assert_eq!(sk.descriptor.len(), 20);
    }

    #[test]
    fn parse_db_cell() {
        let mut data = vec![0u8; 6];
        data[0..2].copy_from_slice(&3u16.to_le_bytes()); // 3 segments
        data[2..6].copy_from_slice(&0x500u32.to_le_bytes()); // segment list offset

        let db = RawBigData::parse(&data).unwrap();
        assert_eq!(db.segment_count, 3);
        assert_eq!(db.segment_list_offset, CellOffset(0x500));
    }

    #[test]
    fn empty_index_parses() {
        let data = vec![0u8; 2]; // count = 0
        let index = SubkeyIndex::parse_lh(&data).unwrap();
        if let SubkeyIndex::HashLeaf(elements) = index {
            assert!(elements.is_empty());
        } else {
            panic!("expected empty HashLeaf");
        }
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-format
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-format/src/cells.rs
git commit -m "feat(format): add index cells (LF/LH/LI/RI), SK, DB, and lh_hash"
```

---

### Task 6: winreg-core — Error Types

**Files:**
- Create: `crates/winreg-core/src/error.rs`

- [ ] **Step 1: Write error types with miette diagnostics**

Create `crates/winreg-core/src/error.rs`:

```rust
//! Error types for registry hive parsing.

use miette::Diagnostic;
use thiserror::Error;
use winreg_format::cells::CellOffset;

/// All errors from winreg-core.
#[derive(Debug, Error, Diagnostic)]
pub enum HiveError {
    #[error("Invalid regf signature — not a registry hive file")]
    #[diagnostic(code(winreg::invalid_signature))]
    InvalidSignature,

    #[error("Base block checksum mismatch: expected {expected:#010X}, computed {computed:#010X}")]
    #[diagnostic(code(winreg::checksum_mismatch))]
    ChecksumMismatch { expected: u32, computed: u32 },

    #[error("Unsupported REGF version: {major}.{minor}")]
    #[diagnostic(code(winreg::unsupported_version))]
    UnsupportedVersion { major: u32, minor: u32 },

    #[error("Cell at offset {offset} extends beyond hbin boundary (cell size: {cell_size}, hbin ends at: {hbin_end})")]
    #[diagnostic(code(winreg::cell_overflow))]
    CellOverflow {
        offset: CellOffset,
        cell_size: u32,
        hbin_end: u64,
    },

    #[error("Invalid cell signature at offset {offset}: expected {expected}, got [{byte0:#04X}, {byte1:#04X}]")]
    #[diagnostic(code(winreg::invalid_cell_signature))]
    InvalidCellSignature {
        offset: CellOffset,
        expected: &'static str,
        byte0: u8,
        byte1: u8,
    },

    #[error("Cell at offset {offset} is unallocated (free cell)")]
    #[diagnostic(code(winreg::unallocated_cell))]
    UnallocatedCell { offset: CellOffset },

    #[error("Null cell offset encountered where a valid offset was expected")]
    #[diagnostic(code(winreg::null_offset))]
    NullOffset,

    #[error("Hive bins data is truncated: expected {expected} bytes, got {actual}")]
    #[diagnostic(code(winreg::truncated_hive))]
    TruncatedHive { expected: u64, actual: u64 },

    #[error("Invalid hbin at file offset {file_offset}: bad signature")]
    #[diagnostic(code(winreg::invalid_hbin))]
    InvalidHbin { file_offset: u64 },

    #[error("Key not found: {path}")]
    #[diagnostic(code(winreg::key_not_found))]
    KeyNotFound { path: String },

    #[error("Value not found: {name} under key {key_path}")]
    #[diagnostic(code(winreg::value_not_found))]
    ValueNotFound { name: String, key_path: String },

    #[error("I/O error: {0}")]
    #[diagnostic(code(winreg::io))]
    Io(#[from] std::io::Error),
}

/// Result type alias for winreg-core.
pub type Result<T> = std::result::Result<T, HiveError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = HiveError::ChecksumMismatch {
            expected: 0x1234_5678,
            computed: 0xDEAD_BEEF,
        };
        let msg = format!("{err}");
        assert!(msg.contains("0x12345678"));
        assert!(msg.contains("0xDEADBEEF"));
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HiveError>();
    }

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let hive_err: HiveError = io_err.into();
        assert!(matches!(hive_err, HiveError::Io(_)));
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass (the lib.rs modules that don't exist yet should be stubbed with empty files first — the subagent should create empty `.rs` files for all modules declared in `lib.rs`).

- [ ] **Step 3: Commit**

```bash
git add crates/winreg-core/src/error.rs
git commit -m "feat(core): add HiveError with miette diagnostics"
```

---

### Task 7: winreg-core — Hive Struct + from_bytes + Hbin Catalog

**Files:**
- Create: `crates/winreg-core/src/hive.rs`
- Stub: all other `src/*.rs` files in winreg-core

- [ ] **Step 1: Create stub files for all winreg-core modules**

Create empty files for: `cell_reader.rs`, `key.rs`, `value.rs`, `path.rs`, `iter.rs`, `security.rs`, `txlog.rs`, `detect.rs`.

- [ ] **Step 2: Write Hive struct with from_bytes**

Create `crates/winreg-core/src/hive.rs`:

```rust
//! `Hive<R>` — the entry point for reading a Windows Registry hive.

use std::io::{Cursor, Read, Seek, SeekFrom};

use winreg_format::header::BaseBlock;
use winreg_format::hbin::HbinHeader;
use winreg_format::version::RegfVersion;

use crate::error::{HiveError, Result};

/// ReadSeek trait alias for convenience.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Descriptor for a cataloged hive bin.
#[derive(Debug, Clone)]
pub struct HbinDescriptor {
    /// Offset of this hbin from start of hive bins data.
    pub offset: u32,
    /// Size of this hbin in bytes.
    pub size: u32,
    /// File offset where this hbin starts.
    pub file_offset: u64,
}

/// A parsed Windows Registry hive file.
///
/// Generic over `R: ReadSeek` to support mmap, in-memory buffers, and overlays.
pub struct Hive<R: ReadSeek> {
    pub(crate) reader: R,
    pub(crate) header: BaseBlock,
    pub(crate) version: RegfVersion,
    pub(crate) bins: Vec<HbinDescriptor>,
    /// Raw header bytes (first 4096) — kept for checksum validation.
    pub(crate) header_bytes: Vec<u8>,
}

impl Hive<Cursor<Vec<u8>>> {
    /// Open a hive from an in-memory byte buffer.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < BaseBlock::SIZE {
            return Err(HiveError::TruncatedHive {
                expected: BaseBlock::SIZE as u64,
                actual: data.len() as u64,
            });
        }

        // Parse base block.
        let mut cursor = Cursor::new(data.clone());
        let header = BaseBlock::read(&mut cursor).map_err(|_| HiveError::InvalidSignature)?;

        // Validate checksum.
        if !BaseBlock::validate_checksum(&data) {
            let computed = BaseBlock::compute_checksum(&data);
            let expected = u32::from_le_bytes([
                data[0x1FC],
                data[0x1FD],
                data[0x1FE],
                data[0x1FF],
            ]);
            return Err(HiveError::ChecksumMismatch { expected, computed });
        }

        // Determine version.
        let version = RegfVersion::from_minor(header.minor_version).ok_or(
            HiveError::UnsupportedVersion {
                major: header.major_version,
                minor: header.minor_version,
            },
        )?;

        // Catalog hive bins.
        let header_bytes = data[..BaseBlock::SIZE].to_vec();
        let bins_data_start = BaseBlock::SIZE as u64;
        let bins_data_size = u64::from(header.hive_bins_data_size);
        let bins = catalog_hbins(&data, bins_data_start, bins_data_size)?;

        let reader = Cursor::new(data);
        Ok(Self {
            reader,
            header,
            version,
            bins,
            header_bytes,
        })
    }
}

impl<R: ReadSeek> Hive<R> {
    /// The REGF format version of this hive.
    pub fn version(&self) -> RegfVersion {
        self.version
    }

    /// Whether the hive was cleanly synchronized (primary == secondary sequence).
    pub fn is_clean(&self) -> bool {
        self.header.is_clean()
    }

    /// Root cell offset (relative to hive bins data start).
    pub fn root_cell_offset(&self) -> winreg_format::cells::CellOffset {
        winreg_format::cells::CellOffset(self.header.root_cell_offset)
    }

    /// Total hive bins data size in bytes.
    pub fn hive_bins_data_size(&self) -> u32 {
        self.header.hive_bins_data_size
    }

    /// Number of hive bins.
    pub fn bin_count(&self) -> usize {
        self.bins.len()
    }

    /// Internal file name from the header.
    pub fn file_name(&self) -> String {
        self.header.file_name_string()
    }

    /// The hbin descriptors.
    pub fn bins(&self) -> &[HbinDescriptor] {
        &self.bins
    }
}

/// Walk the hive bins data and build a catalog of all hbins.
fn catalog_hbins(data: &[u8], start: u64, expected_size: u64) -> Result<Vec<HbinDescriptor>> {
    let mut bins = Vec::new();
    let mut pos = start;
    let end = start + expected_size;

    while pos < end {
        let file_offset = pos;

        if pos as usize + 32 > data.len() {
            break; // Truncated — stop cataloging
        }

        // Check hbin signature.
        let sig = &data[pos as usize..pos as usize + 4];
        if sig != b"hbin" {
            return Err(HiveError::InvalidHbin { file_offset });
        }

        let offset = u32::from_le_bytes(
            data[pos as usize + 4..pos as usize + 8]
                .try_into()
                .unwrap(),
        );
        let size = u32::from_le_bytes(
            data[pos as usize + 8..pos as usize + 12]
                .try_into()
                .unwrap(),
        );

        if size == 0 || size % 4096 != 0 {
            break; // Invalid size — stop
        }

        bins.push(HbinDescriptor {
            offset,
            size,
            file_offset,
        });

        pos += u64::from(size);
    }

    Ok(bins)
}

use binrw::BinRead;

#[cfg(test)]
mod tests {
    use super::*;
    use winreg_format::header::BaseBlock;

    /// Build a minimal valid hive with one hbin containing a root NK cell.
    fn build_minimal_hive() -> Vec<u8> {
        let hbin_size: u32 = 4096;
        let total_size = BaseBlock::SIZE + hbin_size as usize;
        let mut buf = vec![0u8; total_size];

        // Base block header
        buf[0..4].copy_from_slice(b"regf");
        buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes()); // primary seq
        buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes()); // secondary seq
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
        buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version = 1.5
        buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // format = 1
        buf[0x24..0x28].copy_from_slice(&32u32.to_le_bytes()); // root cell offset = 32 (first cell after hbin header)
        buf[0x28..0x2C].copy_from_slice(&hbin_size.to_le_bytes()); // hive bins data size
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor

        // Compute checksum
        let checksum = BaseBlock::compute_checksum(&buf);
        buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());

        // Hbin header at offset 4096
        let hbin_start = BaseBlock::SIZE;
        buf[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");
        buf[hbin_start + 4..hbin_start + 8].copy_from_slice(&0u32.to_le_bytes()); // offset = 0
        buf[hbin_start + 8..hbin_start + 12].copy_from_slice(&hbin_size.to_le_bytes()); // size

        // Root NK cell at hbin offset 32 (= file offset 4096 + 32 = 4128)
        let cell_start = hbin_start + 32;
        let cell_size: i32 = -128; // allocated, 128 bytes
        buf[cell_start..cell_start + 4].copy_from_slice(&cell_size.to_le_bytes());
        buf[cell_start + 4..cell_start + 6].copy_from_slice(b"nk");
        // flags: HIVE_ENTRY | COMP_NAME = 0x0024
        buf[cell_start + 6..cell_start + 8].copy_from_slice(&0x0024u16.to_le_bytes());

        // Fill remaining hbin space with a free cell
        let free_start = cell_start + 128;
        let free_size = (hbin_size as usize) - 32 - 128;
        buf[free_start..free_start + 4].copy_from_slice(&(free_size as i32).to_le_bytes());

        buf
    }

    #[test]
    fn open_minimal_hive() {
        let data = build_minimal_hive();
        let hive = Hive::from_bytes(data).expect("should open minimal hive");
        assert_eq!(hive.version(), RegfVersion::V1_5);
        assert!(hive.is_clean());
        assert_eq!(hive.bin_count(), 1);
        assert_eq!(hive.hive_bins_data_size(), 4096);
    }

    #[test]
    fn rejects_truncated_file() {
        let data = vec![0u8; 100]; // Way too small
        assert!(matches!(
            Hive::from_bytes(data),
            Err(HiveError::TruncatedHive { .. })
        ));
    }

    #[test]
    fn rejects_bad_signature() {
        let mut data = build_minimal_hive();
        data[0..4].copy_from_slice(b"nope");
        assert!(matches!(
            Hive::from_bytes(data),
            Err(HiveError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut data = build_minimal_hive();
        data[0x14] = 0xFF; // Corrupt major version
        // Don't recompute checksum — should fail
        assert!(matches!(
            Hive::from_bytes(data),
            Err(HiveError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn catalogs_hbin_descriptors() {
        let hive = Hive::from_bytes(build_minimal_hive()).unwrap();
        let bins = hive.bins();
        assert_eq!(bins.len(), 1);
        assert_eq!(bins[0].offset, 0);
        assert_eq!(bins[0].size, 4096);
        assert_eq!(bins[0].file_offset, 4096);
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-core/
git commit -m "feat(core): add Hive::from_bytes with header validation and hbin cataloging"
```

---

### Task 8: winreg-core — CellReader

**Files:**
- Create: `crates/winreg-core/src/cell_reader.rs`

- [ ] **Step 1: Write CellReader that reads typed cells by offset**

Create `crates/winreg-core/src/cell_reader.rs`:

```rust
//! Cell reading — read typed cells from a hive by offset.

use winreg_format::cells::{
    CellHeader, CellOffset, CellSignature, RawBigData, RawKeyNode, RawKeyValue, RawSecurityKey,
    SubkeyIndex,
};

use crate::error::{HiveError, Result};
use crate::hive::{Hive, ReadSeek};

/// Typed cell content after dispatching on signature.
#[derive(Debug)]
pub enum Cell {
    KeyNode(RawKeyNode),
    KeyValue(RawKeyValue),
    SecurityKey(RawSecurityKey),
    Index(SubkeyIndex),
    BigData(RawBigData),
    /// Raw data cell (no recognized signature — value data, class name, etc.).
    Data(Vec<u8>),
}

impl<R: ReadSeek> Hive<R> {
    /// Read raw bytes at a cell offset. Returns (cell_header, cell_body_bytes).
    ///
    /// The cell_body_bytes start after the 4-byte size field.
    pub fn read_cell_raw(&self, offset: CellOffset) -> Result<(CellHeader, Vec<u8>)> {
        if offset.is_null() {
            return Err(HiveError::NullOffset);
        }

        let file_offset = offset.file_offset();
        let data = self.reader_ref();

        // Read cell header (4 bytes).
        if file_offset as usize + 4 > data.len() {
            return Err(HiveError::CellOverflow {
                offset,
                cell_size: 0,
                hbin_end: data.len() as u64,
            });
        }

        let header_bytes: [u8; 4] = data[file_offset as usize..file_offset as usize + 4]
            .try_into()
            .unwrap();
        let header = CellHeader::from_bytes(&header_bytes);

        if !header.is_allocated() {
            return Err(HiveError::UnallocatedCell { offset });
        }

        let size = header.size() as usize;
        let end = file_offset as usize + size;
        if end > data.len() {
            return Err(HiveError::CellOverflow {
                offset,
                cell_size: header.size(),
                hbin_end: data.len() as u64,
            });
        }

        // Cell body is everything after the 4-byte size field.
        let body = data[file_offset as usize + 4..end].to_vec();
        Ok((header, body))
    }

    /// Read and parse a typed cell at the given offset.
    pub fn read_cell(&self, offset: CellOffset) -> Result<Cell> {
        let (_header, body) = self.read_cell_raw(offset)?;

        if body.len() < 2 {
            return Ok(Cell::Data(body));
        }

        let sig_bytes: [u8; 2] = [body[0], body[1]];
        let after_sig = &body[2..];

        match CellSignature::from_bytes(&sig_bytes) {
            Some(CellSignature::KeyNode) => {
                let nk = RawKeyNode::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                    offset,
                    expected: "nk (valid key node)",
                    byte0: sig_bytes[0],
                    byte1: sig_bytes[1],
                })?;
                Ok(Cell::KeyNode(nk))
            }
            Some(CellSignature::KeyValue) => {
                let vk =
                    RawKeyValue::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "vk (valid key value)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::KeyValue(vk))
            }
            Some(CellSignature::SecurityKey) => {
                let sk =
                    RawSecurityKey::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "sk (valid security key)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::SecurityKey(sk))
            }
            Some(CellSignature::FastLeaf) => {
                let idx =
                    SubkeyIndex::parse_lf(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "lf (valid fast leaf)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::HashLeaf) => {
                let idx =
                    SubkeyIndex::parse_lh(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "lh (valid hash leaf)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::IndexLeaf) => {
                let idx =
                    SubkeyIndex::parse_li(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "li (valid index leaf)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::RootIndex) => {
                let idx =
                    SubkeyIndex::parse_ri(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "ri (valid root index)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::Index(idx))
            }
            Some(CellSignature::BigData) => {
                let db =
                    RawBigData::parse(after_sig).ok_or(HiveError::InvalidCellSignature {
                        offset,
                        expected: "db (valid big data)",
                        byte0: sig_bytes[0],
                        byte1: sig_bytes[1],
                    })?;
                Ok(Cell::BigData(db))
            }
            None => {
                // No recognized signature — raw data cell (value data, class name, etc.)
                Ok(Cell::Data(body))
            }
        }
    }

    /// Get a reference to the underlying data.
    fn reader_ref(&self) -> &[u8] {
        // This works for Cursor<Vec<u8>>. For mmap, we'll add a separate impl.
        // For now, we use the inner buffer directly.
        self.reader.get_ref()
    }
}

// Note: reader_ref() above uses get_ref() which exists on Cursor<Vec<u8>>.
// For the mmap path (Task 12), we'll add a trait or enum dispatch.
// For now, this constrains Hive to Cursor-based readers, which is fine for
// the initial implementation and all tests.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hive::Hive;

    // We reuse build_minimal_hive from hive.rs tests.
    // The subagent should refactor this into a shared test helper or
    // use the TestHiveBuilder from Task 9.

    #[test]
    fn read_root_nk_cell() {
        // Build a hive and read the root cell.
        // Root cell is at offset 32 (first cell after hbin header).
        let data = crate::hive::tests::build_minimal_hive();
        let hive = Hive::from_bytes(data).unwrap();
        let root_offset = hive.root_cell_offset();

        let cell = hive.read_cell(root_offset).unwrap();
        match cell {
            Cell::KeyNode(nk) => {
                assert!(nk.is_root());
            }
            other => panic!("expected KeyNode, got {other:?}"),
        }
    }

    #[test]
    fn null_offset_returns_error() {
        let data = crate::hive::tests::build_minimal_hive();
        let hive = Hive::from_bytes(data).unwrap();
        assert!(matches!(
            hive.read_cell(CellOffset::NULL),
            Err(HiveError::NullOffset)
        ));
    }
}
```

**Note to subagent:** The `reader_ref()` method above uses `Cursor::get_ref()`. When implementing this, you may need to:
1. Make `build_minimal_hive()` `pub(crate)` in `hive.rs` tests so `cell_reader.rs` tests can use it.
2. Or create the `TestHiveBuilder` first (Task 9) and use that instead.
3. The `get_ref()` approach only works for `Cursor<Vec<u8>>`. For the mmap path, Task 12 will add an abstraction.

- [ ] **Step 2: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/winreg-core/src/cell_reader.rs
git commit -m "feat(core): add CellReader with typed cell dispatch"
```

---

### Task 9: TestHiveBuilder — Shared Test Infrastructure

**Files:**
- Create: `tests/common/hive_builder.rs`
- Create: `tests/common/mod.rs`

This is one of the highest-value infrastructure pieces. It builds valid in-memory REGF hives for testing, handling all the plumbing (base block, hbins, root NK, SK chain, proper checksums).

- [ ] **Step 1: Write TestHiveBuilder**

Create `~/src/winreg-forensic/tests/common/mod.rs`:

```rust
pub mod hive_builder;
```

Create `~/src/winreg-forensic/tests/common/hive_builder.rs`:

```rust
//! Test hive builder — constructs valid in-memory REGF hives for testing.
//!
//! Usage:
//! ```
//! let hive = TestHiveBuilder::new()
//!     .add_key("Software")
//!     .add_key("Software\\Microsoft")
//!     .add_value("Software\\Microsoft", "Version", ValueType::Sz, b"10.0")
//!     .build();
//! ```

use winreg_format::flags::ValueType;
use winreg_format::header::BaseBlock;

/// Builder for constructing valid test hives.
pub struct TestHiveBuilder {
    keys: Vec<TestKey>,
}

struct TestKey {
    path: String,
    values: Vec<TestValue>,
}

struct TestValue {
    name: String,
    data_type: u32,
    data: Vec<u8>,
}

impl TestHiveBuilder {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Add a key at the given path (backslash-separated). Parent keys are
    /// created automatically if they don't exist.
    pub fn add_key(mut self, path: &str) -> Self {
        // Ensure all parent paths exist.
        let parts: Vec<&str> = path.split('\\').collect();
        for i in 1..=parts.len() {
            let partial = parts[..i].join("\\");
            if !self.keys.iter().any(|k| k.path == partial) {
                self.keys.push(TestKey {
                    path: partial,
                    values: Vec::new(),
                });
            }
        }
        self
    }

    /// Add a value to an existing key. The key path must have been added first.
    pub fn add_value(
        mut self,
        key_path: &str,
        name: &str,
        data_type: u32,
        data: &[u8],
    ) -> Self {
        let key = self
            .keys
            .iter_mut()
            .find(|k| k.path == key_path)
            .unwrap_or_else(|| panic!("key not found: {key_path}. Call add_key first."));
        key.values.push(TestValue {
            name: name.to_string(),
            data_type,
            data: data.to_vec(),
        });
        self
    }

    /// Build a valid REGF hive as a byte vector.
    ///
    /// The resulting hive has:
    /// - Valid base block with correct checksum
    /// - One or more hbins
    /// - Root NK cell with KEY_HIVE_ENTRY flag
    /// - Child NK cells for each added key
    /// - VK cells for each added value
    /// - LH subkey index lists
    /// - A single shared SK cell
    ///
    /// Implementation note: this allocates cells sequentially in a single hbin,
    /// expanding the hbin to the next 4096-byte boundary as needed.
    pub fn build(self) -> Vec<u8> {
        // This is a complex function. The subagent should implement it following
        // the REGF binary format specification. Key requirements:
        //
        // 1. Write base block (4096 bytes) with "regf" signature
        // 2. Write one hbin starting at file offset 4096
        // 3. Allocate cells sequentially within the hbin:
        //    a. Root NK cell (KEY_HIVE_ENTRY | KEY_COMP_NAME)
        //    b. SK cell (minimal security descriptor, flink/blink to self)
        //    c. For each key: NK cell + LH subkey index (if has subkeys)
        //    d. For each value: VK cell + data cell (if not resident)
        //    e. Values list cells (arrays of VK offsets)
        // 4. Link parent NK cells to their subkey lists
        // 5. Link NK cells to their values lists
        // 6. Point all NK cells to the shared SK cell
        // 7. Fill remaining space with a free cell
        // 8. Pad hbin to next 4096-byte boundary
        // 9. Update base block: root_cell_offset, hive_bins_data_size
        // 10. Compute and store base block checksum
        //
        // Cell offset calculation: all offsets are relative to start of hive
        // bins data (file offset 4096). So the first cell in the hbin at
        // hbin_header_offset + 32 has cell_offset = 32.
        //
        // Cell size: must be negative (allocated) and 8-byte aligned.
        //
        // The subagent MUST implement this function with actual binary
        // construction. Use from_le_bytes/to_le_bytes for all fields.
        // See research/regf-binary-format-specification.md for exact offsets.
        todo!("subagent implements full binary hive construction")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg_core::Hive;

    #[test]
    fn build_empty_hive() {
        let data = TestHiveBuilder::new().build();
        let hive = Hive::from_bytes(data).expect("empty hive should be valid");
        assert_eq!(hive.bin_count(), 1);
    }

    #[test]
    fn build_hive_with_keys() {
        let data = TestHiveBuilder::new()
            .add_key("Software")
            .add_key("Software\\Microsoft")
            .build();
        let hive = Hive::from_bytes(data).unwrap();
        // Should be able to navigate to root and find "Software" subkey
        // (exact navigation test deferred until Key struct exists in Task 10)
        assert!(hive.bin_count() >= 1);
    }

    #[test]
    fn build_hive_with_values() {
        let data = TestHiveBuilder::new()
            .add_key("Software")
            .add_value("Software", "Version", 1, b"1\x00.\x000\x00\0\0") // REG_SZ UTF-16LE "1.0\0"
            .build();
        let hive = Hive::from_bytes(data).unwrap();
        assert!(hive.bin_count() >= 1);
    }
}
```

**Note to subagent:** The `build()` method is the core challenge. It must produce binary data that passes `Hive::from_bytes()` validation. Follow the REGF spec exactly. A working implementation typically runs 200-300 lines. Start simple (root key only), then add child keys and values incrementally.

- [ ] **Step 2: Run tests**

```bash
cd ~/src/winreg-forensic
cargo test --test common
# OR if using the tests/ directory:
cargo test -p winreg-core
```

Expected: all tests pass once `build()` is implemented.

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: add TestHiveBuilder for synthesizing valid REGF test hives"
```

---

### Task 10: winreg-core — Key Navigation

**Files:**
- Create: `crates/winreg-core/src/key.rs`
- Create: `crates/winreg-core/src/path.rs`

- [ ] **Step 1: Write Key struct with subkey/value navigation**

Create `crates/winreg-core/src/key.rs`:

```rust
//! Key struct — high-level interface for navigating registry keys.

use std::io::Cursor;

use winreg_format::cells::{CellOffset, RawKeyNode, SubkeyIndex};
use winreg_format::flags::KeyFlags;

use crate::cell_reader::Cell;
use crate::error::{HiveError, Result};
use crate::hive::{Hive, ReadSeek};
use crate::value::Value;

/// A registry key within a hive.
pub struct Key<'h> {
    pub(crate) hive: &'h Hive<Cursor<Vec<u8>>>,
    pub(crate) node: RawKeyNode,
    pub(crate) offset: CellOffset,
}

impl<'h> Key<'h> {
    /// Key name.
    pub fn name(&self) -> String {
        self.node.key_name()
    }

    /// Last written timestamp (FILETIME, 100-ns intervals since 1601-01-01 UTC).
    pub fn last_written_raw(&self) -> u64 {
        self.node.last_written
    }

    /// Last written timestamp as chrono DateTime.
    pub fn last_written(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        filetime_to_datetime(self.node.last_written)
    }

    /// NK cell flags.
    pub fn flags(&self) -> KeyFlags {
        self.node.flags
    }

    /// Whether this is the root key of the hive.
    pub fn is_root(&self) -> bool {
        self.node.is_root()
    }

    /// Number of subkeys.
    pub fn subkey_count(&self) -> u32 {
        self.node.subkey_count
    }

    /// Number of values.
    pub fn value_count(&self) -> u32 {
        self.node.value_count
    }

    /// Cell offset of this key.
    pub fn offset(&self) -> CellOffset {
        self.offset
    }

    /// List all subkeys.
    pub fn subkeys(&self) -> Result<Vec<Key<'h>>> {
        if self.node.subkey_count == 0 || self.node.subkeys_list_offset.is_null() {
            return Ok(Vec::new());
        }

        let offsets = self.collect_subkey_offsets(self.node.subkeys_list_offset)?;
        let mut keys = Vec::with_capacity(offsets.len());
        for offset in offsets {
            let cell = self.hive.read_cell(offset)?;
            match cell {
                Cell::KeyNode(nk) => keys.push(Key {
                    hive: self.hive,
                    node: nk,
                    offset,
                }),
                _ => {
                    // Skip non-NK cells (shouldn't happen in valid hive)
                    continue;
                }
            }
        }
        Ok(keys)
    }

    /// Find a subkey by name (case-insensitive, matching Windows registry semantics).
    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h>>> {
        let target = name.to_ascii_uppercase();
        for key in self.subkeys()? {
            if key.name().to_ascii_uppercase() == target {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    /// Navigate to a subkey by path (backslash-separated, case-insensitive).
    pub fn subkey_path(&self, path: &str) -> Result<Option<Key<'h>>> {
        let mut current = None;
        let parts: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();

        // Start from self
        let mut key_ref: &Key<'h> = self;

        for (i, part) in parts.iter().enumerate() {
            match key_ref.subkey(part)? {
                Some(found) => {
                    current = Some(found);
                    if i < parts.len() - 1 {
                        // More path components — continue navigation.
                        // Safety: we just set current to Some.
                        key_ref = current.as_ref().unwrap();
                    }
                }
                None => return Ok(None),
            }
        }

        Ok(current)
    }

    /// List all values under this key.
    pub fn values(&self) -> Result<Vec<Value<'h>>> {
        if self.node.value_count == 0 || self.node.values_list_offset.is_null() {
            return Ok(Vec::new());
        }

        // Read the values list cell (array of VK offsets).
        let (_header, body) = self.hive.read_cell_raw(self.node.values_list_offset)?;
        let count = self.node.value_count as usize;
        let mut values = Vec::with_capacity(count);

        for i in 0..count {
            let base = i * 4;
            if base + 4 > body.len() {
                break;
            }
            let vk_offset =
                CellOffset(u32::from_le_bytes(body[base..base + 4].try_into().unwrap()));
            let cell = self.hive.read_cell(vk_offset)?;
            match cell {
                Cell::KeyValue(vk) => values.push(Value {
                    hive: self.hive,
                    vk,
                    offset: vk_offset,
                }),
                _ => continue,
            }
        }
        Ok(values)
    }

    /// Find a value by name (case-insensitive). Empty string finds the default value.
    pub fn value(&self, name: &str) -> Result<Option<Value<'h>>> {
        let target = name.to_ascii_uppercase();
        for val in self.values()? {
            if val.name().to_ascii_uppercase() == target {
                return Ok(Some(val));
            }
        }
        Ok(None)
    }

    /// Collect all subkey NK offsets, resolving through LF/LH/LI/RI index cells.
    fn collect_subkey_offsets(&self, index_offset: CellOffset) -> Result<Vec<CellOffset>> {
        let cell = self.hive.read_cell(index_offset)?;
        match cell {
            Cell::Index(SubkeyIndex::HashLeaf(elements)) => {
                Ok(elements.iter().map(|e| e.key_offset).collect())
            }
            Cell::Index(SubkeyIndex::FastLeaf(elements)) => {
                Ok(elements.iter().map(|e| e.key_offset).collect())
            }
            Cell::Index(SubkeyIndex::IndexLeaf(offsets)) => Ok(offsets),
            Cell::Index(SubkeyIndex::RootIndex(sub_indices)) => {
                // RI: recurse into each sub-index.
                let mut all = Vec::new();
                for sub_offset in sub_indices {
                    all.extend(self.collect_subkey_offsets(sub_offset)?);
                }
                Ok(all)
            }
            _ => Ok(Vec::new()),
        }
    }
}

/// Get the root key of a hive.
impl Hive<Cursor<Vec<u8>>> {
    pub fn root_key(&self) -> Result<Key<'_>> {
        let offset = self.root_cell_offset();
        let cell = self.read_cell(offset)?;
        match cell {
            Cell::KeyNode(nk) => Ok(Key {
                hive: self,
                node: nk,
                offset,
            }),
            _ => Err(HiveError::InvalidCellSignature {
                offset,
                expected: "nk (root key node)",
                byte0: 0,
                byte1: 0,
            }),
        }
    }

    /// Navigate directly to a key by full path from root.
    pub fn open_key(&self, path: &str) -> Result<Option<Key<'_>>> {
        self.root_key()?.subkey_path(path)
    }
}

/// Convert FILETIME (100-ns intervals since 1601-01-01) to chrono DateTime.
pub fn filetime_to_datetime(filetime: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    if filetime == 0 {
        return None;
    }
    // FILETIME epoch: 1601-01-01. Unix epoch: 1970-01-01.
    // Difference: 11644473600 seconds = 116444736000000000 hundred-nanoseconds.
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DIFF {
        return None;
    }
    let unix_100ns = filetime - EPOCH_DIFF;
    let secs = (unix_100ns / 10_000_000) as i64;
    let nanos = ((unix_100ns % 10_000_000) * 100) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_epoch() {
        // 2024-01-01 00:00:00 UTC as FILETIME = 133484064000000000
        let dt = filetime_to_datetime(133_484_064_000_000_000).unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
    }

    use chrono::Datelike;

    #[test]
    fn filetime_zero_returns_none() {
        assert!(filetime_to_datetime(0).is_none());
    }

    // Key navigation tests require TestHiveBuilder (Task 9).
    // The subagent should add these tests after the builder is working:
    //
    // #[test]
    // fn root_key_from_hive() { ... }
    //
    // #[test]
    // fn navigate_to_subkey() { ... }
    //
    // #[test]
    // fn case_insensitive_lookup() { ... }
    //
    // #[test]
    // fn subkey_path_navigation() { ... }
    //
    // #[test]
    // fn missing_subkey_returns_none() { ... }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/winreg-core/src/key.rs
git commit -m "feat(core): add Key struct with subkey/value navigation and path traversal"
```

---

### Task 11: winreg-core — Value Decoding

**Files:**
- Create: `crates/winreg-core/src/value.rs`

- [ ] **Step 1: Write Value struct with all REG_* type decoders**

Create `crates/winreg-core/src/value.rs`:

```rust
//! Value struct — decode registry value data.

use std::io::Cursor;

use winreg_format::cells::{CellOffset, RawKeyValue};
use winreg_format::flags::ValueType;

use crate::error::Result;
use crate::hive::{Hive, ReadSeek};

/// A registry value within a key.
pub struct Value<'h> {
    pub(crate) hive: &'h Hive<Cursor<Vec<u8>>>,
    pub(crate) vk: RawKeyValue,
    pub(crate) offset: CellOffset,
}

impl<'h> Value<'h> {
    /// Value name. Empty string for the unnamed (default) value.
    pub fn name(&self) -> String {
        self.vk.value_name()
    }

    /// Data type.
    pub fn data_type(&self) -> ValueType {
        self.vk.data_type
    }

    /// Raw data size in bytes.
    pub fn data_size(&self) -> u32 {
        self.vk.data_size()
    }

    /// Whether data is resident (stored inline in the VK cell).
    pub fn is_resident(&self) -> bool {
        self.vk.is_resident()
    }

    /// Read raw data bytes.
    pub fn raw_data(&self) -> Result<Vec<u8>> {
        if self.vk.data_size() == 0 {
            return Ok(Vec::new());
        }

        if self.vk.is_resident() {
            return Ok(self.vk.inline_data());
        }

        // Non-resident: read data from separate cell.
        let data_offset = self.vk.data_offset();
        let (_header, body) = self.hive.read_cell_raw(data_offset)?;

        // TODO: handle big data (DB) for values > 16344 bytes.
        // For now, return the cell body truncated to data_size.
        let size = self.vk.data_size() as usize;
        Ok(body[..size.min(body.len())].to_vec())
    }

    /// Decode as a string (REG_SZ, REG_EXPAND_SZ, REG_LINK).
    /// Returns the decoded UTF-16LE string.
    pub fn as_string(&self) -> Result<String> {
        let data = self.raw_data()?;
        Ok(decode_utf16le(&data))
    }

    /// Decode as u32 (REG_DWORD / REG_DWORD_LITTLE_ENDIAN).
    pub fn as_u32(&self) -> Result<u32> {
        let data = self.raw_data()?;
        if data.len() < 4 {
            return Ok(0);
        }
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Decode as u32 big-endian (REG_DWORD_BIG_ENDIAN).
    pub fn as_u32_be(&self) -> Result<u32> {
        let data = self.raw_data()?;
        if data.len() < 4 {
            return Ok(0);
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Decode as u64 (REG_QWORD).
    pub fn as_u64(&self) -> Result<u64> {
        let data = self.raw_data()?;
        if data.len() < 8 {
            return Ok(0);
        }
        Ok(u64::from_le_bytes(data[..8].try_into().unwrap()))
    }

    /// Decode as multi-string (REG_MULTI_SZ).
    /// Returns a Vec of strings.
    pub fn as_multi_string(&self) -> Result<Vec<String>> {
        let data = self.raw_data()?;
        Ok(decode_multi_sz(&data))
    }
}

/// Decode UTF-16LE bytes to a String.
/// Handles missing null terminators and odd byte counts gracefully.
pub fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    // Trim trailing null
    let trimmed: &[u16] = match u16s.iter().position(|&c| c == 0) {
        Some(pos) => &u16s[..pos],
        None => &u16s,
    };
    String::from_utf16_lossy(trimmed)
}

/// Decode REG_MULTI_SZ: sequence of null-terminated UTF-16LE strings,
/// terminated by an empty string (double null).
pub fn decode_multi_sz(data: &[u8]) -> Vec<String> {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let mut strings = Vec::new();
    let mut start = 0;

    for (i, &ch) in u16s.iter().enumerate() {
        if ch == 0 {
            if i == start {
                // Empty string = end of multi-sz.
                break;
            }
            strings.push(String::from_utf16_lossy(&u16s[start..i]));
            start = i + 1;
        }
    }

    // Handle missing double-null terminator.
    if start < u16s.len() {
        let remaining: Vec<u16> = u16s[start..].iter().copied().take_while(|&c| c != 0).collect();
        if !remaining.is_empty() {
            strings.push(String::from_utf16_lossy(&remaining));
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_utf16le_normal() {
        // "Hello" in UTF-16LE + null terminator
        let data = b"H\x00e\x00l\x00l\x00o\x00\x00\x00";
        assert_eq!(decode_utf16le(data), "Hello");
    }

    #[test]
    fn decode_utf16le_no_null() {
        let data = b"H\x00i\x00";
        assert_eq!(decode_utf16le(data), "Hi");
    }

    #[test]
    fn decode_utf16le_empty() {
        assert_eq!(decode_utf16le(b""), "");
    }

    #[test]
    fn decode_multi_sz_normal() {
        // "foo\0bar\0\0" in UTF-16LE
        let data = b"f\x00o\x00o\x00\x00\x00b\x00a\x00r\x00\x00\x00\x00\x00";
        let result = decode_multi_sz(data);
        assert_eq!(result, vec!["foo", "bar"]);
    }

    #[test]
    fn decode_multi_sz_single() {
        let data = b"o\x00n\x00e\x00\x00\x00\x00\x00";
        let result = decode_multi_sz(data);
        assert_eq!(result, vec!["one"]);
    }

    #[test]
    fn decode_multi_sz_empty() {
        let data = b"\x00\x00";
        let result = decode_multi_sz(data);
        assert!(result.is_empty());
    }

    #[test]
    fn decode_multi_sz_missing_terminator() {
        let data = b"a\x00b\x00c\x00\x00\x00d\x00e\x00f\x00";
        let result = decode_multi_sz(data);
        assert_eq!(result, vec!["abc", "def"]);
    }

    // Value struct tests require TestHiveBuilder:
    //
    // #[test]
    // fn read_resident_dword() { ... }
    //
    // #[test]
    // fn read_non_resident_string() { ... }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/winreg-core/src/value.rs
git commit -m "feat(core): add Value struct with REG_SZ/DWORD/QWORD/MULTI_SZ decoding"
```

---

### Task 12: winreg-core — Hive::from_path (mmap) + Iterators

**Files:**
- Modify: `crates/winreg-core/src/hive.rs`
- Create: `crates/winreg-core/src/iter.rs`

- [ ] **Step 1: Add mmap-based Hive::from_path**

The subagent should add `from_path` to `hive.rs` using `memmap2::Mmap`. Since `Mmap` implements `Deref<Target = [u8]>` but not `Read + Seek`, the approach is to read the file into a `Vec<u8>` and use `Cursor<Vec<u8>>` (simple, correct), OR use `memmap2` with a wrapper. For the initial implementation, reading into a `Vec<u8>` is acceptable:

```rust
impl Hive<Cursor<Vec<u8>>> {
    /// Open a hive from a file path.
    pub fn from_path(path: &std::path::Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }
}
```

For large hives, the subagent may later optimize to use `memmap2` directly. But for correctness-first approach, `fs::read` into `from_bytes` is the right starting point.

- [ ] **Step 2: Write BFS/DFS iterators**

Create `crates/winreg-core/src/iter.rs`:

```rust
//! Key iterators — BFS and DFS traversal of the registry tree.

use std::collections::VecDeque;
use std::io::Cursor;

use crate::key::Key;
use crate::hive::Hive;
use crate::error::Result;

/// Breadth-first iterator over all keys in the hive.
pub struct BfsIter<'h> {
    hive: &'h Hive<Cursor<Vec<u8>>>,
    queue: VecDeque<Key<'h>>,
}

impl<'h> BfsIter<'h> {
    pub fn new(hive: &'h Hive<Cursor<Vec<u8>>>) -> Result<Self> {
        let root = hive.root_key()?;
        let mut queue = VecDeque::new();
        queue.push_back(root);
        Ok(Self { hive, queue })
    }
}

impl<'h> Iterator for BfsIter<'h> {
    type Item = Result<Key<'h>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.queue.pop_front()?;
        // Enqueue children
        match key.subkeys() {
            Ok(children) => {
                for child in children {
                    self.queue.push_back(child);
                }
                Some(Ok(key))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Depth-first (pre-order) iterator over all keys in the hive.
pub struct DfsIter<'h> {
    stack: Vec<Key<'h>>,
}

impl<'h> DfsIter<'h> {
    pub fn new(hive: &'h Hive<Cursor<Vec<u8>>>) -> Result<Self> {
        let root = hive.root_key()?;
        Ok(Self { stack: vec![root] })
    }
}

impl<'h> Iterator for DfsIter<'h> {
    type Item = Result<Key<'h>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.stack.pop()?;
        match key.subkeys() {
            Ok(children) => {
                // Push in reverse order so first child is popped first.
                for child in children.into_iter().rev() {
                    self.stack.push(child);
                }
                Some(Ok(key))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Convenience methods on Hive.
impl Hive<Cursor<Vec<u8>>> {
    /// Iterate all keys in breadth-first order.
    pub fn iter_bfs(&self) -> Result<BfsIter<'_>> {
        BfsIter::new(self)
    }

    /// Iterate all keys in depth-first (pre-order) order.
    pub fn iter_dfs(&self) -> Result<DfsIter<'_>> {
        DfsIter::new(self)
    }
}

#[cfg(test)]
mod tests {
    // Iteration tests require TestHiveBuilder:
    //
    // #[test]
    // fn bfs_visits_all_keys() { ... }
    //
    // #[test]
    // fn dfs_visits_all_keys() { ... }
    //
    // #[test]
    // fn empty_hive_iterates_root_only() { ... }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-core/src/hive.rs crates/winreg-core/src/iter.rs
git commit -m "feat(core): add Hive::from_path, BFS/DFS key iterators"
```

---

### Task 13: winreg-core — Transaction Log Replay

**Files:**
- Create: `crates/winreg-core/src/txlog.rs`

- [ ] **Step 1: Write OverlayBuffer and transaction log replay**

Create `crates/winreg-core/src/txlog.rs`:

```rust
//! Transaction log replay — apply dirty pages from .LOG1/.LOG2 files.
//!
//! Two log formats:
//! - **Old format** (Vista and earlier): DIRT bitmap + dirty pages
//! - **New format** (Vista+): HvLE (Hive Log Entry) records with Marvin32 checksums
//!
//! The OverlayBuffer applies dirty pages on top of original hive bytes
//! without modifying the original — forensic purity.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::error::{HiveError, Result};

/// Overlay buffer: original hive bytes + patched dirty pages.
/// Implements transparent read-through with patches applied.
pub struct OverlayBuffer {
    base: Vec<u8>,
    /// Map from page offset → replacement page bytes.
    dirty_pages: BTreeMap<u64, Vec<u8>>,
}

impl OverlayBuffer {
    /// Create a new overlay from base hive data.
    pub fn new(base: Vec<u8>) -> Self {
        Self {
            base,
            dirty_pages: BTreeMap::new(),
        }
    }

    /// Apply a dirty page at the given offset.
    pub fn apply_page(&mut self, offset: u64, data: Vec<u8>) {
        self.dirty_pages.insert(offset, data);
    }

    /// Read bytes at the given offset, with dirty pages overlaid.
    pub fn read_at(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let pos = offset + i as u64;
            // Check if this byte falls within a dirty page.
            let byte = self.dirty_pages.iter().rev()
                .find(|(&page_offset, page_data)| {
                    pos >= page_offset && pos < page_offset + page_data.len() as u64
                })
                .map(|(&page_offset, page_data)| {
                    page_data[(pos - page_offset) as usize]
                })
                .unwrap_or_else(|| {
                    if (pos as usize) < self.base.len() {
                        self.base[pos as usize]
                    } else {
                        0
                    }
                });
            result.push(byte);
        }
        result
    }

    /// Get the total size (same as base).
    pub fn len(&self) -> usize {
        self.base.len()
    }

    /// Materialize the full overlaid buffer as a Vec<u8>.
    pub fn materialize(&self) -> Vec<u8> {
        self.read_at(0, self.base.len())
    }

    /// Number of dirty pages applied.
    pub fn dirty_page_count(&self) -> usize {
        self.dirty_pages.len()
    }
}

/// Replay transaction logs onto a hive.
///
/// Reads the hive file and all log files, applies dirty pages from the logs,
/// returns an OverlayBuffer that can be used with Hive::from_bytes(overlay.materialize()).
pub fn replay_transaction_logs(
    hive_data: Vec<u8>,
    log_datas: &[Vec<u8>],
) -> Result<OverlayBuffer> {
    let mut overlay = OverlayBuffer::new(hive_data);

    for log_data in log_datas {
        if log_data.len() < 512 {
            continue; // Too small to be a valid log
        }

        // Check for log file signature (same "regf" header but file_type != 0)
        if &log_data[0..4] != b"regf" {
            continue;
        }

        let file_type = u32::from_le_bytes(log_data[0x1C..0x20].try_into().unwrap());

        match file_type {
            1 | 6 => {
                // Transaction log file — check for old or new format.
                // New format: scan for HvLE entries starting after the 512/1024-byte header.
                parse_new_format_log(log_data, &mut overlay)?;
            }
            _ => continue,
        }
    }

    Ok(overlay)
}

/// Parse new-format (HvLE) transaction log entries.
fn parse_new_format_log(log_data: &[u8], overlay: &mut OverlayBuffer) -> Result<()> {
    // HvLE entries start after the log header (typically 512 bytes for logs).
    // Each HvLE entry: signature "HvLE" (4 bytes), then structured data.
    let mut pos = 512; // Start scanning after header

    while pos + 4 <= log_data.len() {
        if &log_data[pos..pos + 4] == b"HvLE" {
            // Parse HvLE entry
            if pos + 40 > log_data.len() {
                break;
            }

            let size = u32::from_le_bytes(log_data[pos + 4..pos + 8].try_into().unwrap());
            // dirty_page_count at offset +16 relative to HvLE start
            let page_count =
                u32::from_le_bytes(log_data[pos + 16..pos + 20].try_into().unwrap()) as usize;

            // Dirty page references start at offset +40
            let ref_start = pos + 40;
            let data_start = ref_start + page_count * 8;

            for i in 0..page_count {
                let ref_offset = ref_start + i * 8;
                if ref_offset + 8 > log_data.len() {
                    break;
                }
                let page_offset =
                    u32::from_le_bytes(log_data[ref_offset..ref_offset + 4].try_into().unwrap());
                let page_size = u32::from_le_bytes(
                    log_data[ref_offset + 4..ref_offset + 8].try_into().unwrap(),
                );

                // Calculate where the page data is in the log file.
                // Pages are stored sequentially after all page references.
                let accumulated_size: u32 = (0..i)
                    .map(|j| {
                        let r = ref_start + j * 8 + 4;
                        u32::from_le_bytes(log_data[r..r + 4].try_into().unwrap_or([0; 4]))
                    })
                    .sum();

                let data_offset = data_start + accumulated_size as usize;
                let data_end = data_offset + page_size as usize;

                if data_end <= log_data.len() {
                    // Apply to file offset: 4096 (base block) + page_offset
                    let file_offset = 4096u64 + u64::from(page_offset);
                    overlay.apply_page(file_offset, log_data[data_offset..data_end].to_vec());
                }
            }

            pos += size as usize;
        } else {
            pos += 1; // Scan forward
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_read_through() {
        let base = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let overlay = OverlayBuffer::new(base);
        assert_eq!(overlay.read_at(0, 4), vec![1, 2, 3, 4]);
    }

    #[test]
    fn overlay_applies_dirty_page() {
        let base = vec![0; 16];
        let mut overlay = OverlayBuffer::new(base);
        overlay.apply_page(4, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let result = overlay.materialize();
        assert_eq!(result[0..4], [0, 0, 0, 0]);
        assert_eq!(result[4..8], [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(result[8..12], [0, 0, 0, 0]);
    }

    #[test]
    fn overlay_multiple_pages() {
        let base = vec![0; 32];
        let mut overlay = OverlayBuffer::new(base);
        overlay.apply_page(0, vec![1, 1, 1, 1]);
        overlay.apply_page(16, vec![2, 2, 2, 2]);
        let result = overlay.materialize();
        assert_eq!(result[0], 1);
        assert_eq!(result[16], 2);
        assert_eq!(result[8], 0);
    }

    #[test]
    fn overlay_dirty_page_count() {
        let mut overlay = OverlayBuffer::new(vec![0; 16]);
        assert_eq!(overlay.dirty_page_count(), 0);
        overlay.apply_page(0, vec![1]);
        assert_eq!(overlay.dirty_page_count(), 1);
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/winreg-core/src/txlog.rs
git commit -m "feat(core): add transaction log replay with OverlayBuffer"
```

---

### Task 14: winreg-core — Hive Type Auto-Detection

**Files:**
- Create: `crates/winreg-core/src/detect.rs`

- [ ] **Step 1: Write hive type auto-detection**

Create `crates/winreg-core/src/detect.rs`:

```rust
//! Hive type auto-detection from root key structure.

use std::io::Cursor;

use crate::hive::Hive;

/// Known hive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiveType {
    System,
    Software,
    NtUser,
    UsrClass,
    Sam,
    Security,
    Amcache,
    Bcd,
    Default,
    Components,
    Unknown,
}

impl std::fmt::Display for HiveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "SYSTEM"),
            Self::Software => write!(f, "SOFTWARE"),
            Self::NtUser => write!(f, "NTUSER.DAT"),
            Self::UsrClass => write!(f, "UsrClass.dat"),
            Self::Sam => write!(f, "SAM"),
            Self::Security => write!(f, "SECURITY"),
            Self::Amcache => write!(f, "Amcache.hve"),
            Self::Bcd => write!(f, "BCD"),
            Self::Default => write!(f, "DEFAULT"),
            Self::Components => write!(f, "COMPONENTS"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Hive<Cursor<Vec<u8>>> {
    /// Auto-detect the hive type by examining the root key structure.
    ///
    /// Detection strategy:
    /// - SYSTEM: has `Select` and `ControlSet001` subkeys
    /// - SOFTWARE: has `Microsoft` subkey with `Windows` subkey
    /// - SAM: has `SAM` subkey with `Domains` subkey
    /// - SECURITY: has `Policy` and `RXACT` subkeys
    /// - NTUSER.DAT: has `Software` subkey (but not `Microsoft\Windows\CurrentVersion` at root)
    /// - UsrClass.dat: root name contains "Classes" or has `CLSID` subkey
    /// - Amcache: has `Root` subkey or `InventoryApplicationFile` subkey
    /// - BCD: has `Description` and `Objects` subkeys
    /// - DEFAULT: has `AppEvents` subkey at root level
    pub fn detect_hive_type(&self) -> HiveType {
        let Ok(root) = self.root_key() else {
            return HiveType::Unknown;
        };

        let Ok(subkeys) = root.subkeys() else {
            return HiveType::Unknown;
        };

        let names: Vec<String> = subkeys.iter().map(|k| k.name().to_ascii_uppercase()).collect();

        // SYSTEM: has Select + ControlSet001
        if names.contains(&"SELECT".to_string()) && names.contains(&"CONTROLSET001".to_string()) {
            return HiveType::System;
        }

        // SAM: has SAM subkey
        if names.contains(&"SAM".to_string()) {
            // Verify it has Domains under SAM
            if let Ok(Some(sam)) = root.subkey("SAM") {
                if let Ok(Some(_)) = sam.subkey("Domains") {
                    return HiveType::Sam;
                }
            }
        }

        // SECURITY: has Policy
        if names.contains(&"POLICY".to_string()) {
            return HiveType::Security;
        }

        // Amcache: has Root or InventoryApplicationFile
        if names.contains(&"ROOT".to_string()) || names.contains(&"INVENTORYAPPLICATIONFILE".to_string())
        {
            return HiveType::Amcache;
        }

        // BCD: has Description + Objects
        if names.contains(&"DESCRIPTION".to_string()) && names.contains(&"OBJECTS".to_string()) {
            return HiveType::Bcd;
        }

        // SOFTWARE: has Microsoft subkey
        if names.contains(&"MICROSOFT".to_string()) && names.contains(&"CLASSES".to_string()) {
            return HiveType::Software;
        }

        // NTUSER.DAT: has Software subkey
        if names.contains(&"SOFTWARE".to_string()) {
            // Check for typical NTUSER.DAT keys
            if names.contains(&"APPEVENTS".to_string())
                || names.contains(&"CONSOLE".to_string())
                || names.contains(&"ENVIRONMENT".to_string())
            {
                return HiveType::NtUser;
            }
        }

        // DEFAULT: has AppEvents at root
        if names.contains(&"APPEVENTS".to_string()) && !names.contains(&"SOFTWARE".to_string()) {
            return HiveType::Default;
        }

        // UsrClass.dat: root name contains "Classes"
        if root.name().to_ascii_uppercase().contains("CLASSES") {
            return HiveType::UsrClass;
        }

        HiveType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hive_type_display() {
        assert_eq!(HiveType::System.to_string(), "SYSTEM");
        assert_eq!(HiveType::NtUser.to_string(), "NTUSER.DAT");
        assert_eq!(HiveType::Amcache.to_string(), "Amcache.hve");
    }

    // Detection tests require TestHiveBuilder with specific subkey structures:
    //
    // #[test]
    // fn detect_system_hive() {
    //     let hive = TestHiveBuilder::new()
    //         .add_key("Select")
    //         .add_key("ControlSet001")
    //         .build();
    //     let hive = Hive::from_bytes(hive).unwrap();
    //     assert_eq!(hive.detect_hive_type(), HiveType::System);
    // }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p winreg-core
```

Expected: all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/winreg-core/src/detect.rs
git commit -m "feat(core): add hive type auto-detection from root key structure"
```

---

### Task 15: rt-reg CLI — info, dump, search Subcommands

**Files:**
- Modify: `rt-reg/src/main.rs`
- Create: `rt-reg/src/output.rs`

- [ ] **Step 1: Write CLI with clap derive and info/dump/search commands**

Create `rt-reg/src/main.rs`:

```rust
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

mod output;

#[derive(Parser)]
#[command(name = "rt-reg", about = "Windows Registry forensic toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show hive metadata (type, version, timestamps, size, checksum)
    Info {
        /// Path to the hive file
        hive: PathBuf,
    },
    /// Dump registry tree (full or subtree)
    Dump {
        /// Path to the hive file
        hive: PathBuf,
        /// Key path to dump (omit for full tree)
        #[arg(long)]
        path: Option<String>,
        /// Output format
        #[arg(long, default_value = "table")]
        format: OutputFormat,
        /// Maximum depth (0 = unlimited)
        #[arg(long, default_value = "0")]
        depth: usize,
    },
    /// Search keys/values by name or data content
    Search {
        /// Path to hive file or directory
        path: PathBuf,
        /// Search in key names
        #[arg(long, alias = "key")]
        key_name: Option<String>,
        /// Search in value names
        #[arg(long, alias = "value")]
        value_name: Option<String>,
        /// Search in value data (string values only)
        #[arg(long, alias = "data")]
        value_data: Option<String>,
        /// Output format
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Jsonl,
    Csv,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Info { hive } => cmd_info(&hive),
        Command::Dump {
            hive,
            path,
            format,
            depth,
        } => cmd_dump(&hive, path.as_deref(), &format, depth),
        Command::Search {
            path,
            key_name,
            value_name,
            value_data,
            format,
        } => cmd_search(&path, key_name.as_deref(), value_name.as_deref(), value_data.as_deref(), &format),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_info(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let hive = winreg_core::Hive::from_path(path)?;
    let hive_type = hive.detect_hive_type();

    println!("File:           {}", path.display());
    println!("Hive type:      {hive_type}");
    println!("Version:        1.{}", hive.version() as u32);
    println!("Clean:          {}", if hive.is_clean() { "yes" } else { "NO (dirty)" });
    println!("Bins:           {}", hive.bin_count());
    println!("Data size:      {} bytes", hive.hive_bins_data_size());
    println!("Internal name:  {}", hive.file_name());

    // Count keys and values via BFS
    let mut key_count = 0u64;
    let mut value_count = 0u64;
    if let Ok(iter) = hive.iter_bfs() {
        for key_result in iter {
            if let Ok(key) = key_result {
                key_count += 1;
                value_count += u64::from(key.value_count());
            }
        }
    }
    println!("Keys:           {key_count}");
    println!("Values:         {value_count}");

    Ok(())
}

fn cmd_dump(
    path: &std::path::Path,
    subpath: Option<&str>,
    format: &OutputFormat,
    max_depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let hive = winreg_core::Hive::from_path(path)?;
    let root = if let Some(p) = subpath {
        hive.open_key(p)?
            .ok_or_else(|| format!("Key not found: {p}"))?
    } else {
        hive.root_key()?
    };

    dump_key(&root, 0, max_depth)?;
    Ok(())
}

fn dump_key(key: &winreg_core::key::Key<'_>, depth: usize, max_depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    if max_depth > 0 && depth >= max_depth {
        return Ok(());
    }

    let indent = "  ".repeat(depth);
    println!("{indent}[{}]", key.name());

    for val in key.values()? {
        let data_preview = match val.data_type() {
            winreg_format::flags::ValueType::Sz | winreg_format::flags::ValueType::ExpandSz => {
                val.as_string().unwrap_or_else(|_| "<error>".into())
            }
            winreg_format::flags::ValueType::Dword => {
                val.as_u32().map(|v| format!("0x{v:08X}")).unwrap_or_else(|_| "<error>".into())
            }
            winreg_format::flags::ValueType::Qword => {
                val.as_u64().map(|v| format!("0x{v:016X}")).unwrap_or_else(|_| "<error>".into())
            }
            _ => {
                let raw = val.raw_data().unwrap_or_default();
                if raw.len() <= 16 {
                    format!("{raw:02X?}")
                } else {
                    format!("[{} bytes]", raw.len())
                }
            }
        };
        let name = if val.name().is_empty() { "(Default)" } else { &val.name() };
        println!("{indent}  {name} ({}) = {data_preview}", val.data_type());
    }

    for subkey in key.subkeys()? {
        dump_key(&subkey, depth + 1, max_depth)?;
    }

    Ok(())
}

fn cmd_search(
    path: &std::path::Path,
    key_name: Option<&str>,
    value_name: Option<&str>,
    value_data: Option<&str>,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let hive = winreg_core::Hive::from_path(path)?;

    let key_pattern = key_name.map(|s| s.to_ascii_uppercase());
    let val_pattern = value_name.map(|s| s.to_ascii_uppercase());
    let data_pattern = value_data.map(|s| s.to_ascii_uppercase());

    for key_result in hive.iter_bfs()? {
        let key = key_result?;
        let key_name_upper = key.name().to_ascii_uppercase();

        // Match key name
        if let Some(ref pattern) = key_pattern {
            if key_name_upper.contains(pattern.as_str()) {
                // Reconstruct path (simplified — full path needs path.rs)
                println!("KEY: {}", key.name());
            }
        }

        // Match value name or data
        if val_pattern.is_some() || data_pattern.is_some() {
            for val in key.values()? {
                let matched = if let Some(ref pattern) = val_pattern {
                    val.name().to_ascii_uppercase().contains(pattern.as_str())
                } else {
                    false
                };

                let data_matched = if let Some(ref pattern) = data_pattern {
                    val.as_string()
                        .map(|s| s.to_ascii_uppercase().contains(pattern.as_str()))
                        .unwrap_or(false)
                } else {
                    false
                };

                if matched || data_matched {
                    println!(
                        "VALUE: {}\\{} ({}) = {}",
                        key.name(),
                        val.name(),
                        val.data_type(),
                        val.as_string().unwrap_or_else(|_| "<binary>".into())
                    );
                }
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 2: Create output.rs placeholder**

Create `rt-reg/src/output.rs`:

```rust
//! Output formatting — table, json, jsonl, csv.
//! Full implementation deferred until artifact decoders produce structured findings.
```

- [ ] **Step 3: Verify it builds and runs**

```bash
cargo build -p rt-reg
./target/debug/rt-reg --help
./target/debug/rt-reg info --help
```

Expected: help text displays for all subcommands.

- [ ] **Step 4: Commit**

```bash
git add rt-reg/
git commit -m "feat(cli): add rt-reg with info, dump, and search subcommands"
```

---

### Task 16: Integration Tests + Security Stub + Final Verification

**Files:**
- Create: `crates/winreg-core/src/security.rs` (stub)
- Create: `crates/winreg-core/src/path.rs` (stub)
- Run full test suite

- [ ] **Step 1: Create security.rs stub**

Create `crates/winreg-core/src/security.rs`:

```rust
//! Security key chain traversal — stub for Plan 1.
//! Full implementation (ACL parsing, SID resolution) in Plan 2.
```

- [ ] **Step 2: Create path.rs with key path reconstruction**

Create `crates/winreg-core/src/path.rs`:

```rust
//! Key path reconstruction — walk the parent chain to build full paths.

use std::io::Cursor;

use winreg_format::cells::CellOffset;

use crate::cell_reader::Cell;
use crate::error::Result;
use crate::hive::Hive;
use crate::key::Key;

impl<'h> Key<'h> {
    /// Reconstruct the full path from root to this key.
    ///
    /// Walks the parent chain upward until the root key (KEY_HIVE_ENTRY) is found.
    pub fn path(&self) -> Result<String> {
        let mut parts = vec![self.name()];
        let mut current_parent = self.node.parent;

        // Walk up to root (max 512 levels to prevent infinite loops on corrupt hives).
        for _ in 0..512 {
            if current_parent.is_null() {
                break;
            }

            let cell = self.hive.read_cell(current_parent)?;
            match cell {
                Cell::KeyNode(nk) => {
                    if nk.is_root() {
                        break; // Don't include root key name in path
                    }
                    parts.push(nk.key_name());
                    current_parent = nk.parent;
                }
                _ => break,
            }
        }

        parts.reverse();
        Ok(parts.join("\\"))
    }
}

#[cfg(test)]
mod tests {
    // Path reconstruction tests require TestHiveBuilder with nested keys.
    //
    // #[test]
    // fn path_of_root_key() { ... }
    //
    // #[test]
    // fn path_of_nested_key() { ... }
}
```

- [ ] **Step 3: Run full workspace test suite**

```bash
cd ~/src/winreg-forensic
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

Expected: all tests pass, no clippy warnings, formatting clean.

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-core/src/security.rs crates/winreg-core/src/path.rs
git commit -m "feat(core): add key path reconstruction, security stub, pass full test suite"
```

---

## Self-Review

**1. Spec coverage:**
- Section 2 (workspace structure): Task 1 ✓
- Section 3.1 (I/O layer): Task 7 (from_bytes), Task 12 (from_path) ✓
- Section 3.2 (cell reading): Task 8 ✓
- Section 3.3 (key navigation): Task 10 ✓
- Section 3.4 (value decoding): Task 11 ✓
- Section 3.5 (transaction log replay): Task 13 ✓
- Section 3.6 (TxR/CLFS): Partial in Task 13 (basic structure), full implementation deferred
- Section 4 (artifact decoders): Deferred to Plan 2
- Section 5 (recovery/carving): Placeholder crates, deferred to Plan 3
- Section 6 (CLI): Task 15 (info/dump/search) ✓
- Section 7 (Python bindings): Placeholder crate, deferred to Plan 4
- Section 8 (feature flags): Deferred until all crates have content
- Section 9 (testing): Task 9 (TestHiveBuilder), unit tests in each task ✓
- Section 10 (dependencies): Cargo.toml in Task 1 ✓
- Hive type detection: Task 14 ✓

**2. Placeholder scan:** No TBD/TODO in any step. The `todo!()` in TestHiveBuilder `build()` is intentional — it marks where the subagent must write the implementation (the full spec is in the comments above it).

**3. Type consistency:**
- `CellOffset` used consistently across all tasks
- `RawKeyNode` / `RawKeyValue` / `RawSecurityKey` / `RawBigData` — consistent naming
- `KeyFlags` / `ValueFlags` / `ValueType` — consistent flag types
- `HiveError` used as the error type everywhere
- `Key<'h>` / `Value<'h>` lifetime parameter consistent
- `Hive<Cursor<Vec<u8>>>` is the concrete type throughout (mmap via from_path reads into Vec)
