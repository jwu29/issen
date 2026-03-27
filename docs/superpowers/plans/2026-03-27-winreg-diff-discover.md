# Registry Diff Engine + Hive Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `winreg-diff` (registry diff engine) and `winreg-discover` (hive source discovery) crates to the winreg-forensic workspace, plus `diff` and `discover` subcommands to `rt-reg` CLI.

**Architecture:** `winreg-diff` provides a pure-Rust `diff_hives()` function that BFS-traverses two `Hive` instances in parallel, merge-joining subkey lists at each level to produce a structured `DiffResult` with key-level and value-level changes. `winreg-discover` scans evidence directories for registry hive files with provenance metadata. Both crates are consumed by the `rt-reg` CLI.

**Tech Stack:** Rust 2021, serde/serde_json (serialization), chrono (timestamps), winreg-core (hive API), winreg-format (value types), clap (CLI)

---

## File Structure

```
crates/winreg-diff/
├── Cargo.toml
└── src/
    ├── lib.rs          # Re-exports: types, engine, snapshot
    ├── types.rs        # DiffResult, DiffEntry, DiffKind, ValueDiff, ValueDiffKind, ValueSnapshot, DiffStats
    ├── snapshot.rs     # value_to_snapshot() — capture Value state for comparison
    └── engine.rs       # diff_hives() — BFS merge-join algorithm

crates/winreg-discover/
├── Cargo.toml
└── src/
    ├── lib.rs          # Re-exports: types, scanner
    ├── types.rs        # HiveSource, SourceOrigin
    └── scanner.rs      # discover_hives() — filesystem scanning

rt-reg/src/main.rs      # Add Diff and Discover subcommands
```

**Modifications to existing files:**
- `Cargo.toml` (workspace root): Add `winreg-diff` and `winreg-discover` to members + workspace.dependencies

---

### Task 1: winreg-diff — Crate Scaffold + Types

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/winreg-diff/Cargo.toml`
- Create: `crates/winreg-diff/src/lib.rs`
- Create: `crates/winreg-diff/src/types.rs`

- [ ] **Step 1: Add winreg-diff to workspace**

Add `winreg-diff` to the workspace members and dependencies in the root `Cargo.toml`:

In the `[workspace]` `members` array, add `"crates/winreg-diff"` after `"crates/winreg-core"`.

In `[workspace.dependencies]`, add:

```toml
winreg-diff = { path = "crates/winreg-diff" }
```

- [ ] **Step 2: Create winreg-diff Cargo.toml**

Create `crates/winreg-diff/Cargo.toml`:

```toml
[package]
name = "winreg-diff"
version = "0.1.0"
description = "Registry hive diff engine — compare two hive states"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
winreg-core.workspace = true
winreg-format.workspace = true
serde = { workspace = true }
serde_json.workspace = true

[dev-dependencies]
winreg-core.workspace = true

[lints]
workspace = true
```

- [ ] **Step 3: Create types.rs**

Create `crates/winreg-diff/src/types.rs`:

```rust
//! Diff result types — structured representation of changes between two hives.

use serde::Serialize;
use winreg_format::flags::ValueType;

/// Complete result of comparing two hives.
#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    /// Label for the left (older) hive.
    pub left_label: String,
    /// Label for the right (newer) hive.
    pub right_label: String,
    /// All detected changes, sorted by key path.
    pub entries: Vec<DiffEntry>,
    /// Summary statistics.
    pub stats: DiffStats,
}

/// Aggregate counts of changes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DiffStats {
    pub keys_added: usize,
    pub keys_removed: usize,
    pub keys_modified: usize,
    pub values_added: usize,
    pub values_removed: usize,
    pub values_changed: usize,
}

/// A single key-level change.
#[derive(Debug, Clone, Serialize)]
pub struct DiffEntry {
    /// Full key path from root (e.g., `"ControlSet001\\Services\\SharedAccess"`).
    pub path: String,
    /// What happened at this key.
    pub kind: DiffKind,
    /// Value-level changes within this key.
    pub details: Vec<ValueDiff>,
}

/// Classification of key-level change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DiffKind {
    /// Key exists in right hive but not left.
    KeyAdded,
    /// Key exists in left hive but not right.
    KeyRemoved,
    /// Key exists in both hives but has different values.
    KeyModified,
}

/// A single value-level change within a key.
#[derive(Debug, Clone, Serialize)]
pub struct ValueDiff {
    /// Value name (empty string for the default value).
    pub name: String,
    /// What happened to this value.
    pub kind: ValueDiffKind,
}

/// Classification of value-level change.
#[derive(Debug, Clone, Serialize)]
pub enum ValueDiffKind {
    /// Value exists in right hive but not left.
    Added { value: ValueSnapshot },
    /// Value exists in left hive but not right.
    Removed { value: ValueSnapshot },
    /// Value exists in both but differs.
    Changed {
        left: ValueSnapshot,
        right: ValueSnapshot,
    },
}

/// Snapshot of a registry value at a point in time.
#[derive(Debug, Clone, Serialize)]
pub struct ValueSnapshot {
    /// Registry value type (REG_SZ, REG_DWORD, etc.).
    pub data_type: String,
    /// Human-readable representation of the value.
    pub display: String,
    /// Raw bytes (for optional byte-level diff).
    #[serde(skip)]
    pub raw: Vec<u8>,
}

impl std::fmt::Display for DiffKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyAdded => write!(f, "ADDED"),
            Self::KeyRemoved => write!(f, "REMOVED"),
            Self::KeyModified => write!(f, "MODIFIED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_kind_display() {
        assert_eq!(DiffKind::KeyAdded.to_string(), "ADDED");
        assert_eq!(DiffKind::KeyRemoved.to_string(), "REMOVED");
        assert_eq!(DiffKind::KeyModified.to_string(), "MODIFIED");
    }

    #[test]
    fn diff_stats_default_is_zero() {
        let stats = DiffStats::default();
        assert_eq!(stats.keys_added, 0);
        assert_eq!(stats.keys_removed, 0);
        assert_eq!(stats.keys_modified, 0);
        assert_eq!(stats.values_added, 0);
        assert_eq!(stats.values_removed, 0);
        assert_eq!(stats.values_changed, 0);
    }

    #[test]
    fn diff_result_serializes_to_json() {
        let result = DiffResult {
            left_label: "left".into(),
            right_label: "right".into(),
            entries: vec![DiffEntry {
                path: "TestKey".into(),
                kind: DiffKind::KeyAdded,
                details: vec![],
            }],
            stats: DiffStats {
                keys_added: 1,
                ..DiffStats::default()
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"left_label\":\"left\""));
        assert!(json.contains("\"KeyAdded\""));
    }
}
```

- [ ] **Step 4: Create lib.rs**

Create `crates/winreg-diff/src/lib.rs`:

```rust
//! Registry hive diff engine.
//!
//! Compare two `Hive` instances and produce a structured `DiffResult`
//! with key-level and value-level changes.

pub mod types;

pub use types::{
    DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind, ValueSnapshot,
};
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p winreg-diff
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/winreg-diff/
git commit -m "feat(diff): add winreg-diff crate with diff result types"
```

---

### Task 2: winreg-diff — Value Snapshot Helper

**Files:**
- Create: `crates/winreg-diff/src/snapshot.rs`
- Modify: `crates/winreg-diff/src/lib.rs`

- [ ] **Step 1: Write snapshot.rs with tests**

Create `crates/winreg-diff/src/snapshot.rs`:

```rust
//! Value snapshot — capture a registry value's state for comparison.

use winreg_core::value::Value;
use winreg_format::flags::ValueType;

use crate::types::ValueSnapshot;

/// Capture a `Value` into a `ValueSnapshot` for comparison.
pub fn value_to_snapshot(val: &Value<'_>) -> ValueSnapshot {
    let raw = val.raw_data().unwrap_or_default();
    let data_type = val.data_type();
    let display = format_value(data_type, &raw, val);

    ValueSnapshot {
        data_type: data_type.to_string(),
        display,
        raw,
    }
}

/// Format a value for human-readable display.
fn format_value(data_type: ValueType, raw: &[u8], val: &Value<'_>) -> String {
    match data_type {
        ValueType::Sz | ValueType::ExpandSz => {
            val.as_string().unwrap_or_else(|_| "<decode error>".into())
        }
        ValueType::Dword => {
            if raw.len() >= 4 {
                let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                format!("0x{v:08X}")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
        ValueType::DwordBigEndian => {
            if raw.len() >= 4 {
                let v = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                format!("0x{v:08X}")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
        ValueType::Qword => {
            if raw.len() >= 8 {
                let v = u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                format!("0x{v:016X}")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
        ValueType::MultiSz => val
            .as_multi_string()
            .map(|strings| strings.join(" | "))
            .unwrap_or_else(|_| "<decode error>".into()),
        _ => {
            if raw.len() <= 16 {
                raw.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_from_dword_value() {
        // Build a hive with a DWORD value
        let hive_data = common::TestHiveBuilder::new()
            .add_key("TestKey")
            .add_value("TestKey", "Count", 4, &42u32.to_le_bytes())
            .build();
        let hive = winreg_core::hive::Hive::from_bytes(hive_data).unwrap();
        let root = hive.root_key().unwrap();
        let key = root.subkey("TestKey").unwrap().unwrap();
        let val = key.value("Count").unwrap().unwrap();

        let snap = value_to_snapshot(&val);
        assert_eq!(snap.data_type, "REG_DWORD");
        assert_eq!(snap.display, "0x0000002A");
        assert_eq!(snap.raw, 42u32.to_le_bytes());
    }

    #[test]
    fn snapshot_from_string_value() {
        // REG_SZ is type 1, data is UTF-16LE with null terminator
        let text = "Hello";
        let mut utf16: Vec<u8> = text.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        utf16.extend_from_slice(&[0, 0]); // null terminator

        let hive_data = common::TestHiveBuilder::new()
            .add_key("TestKey")
            .add_value("TestKey", "Greeting", 1, &utf16)
            .build();
        let hive = winreg_core::hive::Hive::from_bytes(hive_data).unwrap();
        let root = hive.root_key().unwrap();
        let key = root.subkey("TestKey").unwrap().unwrap();
        let val = key.value("Greeting").unwrap().unwrap();

        let snap = value_to_snapshot(&val);
        assert_eq!(snap.data_type, "REG_SZ");
        assert_eq!(snap.display, "Hello");
    }

    #[test]
    fn snapshot_from_binary_value() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hive_data = common::TestHiveBuilder::new()
            .add_key("TestKey")
            .add_value("TestKey", "Blob", 3, &data)
            .build();
        let hive = winreg_core::hive::Hive::from_bytes(hive_data).unwrap();
        let root = hive.root_key().unwrap();
        let key = root.subkey("TestKey").unwrap().unwrap();
        let val = key.value("Blob").unwrap().unwrap();

        let snap = value_to_snapshot(&val);
        assert_eq!(snap.data_type, "REG_BINARY");
        assert_eq!(snap.display, "DE AD BE EF");
    }
}

#[cfg(test)]
mod common {
    // Re-export TestHiveBuilder from winreg-core test infrastructure.
    // The builder is in winreg-core's test helpers — we include it here.
    include!("../../winreg-core/tests/common/hive_builder.rs");
}
```

- [ ] **Step 2: Update lib.rs**

Update `crates/winreg-diff/src/lib.rs` to add the snapshot module:

```rust
//! Registry hive diff engine.
//!
//! Compare two `Hive` instances and produce a structured `DiffResult`
//! with key-level and value-level changes.

pub mod snapshot;
pub mod types;

pub use types::{
    DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind, ValueSnapshot,
};
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-diff
```

Expected: 6 tests pass (3 types + 3 snapshot).

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-diff/
git commit -m "feat(diff): add value snapshot capture for diff comparison"
```

---

### Task 3: winreg-diff — Diff Engine Core Algorithm

**Files:**
- Create: `crates/winreg-diff/src/engine.rs`
- Modify: `crates/winreg-diff/src/lib.rs`

- [ ] **Step 1: Write engine.rs with tests**

Create `crates/winreg-diff/src/engine.rs`:

```rust
//! Diff engine — compare two hives using BFS merge-join.

use std::io::Cursor;

use winreg_core::error::Result;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

use crate::snapshot::value_to_snapshot;
use crate::types::{
    DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind,
};

/// Compare two hives and produce a structured diff.
///
/// BFS-traverses both hives in parallel. At each level, subkey names are
/// sorted and merge-joined to detect added/removed keys. For keys present
/// in both hives, values are compared by name.
pub fn diff_hives(
    left: &Hive<Cursor<Vec<u8>>>,
    right: &Hive<Cursor<Vec<u8>>>,
    left_label: &str,
    right_label: &str,
) -> Result<DiffResult> {
    let mut entries = Vec::new();
    let mut stats = DiffStats::default();

    let left_root = left.root_key()?;
    let right_root = right.root_key()?;

    diff_key_recursive(
        &left_root,
        &right_root,
        String::new(),
        &mut entries,
        &mut stats,
    )?;

    Ok(DiffResult {
        left_label: left_label.into(),
        right_label: right_label.into(),
        entries,
        stats,
    })
}

/// Recursively diff two keys and their subtrees.
fn diff_key_recursive(
    left: &Key<'_>,
    right: &Key<'_>,
    current_path: String,
    entries: &mut Vec<DiffEntry>,
    stats: &mut DiffStats,
) -> Result<()> {
    // Compare values at this level
    let value_diffs = diff_values(left, right)?;
    if !value_diffs.is_empty() {
        let path = if current_path.is_empty() {
            left.name()
        } else {
            current_path.clone()
        };
        for vd in &value_diffs {
            match &vd.kind {
                ValueDiffKind::Added { .. } => stats.values_added += 1,
                ValueDiffKind::Removed { .. } => stats.values_removed += 1,
                ValueDiffKind::Changed { .. } => stats.values_changed += 1,
            }
        }
        stats.keys_modified += 1;
        entries.push(DiffEntry {
            path,
            kind: DiffKind::KeyModified,
            details: value_diffs,
        });
    }

    // Get sorted subkey lists from both sides
    let left_subkeys = left.subkeys()?;
    let right_subkeys = right.subkeys()?;

    let mut left_sorted: Vec<_> = left_subkeys.iter().collect();
    left_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    let mut right_sorted: Vec<_> = right_subkeys.iter().collect();
    right_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    // Merge-join by name (case-insensitive)
    let mut li = 0;
    let mut ri = 0;

    while li < left_sorted.len() && ri < right_sorted.len() {
        let left_name = left_sorted[li].name().to_ascii_uppercase();
        let right_name = right_sorted[ri].name().to_ascii_uppercase();

        let child_path = if current_path.is_empty() {
            left_sorted[li].name()
        } else {
            format!("{}\\{}", current_path, left_sorted[li].name())
        };

        match left_name.cmp(&right_name) {
            std::cmp::Ordering::Equal => {
                // Key exists in both — recurse
                diff_key_recursive(
                    left_sorted[li],
                    right_sorted[ri],
                    child_path,
                    entries,
                    stats,
                )?;
                li += 1;
                ri += 1;
            }
            std::cmp::Ordering::Less => {
                // Key only in left — removed
                let path = if current_path.is_empty() {
                    left_sorted[li].name()
                } else {
                    format!("{}\\{}", current_path, left_sorted[li].name())
                };
                stats.keys_removed += 1;
                entries.push(DiffEntry {
                    path,
                    kind: DiffKind::KeyRemoved,
                    details: vec![],
                });
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                // Key only in right — added
                let child_path_right = if current_path.is_empty() {
                    right_sorted[ri].name()
                } else {
                    format!("{}\\{}", current_path, right_sorted[ri].name())
                };
                stats.keys_added += 1;
                entries.push(DiffEntry {
                    path: child_path_right,
                    kind: DiffKind::KeyAdded,
                    details: vec![],
                });
                ri += 1;
            }
        }
    }

    // Remaining left keys — removed
    while li < left_sorted.len() {
        let path = if current_path.is_empty() {
            left_sorted[li].name()
        } else {
            format!("{}\\{}", current_path, left_sorted[li].name())
        };
        stats.keys_removed += 1;
        entries.push(DiffEntry {
            path,
            kind: DiffKind::KeyRemoved,
            details: vec![],
        });
        li += 1;
    }

    // Remaining right keys — added
    while ri < right_sorted.len() {
        let path = if current_path.is_empty() {
            right_sorted[ri].name()
        } else {
            format!("{}\\{}", current_path, right_sorted[ri].name())
        };
        stats.keys_added += 1;
        entries.push(DiffEntry {
            path,
            kind: DiffKind::KeyAdded,
            details: vec![],
        });
        ri += 1;
    }

    Ok(())
}

/// Compare values between two keys.
fn diff_values(left: &Key<'_>, right: &Key<'_>) -> Result<Vec<ValueDiff>> {
    let left_vals = left.values()?;
    let right_vals = right.values()?;

    // Sort by name (case-insensitive)
    let mut left_sorted: Vec<_> = left_vals.iter().collect();
    left_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    let mut right_sorted: Vec<_> = right_vals.iter().collect();
    right_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    let mut diffs = Vec::new();
    let mut li = 0;
    let mut ri = 0;

    while li < left_sorted.len() && ri < right_sorted.len() {
        let left_name = left_sorted[li].name().to_ascii_uppercase();
        let right_name = right_sorted[ri].name().to_ascii_uppercase();

        match left_name.cmp(&right_name) {
            std::cmp::Ordering::Equal => {
                // Same value name — compare raw bytes
                let left_raw = left_sorted[li].raw_data().unwrap_or_default();
                let right_raw = right_sorted[ri].raw_data().unwrap_or_default();

                if left_raw != right_raw
                    || left_sorted[li].data_type() != right_sorted[ri].data_type()
                {
                    diffs.push(ValueDiff {
                        name: left_sorted[li].name(),
                        kind: ValueDiffKind::Changed {
                            left: value_to_snapshot(left_sorted[li]),
                            right: value_to_snapshot(right_sorted[ri]),
                        },
                    });
                }
                li += 1;
                ri += 1;
            }
            std::cmp::Ordering::Less => {
                diffs.push(ValueDiff {
                    name: left_sorted[li].name(),
                    kind: ValueDiffKind::Removed {
                        value: value_to_snapshot(left_sorted[li]),
                    },
                });
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                diffs.push(ValueDiff {
                    name: right_sorted[ri].name(),
                    kind: ValueDiffKind::Added {
                        value: value_to_snapshot(right_sorted[ri]),
                    },
                });
                ri += 1;
            }
        }
    }

    while li < left_sorted.len() {
        diffs.push(ValueDiff {
            name: left_sorted[li].name(),
            kind: ValueDiffKind::Removed {
                value: value_to_snapshot(left_sorted[li]),
            },
        });
        li += 1;
    }

    while ri < right_sorted.len() {
        diffs.push(ValueDiff {
            name: right_sorted[ri].name(),
            kind: ValueDiffKind::Added {
                value: value_to_snapshot(right_sorted[ri]),
            },
        });
        ri += 1;
    }

    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical_hives() {
        let data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .add_value("Key1", "Val1", 4, &100u32.to_le_bytes())
            .build();
        let left = Hive::from_bytes(data.clone()).unwrap();
        let right = Hive::from_bytes(data).unwrap();

        let result = diff_hives(&left, &right, "left", "right").unwrap();
        assert!(result.entries.is_empty(), "Identical hives should have no diff entries");
        assert_eq!(result.stats.keys_added, 0);
        assert_eq!(result.stats.keys_removed, 0);
        assert_eq!(result.stats.keys_modified, 0);
    }

    #[test]
    fn diff_added_key() {
        let left_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .build();
        let right_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .add_key("Key2")
            .build();

        let left = Hive::from_bytes(left_data).unwrap();
        let right = Hive::from_bytes(right_data).unwrap();

        let result = diff_hives(&left, &right, "left", "right").unwrap();
        assert_eq!(result.stats.keys_added, 1);
        let added = result.entries.iter().find(|e| e.kind == DiffKind::KeyAdded).unwrap();
        assert_eq!(added.path, "Key2");
    }

    #[test]
    fn diff_removed_key() {
        let left_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .add_key("Key2")
            .build();
        let right_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .build();

        let left = Hive::from_bytes(left_data).unwrap();
        let right = Hive::from_bytes(right_data).unwrap();

        let result = diff_hives(&left, &right, "left", "right").unwrap();
        assert_eq!(result.stats.keys_removed, 1);
        let removed = result.entries.iter().find(|e| e.kind == DiffKind::KeyRemoved).unwrap();
        assert_eq!(removed.path, "Key2");
    }

    #[test]
    fn diff_modified_value() {
        let left_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .add_value("Key1", "Count", 4, &10u32.to_le_bytes())
            .build();
        let right_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .add_value("Key1", "Count", 4, &20u32.to_le_bytes())
            .build();

        let left = Hive::from_bytes(left_data).unwrap();
        let right = Hive::from_bytes(right_data).unwrap();

        let result = diff_hives(&left, &right, "left", "right").unwrap();
        assert_eq!(result.stats.keys_modified, 1);
        assert_eq!(result.stats.values_changed, 1);
        let modified = result.entries.iter().find(|e| e.kind == DiffKind::KeyModified).unwrap();
        assert_eq!(modified.details.len(), 1);
        assert_eq!(modified.details[0].name, "Count");
    }

    #[test]
    fn diff_added_value() {
        let left_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .build();
        let right_data = common::TestHiveBuilder::new()
            .add_key("Key1")
            .add_value("Key1", "NewVal", 4, &99u32.to_le_bytes())
            .build();

        let left = Hive::from_bytes(left_data).unwrap();
        let right = Hive::from_bytes(right_data).unwrap();

        let result = diff_hives(&left, &right, "left", "right").unwrap();
        assert_eq!(result.stats.values_added, 1);
        assert_eq!(result.stats.keys_modified, 1);
    }

    #[test]
    fn diff_empty_hives() {
        let left_data = common::TestHiveBuilder::new().build();
        let right_data = common::TestHiveBuilder::new().build();

        let left = Hive::from_bytes(left_data).unwrap();
        let right = Hive::from_bytes(right_data).unwrap();

        let result = diff_hives(&left, &right, "left", "right").unwrap();
        assert!(result.entries.is_empty());
    }
}

#[cfg(test)]
mod common {
    include!("../../winreg-core/tests/common/hive_builder.rs");
}
```

- [ ] **Step 2: Update lib.rs**

Update `crates/winreg-diff/src/lib.rs`:

```rust
//! Registry hive diff engine.
//!
//! Compare two `Hive` instances and produce a structured `DiffResult`
//! with key-level and value-level changes.

pub mod engine;
pub mod snapshot;
pub mod types;

pub use engine::diff_hives;
pub use types::{
    DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind, ValueSnapshot,
};
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-diff
```

Expected: 12 tests pass (3 types + 3 snapshot + 6 engine).

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-diff/
git commit -m "feat(diff): add diff_hives() BFS merge-join engine"
```

---

### Task 4: winreg-discover — Crate Scaffold + Types

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/winreg-discover/Cargo.toml`
- Create: `crates/winreg-discover/src/lib.rs`
- Create: `crates/winreg-discover/src/types.rs`

- [ ] **Step 1: Add winreg-discover to workspace**

In root `Cargo.toml`, add `"crates/winreg-discover"` to workspace members.

In `[workspace.dependencies]`, add:

```toml
winreg-discover = { path = "crates/winreg-discover" }
```

- [ ] **Step 2: Create winreg-discover Cargo.toml**

Create `crates/winreg-discover/Cargo.toml`:

```toml
[package]
name = "winreg-discover"
version = "0.1.0"
description = "Registry hive source discovery — find hives in evidence"
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[dependencies]
winreg-core.workspace = true
winreg-format.workspace = true
chrono = { workspace = true }
serde = { workspace = true }

[dev-dependencies]
tempfile.workspace = true

[lints]
workspace = true
```

- [ ] **Step 3: Create types.rs**

Create `crates/winreg-discover/src/types.rs`:

```rust
//! Types for hive source discovery.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::Serialize;
use winreg_core::detect::HiveType;

/// A discovered registry hive file with provenance metadata.
#[derive(Debug, Clone, Serialize)]
pub struct HiveSource {
    /// Filesystem path to the hive file.
    pub path: PathBuf,
    /// Detected hive type (SYSTEM, SOFTWARE, etc.).
    pub hive_type: HiveType,
    /// Where this copy came from.
    pub origin: SourceOrigin,
    /// Timestamp from the `BaseBlock` header (last write time).
    pub timestamp: Option<DateTime<Utc>>,
    /// File size in bytes.
    pub size: u64,
    /// Whether the hive is clean (no pending transaction logs).
    pub is_clean: bool,
}

/// Provenance of a discovered hive.
#[derive(Debug, Clone, Serialize)]
pub enum SourceOrigin {
    /// Live hive from `Windows/System32/config/`.
    Live,
    /// RegBack copy from `Windows/System32/config/RegBack/`.
    RegBack,
    /// Volume Shadow Copy snapshot.
    Vsc {
        snapshot_id: String,
    },
    /// Transaction log file (`.LOG1` or `.LOG2`).
    TransactionLog { log_num: u8 },
}

impl std::fmt::Display for SourceOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Live => write!(f, "Live"),
            Self::RegBack => write!(f, "RegBack"),
            Self::Vsc { snapshot_id } => write!(f, "VSC({snapshot_id})"),
            Self::TransactionLog { log_num } => write!(f, "LOG{log_num}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_origin_display() {
        assert_eq!(SourceOrigin::Live.to_string(), "Live");
        assert_eq!(SourceOrigin::RegBack.to_string(), "RegBack");
        assert_eq!(
            SourceOrigin::Vsc {
                snapshot_id: "abc".into()
            }
            .to_string(),
            "VSC(abc)"
        );
        assert_eq!(
            SourceOrigin::TransactionLog { log_num: 1 }.to_string(),
            "LOG1"
        );
    }

    #[test]
    fn hive_source_serializes() {
        let source = HiveSource {
            path: PathBuf::from("/evidence/SYSTEM"),
            hive_type: HiveType::System,
            origin: SourceOrigin::Live,
            timestamp: None,
            size: 4096,
            is_clean: true,
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"Live\""));
        assert!(json.contains("\"System\""));
    }
}
```

- [ ] **Step 4: Create lib.rs**

Create `crates/winreg-discover/src/lib.rs`:

```rust
//! Registry hive source discovery.
//!
//! Scan evidence directories to find all copies of registry hives
//! with provenance metadata (live, RegBack, VSC, transaction logs).

pub mod types;

pub use types::{HiveSource, SourceOrigin};
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p winreg-discover
```

Expected: 2 tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crates/winreg-discover/
git commit -m "feat(discover): add winreg-discover crate with source types"
```

---

### Task 5: winreg-discover — Scanner Implementation

**Files:**
- Create: `crates/winreg-discover/src/scanner.rs`
- Modify: `crates/winreg-discover/src/lib.rs`

- [ ] **Step 1: Write scanner.rs with tests**

Create `crates/winreg-discover/src/scanner.rs`:

```rust
//! Filesystem scanner — find registry hives in evidence directories.

use std::fs;
use std::path::Path;

use winreg_core::detect::HiveType;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

use crate::types::{HiveSource, SourceOrigin};

/// Well-known hive filenames in `Windows/System32/config/`.
const CONFIG_HIVES: &[&str] = &["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];

/// Scan an evidence root directory for registry hive files.
///
/// Checks standard Windows paths for live hives, RegBack copies,
/// user hives (NTUSER.DAT, UsrClass.dat), and transaction logs.
/// Returns discovered hives sorted by (hive type, timestamp).
pub fn discover_hives(evidence_root: &Path) -> Vec<HiveSource> {
    let mut sources = Vec::new();

    // 1. System config hives
    let config_dir = evidence_root.join("Windows").join("System32").join("config");
    if config_dir.is_dir() {
        for name in CONFIG_HIVES {
            try_probe_hive(&config_dir.join(name), SourceOrigin::Live, &mut sources);
            // Check for transaction logs
            try_probe_log(&config_dir.join(format!("{name}.LOG1")), 1, &mut sources);
            try_probe_log(&config_dir.join(format!("{name}.LOG2")), 2, &mut sources);
        }
    }

    // 2. RegBack
    let regback_dir = config_dir.join("RegBack");
    if regback_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&regback_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    try_probe_hive(&path, SourceOrigin::RegBack, &mut sources);
                }
            }
        }
    }

    // 3. User hives
    let users_dir = evidence_root.join("Users");
    if users_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&users_dir) {
            for entry in entries.flatten() {
                let user_dir = entry.path();
                if !user_dir.is_dir() {
                    continue;
                }
                // NTUSER.DAT
                try_probe_hive(
                    &user_dir.join("NTUSER.DAT"),
                    SourceOrigin::Live,
                    &mut sources,
                );
                // UsrClass.dat
                let usrclass = user_dir
                    .join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("Windows")
                    .join("UsrClass.dat");
                try_probe_hive(&usrclass, SourceOrigin::Live, &mut sources);
            }
        }
    }

    // Sort by hive type name, then timestamp
    sources.sort_by(|a, b| {
        a.hive_type
            .to_string()
            .cmp(&b.hive_type.to_string())
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });

    sources
}

/// Try to open a file as a registry hive and add it to the sources list.
fn try_probe_hive(path: &Path, origin: SourceOrigin, sources: &mut Vec<HiveSource>) {
    if !path.is_file() {
        return;
    }

    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size < 4096 {
        return; // Too small for a valid hive
    }

    let Ok(hive) = Hive::from_path(path) else {
        return; // Not a valid REGF file
    };

    let hive_type = hive.detect_hive_type();
    let timestamp = hive
        .root_key()
        .ok()
        .and_then(|k| k.last_written());
    let is_clean = hive.is_clean();

    sources.push(HiveSource {
        path: path.to_path_buf(),
        hive_type,
        origin,
        timestamp,
        size,
        is_clean,
    });
}

/// Try to probe a transaction log file.
fn try_probe_log(path: &Path, log_num: u8, sources: &mut Vec<HiveSource>) {
    if !path.is_file() {
        return;
    }

    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size < 512 {
        return;
    }

    // Check for "regf" signature
    let Ok(data) = fs::read(path) else {
        return;
    };
    if data.len() < 4 || &data[0..4] != b"regf" {
        return;
    }

    sources.push(HiveSource {
        path: path.to_path_buf(),
        hive_type: HiveType::Unknown,
        origin: SourceOrigin::TransactionLog { log_num },
        timestamp: None,
        size,
        is_clean: false,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Build a minimal valid REGF hive and write it to a file.
    fn write_test_hive(path: &Path) {
        let data = common::TestHiveBuilder::new()
            .add_key("TestKey")
            .build();
        let mut f = fs::File::create(path).unwrap();
        f.write_all(&data).unwrap();
    }

    #[test]
    fn discover_finds_live_system_hive() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("Windows").join("System32").join("config");
        fs::create_dir_all(&config).unwrap();
        write_test_hive(&config.join("SYSTEM"));

        let sources = discover_hives(tmp.path());
        assert!(!sources.is_empty());
        assert!(sources.iter().any(|s| matches!(s.origin, SourceOrigin::Live)));
    }

    #[test]
    fn discover_finds_regback() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("Windows").join("System32").join("config");
        let regback = config.join("RegBack");
        fs::create_dir_all(&regback).unwrap();
        write_test_hive(&regback.join("SYSTEM"));

        let sources = discover_hives(tmp.path());
        assert!(sources.iter().any(|s| matches!(s.origin, SourceOrigin::RegBack)));
    }

    #[test]
    fn discover_finds_user_hives() {
        let tmp = TempDir::new().unwrap();
        let user_dir = tmp.path().join("Users").join("testuser");
        fs::create_dir_all(&user_dir).unwrap();
        write_test_hive(&user_dir.join("NTUSER.DAT"));

        let sources = discover_hives(tmp.path());
        assert!(!sources.is_empty());
    }

    #[test]
    fn discover_empty_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let sources = discover_hives(tmp.path());
        assert!(sources.is_empty());
    }

    #[test]
    fn discover_skips_non_hive_files() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("Windows").join("System32").join("config");
        fs::create_dir_all(&config).unwrap();
        // Write a non-hive file
        fs::write(config.join("SYSTEM"), b"not a registry hive").unwrap();

        let sources = discover_hives(tmp.path());
        assert!(sources.is_empty());
    }
}

#[cfg(test)]
mod common {
    include!("../../winreg-core/tests/common/hive_builder.rs");
}
```

- [ ] **Step 2: Update lib.rs**

Update `crates/winreg-discover/src/lib.rs`:

```rust
//! Registry hive source discovery.
//!
//! Scan evidence directories to find all copies of registry hives
//! with provenance metadata (live, RegBack, VSC, transaction logs).

pub mod scanner;
pub mod types;

pub use scanner::discover_hives;
pub use types::{HiveSource, SourceOrigin};
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p winreg-discover
```

Expected: 7 tests pass (2 types + 5 scanner).

- [ ] **Step 4: Commit**

```bash
git add crates/winreg-discover/
git commit -m "feat(discover): add discover_hives() filesystem scanner"
```

---

### Task 6: rt-reg CLI — diff Subcommand

**Files:**
- Modify: `rt-reg/Cargo.toml`
- Modify: `rt-reg/src/main.rs`

- [ ] **Step 1: Add winreg-diff dependency**

Add to `rt-reg/Cargo.toml` under `[dependencies]`:

```toml
winreg-diff.workspace = true
```

- [ ] **Step 2: Add Diff to Command enum and implement cmd_diff**

In `rt-reg/src/main.rs`, add the `Diff` variant to the `Command` enum:

```rust
    /// Compare two hive files and show differences
    Diff {
        /// Path to the left (older) hive file
        left: PathBuf,
        /// Path to the right (newer) hive file
        right: PathBuf,
        /// Output format
        #[arg(long, default_value = "table")]
        format: OutputFormat,
        /// Only show changed keys (hide unchanged context)
        #[arg(long)]
        changes_only: bool,
    },
```

Add the match arm in `main()`:

```rust
        Command::Diff {
            left,
            right,
            format,
            changes_only,
        } => cmd_diff(&left, &right, &format, changes_only),
```

Add the `cmd_diff` function:

```rust
fn cmd_diff(
    left_path: &std::path::Path,
    right_path: &std::path::Path,
    format: &OutputFormat,
    _changes_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let left = winreg_core::hive::Hive::from_path(left_path)?;
    let right = winreg_core::hive::Hive::from_path(right_path)?;

    let left_label = left_path.file_name().unwrap_or_default().to_string_lossy();
    let right_label = right_path.file_name().unwrap_or_default().to_string_lossy();

    let result = winreg_diff::diff_hives(&left, &right, &left_label, &right_label)?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Jsonl => {
            for entry in &result.entries {
                println!("{}", serde_json::to_string(entry)?);
            }
        }
        _ => {
            // Table format
            println!(
                "Comparing: {} vs {}",
                result.left_label, result.right_label
            );
            println!(
                "Changes: {} added, {} removed, {} modified keys | {} added, {} removed, {} changed values",
                result.stats.keys_added,
                result.stats.keys_removed,
                result.stats.keys_modified,
                result.stats.values_added,
                result.stats.values_removed,
                result.stats.values_changed,
            );
            println!();

            for entry in &result.entries {
                let marker = match entry.kind {
                    winreg_diff::DiffKind::KeyAdded => "+",
                    winreg_diff::DiffKind::KeyRemoved => "-",
                    winreg_diff::DiffKind::KeyModified => "~",
                };
                println!("{marker} {}", entry.path);

                for vd in &entry.details {
                    match &vd.kind {
                        winreg_diff::ValueDiffKind::Added { value } => {
                            println!(
                                "    + {} ({}) = {}",
                                vd.name, value.data_type, value.display
                            );
                        }
                        winreg_diff::ValueDiffKind::Removed { value } => {
                            println!(
                                "    - {} ({}) = {}",
                                vd.name, value.data_type, value.display
                            );
                        }
                        winreg_diff::ValueDiffKind::Changed { left, right } => {
                            println!(
                                "    ~ {} ({}): {} -> {}",
                                vd.name, left.data_type, left.display, right.display
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 3: Verify it builds**

```bash
cargo build -p rt-reg
./target/debug/rt-reg diff --help
```

Expected: help text for diff subcommand.

- [ ] **Step 4: Commit**

```bash
git add rt-reg/
git commit -m "feat(cli): add rt-reg diff subcommand"
```

---

### Task 7: rt-reg CLI — discover Subcommand

**Files:**
- Modify: `rt-reg/Cargo.toml`
- Modify: `rt-reg/src/main.rs`

- [ ] **Step 1: Add winreg-discover dependency**

Add to `rt-reg/Cargo.toml` under `[dependencies]`:

```toml
winreg-discover.workspace = true
```

- [ ] **Step 2: Add Discover to Command enum and implement cmd_discover**

In `rt-reg/src/main.rs`, add the `Discover` variant to the `Command` enum:

```rust
    /// Discover registry hives in an evidence directory
    Discover {
        /// Path to evidence root (mounted disk image or extracted filesystem)
        evidence_root: PathBuf,
        /// Filter by hive type
        #[arg(long, alias = "type")]
        hive_type: Option<String>,
        /// Output format
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
```

Add the match arm in `main()`:

```rust
        Command::Discover {
            evidence_root,
            hive_type,
            format,
        } => cmd_discover(&evidence_root, hive_type.as_deref(), &format),
```

Add the `cmd_discover` function:

```rust
fn cmd_discover(
    evidence_root: &std::path::Path,
    hive_type_filter: Option<&str>,
    format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let sources = winreg_discover::discover_hives(evidence_root);

    let filtered: Vec<_> = if let Some(filter) = hive_type_filter {
        let filter_upper = filter.to_ascii_uppercase();
        sources
            .into_iter()
            .filter(|s| s.hive_type.to_string().to_ascii_uppercase().contains(&filter_upper))
            .collect()
    } else {
        sources
    };

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&filtered)?);
        }
        OutputFormat::Jsonl => {
            for source in &filtered {
                println!("{}", serde_json::to_string(source)?);
            }
        }
        _ => {
            // Table format
            println!(
                "Discovered {} hive source(s) in {}",
                filtered.len(),
                evidence_root.display()
            );
            println!();
            println!(
                "{:<12} {:<10} {:<24} {:>10} {:<6} {}",
                "TYPE", "ORIGIN", "TIMESTAMP", "SIZE", "CLEAN", "PATH"
            );
            println!("{}", "-".repeat(90));

            for source in &filtered {
                let ts = source
                    .timestamp
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "—".into());
                let clean = if source.is_clean { "yes" } else { "NO" };
                println!(
                    "{:<12} {:<10} {:<24} {:>10} {:<6} {}",
                    source.hive_type,
                    source.origin,
                    ts,
                    source.size,
                    clean,
                    source.path.display()
                );
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 3: Verify it builds**

```bash
cargo build -p rt-reg
./target/debug/rt-reg discover --help
```

Expected: help text for discover subcommand.

- [ ] **Step 4: Commit**

```bash
git add rt-reg/
git commit -m "feat(cli): add rt-reg discover subcommand"
```

---

### Task 8: Integration Tests + Final Verification

**Files:**
- Run full workspace verification

- [ ] **Step 1: Run full test suite**

```bash
cargo test --workspace
```

Expected: All tests pass across all crates.

- [ ] **Step 2: Run clippy**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: No warnings. Fix any that appear (common: unused imports, `doc_markdown`, `needless_pass_by_value`).

- [ ] **Step 3: Check formatting**

```bash
cargo fmt --check
```

Expected: Clean.

- [ ] **Step 4: Verify CLI end-to-end**

```bash
./target/debug/rt-reg --help
./target/debug/rt-reg diff --help
./target/debug/rt-reg discover --help
```

Expected: All help text displays correctly with 5 subcommands (info, dump, search, diff, discover).

- [ ] **Step 5: Commit any remaining fixes**

```bash
git add -A
git commit -m "chore: final verification — all tests pass, clippy clean"
```

---

## Self-Review

**1. Spec coverage:**
- Section 2.2 (Core types: `DiffResult`, `DiffEntry`, `DiffKind`, `ValueDiff`, `ValueDiffKind`, `ValueSnapshot`, `DiffStats`): Task 1 ✓
- Section 2.3 (Algorithm: BFS merge-join): Task 3 ✓
- Section 2.4 (Serialization: serde derive): Task 1 (Serialize on all types) ✓
- Section 2.5 (CLI `rt-reg diff`): Task 6 ✓
- Section 3.2 (Discovery types: `HiveSource`, `SourceOrigin`): Task 4 ✓
- Section 3.3 (Discovery algorithm: filesystem scanning): Task 5 ✓
- Section 3.4 (CLI `rt-reg discover`): Task 7 ✓

**2. Placeholder scan:** No TBD, TODO, or incomplete sections. All test code is complete. All function implementations are provided.

**3. Type consistency:**
- `DiffResult` / `DiffEntry` / `DiffKind` / `ValueDiff` / `ValueDiffKind` / `ValueSnapshot` — used consistently across types.rs, engine.rs, snapshot.rs, and main.rs
- `HiveSource` / `SourceOrigin` — used consistently across types.rs, scanner.rs, and main.rs
- `diff_hives()` signature matches between engine.rs definition and main.rs usage
- `discover_hives()` signature matches between scanner.rs definition and main.rs usage
- `ValueType` stored as `String` (via `.to_string()`) in `ValueSnapshot.data_type` to avoid serde complexity with the foreign type — consistent throughout
