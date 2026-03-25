//! MFT → in-memory file tree reconstruction.
//!
//! Parses a raw `$MFT` file, extracts every allocated entry with its
//! `$STANDARD_INFORMATION` and `$FILE_NAME` attributes, resolves
//! parent-child relationships via MFT entry references, and builds an
//! arena-style tree that can be traversed interactively.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use mft::attribute::MftAttributeContent;
use mft::attribute::MftAttributeType;
use mft::MftParser;

/// NTFS root directory is always MFT entry 5.
const ROOT_MFT_ENTRY: u64 = 5;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A single file or directory extracted from the MFT.
#[derive(Debug, Clone)]
#[allow(dead_code)] // accessed / mft_modified reserved for future columns
pub struct FileNode {
    pub name: String,
    pub mft_entry: u64,
    pub parent_entry: u64,
    pub is_dir: bool,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub created: DateTime<Utc>,
    pub mft_modified: DateTime<Utc>,
    /// Number of USN journal change records referencing this entry.
    pub usn_change_count: u32,
}

/// Arena-style file tree built from an MFT.
pub struct FileTree {
    nodes: Vec<FileNode>,
    children: Vec<Vec<usize>>,
    entry_map: HashMap<u64, usize>,
    root_idx: Option<usize>,
    /// Pre-computed lowercase full paths for every node (parallel to `nodes`).
    paths: Vec<String>,
    pub total_mft_entries: u64,
    pub allocated_entries: usize,
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

impl FileTree {
    /// Build a tree from pre-collected nodes (used by `from_mft` and tests).
    pub fn from_nodes(nodes: Vec<FileNode>) -> Self {
        let allocated = nodes.len();
        let mut entry_map: HashMap<u64, usize> = HashMap::with_capacity(allocated);
        for (idx, node) in nodes.iter().enumerate() {
            entry_map.insert(node.mft_entry, idx);
        }

        // Build parent → children lists.
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); allocated];
        for (idx, node) in nodes.iter().enumerate() {
            if let Some(&parent_idx) = entry_map.get(&node.parent_entry) {
                if parent_idx != idx {
                    children[parent_idx].push(idx);
                }
            }
        }

        // Sort children: directories first, then case-insensitive name.
        for child_list in &mut children {
            let n = &nodes;
            child_list.sort_by(|&a, &b| {
                n[b].is_dir
                    .cmp(&n[a].is_dir)
                    .then_with(|| n[a].name.to_lowercase().cmp(&n[b].name.to_lowercase()))
            });
        }

        let root_idx = entry_map.get(&ROOT_MFT_ENTRY).copied();

        // Pre-compute full paths top-down via BFS from the root.
        let mut paths = vec![String::new(); allocated];
        if let Some(root) = root_idx {
            paths[root] = "/".to_string();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(root);
            while let Some(parent) = queue.pop_front() {
                for &child in &children[parent] {
                    let parent_path = &paths[parent];
                    paths[child] = if parent_path == "/" {
                        format!("/{}", nodes[child].name)
                    } else {
                        format!("{}/{}", parent_path, nodes[child].name)
                    };
                    queue.push_back(child);
                }
            }
        }

        // Orphan nodes (not reachable from root) — fall back to walk-up.
        // This is only computed once at construction, not per keystroke.
        for (idx, path) in paths.iter_mut().enumerate() {
            if path.is_empty() {
                let mut parts = Vec::new();
                let mut current = idx;
                let mut visited = std::collections::HashSet::new();
                loop {
                    if !visited.insert(current) {
                        break;
                    }
                    let node = &nodes[current];
                    if node.mft_entry == ROOT_MFT_ENTRY {
                        break;
                    }
                    parts.push(node.name.as_str());
                    match entry_map.get(&node.parent_entry) {
                        Some(&pi) if pi != current => current = pi,
                        _ => break,
                    }
                }
                parts.reverse();
                *path = if parts.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", parts.join("/"))
                };
            }
        }

        Self {
            nodes,
            children,
            entry_map,
            root_idx,
            paths,
            total_mft_entries: allocated as u64,
            allocated_entries: allocated,
        }
    }
}

// ---------------------------------------------------------------------------
// MFT parsing
// ---------------------------------------------------------------------------

impl FileTree {
    /// Parse an `$MFT` file on disk and build the tree.
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_mft(path: &Path) -> Result<Self> {
        let buffer =
            std::fs::read(path).with_context(|| format!("Failed to read: {}", path.display()))?;

        let mut parser =
            MftParser::from_buffer(buffer).context("Failed to initialise MFT parser")?;

        let total = parser.get_entry_count();
        let capacity = (total as usize) / 2;
        let mut nodes = Vec::with_capacity(capacity);

        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "  Parsing MFT [{bar:40.cyan/dim}] {pos}/{len} entries ({percent}%)",
            )
            .expect("valid template")
            .progress_chars("##-"),
        );

        for i in 0..total {
            pb.set_position(i);

            let Ok(entry) = parser.get_entry(i) else {
                continue;
            };

            if !entry.is_allocated() {
                continue;
            }

            let Some(fname) = entry.find_best_name_attribute() else {
                continue;
            };

            let is_dir = entry.is_dir();
            let entry_id = entry.header.record_number;
            let parent_entry = fname.parent.entry;

            let (modified, accessed, created, mft_modified) = entry
                .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
                .filter_map(std::result::Result::ok)
                .find_map(|attr| {
                    if let MftAttributeContent::AttrX10(si) = attr.data {
                        Some((si.modified, si.accessed, si.created, si.mft_modified))
                    } else {
                        None
                    }
                })
                .unwrap_or((
                    fname.modified,
                    fname.accessed,
                    fname.created,
                    fname.mft_modified,
                ));

            let size = if is_dir { 0 } else { fname.logical_size };

            nodes.push(FileNode {
                name: fname.name.clone(),
                mft_entry: entry_id,
                parent_entry,
                is_dir,
                size,
                modified,
                accessed,
                created,
                mft_modified,
                usn_change_count: 0,
            });
        }

        pb.finish_and_clear();
        let allocated = nodes.len();
        eprintln!("  Parsed {allocated} allocated entries from {total} MFT records.");

        let pb2 = ProgressBar::new_spinner();
        pb2.set_style(
            ProgressStyle::with_template("  {spinner:.cyan} Building directory tree...")
                .expect("valid template"),
        );
        pb2.enable_steady_tick(std::time::Duration::from_millis(80));

        let mut tree = Self::from_nodes(nodes);
        tree.total_mft_entries = total;

        pb2.finish_and_clear();
        Ok(tree)
    }
}

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

impl FileTree {
    /// Index of the NTFS root directory, if present.
    pub fn root_idx(&self) -> Option<usize> {
        self.root_idx
    }

    /// Reference to a node by arena index.
    pub fn node(&self, idx: usize) -> &FileNode {
        &self.nodes[idx]
    }

    /// Look up an arena index by MFT entry number.
    pub fn entry_to_idx(&self, mft_entry: u64) -> Option<&usize> {
        self.entry_map.get(&mft_entry)
    }

    /// Pre-sorted child indices for the given node.
    pub fn children(&self, idx: usize) -> &[usize] {
        &self.children[idx]
    }

    /// Pre-computed full path for a node (O(1) lookup).
    pub fn cached_path(&self, idx: usize) -> &str {
        &self.paths[idx]
    }

    /// Search all nodes whose full path contains `query` (case-insensitive).
    ///
    /// Uses the pre-computed path index for O(N) scanning instead of
    /// O(N×depth) tree walks.
    pub fn search(&self, query: &str) -> Vec<usize> {
        let query_lower = query.to_lowercase();
        (0..self.nodes.len())
            .filter(|&idx| {
                if self.nodes[idx].mft_entry == ROOT_MFT_ENTRY {
                    return false;
                }
                self.paths[idx].to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    /// (directories, files, `total_file_bytes`) for a directory's immediate children.
    pub fn dir_stats(&self, idx: usize) -> (usize, usize, u64) {
        let children = &self.children[idx];
        let dirs = children.iter().filter(|&&c| self.nodes[c].is_dir).count();
        let files = children.len() - dirs;
        let total_size: u64 = children
            .iter()
            .filter(|&&c| !self.nodes[c].is_dir)
            .map(|&c| self.nodes[c].size)
            .sum();
        (dirs, files, total_size)
    }

    /// Enrich nodes with USN journal change counts.
    ///
    /// Each tuple is `(mft_entry_number, filename)`. The filename is
    /// informational — matching is done solely by MFT entry number.
    pub fn enrich_usn(&mut self, records: &[(u64, String)]) {
        for &(mft_entry, _) in records {
            if let Some(&idx) = self.entry_map.get(&mft_entry) {
                self.nodes[idx].usn_change_count += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// Helper: build a timestamp for tests.
    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    /// Helper: create a directory FileNode.
    fn dir_node(name: &str, mft_entry: u64, parent_entry: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry,
            parent_entry,
            is_dir: true,
            size: 0,
            modified: ts(2024, 1, 1),
            accessed: ts(2024, 1, 1),
            created: ts(2024, 1, 1),
            mft_modified: ts(2024, 1, 1),
            usn_change_count: 0,
        }
    }

    /// Helper: create a file FileNode.
    fn file_node(name: &str, mft_entry: u64, parent_entry: u64, size: u64) -> FileNode {
        FileNode {
            name: name.to_string(),
            mft_entry,
            parent_entry,
            is_dir: false,
            size,
            modified: ts(2024, 6, 15),
            accessed: ts(2024, 6, 15),
            created: ts(2024, 1, 1),
            mft_modified: ts(2024, 6, 15),
            usn_change_count: 0,
        }
    }

    /// Helper: build a sample tree for tests.
    ///
    /// Structure:
    /// ```text
    /// / (root, MFT#5)
    /// ├── Windows/ (MFT#30)
    /// │   ├── System32/ (MFT#31)
    /// │   │   ├── cmd.exe (MFT#100, 289K)
    /// │   │   └── notepad.exe (MFT#101, 201K)
    /// │   └── explorer.exe (MFT#102, 4.7M)
    /// ├── Users/ (MFT#40)
    /// │   └── admin/ (MFT#41)
    /// │       └── Desktop/ (MFT#42)
    /// │           └── report.docx (MFT#200, 52K)
    /// └── pagefile.sys (MFT#10, 2G)
    /// ```
    fn sample_nodes() -> Vec<FileNode> {
        vec![
            dir_node(".", 5, 5), // root (self-referencing)
            dir_node("Windows", 30, 5),
            dir_node("System32", 31, 30),
            file_node("cmd.exe", 100, 31, 289_000),
            file_node("notepad.exe", 101, 31, 201_000),
            file_node("explorer.exe", 102, 30, 4_700_000),
            dir_node("Users", 40, 5),
            dir_node("admin", 41, 40),
            dir_node("Desktop", 42, 41),
            file_node("report.docx", 200, 42, 52_000),
            file_node("pagefile.sys", 10, 5, 2_000_000_000),
        ]
    }

    // -- Construction tests --------------------------------------------------

    #[test]
    fn from_nodes_builds_tree_with_correct_entry_count() {
        let nodes = sample_nodes();
        let tree = FileTree::from_nodes(nodes);
        assert_eq!(tree.allocated_entries, 11);
    }

    #[test]
    fn from_nodes_finds_root_at_entry_5() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().expect("should have root");
        assert_eq!(tree.node(root).mft_entry, ROOT_MFT_ENTRY);
    }

    #[test]
    fn empty_nodes_produces_no_root() {
        let tree = FileTree::from_nodes(vec![]);
        assert!(tree.root_idx().is_none());
    }

    // -- Children tests ------------------------------------------------------

    #[test]
    fn root_has_three_children() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        // Windows/, Users/, pagefile.sys
        assert_eq!(tree.children(root).len(), 3);
    }

    #[test]
    fn children_sorted_dirs_before_files() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        let kids = tree.children(root);

        // First two should be dirs (Users, Windows alphabetically), last is file
        assert!(tree.node(kids[0]).is_dir, "first child should be a dir");
        assert!(tree.node(kids[1]).is_dir, "second child should be a dir");
        assert!(
            !tree.node(kids[kids.len() - 1]).is_dir,
            "last child should be a file"
        );
    }

    #[test]
    fn children_dirs_sorted_case_insensitive() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        let kids = tree.children(root);

        let dir_names: Vec<&str> = kids
            .iter()
            .filter(|&&i| tree.node(i).is_dir)
            .map(|&i| tree.node(i).name.as_str())
            .collect();
        // Users before Windows (alphabetical)
        assert_eq!(dir_names, vec!["Users", "Windows"]);
    }

    #[test]
    fn system32_has_two_files() {
        let tree = FileTree::from_nodes(sample_nodes());
        let sys32 = tree.entry_to_idx(31).expect("System32 should exist");
        assert_eq!(tree.children(*sys32).len(), 2);
    }

    // -- cached_path tests ---------------------------------------------------

    #[test]
    fn cached_path_of_root_is_slash() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        assert_eq!(tree.cached_path(root), "/");
    }

    #[test]
    fn cached_path_of_direct_child() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(30).unwrap();
        assert_eq!(tree.cached_path(idx), "/Windows");
    }

    #[test]
    fn cached_path_of_deeply_nested_file() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(200).unwrap();
        assert_eq!(tree.cached_path(idx), "/Users/admin/Desktop/report.docx");
    }

    #[test]
    fn cached_path_of_system32_exe() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(100).unwrap();
        assert_eq!(tree.cached_path(idx), "/Windows/System32/cmd.exe");
    }

    // -- search tests --------------------------------------------------------

    #[test]
    fn search_finds_file_by_name() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("cmd.exe");
        assert_eq!(results.len(), 1);
        assert_eq!(tree.node(results[0]).name, "cmd.exe");
    }

    #[test]
    fn search_matches_directory_path() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("System32");
        // Should match System32 dir, plus cmd.exe and notepad.exe (path contains System32)
        assert!(results.len() >= 3);
    }

    #[test]
    fn search_is_case_insensitive() {
        let tree = FileTree::from_nodes(sample_nodes());
        let lower = tree.search("windows");
        let upper = tree.search("WINDOWS");
        assert_eq!(lower.len(), upper.len());
        assert!(!lower.is_empty());
    }

    #[test]
    fn search_anywhere_in_path() {
        let tree = FileTree::from_nodes(sample_nodes());
        // "admin/Desktop" spans two path components
        let results = tree.search("admin/Desktop");
        assert!(!results.is_empty());
        // Should find Desktop dir and report.docx
        assert!(results.len() >= 2);
    }

    #[test]
    fn search_with_no_match_returns_empty() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("nonexistent_file.txt");
        assert!(results.is_empty());
    }

    #[test]
    fn search_excludes_root_node() {
        let tree = FileTree::from_nodes(sample_nodes());
        let results = tree.search("/");
        // Every path starts with /, so we'd get all non-root nodes, but NOT root itself
        for &idx in &results {
            assert_ne!(tree.node(idx).mft_entry, ROOT_MFT_ENTRY);
        }
    }

    // -- dir_stats tests -----------------------------------------------------

    #[test]
    fn dir_stats_for_root() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        let (dirs, files, size) = tree.dir_stats(root);
        assert_eq!(dirs, 2); // Windows, Users
        assert_eq!(files, 1); // pagefile.sys
        assert_eq!(size, 2_000_000_000);
    }

    #[test]
    fn dir_stats_for_system32() {
        let tree = FileTree::from_nodes(sample_nodes());
        let sys32 = *tree.entry_to_idx(31).unwrap();
        let (dirs, files, size) = tree.dir_stats(sys32);
        assert_eq!(dirs, 0);
        assert_eq!(files, 2); // cmd.exe, notepad.exe
        assert_eq!(size, 289_000 + 201_000);
    }

    #[test]
    fn dir_stats_for_empty_dir() {
        // admin/Desktop has one file, but let's test a dir with only that
        let tree = FileTree::from_nodes(sample_nodes());
        let desktop = *tree.entry_to_idx(42).unwrap();
        let (dirs, files, size) = tree.dir_stats(desktop);
        assert_eq!(dirs, 0);
        assert_eq!(files, 1);
        assert_eq!(size, 52_000);
    }

    // -- entry_to_idx tests --------------------------------------------------

    #[test]
    fn entry_to_idx_known_entry() {
        let tree = FileTree::from_nodes(sample_nodes());
        assert!(tree.entry_to_idx(30).is_some());
    }

    #[test]
    fn entry_to_idx_unknown_entry() {
        let tree = FileTree::from_nodes(sample_nodes());
        assert!(tree.entry_to_idx(99999).is_none());
    }

    // -- from_mft tests (integration with mft crate) -------------------------

    #[test]
    fn from_mft_rejects_nonexistent_file() {
        let result = FileTree::from_mft(Path::new("/nonexistent/$MFT"));
        assert!(result.is_err());
    }

    #[test]
    fn from_mft_rejects_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let result = FileTree::from_mft(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn from_mft_rejects_garbage_data() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"this is not an MFT file at all").unwrap();
        let result = FileTree::from_mft(tmp.path());
        assert!(result.is_err());
    }

    // -- USN journal enrichment tests ----------------------------------------

    #[test]
    fn enrich_usn_increments_change_count() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        // Simulate USN records referencing MFT entry 100 (cmd.exe)
        let usn_records = vec![
            (100_u64, "cmd.exe".to_string()),
            (100, "cmd.exe".to_string()),
            (100, "cmd.exe".to_string()),
        ];
        tree.enrich_usn(&usn_records);
        let idx = *tree.entry_to_idx(100).unwrap();
        assert_eq!(tree.node(idx).usn_change_count, 3);
    }

    #[test]
    fn enrich_usn_ignores_unknown_entries() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![(99999_u64, "phantom.txt".to_string())];
        tree.enrich_usn(&usn_records); // should not panic
    }

    #[test]
    fn enrich_usn_multiple_files() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![
            (100_u64, "cmd.exe".to_string()),
            (101, "notepad.exe".to_string()),
            (101, "notepad.exe".to_string()),
            (200, "report.docx".to_string()),
        ];
        tree.enrich_usn(&usn_records);

        assert_eq!(
            tree.node(*tree.entry_to_idx(100).unwrap()).usn_change_count,
            1
        );
        assert_eq!(
            tree.node(*tree.entry_to_idx(101).unwrap()).usn_change_count,
            2
        );
        assert_eq!(
            tree.node(*tree.entry_to_idx(200).unwrap()).usn_change_count,
            1
        );
    }

    #[test]
    fn enrich_usn_leaves_unenriched_at_zero() {
        let mut tree = FileTree::from_nodes(sample_nodes());
        let usn_records = vec![(100_u64, "cmd.exe".to_string())];
        tree.enrich_usn(&usn_records);
        // notepad.exe should still be 0
        let idx = *tree.entry_to_idx(101).unwrap();
        assert_eq!(tree.node(idx).usn_change_count, 0);
    }

    // -- Cached path index tests ---------------------------------------------

    #[test]
    fn cached_path_all_start_with_slash() {
        let tree = FileTree::from_nodes(sample_nodes());
        for idx in 0..tree.allocated_entries {
            let path = tree.cached_path(idx);
            assert!(
                path.starts_with('/'),
                "path at index {idx} should start with /: {path}"
            );
        }
    }

    #[test]
    fn cached_path_root_is_slash() {
        let tree = FileTree::from_nodes(sample_nodes());
        let root = tree.root_idx().unwrap();
        assert_eq!(tree.cached_path(root), "/");
    }

    #[test]
    fn cached_path_deeply_nested() {
        let tree = FileTree::from_nodes(sample_nodes());
        let idx = *tree.entry_to_idx(200).unwrap();
        assert_eq!(tree.cached_path(idx), "/Users/admin/Desktop/report.docx");
    }

    #[test]
    fn cached_path_empty_tree() {
        let tree = FileTree::from_nodes(vec![]);
        assert_eq!(tree.allocated_entries, 0);
        // No paths to check — just ensure it doesn't panic
    }

    #[test]
    fn search_uses_cached_paths_same_results() {
        let tree = FileTree::from_nodes(sample_nodes());
        // search should return the same results as before (now backed by cache)
        let results = tree.search("System32");
        assert!(results.len() >= 3); // dir + 2 files
        for &idx in &results {
            assert!(
                tree.cached_path(idx).to_lowercase().contains("system32"),
                "result path should contain 'system32'"
            );
        }
    }
}
