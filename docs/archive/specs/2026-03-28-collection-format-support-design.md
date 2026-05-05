# Collection Format Support: UAC & Velociraptor

## Overview

Add support for opening forensic collection archives (UAC `.tar.gz` and Velociraptor `.zip`), discovering artifacts inside them, and routing them to existing parsers. The design introduces a two-stage pipeline: `rt-unpack` opens the archive envelope and extracts to a temp directory, then `rt-fswalker` (renamed from `rt-pipeline`) walks the extracted tree using existing artifact discovery and parser dispatch.

## Goals

- **Format-agnostic unpacking** — a `CollectionProvider` trait with confidence-based probing so archive formats are detected by internal structure, never by file extension
- **UAC full parsing** — parse every UAC category (bodyfile, live_response, system, etc.) into typed structs with timeline event emission where timestamps exist
- **Velociraptor artifact routing** — URL-decode Velociraptor's encoded paths, extract to normalized layout, route to existing Windows artifact parsers ($MFT, $UsnJrnl, evtx, registry, LNK)
- **Clean pipeline integration** — `rt-unpack` sits before `rt-fswalker`; the existing filesystem walk + parser dispatch works unchanged on extracted directories
- **Dual output model** — typed structs per artifact category for structured analysis, plus `TimelineEvent` emission for unified timeline

## Non-Goals

- Streaming extraction (read artifacts directly from archive without extracting to disk) — future optimization
- Parsing Velociraptor result sets / VQL output JSON — only raw artifact files under `uploads/`
- Relativity, iTunes backup, or other zip-based formats — future `CollectionProvider` implementations
- GUI integration — this is CLI/library only; desktop integration is a separate spec

---

## Architecture

### Pipeline Flow

```
Collection file (.tar.gz, .zip, .dar, etc.)
    -> rt-unpack: probe registered providers, extract to temp dir
        -> rt-fswalker: walk temp dir, detect artifacts, dispatch parsers
            -> existing parsers ($MFT, evtx, USN, registry, etc.)
            -> UAC-specific sub-parsers (bodyfile, netstat, ps, etc.)
```

### Crate Structure

```
rt-unpack (NEW) — collection envelope opener
├── src/
│   ├── lib.rs              — CollectionProvider trait, Confidence, CollectionManifest
│   ├── registry.rs         — inventory-based provider registration + probe orchestration
│   └── tempdir.rs          — managed temp directory creation + cleanup

rt-parser-velociraptor (NEW) — Velociraptor zip handler
├── src/
│   ├── lib.rs              — VelociraptorProvider impl + inventory registration
│   ├── probe.rs            — zip inspection: uploads/ dir + URL-encoded paths
│   ├── extract.rs          — extraction with path normalization
│   └── path_decoder.rs     — URL-decode + Windows path -> ArtifactType mapping

rt-parser-uac (NEW) — UAC tar.gz handler
├── src/
│   ├── lib.rs              — UacProvider impl + inventory registration
│   ├── probe.rs            — tar.gz inspection: uac.log + known directory structure
│   ├── extract.rs          — extraction preserving UAC directory layout
│   └── parsers/
│       ├── mod.rs           — category dispatcher
│       ├── bodyfile.rs      — mactime bodyfile format parser
│       ├── network.rs       — netstat, ss, arp, iptables, routing output
│       ├── process.rs       — ps, lsof, crontab, proc maps
│       ├── packages.rs      — dpkg, rpm, pip, snap listings
│       ├── system.rs        — last, loginctl, uptime, uname, env, users
│       ├── hardware.rs      — dmesg, lspci, lsusb, dmidecode
│       ├── storage.rs       — df, mount, lsblk, fstab
│       ├── hash_execs.rs    — executable hash listings (MD5/SHA1/SHA256)
│       ├── chkrootkit.rs    — rootkit scan result parser
│       └── configs.rs       — /etc configs, passwd, shadow, systemd units

rt-fswalker (RENAMED from rt-pipeline) — filesystem walker + artifact dispatch
├── src/
│   └── orchestrator.rs     — add run_collection_pipeline() entry point

rt-core (MODIFIED) — add Linux/UAC artifact types
├── src/
│   └── artifacts/types.rs  — add Bodyfile, NetworkState, ProcessList, etc.
```

---

## Section 1: Collection Detection & Opening (`rt-unpack`)

### CollectionProvider Trait

```rust
pub trait CollectionProvider: Send + Sync {
    fn name(&self) -> &str;
    fn probe(&self, path: &Path) -> Result<Confidence>;
    fn open(&self, path: &Path, dest: &Path) -> Result<CollectionManifest>;
}

pub enum Confidence {
    None,
    Low,      // structure looks plausible
    Medium,   // key markers found (e.g., uploads/ dir)
    High,     // definitive signature (e.g., uac.log present)
}

pub struct CollectionManifest {
    pub format_name: String,
    pub extracted_root: PathBuf,
    pub artifacts: Vec<ManifestEntry>,
    pub metadata: CollectionMetadata,
}

pub struct ManifestEntry {
    pub path: PathBuf,                     // relative to extracted_root
    pub artifact_type: Option<ArtifactType>, // pre-classified by provider, None = let fswalker detect
}

pub struct CollectionMetadata {
    pub hostname: Option<String>,
    pub collection_time: Option<DateTime<Utc>>,
    pub os_type: Option<OsType>,
    pub tool_version: Option<String>,
}

pub enum OsType { Windows, Linux, MacOS, Unknown }
```

### Detection Flow

1. Caller passes archive path to `rt-unpack::open_collection(path)`
2. All registered `CollectionProvider`s are probed via `inventory` iteration
3. Each provider inspects internal archive structure (not file extension) and returns a `Confidence`
4. Highest-confidence provider is selected. If all return `None`, return error listing probed formats.
5. Selected provider extracts to a managed temp directory and returns `CollectionManifest`

### Provider Registration

Uses the `inventory` crate for compile-time registration, matching the existing `ForensicParser` pattern:

```rust
inventory::collect!(Box<dyn CollectionProvider>);

pub fn open_collection(path: &Path) -> Result<CollectionManifest> {
    let tempdir = create_managed_tempdir()?;
    let mut best: Option<(&dyn CollectionProvider, Confidence)> = None;

    for provider in inventory::iter::<Box<dyn CollectionProvider>> {
        let confidence = provider.probe(path)?;
        // keep highest confidence
    }

    match best {
        Some((provider, _)) => provider.open(path, tempdir.path()),
        None => Err(Error::UnrecognizedFormat { path, probed: list_providers() }),
    }
}
```

---

## Section 2: Velociraptor Collection Provider (`rt-parser-velociraptor`)

### Detection (probe)

Inspects the zip file without full extraction:
1. Open as zip archive, enumerate top-level entries
2. Look for `uploads/` directory prefix
3. Check for URL-encoded path separators (`%5C` for `\`) in entry names
4. If both present: `Confidence::High`. If only `uploads/`: `Confidence::Medium`.

### Velociraptor Archive Structure

Velociraptor stores collected files under two prefixes:

- **`uploads/ntfs/`** — raw NTFS artifacts with URL-encoded Windows paths:
  - `\\.\C:%5C$MFT` -> `$MFT`
  - `\\.\C:%5C$Extend%5C$UsnJrnl%3A$J` -> `$UsnJrnl:$J`
  - `\\.\C:%5C$LogFile` -> `$LogFile`
  - `\\.\C:%5C$Secure%3A$SDS` -> `$Secure:$SDS`
  - `\\.\C:%5C$Boot` -> `$Boot`

- **`uploads/auto/`** — auto-collected files with URL-encoded paths:
  - `.evtx` files (Windows Event Logs)
  - `.lnk` files (shortcuts)
  - Registry hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat)
  - WER reports, Defender logs, etc.

### Path Decoding

Port URL-decode logic from `~/src/tl`'s Velociraptor handler:
1. URL-decode all `%XX` sequences
2. Strip drive prefix (`\\.\C:\` -> root)
3. Convert Windows backslashes to platform path separators
4. Map known paths to `ArtifactType` (e.g., `$MFT` -> `ArtifactType::Mft`)

### Extraction

Extract to temp directory with normalized paths. The manifest maps each extracted file to its detected `ArtifactType`, so the fswalker can skip re-detection for known artifacts.

---

## Section 3: UAC Collection Provider (`rt-parser-uac`)

### Detection (probe)

Inspects the tar.gz file:
1. Open as gzip-compressed tar
2. Scan first ~100 entries for `uac.log` at archive root level
3. Check for known UAC directories: `bodyfile/`, `live_response/`, `system/`
4. If `uac.log` found: `Confidence::High`. If UAC directories but no log: `Confidence::Medium`.

### UAC Archive Structure

UAC produces a structured collection with these categories:

| Category | Path Pattern | Contents |
|----------|-------------|----------|
| Bodyfile | `bodyfile/bodyfile.txt` | Mactime bodyfile (full filesystem timeline) |
| Chkrootkit | `chkrootkit/chkrootkit.log` | Rootkit scan results |
| Hash executables | `hash_executables/*.txt` | MD5/SHA1/SHA256 of executables |
| Hardware | `live_response/hardware/` | dmesg, lspci, lsusb, dmidecode |
| Network | `live_response/network/` | arp, netstat, ss, iptables, routing tables |
| Packages | `live_response/packages/` | dpkg, rpm, pip, snap package listings |
| Process | `live_response/process/` | ps, lsof, proc maps, crontab |
| Storage | `live_response/storage/` | df, mount, lsblk, fstab |
| System | `live_response/system/` | hostname, uptime, uname, env, users, last, loginctl |
| Memory dump | `memory_dump/` | Process memory dumps (metadata only) |
| System configs | `system/` | /etc configs, passwd, shadow, crontabs, systemd units |

### Category Sub-Parsers

Each UAC category gets a focused sub-parser module. Each sub-parser:
- Takes a directory path (the extracted category directory)
- Produces typed structs specific to that category
- Emits `TimelineEvent`s where timestamps exist naturally

**Typed output structs (examples):**

```rust
// bodyfile.rs
pub struct BodyfileEntry {
    pub md5: String,
    pub path: String,
    pub inode: u64,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Option<DateTime<Utc>>,
    pub mtime: Option<DateTime<Utc>>,
    pub ctime: Option<DateTime<Utc>>,
    pub crtime: Option<DateTime<Utc>>,
}

// network.rs
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub pid: Option<u32>,
    pub program: Option<String>,
}

// process.rs
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub user: String,
    pub command: String,
    pub cpu_pct: f32,
    pub mem_pct: f32,
    pub start_time: Option<String>,
}

pub struct CrontabEntry {
    pub schedule: String,
    pub command: String,
    pub user: String,
}

// packages.rs
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub manager: PackageManager,  // Dpkg, Rpm, Pip, Snap
    pub install_date: Option<String>,
}

// system.rs — `last` command output produces timeline events
pub struct LoginRecord {
    pub user: String,
    pub terminal: String,
    pub source: String,
    pub login_time: Option<DateTime<Utc>>,
    pub logout_time: Option<DateTime<Utc>>,
    pub duration: Option<String>,
}
```

**Timeline event emission:** Sub-parsers that encounter timestamps emit `TimelineEvent`s through the standard `EventEmitter` trait. For example:
- `bodyfile.rs` emits events for each file's atime/mtime/ctime/crtime
- `system.rs` emits events for login/logout records from `last`
- `process.rs` emits events for crontab entries with scheduled times

### Extraction

Extract tar.gz to temp directory preserving the UAC directory structure. The manifest maps each category directory to its sub-parser.

### Metadata Extraction

Parse `uac.log` for collection metadata:
- Hostname (from log header or `live_response/system/hostname.txt`)
- Collection timestamp (from log timestamps)
- OS type (Linux/macOS from uname output)
- UAC version

---

## Section 4: Integration with rt-fswalker

### Rename: rt-pipeline -> rt-fswalker

Rename the existing `rt-pipeline` crate to `rt-fswalker`. This reflects its core responsibility: walking a filesystem tree while detecting and dispatching artifacts along the way. Update all workspace references.

### New Entry Point

Add `run_collection_pipeline()` to `rt-fswalker/src/orchestrator.rs`:

```rust
pub fn run_collection_pipeline(
    collection_path: &Path,
    progress: &dyn ProgressReporter,
) -> Result<PipelineResult> {
    // 1. rt-unpack probes all registered CollectionProviders
    let manifest = rt_unpack::open_collection(collection_path)?;

    // 2. Walk extracted directory using existing pipeline
    let result = run_pipeline(&manifest.extracted_root, progress)?;

    // 3. Attach collection metadata to result
    Ok(result.with_metadata(manifest.metadata))
}
```

### Transparent CLI Integration

The existing CLI detects whether the input path is an archive file or a directory:
- **Directory** -> call `run_pipeline(path)` (existing behavior)
- **File** -> call `run_collection_pipeline(path)` (new path through `rt-unpack`)

No new subcommand needed. The distinction is transparent to the user.

### ArtifactType Extensions

Add new variants to `rt-core::ArtifactType` for Linux/UAC artifacts:

```rust
pub enum ArtifactType {
    // Existing Windows types
    UsnJournal, Mft, EventLog, Prefetch, Registry, Shellbags,
    Lnk, Amcache, Bam, BrowserHistory, JumpLists, Srum, Assessment,

    // New Linux/UAC types
    Bodyfile,
    NetworkState,
    ProcessList,
    PackageList,
    SystemInfo,
    LoginHistory,
    CrontabConfig,
    HashManifest,
    RootkitScan,
    SystemConfig,
}
```

---

## Section 5: Reusable Code

### From ~/src/tl

- **Velociraptor zip handling** — `CollectionProvider` trait pattern, URL-decode logic, path normalization. Port the path decoding and zip entry enumeration into `rt-parser-velociraptor`.

### From ~/src/usnjrnl-forensic

- Not directly needed for this spec (USN parsing is already in `rt-parser-usnjrnl`), but the analysis modules (timestomping detection, SDelete patterns) inform how UAC sub-parsers should structure their output for downstream analysis.

---

## Testing Strategy

### rt-unpack

- Unit tests for `Confidence` ordering and provider selection logic
- Integration test with a small synthetic tar.gz and zip to verify probe + extract
- Test that unrecognized formats return clear error

### rt-parser-velociraptor

- Integration test against `tests/data/Collection-A380_localdomain-2025-08-10T03_41_20Z.zip`
- Unit tests for URL path decoding (known Velociraptor path patterns)
- Verify correct ArtifactType mapping for $MFT, $UsnJrnl, evtx, registry, LNK

### rt-parser-uac

- Integration test against `tests/data/uac-vbox-linux-20260324193807.tar.gz`
- Unit tests for each category sub-parser with sample output snippets
- Verify timeline event emission from bodyfile, last, crontab parsers

### rt-fswalker

- Integration test: collection file -> full pipeline -> timeline events
- Verify transparent file-vs-directory detection
- Verify collection metadata attached to output

---

## Dependencies

- `zip` crate — for Velociraptor zip reading
- `flate2` + `tar` — for UAC tar.gz reading
- `percent-encoding` — for URL-decode of Velociraptor paths
- `tempfile` — for managed temp directories
- `inventory` — for compile-time provider registration (already in workspace)
- `chrono` — for timestamp parsing (already in workspace)
