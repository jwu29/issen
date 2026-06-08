# State-History Layer: Forensic Temporal Architecture

**Status**: DESIGN  
**Authors**: Research: Claude Opus 4.6 ultrathink; Critical review: Claude Opus 4.7 ultrathink  
**Context**: Motivated by `~/src/chat4n6`, specifically `WalMode::Both` — the simplest coded instance  
of what generalises to this entire layer.

---

## Why This Exists

Forensic artifacts are not point-in-time facts. A single logical artifact — `msgstore.db` — exists
simultaneously in dozens of distinct temporal states: live file, WAL overlay, APFS snapshot from
last week, encrypted iTunes backup from 2024, seven daily `.crypt15` backups on-device, Time Machine
history on a Mac, Google Drive version history. The current Issen layer hierarchy treats each of these
as a separate input to be parsed individually; no layer reasons about them as a **temporal cohort of
the same artifact**.

`chat4n6` has already encoded the core insight:

```rust
// crates/chat4n6-sqlite-forensics/src/wal.rs
WalMode::Both   // pre-replay state AND post-replay state, surfaced side-by-side
```

`WalMode::Both` is the state-history layer in microcosm: two states of the same artifact,
presented together, with deltas attributed by provenance. This plan generalises that from
`(main_db, wal)` to `(snapshot_1 … snapshot_N)` across every temporal source a forensic
system encounters.

---

## Naming

**NOT "TEMPORAL"** — `forensicnomicon::temporal` already exists and means *cross-artifact
temporal correlation hints* (compile-time fact relationships). Shadowing it would cause
import confusion across the entire workspace.

Correct name: **`state-history`**  
Layer sigil: **`[H]`**  
Core crate: **`state-history-forensic`** (new repo, sibling of `forensicnomicon`)

---

## What [H] Is (and Is Not)

The existing five navigation primitives each navigate **to content within one address space**:

| Primitive | Key | Result |
|---|---|---|
| `[P]` Disk | `name → inode → block address` | file bytes, one filesystem |
| `[M]` Memory | `PID → EPROCESS → VA → PA` | page bytes, one dump |
| `[L]` Log | `timestamp → record → field` | one event, one stream |
| `[Q]` Live | `(endpoint, query, cursor) → rows` | live result set |
| `[C]` Content | `hash → blob → graph` | one blob, hash-identified |

`[H]` does **not** navigate to content. It produces a **set of address spaces** for the
existing primitives to navigate within:

```
[H]: (artifact_ref, time_range) → Stream<(epoch_tag, provenance, address_space_handle)>
                                                                 │
                                                          same kind as base primitive:
                                                          VssShadow → [P] handle
                                                          WalEpoch  → PARSER handle
                                                          GitCommit → [C] handle
```

`[H]` is a **functor** that lifts each base primitive to a time-indexed variant:

- `[P^H]` — time-indexed disk (VSS, APFS snapshots, Time Machine, btrfs)
- `[M^H]` — time-indexed memory (hiberfil chain, VMware memory snapshots)
- `[L^H]` — time-indexed log (rotated logs, journald sealed epochs)
- `[Q^H]` — time-indexed live query (point-in-time osquery exports)
- **`[C^H] ≅ [C]`** — Git already is time-indexed; `[H]` applied to `[C]` is the identity functor

**This is the most important invariant**: content-addressed storage is the only base primitive
that natively encodes its own history. Every other primitive requires an external `[H]`
mechanism.

---

## Layer Placement (Corrected)

The obvious placement "between CONTAINER and FILESYSTEM" is wrong. Consider:
- VSS shadow copies ARE NTFS volumes — you still need `ntfs-forensic` to navigate one
- SQLite WAL files are reached through the SQLite parser — `[H]` depends on PARSER here
- iTunes backups are files inside a FILESYSTEM — `[H]` sits above, not below, FILESYSTEM
- Git history is blobs in a FILESYSTEM directory — `[H]` depends on `[C]`

`[H]` is a **cross-cutting operator, not a vertical tier**. Each `*-history` crate depends on
**the specific layer it observes**:

```
                        ORCHESTRATION (Issen)
                               │
              consumes TemporalCohort<'_>
              feeds TemporalEventGraph (in issen-correlation)
                               │
    ┌──────────┬───────────────┼───────────────┬──────────────┐
    │          │               │               │              │
 vss-      apfs-snap-       wal-            git-           logrotate-
 history   history          history         history        history
    │          │               │               │              │
 [P^H]      [P^H]           [PARSER^H]      [C^H]          [L^H]
    │          │               │               │              │
    ▼          ▼               ▼               ▼              ▼
 ntfs-      apfs-          sqlite-          git-           journald
 forensic   forensic       forensic         forensic       crates
    │          │               │               │              │
    ▼          ▼               ▼               ▼              ▼
  ewf         ewf           (bytes/path)    fs path        fs path
                                                               │
                                                               ▼
                                                     KNOWLEDGE (forensicnomicon)
                                                     + state-history-forensic (traits)
```

**Dependency rule**: `[H]` crates may depend on **any layer below ORCHESTRATION** as needed.
They export a uniform `TemporalCohort<'_>` interface that ORCHESTRATION consumes.

---

## Artifact Identity (Corrected)

`identity: String` (original proposal) collapses four orthogonal identity facets. Identity
disagreement between facets is itself forensic evidence.

```rust
pub struct ArtifactRef {
    pub claims: Vec<IdentityClaim>,
}

pub enum IdentityClaim {
    CanonicalPath     { volume: VolumeId, path: PathBuf },
    InodeIdentity     { volume: VolumeId, inode: u64, generation: Option<u32> },
    NtfsFileRef       { volume: VolumeId, mft_record: u64, sequence: u16 },
    ApfsFileId        { volume_uuid: Uuid, file_id: u64 },
    ContentHash       { algo: HashAlgo, digest: Vec<u8> },
    RecordIdentity    { schema: SchemaRef, primary_key: Vec<u8> },
    ApplicationGuid   { app: AppId, guid: Uuid },
    SigningSubject     { issuer: String, subject: String },
}

pub enum IdentityDiscipline {
    PathStable,     // same canonical path across snapshots
    ContentStable,  // same content hash (groups copies/duplicates)
    ObjectStable,   // same filesystem object (inode+generation, MFT record+sequence)
    RecordStable,   // same application-level record (rowid, message_id)
    LogicalStable,  // same logical artifact across reinstalls (rarely provable)
}
```

Callers select a discipline at query time. Discipline mismatch within a cohort is a finding:

| Scenario | Forensic reading |
|---|---|
| `PathStable` cohort whose `ContentStable` subcohorts split | File swapped at path while preserving name |
| `ObjectStable` cohort with inode reuse (sequence differs) | Classic timestomp/swap signal |
| `RecordStable` cohort restarting at rowid=1 | App reinstall; treat as separate logical artifact |
| `ContentStable` cohort crossing two volume paths | Clone / copy without GUID refresh |

---

## Clock Trust Model (Corrected)

Original's 4-level flat enum conflates four independent dimensions. Trust is multidimensional.

```rust
pub struct ClockProvenance {
    pub source:           ClockSource,
    pub trust_grade:      TrustGrade,
    pub tamper_resistance: TamperResistance,
    pub ordering_only:    bool,              // true = LSN/seqnum, no absolute time
    pub skew_known:       Option<Duration>,
    pub authenticated:    Option<AuthMechanism>,
}

pub enum TrustGrade {
    ExternallyAttested,   // RFC3161 TSA, Sigstore, server-side WhatsApp timestamp, TPM
    LocallyAttested,      // systemd-journald FSS, iOS APFS via Secure Enclave
    CustodialThirdParty,  // Google Drive version time, cloud object timestamp (no crypto)
    LocalSubsystem,       // VSS timestamp, journald wall-clock without FSS — same host
    LocalApplication,     // browser cookie expiry, file mtime set by writing program
    OrderingOnly,         // LSN, git parent links, USN seqnum — no absolute time
    Reconstructed,        // inferred by analyst from bracketing
    Unknown,
}

pub enum TamperResistance {
    AppendOnlyAttested,   // transparency log, TPM event log
    AppendOnlyLocal,      // journald FSS sealed (no external proof)
    SignedImmutable,      // RFC3161 token, signed iOS APFS snapshot
    AdminWritable,        // VSS, journald without FSS
    UserWritable,         // mtime, ctime via touch
    Trivial,              // embedded date string in file content
}
```

Key distinctions the original collapsed:

| Source | Grade | Resistance |
|---|---|---|
| VSS timestamp | `LocalSubsystem` | `AdminWritable` — same host as evidence |
| iOS APFS snapshot | `LocallyAttested` | `SignedImmutable` — Secure Enclave |
| macOS APFS snapshot | `LocalSubsystem` | `AdminWritable` — **different trust, same format** |
| WhatsApp filename | `LocalApplication` | `UserWritable` |
| WhatsApp inner row timestamp | `CustodialThirdParty` | `AppendOnlyLocal` (server-side) |
| ESE LSN | n/a | n/a — `ordering_only: true` |
| systemd-journald with FSS | `LocallyAttested` | `AppendOnlyLocal` |
| RFC3161 TSA token | `ExternallyAttested` | `SignedImmutable` |

---

## Epoch Model — N-State, Not 2-State

The WAL duality (pre vs post) is the 2-state degenerate case. The general model:

A SQLite WAL with `N` committed transactions has `(2 + N)`-states:
- **State 0**: main DB + WAL ignored
- **State k** for `k ∈ [1, N]`: main DB + WAL frames `[1..k]` applied (each commit boundary)
- **State N+1**: fully replayed (auto-checkpoint result)
- Plus **uncommitted tail**: frames beyond the last commit — in-flight transactions at acquisition

```rust
pub enum WalEpoch {
    PreReplay,
    Committed { transaction_seq: u32, end_frame: u32 },
    UncommittedTail { frames: Vec<u32> },
    FullyReplayed,
}
```

This generalises to every journaling source:

| Source | Epoch type | N-states |
|---|---|---|
| SQLite WAL | `SqliteWalFrame { frame_seq, commit_seq }` | `2 + N_committed` |
| ESE `.jrs` journal | `EseLsn(u64)` | one per log record |
| NTFS `$LogFile` | `NtfsLfs { record: u64 }` | one per LFS record |
| Windows Registry `.LOG1/.LOG2` | dirty page granularity | ~hundreds per dirty hive |
| systemd-journald (FSS) | `JournaldSeq(u64)` | one per sealed epoch |
| Git reflog | `GitCommitSha(String)` | reflog entry count |
| PostgreSQL WAL archive | WAL LSN | millions in production |

Sources have a **topology**:

```rust
pub enum CohortTopology {
    DiscreteSet,       // VSS shadow copies, Time Machine backups, APFS snapshots
    LinearJournal { lsn_type: LsnKind },   // WAL, $LogFile, journald, ESE
    SubJournalCommits, // WAL at per-transaction granularity
    Dag,               // git, btrfs subvolumes with send -p
}
```

---

## Materialization Safety (All States Are Not Immutable)

The original assumes all temporal states are immutable reads. This is wrong for ~half the sources.

```rust
pub enum MaterializationSafety {
    /// Reading does not modify any file.
    /// e.g. VSS block range, Time Machine backup dir, OCI lower layer
    ReadOnlySafe,

    /// Requires a careful reader — libsqlite3 would auto-checkpoint and destroy the state.
    /// e.g. SQLite WAL pre-replay, ESE journal interpretation without recovery
    ReadOnlyRequiresCareful,

    /// Materialisation MODIFIES the source on disk.
    /// e.g. `esentutl /r`, libsqlite3 default open, `fsck`
    /// RULE: always work on a verified write-blocked copy
    Destructive,

    /// State is ephemeral and cannot be re-materialised after this window.
    /// e.g. LVM snapshot on overflow, ring buffer overwritten
    /// RULE: acquire now or lose forever
    EphemeralOnce,

    /// Destroyed automatically by a background process.
    /// e.g. git gc, Time Machine deleting oldest backups, log rotation
    AutoPruned { trigger: PruneTrigger },
}
```

**Type-system enforcement**: the `StateMaterializer` trait takes `&Evidence` for
`ReadOnlySafe`/`ReadOnlyRequiresCareful` and `&mut WorkingCopy` for `Destructive`:

```rust
pub trait StateMaterializer {
    fn safety(&self) -> MaterializationSafety;
    fn materialize<'a>(&'a self, epoch: EpochTag, ev: &'a Evidence) -> Result<StateHandle<'a>>;
    fn materialize_via_working_copy(
        &self,
        epoch: EpochTag,
        wc: &mut WorkingCopy,
    ) -> Result<StateHandle<'_>>;
}
```

The Rust type system prevents calling the evidence-path method when the source requires a
working copy, without any runtime check.

---

## Complete Temporal Source Inventory

### Sources in research (26):
VSS, APFS snapshots, ZFS snapshots, LVM snapshots, Time Machine, Windows Backup/File History,
iTunes/Finder backups, Android `.ab`, WhatsApp `.crypt12/14/15`, cloud sync
(Dropbox/OneDrive/iCloud/GDrive), SQLite WAL, ESE `.jrs` journals, VHDX differencing chains,
VMware snapshots (.vmdk/.vmsn), Docker OCI layers, Git history, archives (ZIP/tar/7z/RAR),
log rotation, hiberfil.sys, iOS encrypted backup, Android `.ab`, Recycle Bin / Trash, NTFS
`$UsnJrnl`, MFT `$FILE_NAME` vs `$STANDARD_INFORMATION` dual timestamps, browser cache /
IndexedDB, email archives (PST/OST/mbox/emlx).

### Critical omissions from review (+25):

| Source | Platform | Why it matters |
|---|---|---|
| **NTFS `$LogFile`** | Windows | NTFS crash-recovery journal (redo/undo); dirty $LogFile = NTFS's SQLite WAL; **major omission** |
| **Windows Registry `.LOG1` / `.LOG2`** | Windows | Pre-flush hive state; equivalent to WAL for all registry hives; every live NTFS acquisition has dirty registry logs |
| **NTFS Transactional NTFS ($TxF)** | Vista/7/2008 era | Per-transaction filesystem state; deprecated but present in old images |
| **ReFS integrity streams + block-clone CoW** | Windows Server | Block-clone history per volume |
| **Windows Restore Points (pre-VSS)** | Windows XP era | Legacy system snapshots; still encountered in older investigations |
| **Windows Search `Windows.edb` tombstones** | Windows | Deleted-row tombstones survive re-index cycles |
| **Outlook dumpster / Recoverable Items** | Windows / Exchange | Soft-deleted MAPI items with restore metadata; distinct from PST rotation |
| **macOS APFS `.fseventsd` log** | macOS | Filesystem-event journal; independent of USN analog |
| **macOS Unified Log (tracev3) time travel** | macOS | `log show --start/--end`; internal timestamp index |
| **Linux auditd `.log.N` rotation + fanotify** | Linux | Temporally segmented audit trail |
| **systemd-journald FSS sealed archives** | Linux | Per-epoch Forward Secure Sealing keys; **temporal authenticity ground truth** |
| **btrfs subvolumes + `btrfs send` streams** | Linux | Same as ZFS snapshots; entirely missed |
| **eBPF ringbuf / perf-event historical buffers** | Linux | Bounded ring of recent kernel events |
| **Container layer delta: overlay2 upper/lower** | Linux | Runtime container state vs base image state |
| **Kubernetes etcd compaction history + audit** | Linux | Time-bounded cluster state |
| **S3 / GCS / Azure Blob versioning** | Cloud | Immutable server-side versions with cryptographic ETags; distinct from "cloud sync" |
| **iOS KnowledgeC.db / interactionC.db / Screen Time** | iOS | Application-level temporal stores with rolling retention |
| **Android WorkManager / JobScheduler records** | Android | Time-bounded execution history |
| **macOS Time Machine local snapshots** | macOS | `tmutil localsnapshot`; on root volume, distinct from external TM backup |
| **Browser session restore (Last Session / Last Tabs)** | Cross | N-deep session history independent of history DB |
| **TPM PCR event log** | Cross | Measured boot history, cryptographically chained; tamper-evident |
| **UEFI `dbx` (Secure Boot revocation) history** | Cross | Temporally ordered revocation list |
| **PostgreSQL WAL archives + MySQL binlogs** | Server | Server-side WAL shipping archives; PITR-capable |
| **NTFS Object IDs (`$ObjId`) reuse history** | Windows | Distributed link tracking journal |
| **Mobile carrier lawful intercept records** | Out-of-band | Out-of-band server-side time-indexed source |

---

## Cross-Artifact Temporal Event Graph

Per-artifact cohorts (`TemporalCohort`) cannot answer the most powerful forensic questions.
Cross-artifact reasoning requires a **temporal event graph** with constraint propagation.
This integrates with the **existing** `issen-correlation` subsystem
(`temporal_checks`, `temporal_rule`, `skew` modules already present).

```rust
// Lives in issen-correlation, fed by [H] crates via StateCohort
pub struct TimedFact {
    pub fact_id:      FactId,
    pub artifact_ref: ArtifactRef,
    pub epoch_tag:    EpochTag,
    pub observed_time: Option<DateTime<Utc>>,
    pub clock:        ClockProvenance,
    pub evidence_chain: Vec<SourceCitation>,
}

pub enum TemporalConstraint {
    HappensBefore    { a: FactId, b: FactId, max_skew: Duration },
    Coincident       { a: FactId, b: FactId, tolerance: Duration },
    Exclusive        { a: FactId, b: FactId, reason: &'static str },
    CausallyDependsOn { effect: FactId, cause: FactId },
    SameIdentity     { a: FactId, b: FactId, discipline: IdentityDiscipline },
}

pub struct TemporalEventGraph {
    facts: HashMap<FactId, TimedFact>,
    constraints: Vec<TemporalConstraint>,
    cohorts: HashMap<CohortKey, TemporalCohort>,
}

impl TemporalEventGraph {
    pub fn detect_inconsistencies(&self) -> Vec<Inconsistency>;
    pub fn topological_chronology(&self) -> Result<Vec<FactId>, CyclicEvidence>;
}
```

This answers the examples that per-artifact cohorts cannot:

| Scenario | Constraint | Violation type |
|---|---|---|
| File B references A, but B's mtime < A's mtime | `HappensBefore { A.create, B.create }` | Timestamp forgery |
| VSS at T=10:00 shows ntoskrnl X, live shows Y with mtime earlier than snapshot | `SameIdentity { live, vss_at_T, ContentStable }` = FALSE | Kernel swap between snapshot and acquisition |
| WhatsApp message at 14:31, device off 14:00–15:00 (MDM log) | `Exclusive { msg_received, device_off }` | Reconciled by noting inner timestamp is `CustodialThirdParty`; device never ack'd — finding stands |

---

## Forensic Acquisition Protocol

Each `[H]` crate ships an `AcquisitionProtocol` companion:

```rust
pub trait AcquisitionProtocol {
    fn preconditions(&self) -> Vec<Precondition>;
    fn forbidden_operations(&self) -> Vec<&'static str>;
    fn required_companion_artifacts(&self) -> Vec<PathPattern>;
    fn destructive_if_skipped(&self) -> Vec<&'static str>;
    fn verify_post_acquisition(&self, captured: &CapturedEvidence) -> Vec<IntegrityFinding>;
}
```

Critical acquisition requirements per source:

| Source | Wrong way | Right way |
|---|---|---|
| NTFS + VSS | `robocopy C:\` (loses all shadow copies) | Block-level image (dd/EWF); or extract per-shadow via `vss_extract.py` before imaging |
| SQLite WAL | `cp main.db` (libsqlite3 auto-checkpoints on reopen) | Copy `main.db` + `main.db-wal` + `main.db-shm` atomically while DB closed; use forensic WAL reader (chat4n6), not libsqlite3 |
| iTunes backup Manifest.db | Parse live (writes back WAL) | Copy entire backup tree first; parse the copy |
| Live ZFS pool | `zfs snapshot` on same pool | `zfs send` to external stream; OR `zpool import -o readonly=on` on separate host |
| Live ext4 + journal | `dd` while mounted (inconsistent) | `fsfreeze --freeze` then image; OR LVM snapshot then image snapshot |
| ESE (SRUDB.dat) | Run `esentutl /r` on evidence copy | Acquire both `.dat` and all `.jrs` / `.log` / `.chk` files; run recovery only on write-blocked copy |
| hiberfil.sys | Power on (hibernation file overwritten on resume) | Acquire before any boot |
| Cloud object versions | GET current version only | List all versions via API; GET each with version_id; preserve ETag |
| systemd-journald + FSS | Copy journal files only | Also acquire FSS verification key (`/var/log/journal/<id>/fss`) |
| Docker overlay2 running | `docker commit` (creates new layer) | `docker pause`; image host filesystem including `/var/lib/docker/overlay2/` |

---

## Core Rust Types

**New repo**: `state-history-forensic` — KNOWLEDGE tier, zero deps, exports only traits and types.

```rust
// state-history-forensic/src/lib.rs

pub mod identity {
    pub enum IdentityClaim { CanonicalPath, InodeIdentity, NtfsFileRef, ApfsFileId,
                             ContentHash, RecordIdentity, ApplicationGuid, SigningSubject }
    pub enum IdentityDiscipline { PathStable, ContentStable, ObjectStable,
                                  RecordStable, LogicalStable }
    pub struct ArtifactRef { pub claims: Vec<IdentityClaim> }
    impl ArtifactRef {
        pub fn matches(&self, other: &Self, discipline: IdentityDiscipline) -> bool;
        pub fn cohort_key(&self, d: IdentityDiscipline) -> CohortKey;
    }
}

pub mod clock {
    pub struct ClockProvenance {
        pub source: ClockSource, pub trust_grade: TrustGrade,
        pub tamper_resistance: TamperResistance,
        pub ordering_only: bool, pub skew_known: Option<Duration>,
        pub authenticated: Option<AuthMechanism>,
    }
    // TrustGrade: ExternallyAttested, LocallyAttested, CustodialThirdParty,
    //             LocalSubsystem, LocalApplication, OrderingOnly, Reconstructed, Unknown
    // TamperResistance: AppendOnlyAttested, AppendOnlyLocal, SignedImmutable,
    //                   AdminWritable, UserWritable, Trivial
}

pub mod epoch {
    pub struct EpochTag(pub [u8; 32]);   // hash of (source_id, ordering_key, wall_time)
    pub enum LsnKind {
        SqliteWalFrame { frame_seq: u32, commit_seq: u32 },
        EseLsn(u64), NtfsLfs { record: u64 }, JournaldSeq(u64),
        GitCommitSha(String), ApfsTransactionId(u64), BtrfsGeneration(u64),
        VssShadowSetId(uuid::Uuid), UsnRecord { usn: u64 }, Custom { name: &'static str, value: Vec<u8> },
    }
    pub enum CohortTopology {
        DiscreteSet,
        LinearJournal { lsn_type: LsnKind },
        SubJournalCommits,   // WAL at per-transaction granularity
        Dag,                 // git, btrfs subvolumes with send -p
    }
    pub enum MaterializationSafety {
        ReadOnlySafe, ReadOnlyRequiresCareful, Destructive,
        EphemeralOnce, AutoPruned { trigger: PruneTrigger },
    }
}

pub mod cohort {
    pub struct TemporalState<'a> {
        pub epoch:       EpochTag,
        pub ordering_key: Option<LsnKind>,
        pub wall_time:   Option<DateTime<Utc>>,
        pub clock:       ClockProvenance,
        pub safety:      MaterializationSafety,
        pub handle:      StateHandle<'a>,
    }
    pub struct TemporalCohort<'a> {
        pub artifact:    ArtifactRef,
        pub discipline:  IdentityDiscipline,
        pub topology:    CohortTopology,
        pub states:      Vec<TemporalState<'a>>,   // chronologically ordered
    }
    impl<'a> TemporalCohort<'a> {
        pub fn at(&self, t: DateTime<Utc>) -> Option<&TemporalState<'a>>;
        pub fn nearest(&self, t: DateTime<Utc>) -> Option<&TemporalState<'a>>;
        pub fn diff(&self, a: EpochTag, b: EpochTag) -> Result<StateDelta>;
        pub fn tombstones(&self) -> Vec<Tombstone>;
        // Identity disagreement between disciplines = forensic finding:
        pub fn identity_discontinuities(&self) -> Vec<IdentityDiscontinuity>;
    }
}

pub mod source {
    pub trait HistoricalSource {
        fn id(&self) -> SourceId;
        fn supported_disciplines(&self) -> &'static [IdentityDiscipline];
        fn enumerate(&self, query: &CohortQuery)
            -> impl Iterator<Item = TemporalCohort<'_>>;
        fn acquisition_protocol(&self) -> &dyn AcquisitionProtocol;
    }
    pub trait StateMaterializer {
        fn safety(&self) -> MaterializationSafety;
        // For ReadOnlySafe + ReadOnlyRequiresCareful:
        fn materialize<'a>(&'a self, epoch: EpochTag, ev: &'a Evidence)
            -> Result<StateHandle<'a>>;
        // For Destructive — compiler enforces working copy, not evidence:
        fn materialize_via_working_copy(&self, epoch: EpochTag, wc: &mut WorkingCopy)
            -> Result<StateHandle<'_>>;
    }
}
```

---

## chat4n6 Migration (5-Step Concrete Plan)

chat4n6 is a **separate repo** (`~/src/chat4n6`), not in the Issen workspace.

1. **Step 1 — Create `state-history-forensic`** as a new standalone repo (sibling of `forensicnomicon`).
   Zero deps. KNOWLEDGE tier. Contains only the traits and types above.

2. **Step 2 — chat4n6 becomes an implementor**. Add dep on `state-history-forensic`.
   Export `SqliteWalHistory` implementing `HistoricalSource`:
   - `topology = LinearJournal { lsn_type: LsnKind::SqliteWalFrame }`
   - `safety = ReadOnlyRequiresCareful`
   - `WalMode::Ignore` = materialize epoch 0; `WalMode::Apply` = epoch N; `WalMode::Both` = enumerate all
   The existing chat4n6 API is preserved; new `HistoricalSource` impl is purely additive.

3. **Step 3 — Issen consumes via `issen-sqlite-history`** in the Issen workspace.
   Thin wrapper that re-exports chat4n6's `SqliteWalHistory` and adapts it to `TimelineEvent`/`Evidence`.

4. **Step 4 — Extract to `state-history-forensic` only what generalises**.
   - WAL commit-boundary semantics → `LinearJournal` (generic)
   - ROWID-reuse detection → stays in chat4n6 (SQLite-specific)
   - FTS shadow-table modeling → chat4n6 internal + `RelatedArtifacts` hook in `state-history-forensic`

5. **Step 5 — Cross-backup comparison** (currently impossible in chat4n6):
   Register each iTunes backup, each `.crypt15` file, and the live device as separate
   `HistoricalSource` impls. `TemporalEventGraph` in `issen-correlation` compares them.
   Enables: message present in `backup-2026-04-10` and absent in `backup-2026-04-15`
   + live → deletion window `2026-04-10..2026-04-15`, cross-corroborated by recipient's iCloud copy.

---

## New Practical Decision Rule Entry

Appending to the 10-question rule in CLAUDE.md:

**11. "Does this enumerate the temporal cohort of states for an artifact?"**  
→ `[H]` state-history layer (`vss-history`, `apfs-snapshot-history`, `wal-history`, `git-history`, etc.)

---

## Summary: Corrections to Original Proposal

| Original claim | Status | Correction |
|---|---|---|
| Name: "TEMPORAL" layer | **Wrong** — naming collision with `forensicnomicon::temporal` | Name: `state-history` / `[H]` |
| Placement: between CONTAINER and FILESYSTEM | **Wrong** — VSS needs FILESYSTEM above it; WAL needs PARSER above it; archives need FILESYSTEM above them | **Cross-cutting functor**: each `[H]` crate sits above whatever layer it observes |
| Sixth navigation primitive `[T]` | **Wrong (category error)** | `[H]` is a **functor** lifting each base primitive; not a sixth primitive in the same sense |
| `identity: String` | **Wrong** | Multi-facet `Vec<IdentityClaim>` + selectable `IdentityDiscipline`; facet disagreement = evidence |
| 4-level flat clock trust | **Wrong (conflated axes)** | 4 orthogonal axes (source / trust_grade / tamper_resistance / ordering_only) × 6+ levels |
| 2-state WAL duality | **Understated** | `(2 + N_committed)`-state; four topology classes: DiscreteSet / LinearJournal / SubJournalCommits / Dag |
| All states immutable | **Wrong** — ESE recovery, libsqlite3 auto-checkpoint are destructive | 5-class `MaterializationSafety`; `Destructive` sources take `&mut WorkingCopy` at the type level |
| Per-artifact cohort only | **Incomplete** | `TemporalEventGraph` with `TemporalConstraint` propagation in `issen-correlation` |
| `[T] × [C]` as combination | **Wrong** | `[C]` is the **fixed point** of `[H]`: CAS is the only natively time-indexed primitive |
| chat4n6 migration: "extract temporal-core" | **Underspecified** | 5-step plan; chat4n6 stays PARSER and becomes a `HistoricalSource` **implementor** via `sqlite-history` |
| 26 temporal sources | **Incomplete** | +25 more; critically: `$LogFile`, registry `.LOG1/.LOG2`, journald FSS, btrfs, TPM event log |
