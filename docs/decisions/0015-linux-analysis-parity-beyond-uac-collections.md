# 0015. Generalize Linux artifact analysis beyond UAC collections (disk-image parity)

Status: Proposed (follow-up to [0014](0014-frontdoor-collection-evidence.md))

## Context

ADR 0014 restored UAC-collection support to the front door: `issen <uac.tar.gz> -o
<db>` routes to the Collection leg (detected by `UacProvider::probe` — `uac.log`
=> `High`, `/bodyfile/`|`/live_response/`|`/system/` => `Medium`, in
`issen-parser-uac/src/probe.rs`) and runs the rootkit / hidden-process /
masquerade analysis (`commands/analyse.rs`), the supertimeline narrative
(`commands/supertimeline.rs`), and the forensic-pivot pack (`commands/pivot.rs`)
over the collection via `run_auto`.

But a **Linux disk image** (ext4 `.E01`/`.dd`) is **not** a UAC collection — it
carries no `uac.log`, so `is_uac_collection` returns `None` and it routes to the
**Disk leg**. The Disk leg (ext4/APFS filesystem support added in the t2
filesystem work — `issen-disk::detect_filesystem` already reports
`ext`/`APFS`/`HFS+`) extracts Linux filesystem artifacts into the case DB, but does
**not** run the rootkit/masquerade/supertimeline/pivot analysis.

So the same Linux host yields different analytical depth depending on whether it
arrived as a UAC package or a raw image. The analysis is currently coupled to its
*source* (a UAC collection consumed by `run_auto`), not to the fact that the
*evidence is Linux*.

## Decision (proposed)

Decouple the Linux rootkit/masquerade/supertimeline/pivot analysis from the
UAC-collection input and run it as a **post-ingest stage keyed on Linux evidence,
regardless of source**:

1. After the ingest stage populates the case DB, run the analysis stage whenever
   the evidence is Linux — a UAC collection (Collection leg) **or** a Linux
   filesystem (Disk leg, where `detect_filesystem` already classifies `ext` /
   `APFS` / `HFS+`).
2. Refactor `analyse.rs`/`supertimeline.rs`/`pivot.rs` to consume the **case-DB
   artifact set** (source-agnostic) rather than a `run_auto` collection handle
   directly. The Collection leg becomes one producer of that artifact set; the
   ext4/APFS Disk leg is another.

## Consequences

- Linux disk images gain analysis parity with UAC collections — the same
  rootkit/masquerade/pivot pass runs on either input.
- The analysis becomes input-source-agnostic (case-DB-driven) — a cleaner
  architecture than binding it to the Collection leg.
- **Larger than 0014.** 0014 *reused* the existing analysis over a collection;
  this *moves* the analysis into the shared post-ingest stage machinery in
  `pipeline_run.rs`, which is under active ingestion-pipeline rework — so it must
  be **sequenced with that work**, not dropped in mid-flight.
- Tests: add a Linux ext4 disk-image fixture asserting the same rootkit/masquerade
  findings the UAC-collection tests assert, proving parity.
- Open question: some UAC-collected inputs (e.g. `live_response/` volatile
  captures) have no disk-image equivalent — the analysis must degrade gracefully
  per-artifact (already the pattern), surfacing whatever the source provides
  rather than failing when a UAC-only artifact is absent.

## Implementation status (2026-07) — partial seam + documented blocker

An investigation for the first draft found the ADR's core premise —
"the ext4/APFS Disk-leg ingest extracts Linux filesystem artifacts into the
case DB" — is **not yet true**, and that two independent gaps block full
disk-image parity. Rather than force a half-wired stage, this branch lands the
clean, tested seam and documents the blocker.

### The live-vs-dead contract (implemented)

A UAC collection captures **live-response** artifacts a **dead** disk image does
not contain. Each indicator is classified once, in `issen_cli::linux_analysis`:

| Indicator | Data source | On a dead disk image |
|---|---|---|
| `ld_preload` (`/etc/ld.so.preload` injection) | on-disk file | **runs** |
| `pam_credential_staging` (`/tmp`,`/var/tmp`,`/dev/shm`,`/run`) | on-disk files | **runs** |
| `hidden_processes` (`/proc` vs `ps`) | live capture | skipped — unavailable |
| `kernel_module` (`lsmod`) | live capture | skipped — unavailable |
| `kernel_taint` (`/proc/sys/kernel/tainted`) | live capture | skipped — unavailable |
| `env_injection` (`LD_PRELOAD` in live env) | live capture | skipped — unavailable |
| `network` (`ss`/`netstat`) | live capture | skipped — unavailable |
| `cpu_anomaly` (`top`) | live capture | skipped — unavailable |

`run_dead_disk_analysis(fs_root)` runs the dead-disk-derivable rows over any
Linux filesystem root and names the live-only rows as "not available for
dead-disk evidence" — never fabricated, never an error. The filesystem-derivable
scan is `issen_parser_uac::parsers::rootkit::scan_filesystem_rootkit_indicators`,
which reads canonical on-disk paths (`/etc/ld.so.preload`, real temp dirs),
distinct from the UAC-layout `scan_rootkit_indicators`. The Linux-evidence
detection primitive is `issen_disk::detect_disk_filesystems` / `is_linux_disk`.

### The blocker (why the front-door stage-dispatch is deferred)

1. **The disk leg extracts no ext4/APFS/HFS+ files.** `issen-disk` only *detects*
   a non-NTFS filesystem (records `ExtractionLimit::UnsupportedFilesystem`); it
   has no ext reader wired (the fleet's `ext4fs-forensic` is not a dependency), so
   no Linux filesystem root is ever produced for the detectors to read. There is
   nothing on a disk image for `run_dead_disk_analysis` to point `fs_root` at.
2. **`commands::analyse` re-parses a UAC directory layout, not the case-DB
   artifact set.** It opens the collection via `UacProvider::open()` and reads
   hardcoded relative paths off `extracted_root`; it never touches the case DB.
   So there is no shared "case-DB artifact set" both legs feed the detectors —
   driving analysis from a disk image needs the detectors refactored onto a
   filesystem-root seam (started: `scan_filesystem_rootkit_indicators`).

### Remaining work (to reach full disk-image parity)

- Wire `ext4fs-forensic` into the disk leg so an ext image extracts
  `/etc/ld.so.preload`, `/tmp`,`/var/tmp`,`/dev/shm`,`/run`, and the persistence
  surfaces (`/etc/cron.*`, `/etc/systemd/system`, SUID sweep, `/var/log/auth.log`)
  into a filesystem root (or the case DB).
- Add a post-ingest Linux-analysis stage that, when `is_linux_disk` (or a Linux
  UAC collection) holds, calls `run_dead_disk_analysis` over that root.
- Extend the dead-disk indicator set beyond the two implemented (cron/systemd
  persistence, SUID, auth/syslog) as the extraction surface grows.
