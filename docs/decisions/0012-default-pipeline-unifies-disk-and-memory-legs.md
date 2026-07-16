# 0012. The default `issen <evidence>` pipeline unifies disk and memory legs into one timeline

- Status: Accepted
- Date: 2026-07
- Deciders: SecurityRonin

## Context

An intrusion leaves evidence on both media: the disk (filesystem artifacts,
registry, event logs) and memory (processes, network connections, injected code).
A triage tool that made the analyst run one command for disk and a second,
differently-shaped command for memory — then reconcile the two outputs by hand —
would just re-import the fragmentation problem the tool exists to remove.

Two internal realities pull against a single command, though. The disk path is
`container → partition → filesystem` over a lazily-seeked sector stream. A raw
memory dump (`.mem`, LiME, AVML, Windows crash dump) is none of those: it has no
partition table and no filesystem, so nominating it as a disk container would be
wrong at every stage (`container.rs` deliberately excludes `.mem`/`.raw` from the
disk first-segment set). The deep, interactive memory commands (EPROCESS walk,
netstat, hashdump) are also a distinct, heavier surface than a one-pass triage
sweep.

## Decision

The **default, no-subcommand `issen <evidence…>` pipeline** accepts disk images,
logical collections, **and** memory dumps together — a file list or a folder — and
runs them in one pass. Internally it splits into two legs: the **disk leg**
(`container → partition → filesystem`, per source) and the **memory leg**
(`Stage::Memory` → `correlate_mem::ingest_memory_leg`, which parses each dump's
memf-windows analysis **into the same DuckDB timeline**). Both legs feed one
`forensicnomicon::report` aggregation, so a `timeline --around` pivot crosses disk
and memory events on one clock.

Two neighbouring entry points stay deliberately narrower, and this is the
distinction that must not drift:

- The **explicit `issen ingest` subcommand is disk-only.** Handed a `.mem`, its
  disk leg finds no artifacts and it fails loud with a pointer: "looks like a
  memory dump; run `issen memory <file>`." Use the *default* command (or `issen
  memory`) for dumps — never `issen ingest`.
- **`issen memory <dump>` is the deep, focused per-dump tool** (`--command
  netstat` / `hashdump` / …). It is the scalpel for one dump, not the one-pass
  triage sweep.

## Consequences

`issen DC01.E01 DESKTOP.E01 DC01.mem DESKTOP.mem -o case.duckdb` is a real,
one-command, disk-plus-memory triage into one timeline — the load-bearing claim
behind "one command, one picture of the host." Memory findings (e.g. a process
holding a C2 connection) surface in `timeline --flagged` next to the disk events
from the same minutes, with no context switch to a second framework.

The cost is a standing three-way distinction that reads as a contradiction if you
only see one part of it: **default command = unified**, **explicit `ingest`
subcommand = disk-only**, **`issen memory` = deep single-dump**. The fleet
`CLAUDE.md` Case-001 validation note previously stated "`issen ingest`/`correlate`
are disk-only" without that framing, which read as "memory can't be in one
command." It could not, *through the explicit subcommand*; it always could through
the default pipeline. This ADR is the standing home for the distinction; CLAUDE.md
now points here.

The default memory leg is a triage subset folded into the timeline, not the full
depth of `issen memory` — deep dump analysis remains the focused command. This is
the same reader/analyzer altitude split the fleet uses elsewhere (ADR 0003): a
fast unified pass, with a specialist command when the case earns it.

## References

- `crates/issen-cli/src/lib.rs` — the default `Cli.evidence` pipeline doc ("ingests, correlates, scans, and analyses memory in one pass"); parse test `["issen", "DC01.E01", "dump.mem"]`
- `crates/issen-cli/src/commands/pipeline_run.rs` — `Stage::Memory` ("parse dumps into the timeline"), `correlate_mem::ingest_memory_leg`
- `crates/issen-core/src/container.rs` — `.mem`/`.raw` excluded from disk first-segment nomination ("they go through the memory leg")
- `crates/issen-cli/src/commands/ingest.rs` — the disk-leg's "looks like a memory dump; run `issen memory <file>`" guard
- `crates/issen-mem`, `crates/memf-format` — dump providers (raw/LiME/AVML/crash dump)
- ADR 0004 (logical collections), ADR 0005 (DuckDB timeline store), ADR 0003 (reader/analyzer split)
