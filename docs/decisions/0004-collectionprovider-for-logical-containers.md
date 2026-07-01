# 0004. CollectionProvider for logical containers, distinct from the disk pipeline

- Status: Accepted
- Date: 2026-07
- Deciders: SecurityRonin

## Context

The disk ingestion pipeline is `container → partition → filesystem`: decode a
sector stream, find partitions, mount a filesystem, walk it by
`name → inode → block`. But a large class of evidence is not a sector image at
all. AD1 (FTK Imager "Custom Content Image"), zip, tar, UAC and Velociraptor
collections are **logical containers** — a tree of files plus metadata, sometimes
compressed — with no MBR/GPT, no partitions, and no filesystem to mount. Forcing
them through the disk pipeline would be wrong at every stage.

## Decision

Logical containers plug in through a `CollectionProvider` trait
(`issen_unpack::CollectionProvider`), distinct from the disk pipeline. A provider
probes a file by **leading magic bytes** (never the extension), and on `open`
extracts its file tree to a temp directory; the fswalker then classifies the
extracted files directly, skipping partition and filesystem detection entirely.
Providers are registered by inventory and force-linked through the
`issen-providers` aggregator so their registration survives dead-code
elimination.

Extraction is safe by construction: every output path is validated to stay inside
the extraction directory (path-traversal guard).

## Consequences

Adding a logical-container format is a small, self-contained provider crate (for
example `issen-ad1`) that implements `probe` and `open` — it needs no knowledge
of partitions or filesystems, and reuses the same downstream fswalker
classification as an extracted disk. Magic-only probing means a mislabeled or
extensionless file is still recognized, and recognized-but-unhandled variants
(e.g. an encrypted AD1) fail loud rather than silently pretending not to match.

The trade-off is that extraction to a temp directory costs disk space and I/O up
front (the whole logical tree is materialized before walking), unlike the
lazy-seek disk path. Encrypted variants are recognized but refused in v1.

## References

- `CLAUDE.md` — "The Reporting Model"/layer notes; the disk pipeline (container → partition → filesystem)
- Crate: `crates/issen-ad1` (`Ad1Provider`), trait in `crates/issen-unpack` (`CollectionProvider`)
- `crates/issen-providers` — inventory force-link aggregator
