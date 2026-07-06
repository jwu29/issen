# 0011. Consolidate hash lookup on forensic-hashdb

- Status: Proposed
- Date: 2026-07
- Deciders: SecurityRonin

## Context

A hash match is source-agnostic: whether a file's bytes came from a memory page or
an NTFS `$DATA` run, matching its SHA-256 against a known-good/known-bad/known-vulnerable
database is the same operation. The fleet already publishes a crate for exactly
this — **`forensic-hashdb`** (`KnownGoodDb` mmap NSRL/CIRCL, `KnownBadDb` provenance,
`lol_drivers` embedded, all keyed on `[u8; 32]`).

But today the capability is implemented **twice**:

| | `forensic-hashdb` | `issen-signatures::engines::ioc_hash::HashIocStore` |
|---|---|---|
| Consumers | `issen-mem` only (memory path) | `issen-signatures` matching engine (disk/scan path) |
| Key | `[u8; 32]` SHA-256 | hex `String`, MD5 / SHA1 / SHA256 |
| Backing | mmap binary search (scales to full NSRL) | in-memory `HashSet` |
| Known-vulnerable drivers | loldrivers embedded | ✗ |
| Known-bad provenance | `BadFileSource` tracked | flat set |
| Analyst-supplied feeds | ✗ | ✅ load text/CSV, one hash per line |

`ioc_hash` re-implements NSRL known-good filtering and malware known-bad matching —
work `forensic-hashdb` already does, better, for the SHA-256 case — so the disk path
duplicates our own published crate. This violates the "prefer our own crates / DRY"
rule (CLAUDE.md). It also means the disk/scan path never benefits from the mmap
NSRL DB or loldrivers.

The one thing `ioc_hash` has that `forensic-hashdb` lacks is **analyst-supplied
runtime feeds**: load an arbitrary hash list (MD5/SHA1/SHA256) from a text or CSV
file the analyst points at.

## Decision

**`forensic-hashdb` is the single hash-lookup capability for the whole fleet.** It
owns both the *curated* reference DBs and the *ad-hoc* analyst feeds:

1. **Curated (unchanged):** `KnownGoodDb` (mmap SHA-256, NSRL/CIRCL), `KnownBadDb`
   (provenance SHA-256), `lol_drivers` (embedded, BYOVD).
2. **Ad-hoc (new `feed` module):** a `HashFeed` — a multi-algorithm (MD5/SHA1/SHA256)
   hex-keyed known-good/known-bad store with text/CSV loaders. This is `ioc_hash`'s
   `HashIocStore` moved down into the crate that owns hash lookup, with no new
   dependencies (it is pure `std` — it stores hex strings, it does not hash).

**`issen-signatures::ioc_hash` becomes a thin adapter.** It keeps only what is
issen-specific: the digest helpers `sha256_hex`/`md5_hex` (they pull `sha2`/`md5`,
which belong on the scanning side, not in a lookup leaf) and the matching-engine
glue. The duplicated `HashIocStore` is deleted and replaced by
`forensic_hashdb::feed::HashFeed`.

**Both paths consume `forensic-hashdb`.** `issen-mem` (memory) and
`issen-signatures` (disk/scan) depend on the same crate — the second, non-memory
consumer that makes `forensic-hashdb` cross-cutting *in fact*, not just in intent.

**Extract `forensic-hashdb` to its own repo.** It currently lives as a member of
`memory-forensic` with **no memory-forensic crate depending on it** — a publishing
home of convenience. Now that it has two independent consumers across two repos, it
moves to `~/src/forensic-hashdb` (its own repo), like `forensicnomicon` and
`4n6mount` (`forensic-mount`). The `forensic-` prefix already signalled a
cross-cutting capability; the home now matches.

## Consequences

- **One implementation, one behavior.** NSRL known-good filtering and malware
  matching are defined once. The disk/scan path gains the mmap NSRL DB and
  loldrivers it never had.
- **Version bump + publish.** The `feed` module ships as `forensic-hashdb 0.2.0`
  from the new repo. During the migration, issen uses a `[patch.crates-io]`
  override to the local `../forensic-hashdb`, dropped once 0.2.0 is published (the
  established winreg/srum pattern).
- **`memory-forensic` loses a member it never consumed** — pure subtraction; its
  build is unaffected.
- **No behavior regression.** `HashFeed` is a straight port of `HashIocStore`
  (same auto-detect-by-length, same `insert`/`lookup_bad`/`is_known_good`/file
  loaders); the matching-engine tests carry over unchanged against the new type.
- **The digest helpers stay put.** `forensic-hashdb` remains a *lookup* leaf (no
  `sha2`/`md5` dependency); computing a file's hash is the caller's job (blazehash
  on the fleet's hashing side, or the local `sha256_hex`/`md5_hex`).

Realizes the "prefer our own crates" and "cross-cutting capability → its own repo"
disciplines for the hash-lookup capability.
