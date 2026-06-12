# Fleet Format-Coverage Audit — *implement the whole spec, not the first variant*

*Scoping document, 2026-06-12. Trigger: the Case-001 DC01 shimcache bug — a
parser built around the one header we'd seen (Win10 `0x34`) silently returned a
sentinel on the documented Win8.1/Server-2012-R2 header. The format set was
closed and published; we'd implemented one member of it. This audit sizes how
widespread that pattern is across the fleet's format readers.*

## Executive summary

**The failure mode:** a `*-core` reader implements the format variant(s) present
in its first test corpus, and **silently degrades** (empty result / sentinel /
best-effort garbage) on the *other documented variants* of the same format. The
spec is finite and known; the gap is latent until a real artifact of the
unimplemented vintage shows up in a case — at which point the tool produces
**silent wrong output**, the most expensive bug class.

**Why this is not YAGNI:** these formats are **closed, published specifications**,
not speculative features. Each unimplemented documented variant is a known
latent bug, not a "might need it later." Completeness against a spec is the
correctness bar for an evidence parser — a DFIR tool that can't read a Win7
ShimCache or an Ex01 image is incomplete for real casework, where legacy systems
are the norm, not the exception.

**Three binding principles this audit enforces (beyond just "decode more"):**
1. **Fail loud on recognized-but-unimplemented.** A reader that recognizes a
   documented header it can't yet decode must say so (`unsupported <format>
   <build>`), never return a blank/sentinel that reads as "nothing here."
2. **Validate each variant against a *real* artifact of that vintage.** Synthetic
   fixtures hid the Win8.1 bug. Implementing XP/Win7 from the spec and testing
   only against self-built fixtures repeats the trap. Real-hive validation is the
   actual gate — and the actual cost.
3. **Delete unspecified guesswork.** Parser branches matching no published layout
   (e.g. shimcache's legacy `0x80`/`parse_win10`) are worse than an honest gap.

## The assessment rubric (four axes per reader)

For every `<format>` a reader claims to parse, the audit records:

| Axis | Question |
|---|---|
| **D — Documented set** | What variants/versions does the authoritative spec define? (enumerate, cite) |
| **I — Implemented** | Which of D does the reader actually decode? |
| **V — Validated** | Which of I are confirmed against a *real* artifact (not just a synthetic fixture)? |
| **F — Fail-loud** | On a variant in D but not I, does the reader error explicitly, or silently sentinel? |

A reader is **complete** when `I = D`, **honest** when `F = loud` for any `D − I`,
and **trustworthy** when `V = I`. The shimcache exemplar before this session:
`D = {XP, 2003, 7, 8.0, 8.1, 10×3}`, `I = {10}`, `V = {10}`, `F = silent` — i.e.
failing on every axis.

## In-scope readers (grounded inventory, ~30 repos)

Grouped by the layer hierarchy. **Status** is a *scoping estimate* (domain
knowledge + this session), confidence-marked — the fan-out produces the verified
matrix. `✓`=confirmed, `~`=inferred, `?`=undetermined.

### CONTAINER (disk-image decoders)
| Reader | Documented variant set (D) | Suspected gap | Conf |
|---|---|---|---|
| **ewf** / ewf-forensic | EWF-E01, **EWF2-Ex01**, L01/Lx01, S01; deflate + **bzip2** compression; encryption | Ex01/L01, bzip2, encryption | ~ |
| **vhdx**-forensic | dynamic, fixed, **differencing**; log replay; BAT | differencing chains | ~ |
| **vmdk**-forensic | monolithicSparse/Flat, twoGbMaxExtent×2, streamOptimized, **SEsparse**, **vmfs**, descriptor-only | SEsparse, vmfs extents | ~ |
| **qcow2**-forensic | v2, v3; zlib + **zstd** compression; AES + **LUKS** encryption; backing; internal snapshots | zstd, LUKS, internal snapshots | ~ |
| **vhd** | fixed, dynamic, differencing (footer+sparse header) | differencing | ? |
| **dd** | raw/split-raw | (likely complete) | ~ |
| **aff4** | AFF4 zip volumes, image streams, maps | map streams | ? |
| **iso9660**-forensic | ISO9660, **Joliet**, **Rock Ridge**, El Torito | Joliet/Rock Ridge extensions | ~ |
| **udf**-forensic | UDF 1.02–2.60 revisions | revision spread | ? |
| **dmg** | UDIF: zlib/bzip2/**LZFSE**/raw blocks; **APFS**/HFS payloads | LZFSE blocks | ? |
| **dar**-forensic | DAR archive format/versions | version spread | ? |

### FILESYSTEM
| Reader | Documented variant set (D) | Suspected gap | Conf |
|---|---|---|---|
| **ntfs**-forensic | attr types ($SI,$FN,$DATA,$ATTRIBUTE_LIST,$INDEX_*,$REPARSE,$EA,$LOGGED_UTILITY); resident/non-resident; **LZNT1 compression**; sparse; ADS; $LogFile; $UsnJrnl | compression, reparse, $EA, $LogFile transactions | ~ |
| **ext4fs**-forensic | ext4 extents **+ ext2/3 indirect block maps**; 64-bit; **inline data**; htree dirs; journal | ext2/3 indirect, inline data | ~ |
| **hfsplus**-forensic | HFS+, HFSX; compression (decmpfs: zlib/**LZVN**/LZFSE); catalog/extents B-trees | decmpfs variants | ? |
| **usnjrnl**-forensic | $UsnJrnl:$J record v2 **+ v3 (128-bit FRN) + v4 (ranges)** | v3/v4 records | ~ |

### REGISTRY
| Reader | Documented variant set (D) | Suspected gap | Conf |
|---|---|---|---|
| **winreg-core** | cell types nk/vk/sk/lf/lh/li/ri/**db**; hive minor v1.3–1.6; big-data | big-data **fixed this session**; minor-version spread | ✓ |
| winreg-artifacts::**shimcache** | XP/2003/Vista/**7**/8.0/8.1/10×3 | **7/XP/2003 (known gap)** | ✓ |
| winreg-artifacts::**amcache** | Win8 (`File`) vs **Win10 (`InventoryApplicationFile`)** schema | schema variant | ~ |
| winreg-artifacts::**userassist**, **sam**, run_keys, … | ROT13 v3/v5; SAM F/V record versions | version spread | ? |

### LOG / APP ARTIFACT
| Reader | Documented variant set (D) | Suspected gap | Conf |
|---|---|---|---|
| **prefetch**-forensic | SCCA v17 (XP), **v23 (Vista/7)**, **v26 (8.1)**, v30 (10), v31 (11); MAM(Xpress-Huff) wrapper | **v17/v23/v26 (suspected)** | ~ |
| **winevt**-forensic | EVTX BinXML token/value-type set; chunk/record; templates | value-type completeness | ~ |
| ese-core (**srum**) | ESE page versions; long-values; multi-values; **column compression (7-bit, LZXPRESS, Unicode)**; tagged cols | compression variants | ~ |
| **sqlite**-forensic | page sizes; overflow; WAL/rollback; freelist; schema fmt 1–4; **text enc UTF8/16LE/16BE**; serial types | text-encoding, freelist edge | ~ |
| **browser**-forensic | Chrome/Firefox/Safari schema versions over time | schema-version drift | ? |
| **journald**-forensic | journal file format versions; **LZ4/XZ/zstd** object compression | compression variants | ? |
| **exec-pe**-forensic | PE32/PE32+; section/import/export/reloc/resource/debug dirs | directory completeness | ? |

### CODEC
| Reader | Documented variant set (D) | Suspected gap | Conf |
|---|---|---|---|
| **xpress-huffman** | [MS-XCA]: LZ77+Huffman **and plain LZ77 (XPRESS, no Huffman)** | **plain-LZ77 variant** | ~ |

### `[H]` STATE-HISTORY / GRAPH
vsc-forensic (VSS), snapshot-forensic, git-forensic — version/format spreads `?`.

## Prioritization (prevalence in real casework × silent-failure risk)

1. **prefetch v17/v23/v26**, **shimcache 7/XP/2003** — execution-evidence parsers
   silently blank on pre-Win10 hosts; Win7 is everywhere in IR. *Highest.*
2. **ewf Ex01/L01**, **ntfs LZNT1 compression / reparse** — common modern evidence
   that silently under-reads.
3. **ese compression**, **usnjrnl v3/v4**, **ext2/3 indirect**, **amcache schema** —
   real but narrower.
4. The long tail (udf revisions, dmg LZFSE, aff4 maps, journald compression, …) —
   implement as artifacts surface; **fail loud** in the meantime.

## Execution plan — read-only fan-out (the audit itself)

The verified matrix is produced by a **read-only agent fan-out** (zero write
contention — the safe concurrency pattern), one agent per cluster. Each agent,
per reader in its cluster:
1. **Research the authoritative spec** → enumerate the full documented variant set
   `D` (cite: format spec / libyal `*-kb` / Zimmerman / [MS-*] / on-disk-format docs).
2. **Read the reader's code** → the implemented set `I` and the dispatch site.
3. **Assess `V`** (which variants have a real-artifact test) and **`F`** (does an
   unimplemented documented variant fail loud or silently sentinel?).
4. Return a per-reader row: `D / I / V / F`, the silent-failure risk, and the
   cheapest fix (fail-loud guard vs full decode + which real artifact validates it).

**Proposed clusters (7 agents):** A CONTAINER · B FILESYSTEM · C REGISTRY · D
LOG/APP-artifact · E MEMORY (memf profile/struct coverage across Windows builds)
· F CODEC+misc · G PARTITION (mbr/gpt/apm type-code coverage). Synthesis → this
doc's matrix filled to `✓`, plus a ranked remediation backlog.

**Cross-cutting deliverables regardless of decode work:**
- A fleet lint/convention: a reader's format dispatch must end in an explicit
  `Unsupported(<recognised-format>)` arm, never a silent empty/sentinel default.
- A `docs/validation.md` line per reader naming the **real** artifact behind each
  validated variant (`V`), exposing the synthetic-only gaps.

## The shimcache precedent (worked example, done 2026-06-12)

`forensicnomicon::appcompatcache` now holds the full documented header/entry-body
table (XP→11) with citations; `winreg-artifacts::shimcache` decodes Win10 + Win8.x
(`I` grew from {10} to {10, 8.0~, 8.1}), validated on the real DC01 hive
(`V`={10,8.1}). Residual on this one reader, folded into priority 1 above:
implement 7/XP/2003 (`D − I`), make the unimplemented arms fail loud, delete the
unspec'd `0x80` legacy parser, source a real Win7 hive for `V`.
