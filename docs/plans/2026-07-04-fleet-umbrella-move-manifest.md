# EXECUTION MANIFEST — Fleet umbrella folder move

**Base:** `2026-06-29-fleet-monorepo-consolidation.md` (taxonomy + gates).
**Form chosen (user, 2026-07-04):** **folder umbrella**, NOT a history-merge monorepo. Each repo
keeps its own `.git`/remote/history and is *relocated* under `~/src/issen/<layer>/<repo>`. This is
**reversible** (a folder move), so the monorepo's history-merge irreversibility does not apply.
**Status:** ready to execute; gated on the user cleaning the dirty/ahead repos first (their choice).

## Target: `~/src/issen/` becomes the umbrella; the current issen repo → `~/src/issen/orchestrator/issen`.

```
~/src/issen/                          # umbrella root (a plain folder — NO .git, NO Cargo.toml)
  knowledge/    forensicnomicon · state-history-forensic · jsonguard
  container/    ewf · ewf-forensic · vhdx-forensic · vmdk-forensic · vhd · qcow2-forensic ·
                aff4-forensic · dmg · dar-forensic · segb-forensic · cfb-forensic ·
                zip-forensic · atx-forensic · ad1-forensic
  filesystem/   ntfs-forensic · ext4fs-forensic · hfsplus-forensic · udf-forensic ·
                iso9660-forensic · apfs-forensic
  mount/        4n6mount · livedisk-forensic
  partition/    mbr-partition-forensic · gpt-partition-forensic · apm-partition-forensic
  memory/       memory-forensic
  log/          winevt-forensic · journald-forensic
  parser/       browser-forensic · srum-forensic · exec-pe-forensic · winreg-forensic ·
                prefetch-forensic · lnk-forensic · trash-forensic · shellhist-forensic ·
                peripheral-forensic · shellitem · snss-forensic · dpapi-forensic ·
                sqlite-forensic · doc4n6
  graph/        git-forensic
  history/      snapshot-forensic · vsc-forensic
  orchestrator/ issen  ·  disk-forensic  ·  useract-forensic
  util/         lzo · lzvn · xpress-huffman · timeglyph · stem-branch · shrinkpath ·
                name-variants · tl · blazehash
  app/          chat4n6
  deprecated/   usnjrnl-forensic
```

~55 repos. **Explicitly OUT** (stay as standalone `~/src/<name>`): all non-forensic products
(nfchat, clawpot/clawscan/clawback, pipeguard*, shepherd*, stackbudget, StrideMark, willitwork,
leakguard, RapidCollect/Proto, login-visualized, ronin-marketplace, ecb-penguin, mpc-demo, alaya,
general, docx-mcp, pdf2xlsx, tls-handshake, …) and every third-party clone (radare2, exiftool,
APOLLO, bulk_extractor, …). `mft` (third-party) stays out per plan.

## Mechanics (avoids the umbrella/repo name collision; run from `~/src`, never inside a moving dir)

1. `mkdir -p ~/src/.issen-umbrella/{knowledge,container,filesystem,mount,partition,memory,log,parser,graph,history,orchestrator,util,app,deprecated}`
2. Move every in-scope repo: `mv ~/src/<repo> ~/src/.issen-umbrella/<layer>/<repo>` — one `mv` per repo,
   verifying each `.git` arrives intact (`git -C <dest> status`). issen itself moves LAST
   (`mv ~/src/issen ~/src/.issen-umbrella/orchestrator/issen`).
3. Swap the umbrella into place: `mv ~/src/.issen-umbrella ~/src/issen`.
   Result: `~/src/issen/orchestrator/issen`, `~/src/issen/knowledge/forensicnomicon`, …

## Path-reference sweep (the only real breakage — folder move, so no history/dep-graph risk)

The fn-1.0 migration made the fleet registry-linked (no `path = "../sibling"` deps), so the sweep is
bounded to a few absolute-path references:

1. **issen `[patch.crates-io]`** (absolute paths) → repoint to new locations, e.g.
   `/Users/4n6h4x0r/src/forensicnomicon` → `/Users/4n6h4x0r/src/issen/knowledge/forensicnomicon`,
   winreg/srum likewise. (These drop entirely once the crates publish — see the patch-drop task.)
2. **Corpus / test-data paths** in `~/src/issen/CLAUDE.md` and env vars (`WINREG_DC01_AMCACHE`,
   `SRUM_*`, iOS-image path, `docs/corpus-catalog.md`): `~/src/issen/tests/data` →
   `~/src/issen/orchestrator/issen/tests/data`.
3. **Hardcoded `~/src/<repo>`** refs in `~/src/issen/CLAUDE.md`, scripts, IDE `.code-workspace`,
   and the personal `~/.claude/CLAUDE*.md` + memory files → new `~/src/issen/<layer>/<repo>` paths.
   A single `grep -rl` sweep across those homes.
4. **Verify:** `cargo check` in issen (orchestrator) resolves via the repointed patches; a sample
   `cargo metadata` in 3–4 moved repos still resolves (they were already registry-linked).

## Gate 0 — repos to clean before the move (user is doing this)

Dirty and/or ahead of remote (folder move preserves everything, but landing first is cleaner):
- **ahead of remote:** `timeglyph` (+93), `shrinkpath` (+12).
- **uncommitted changes:** `sqlite-forensic` (9), `doc4n6` (8), `stem-branch` (5), and single-file
  dirt in `vhdx-forensic`, `ext4fs-forensic`, `apfs-forensic`, `mbr-partition-forensic`,
  `memory-forensic`, `trash-forensic`, `4n6mount`.
- **verify remote:** `~/src/vhd` currently shows **no origin remote** — confirm it's the real
  `SecurityRonin/vhd` (or re-add remote) before moving.

## Open placements to confirm during execution
- `chat4n6` → `app/` (front-end tool) — reclassify to `parser/` if it's chat-artifact parsing.
- `tl`, `name-variants` → `util/` (tentative).
- `atx-forensic` → `container/` (verify what ATX is).
