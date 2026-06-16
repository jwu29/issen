# Issen Fleet — Current Plan (2026-06-17)

**This is the current tactical snapshot.** Strategic roadmap: `2026-06-09-issen-grand-plan.md`.
Supersedes the day-to-day status in older plan docs (the obsolete ones are in `archive/`).

## Just completed (this session)

- **Publish backlog closed** — 14 new crates on crates.io (`blazehash-core`, `blazehash 0.2.5`,
  `ese-carver/-integrity`, `winevt-cli`, `forensicnomicon-cli`, `srum-analysis/-cli`,
  `ext4fs-core/-cli/-fuse`, `dmg-core`, `exec-pe-core/-analysis`, `forensic-mount`). Only `srum-gui`
  (Tauri) unpublished — not a crates.io target.
- **blazehash split** live (lean `blazehash-core` + full `blazehash` binary).
- **Dark winreg artifacts wired** (#113): comhijack/lsadump/svcdiff/typedurls/lxss + regcatalog,
  force-linked into the binary.
- **Link-completeness gate** (#114 item 1) + revived 7 orphaned parsers (mft/usnjrnl/pe/lnk/linux/
  macos/setupapi) — MFT/USN/PE/LNK/Linux/macOS/USB now reach the supertimeline.
- **17 temporal rules** added to the shared registry (#112). **Timeline sorted** (mode 6E).
- **Standards codified in CLAUDE.md:** Batteries-Included; lean-lib/full-binary split; Fleet GUI
  Standard (egui + egui-phosphor, Tauri banned/`publish=false`).

## Active — prioritized

### A. Resumable ingestion (#115) — IN PROGRESS, the current focus
Design: `2026-06-17-resumable-ingestion-design.md` (Codex-critiqued). MVP order:
1. **Completion contract** — DONE for MFT/USN/EVTX/Prefetch (`ParseCompletion`, secure-by-default).
   Remaining: other parsers declare completion as touched.
2. **Schema + migration** — `ingest_log` table + `timeline.ingest_unit_id` + indexes (additive;
   legacy rows immutable). ← next.
3. **Per-unit transaction** — `begin → delete unit rows → insert → mark complete → commit`, reusing
   `insert_batch_at_epoch`.
4. **Stable unit ids** + sorted/deterministic discovery.
5. **Streaming `StoreEmitter`** (replace collect-all-in-RAM).
6. **Case-level ingest lock** + `--refresh` (CLI) / `ingest.refresh` (config).
Defer to phase 2: nested-volume recursion (threaded/bounded), per-artifact-type + intra-artifact progress.

### B. All-encompassing supertimeline mechanism (#114) — IN PROGRESS
Design: `2026-06-16-all-encompassing-supertimeline-design.md` (Codex-critiqued). Item 1 (link gate)
done; sort done. Remaining, Codex order: 2 stub-parse gate · 3 classifier-producer gate · 4
CoverageManifest in the supertimeline header · 5 catalog-driven `detect_artifact_type` (discovery
knowledge → forensicnomicon) · 6 dirty-hive `.LOG` replay · 8 catalog breadth scanner · 9 breadth/
depth dedup · 10 fleet-capability gate · 11 nested archive/VHD/VSS expansion.

### C. Unified timeline workflow (#110) — IN PROGRESS
Design: `2026-06-16-unified-timeline-workflow-design.md`. P1 (narrative-over-DB) + P2 (rule registry)
done. Remaining: **P3** supertimeline smart front-door (ingest-if-evidence, managed workspace DB);
**P4** forensic soundness (per-event provenance, `timestamp_quality`, manifest-keyed cache).

### D. Temporal-rule registry (#112)
17 rules integrated. Remaining: **de-specialize the 2 over-fit originals** (`/tmp/silly.txt` PAM hook,
boot-log-predates-mft); **real Case-001 validation** of the new rules (not synthetic-only).

### E. CI greening (#109)
6/7 repos green. **issen CI** remains — run after the timeline/parser churn settles.

## Housekeeping / fleet-wide

- **Set `publish = false`** on `srum-gui` (+ audit fleet for other Tauri/app crates) — make the
  exclusion intentional, not a missing-publish.
- **Re-platform `srum-gui` on egui** (per the new GUI standard) → then it ships like `srum-cli`.
- **`forensic-mount` relicense** MIT → Apache-2.0 (fleet standard).
- **ext4fs/ewf → `blazehash-core`** migration (drop `default-features=false`; batteries-included).
- **clippy/fmt automation** (proposed): a Stop hook running `fmt` + `clippy --fix` + `clippy -D
  warnings` on changed crates, and a `rust-toolchain.toml` pinned to CI's version (kills the
  "passed local, failed CI 1.96" class).

## Larger / strategic (own efforts)

- **Fleet hierarchy reorg** (#70) — `2026-06-09-fleet-hierarchy-reorg.md`.
- **issen correlate capstone** (#37) — `2026-06-11-issen-correlate-capstone-v5.md`.
- **FindEvil MCP fleet** — `2026-06-15-findevil-mcp-fleet-design.md` (design only).
- **forensicnomicon version unification** — `2026-06-14-...md` (Phase 1 partial).
