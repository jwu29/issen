# Implementation Plan — Universal VFS topology + Archive-detour

Master tracking doc for the work identified during the 2026-07-18 design sessions
(VFS crate topology + the archive-detour two-phase model + the Fable/Gemini/Codex
resolver-placement panel). Captures completed work, identified bugs, and the
remaining build items so nothing is forgotten. **All commits below are signed and
LOCAL/UNPUSHED unless noted.**

Status: ✅ done+verified · 🔄 in progress · ⬜ todo · 📅 scheduled/gated

Governing records: `forensic-vfs/docs/decisions/0007-*` (VFS topology),
`forensic-vfs/docs/decisions/0008-archives-as-probes.md` (archive detour + two-phase),
`issen/docs/plans/archive-support-design.md` (design detail).

---

## A. VFS crate topology & resolver (ADR 0007 — revised `9c2b8cb`)

- ✅ **Revise ADR 0007** Proposed→Accepted to the settled topology (contract leaf +
  separate published engine); redefine leaf invariant = "zero reader deps / zero format
  knowledge / no dep+MSRV raise" (not "zero logic"). `forensic-vfs 9c2b8cb`.
- ✅ **Delete engine's duplicate `fn resolve`** → delegate to `Registry::resolve` (verified
  line-for-line duplicate; `open_base()` host-bootstrap kept). Golden equivalence test.
  `forensic-vfs-engine 2f17f5d` (test) + `7c0988e` (refactor). Verified: tests/clippy/fmt clean.
- ✅ **Extract `forensic-vfs-resolver` — LEAF SIDE DONE** (`forensic-vfs 33f83a6`, verified). New
  `crates/resolver` → `forensic-vfs-resolver 0.1.0`; `resolve`→`Resolve` extension trait (orphan
  rule); `walk`/`snapshot_view`/types moved out; leaf → **0.4.0 breaking**; leaf builds standalone;
  66 tests pass, clippy/fmt clean. Committed, UNPUSHED.
- ⛔ **Engine repoint + fleet adoption — GATED on a coordinated 0.4 FLEET CUT.** Key finding: the
  extraction is a *fleet-wide breaking migration*, not a two-repo refactor. The engine's **8 reader
  crates pin `forensic-vfs ^0.3`** (apfs/ewf/ext4fs/fat/hfsplus/iso9660/ntfs/xfs), so the graph
  can't hold both 0.3 (readers) and 0.4 (engine); the engine can't consume the extracted resolver
  until every reader republishes against 0.4 (trivial no-code bump — traits unchanged). **Rejected
  the `[patch]`-onto-0.3.1-with-resolve-removed workaround (semver-cheat the panel condemned).**
  Engine stays clean on published 0.3 meanwhile. Bundle the 0.4 cut with: publish forensic-vfs 0.4
  + forensic-vfs-resolver 0.1 + bump the 8 readers to 0.4 + engine repoint + the archive-core vfs
  adapter (this is the one-time fleet-sweep cost — pay it once, timed with the archive work).
  Rationale for the whole extraction: firewall high-churn resolver behavior from the frozen contract.
- ⬜ **#3 Crypto descent (BUG — verified gap).** `Registry::resolve` descends filesystems /
  volume_systems / containers but **NOT `CryptoProbe`** → the headline `E01 → GPT → BitLocker →
  NTFS` does not auto-resolve the crypto layer. Add a crypto-descent path. Feature-sized: needs a
  **`CredentialSource`** injected into the resolver (crypto can't descend without a key; keep keys
  out of `PathSpec`). Do this in `forensic-vfs-resolver` (post-extraction), not the leaf.
- ⬜ **Resolver behavioral-semver discipline.** `#[non_exhaustive]` doesn't cover behavior changes
  that alter the resolved tree. Add: deterministic probe ordering (documented), **ambiguity
  reporting** (not silent first-wins), **golden-stack fixtures** across container/volume/crypto/
  filesystem/archive, a `ResolverOptions` knob surface, and an engine↔resolver compat test.
- ⬜ **Strengthen the `ImageSource` threading contract** (Codex). Document/enforce: deterministic
  positioned reads, concurrent-read safety under `&self`, bounded allocation, no lock inversion
  across stacked parent/child sources, clear short-read/error semantics. Matters most with
  zran/archives + N worker threads.
- 📅 **Publish** `forensic-vfs 0.4` + `forensic-vfs-resolver 0.1` (gated: pre-publish checklist,
  human auth). THEN revert `forensic-vfs-engine` path deps → registry versions.

## B. Archive-detour (ADR 0008 — two-phase Detect → AccessPlan → Peel)

- ✅ **ADR 0008** archives-as-probes (gz/bz2 = `ContainerDecoder`, tar/zip/7z = `FileSystemProbe`,
  no new leaf trait) + O(n) streaming requirement + two-phase model + per-segment `Zran` +
  the 5 content-authoritative `detect` rules. `forensic-vfs` (ADR) + `issen archive-support-design.md`.
- ✅ **Phase 1 `detect()` → `AccessPlan`** classifier — content-authoritative, name-free; variants
  Direct/Wrapper/Member/SegmentSet/Collection; per-member `Access` (InPlace/Zran/SpillToTemp);
  segment-set naming (EWF/.00N/split-VMDK). `archive-forensic 15be9c6` (RED) + `3d188a2` (GREEN).
  Verified: 33 lib + integration tests, clippy/fmt clean.
- ⬜ **Phase 2 — peel executors.** `InPlace` (zero-copy sub-range) + `SpillToTemp` (one streaming
  pass to a temp file). Subsumes today's in-memory `peel_detour`; API change `Vec<u8>` → a
  temp-backed seekable handle. Both consumers already stage to temp, so it's a shape change.
- ⬜ **Phase 3 — `Zran`** random access for Deflate/Deflate64 members (reuse `zip-forensic-core`'s
  `DeflateSeekReader` / `deflate64_seek`). Later: bzip2 block-index (currently bzip2 → SpillToTemp).
- ⬜ **Phase 4 — `SegmentSet` reassembly** via ewf `SegmentBacking` (per-segment `Access`; a
  Deflate `E01/E02/E03`-in-zip is randomly accessible with only per-segment checkpoint indexes,
  zero temp spill).
- ⬜ **archive-core `vfs` adapter** — implement the leaf's `ContainerDecoder` (gz/bz2) +
  `FileSystemProbe` (tar/zip/7z), registered in the consumer's `default_registry()`, so archives
  resolve *inside* `resolve()` (ADR 0008). Needs additive leaf variants `ContainerFormat::{Gzip,Bzip2}`.
  THEN `disk-forensic` + `4n6mount` drop their pre-resolver `peel_detour` on-ramp.
- ⬜ **`ustar@257` content-verification robustness** — before committing to a tar walk, verify the
  decompressed head; a bare gz/bz2 misnamed `.tbz`/`.tgz` falls back gracefully instead of erroring
  (the direction-2 misnaming fix). Generalizes to running the *full probe set* on the decompressed
  head (positive identification, not "not a tar").
- ✅ **Streaming tar peel (O(n))** — `.tgz`/`.tbz2` stream through `GzDecoder`/`DecoderReader`, whole-
  tar `Vec` eliminated, per-member cap. `archive-forensic ea4d64c`+`ac76164`. Verified.
- ✅ **`.tbz`/`.tb2` tar.bz2 aliases.** `archive-forensic b10b3f6`+`2170261`. Verified.

## C. Completed capabilities (this session, verified)

- ✅ **SecureZIP strong-AES decrypt** in `zip-forensic-core` — byte-for-byte vs `7zz`, wrong-pw
  refuses loud, cert/3DES/non-AES refused. `zip-forensic 7e1834c`+`0ec7933`. (Algorithm gotcha:
  file-data CBC chains from the validation-blob last cipher block, NOT the header IV.)
- ✅ **Deflate64 checkpoint seek** in `zip-forensic-core`. `zip-forensic e213d75`+`cd146ee`.
- ✅ **Architecture diagram refresh** — universal-VFS + archive-detour (archive-detour correctly
  inside the forensic-vfs bracket). `issen 5d4cf53`.
- ✅ **VFS doc consolidation** — removed the duplicated 649-line design doc from disk-forensic,
  slimmed `architecture.md` to the consumer view, preserved prior-art + adversarial review log in
  `forensic-vfs/docs/design-history.md`. `disk-forensic 391f781` + `forensic-vfs 84fcdbe`.

## D. Housekeeping / follow-ups (don't forget)

- 📅 **Push the verified work** across 5 repos — forensic-vfs, forensic-vfs-engine, archive-forensic,
  zip-forensic, issen, disk-forensic (all signed, currently unpushed). User's call; branch off main first.
- ⬜ **`issen/docs/corpus-catalog.md`** — add entries for the 5 new archive-core zip fixtures
  (`stored_one`, `deflate_one`, `seg_ewf`, `seg_split`, `bzip2_member`) with mint commands (already
  in `archive-forensic/tests/data/README.md`).
- ⬜ **timeglyph README** — remove/correct the SignPath signing claim (rejected by SignPath, never
  implemented).
- ⬜ **disk-forensic `architecture.md`** — the "engine being relocated to its own repo" phase line is
  stale (engine IS a separate published repo now). Minor fix.
- ⬜ **disk-forensic `docs/assets/umbrella-architecture.svg`** (embedded in `validation-inventory.md`) —
  partially stale: has forensic-vfs/engine/crypto/container but predates ADR 0008 (shows the older
  "two-path logical archives" model, NOT archives-as-probes) and omits the resolver extraction +
  two-phase detect. Regenerate via the architecture-diagram skill (process at `validation-inventory.md`)
  AFTER the resolver extraction + archive-core vfs adapter land — don't diagram the mid-restructure state.
  Should match the refreshed issen fleet diagram's model.
- ⬜ **forensic-vfs-engine path deps → registry** — revert once forensic-vfs 0.4 + resolver 0.1 publish.

---

## The 0.4 Fleet Cut (bundled milestone — DECISION 2026-07-18: option **(b)**)

Chosen: **hold** the resolver extraction (leaf `33f83a6`, unpushed) and run ONE coordinated 0.4
fleet cut **triggered by the archive-core vfs adapter being ready**, rather than a standalone
sweep now. Everything 0.4-worthy ships in this single cut, so the fleet sweep is paid once:

1. Publish **forensic-vfs 0.4.0** (resolver extracted) + **forensic-vfs-resolver 0.1.0**.
2. Bump the **8 reader crates** (apfs/ewf/ext4fs/fat/hfsplus/iso9660/ntfs/xfs) `forensic-vfs ^0.3 → ^0.4`
   (no-code Cargo.toml bump — traits unchanged) + republish.
3. Additive leaf variants **`ContainerFormat::{Gzip,Bzip2}`** (for the archive adapter).
4. **archive-core vfs adapter** (`ContainerDecoder` gz/bz2 + `FileSystemProbe` tar/zip/7z) published + registered.
5. **forensic-vfs-engine** repoint: `use forensic_vfs_resolver::Resolve;` + deps on 0.4 leaf + resolver
   (path→registry), then `disk-forensic`/`4n6mount` drop their pre-resolver `peel_detour` on-ramp.
6. Ideally fold in the crypto-descent (#3) so the cut also delivers the BitLocker/LUKS/FileVault path.

All gated on the pre-publish checklist + explicit human auth. Until then the extraction sits
committed-unpushed and the engine stays on published 0.3 (green).

## Critical path / sequencing

1. `resolver-extract` lands (🔄) → verify → **single canonical resolver in its own crate.**
2. Then #3 crypto-descent + `CredentialSource` go into `forensic-vfs-resolver` (not the leaf).
3. Archive phases 2→3→4 proceed on the stable `AccessPlan` types (Phase 1 done); the archive-core
   `vfs` adapter (B) is what makes archives resolve *through* `resolve()` — and its multi-result
   selection policy is the churn that justified extracting the resolver crate.
4. Behavioral-semver + threading contracts (A) harden the resolver as its policy grows.
5. Publish gate (forensic-vfs 0.4 + resolver 0.1) → revert path deps.

The extraction (A) and the archive adapter (B) are the two structural moves; crypto-descent and
the semver/threading contracts are the correctness hardening; C is banked; D is hygiene.
