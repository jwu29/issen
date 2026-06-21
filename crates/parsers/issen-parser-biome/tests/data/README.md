# `issen-parser-biome` test fixtures

Per-file provenance for the committed test data. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](../../../../docs/corpus-catalog.md); this README is the
co-located human detail.

#### Device.Power.LowPowerMode.v1.crc-tampered.segb

- **Source / Identity:** a real Apple Biome SEGB stream (`Device.Power.LowPowerMode.v1`) —
  the genuine Apple on-disk structure (16 records, v1 SEGB) — **with one deliberate tamper**:
  the stored CRC-32 of `Written` record index **12** was flipped. The surrounding 15 records
  and the stream framing are untouched genuine Apple output and parse cleanly; only record 12
  fails its CRC. This is **REAL-self-derived** data (a real Apple stream + a single documented
  tamper), NOT a synthetic builder fixture — it validates the integrity wiring against an
  authentic SEGB layout, not just the in-code `synthetic_segb_bad_crc()` builder. The fleet's
  real-Biome source corpus is the josh-hickman iOS Biome research corpus (per the build-C
  design in `docs/plans/2026-06-21-four-depth-builds-design.md` §C).
- **Tamper method:** flip the 4-byte stored CRC-32 in record 12's header. `segb-forensic::audit`
  recomputes the payload CRC-32 over the genuine payload and reports the mismatch (stored vs
  computed) — a real-data CRC-mismatch, not a contrived all-zero CRC.
- **Used by:**
  - `src/lib.rs` `real_segb_crc_tamper_surfaces_integrity_event` — asserts a single
    `SEGB-CRC-MISMATCH` `Integrity` event surfaces, located at record 12, carrying the
    stored/computed CRC.
  - `crates/issen-cli/tests/parser_depth_gate.rs` — the "biome SEGB integrity" depth case
    (locks the capability in against regression).

| File | Bytes | MD5 |
|---|---|---|
| `Device.Power.LowPowerMode.v1.crc-tampered.segb` | 131072 | `3772c3fb700439d1182b3184dd82bef1` |
