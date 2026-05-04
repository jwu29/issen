## Strategic Context

This project was planned using North Star Advisor.
Before implementing features, read:

- `north-star-advisor/ai-context.yml` - Strategic context (start here)
- `north-star-advisor/docs/INDEX.md` - Documentation hub

## Multi-Repo Architecture

RapidTriage orchestrates a family of standalone forensic libraries. Each
library is a deep, self-contained expert in one artifact family; RapidTriage
is the thin wrapping and correlation layer on top.

### The Three-Layer Pattern

```
forensicnomicon          ← KNOWLEDGE layer
srum-forensic            ← ALGORITHM layer (depends on forensicnomicon)
winevt-forensic          ← ALGORITHM layer (depends on forensicnomicon)
browser-forensic         ← ALGORITHM layer (depends on forensicnomicon)
memory-forensic          ← ALGORITHM layer (depends on forensicnomicon)
        ↓
RapidTriage              ← ORCHESTRATION layer (wraps all of the above)
```

### Layer Responsibilities

**forensicnomicon** — structural knowledge only:
- Magic bytes / file signatures / record markers for carving
- Container/format header field offsets and layouts (ESE page structure,
  EVTX chunk layout, REGF hive header, etc.)
- Field schemas: column names, types, IDs for application-level formats
  (SRUM table column definitions, ShimCache entry fields, etc.)
- Invariants and parsing hints that any parser must respect
- NO parsing algorithms, NO file I/O, NO binary deserialization

**Parser repos** (srum-forensic, winevt-forensic, browser-forensic, etc.):
- Depend on forensicnomicon for structural constants and schemas
- Implement the actual parsing, carving, and recovery algorithms
- Each follows the deep-library pattern:
  - `<format>-core`: domain types + format constants (may re-export from forensicnomicon)
  - `<format>-carver`: disk/raw-image recovery via magic scan
  - `<format>-antiforensic`: tampering and deletion detection
  - `<format>-memory`: types for data recovered from memory dumps
- Provide a standalone public library usable outside RapidTriage

**RapidTriage** (this repo):
- Thin `rt-<artifact>` wrapping crates (e.g., `rt-evtx`, `rt-parser-srum`)
- Converts parser output into `TimelineEvent` / `Evidence` types
- Cross-artifact correlation via `rt-correlation` and `forensic-pivot`
- User-facing CLI via `rt-cli`

### Practical Rule

When deciding where code lives, ask:
- "Is this a fact about a file format?" → forensicnomicon
- "Is this an algorithm that reads/carves/recovers data?" → parser repo
- "Is this correlation, triage, or reporting?" → RapidTriage
