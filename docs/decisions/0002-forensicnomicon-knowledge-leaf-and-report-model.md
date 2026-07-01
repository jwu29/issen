# 0002. forensicnomicon as the zero-dependency KNOWLEDGE leaf and shared report model

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

Two kinds of knowledge recur across every analyzer in the fleet. First, **format
facts** — magic bytes, record markers, header offsets, field schemas — which, if
duplicated per crate, drift and disagree. Second, a **reporting vocabulary**: if
each of N analyzers returns its own bespoke `XxxAnalysis` type, the orchestrator
(and any future GUI) needs N bespoke rendering paths, and there is no uniform way
to sort, threshold, or aggregate findings across artifact families.

## Decision

`forensicnomicon` is the **zero-dependency KNOWLEDGE leaf**. It carries format
constants and schemas plus the normalized reporting model under
`forensicnomicon::report`, and it depends on nothing — every analyzer depends
*down* onto it. It performs no parsing, no file I/O, and no binary
deserialization.

Every analyzer emits its findings as the single `report::Finding` model. The
model is the **union (superset) of the analyzers' data, not a flattening**:
`Finding { severity, category, code, note, source, subjects, evidence, context }`,
with `FindingContext` carrying the behavioral superset that disk findings leave
empty and memory/log findings populate. Each analyzer keeps its own typed
`AnomalyKind` (its domain knowledge) and converts to a canonical `Finding` via
`impl Observation` (static codes) or an inherent `to_finding` (dynamic codes);
`forensicnomicon` never enumerates every anomaly kind itself.

## Consequences

The orchestrator aggregates all analyzers into one `Report` and renders them
uniformly (`Report::max_severity`, `findings_at_least`, `unrated_findings`); a
future GUI gets one model to draw. `code` is a published contract
(scheme-prefixed SCREAMING-KEBAB, e.g. `MEM-PROCESS-HOLLOWING`) — never changed
once shipped. `#[non_exhaustive]` enums plus builders keep the model additively
evolvable, so a new field or `Category` is a non-breaking minor bump rather than
a fleet-wide break; consumers must include a `_` arm when matching shared enums.

The costs: every analyzer applies a documented severity-normalization mapping from
its native scale to the canonical five-level `Severity`, and findings are
constrained to be **observations, never legal conclusions** — MITRE/threat
narration uses "consistent with," and the analyst or tribunal draws the
conclusion.

## References

- `CLAUDE.md` — "The Reporting Model — `forensicnomicon::report`", layer "Dependency direction"
- Crate: `forensicnomicon` (KNOWLEDGE leaf), `forensicnomicon::report`
- Orchestration aggregation: `crates/issen-report`
