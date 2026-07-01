# 0003. The `<x>-core` reader / `<x>-forensic` analyzer split

- Status: Accepted
- Date: 2026-06
- Deciders: SecurityRonin

## Context

A reader built to consume *valid* data robustly abstracts away exactly the detail
a forensic auditor must see: raw byte and section layout, slack between records,
deleted or overwritten regions, malformed fields a robust reader silently
normalizes or skips, checksums it transparently verifies and discards. If the
auditor is forced to look at the format only through the reader's happy-path API,
it cannot see the anomaly it is hunting.

## Decision

Every single-format repo is named `<x>-forensic` (the analyzer is the headline)
and holds two crates:

- `core/` → crate `<x>-core`: the raw reader/parser exposing `Read + Seek` or a
  navigation API. No findings.
- `forensic/` → crate `<x>-forensic`: the anomaly auditor emitting
  `forensicnomicon::report::Finding`.

Crucially, **`-forensic` is not required to depend on `-core`.** The default is to
build the analyzer on `-core`; but where `-core`'s API hides the very structure
the audit needs, `-forensic` may parse the format itself at a lower level over the
raw bytes, or depend on a layer *below* `-core` (the CONTAINER byte stream, or
`forensicnomicon` constants directly), instead of or in addition to `-core`. The
decision rule: build on `-core` when its API exposes everything the audit needs;
drop lower when it does not. Never contort an audit through a happy-path reader
API that hides the anomaly.

## Consequences

Consumers who only want to *read* a format take the lean `-core` crate; the
analyzer is a separate dependency. The auditor sees the raw, possibly-broken
structure rather than the reader's normalized view. Established fleet models
embody both patterns: `ewf-forensic` consumes only `ewf::sections` (the
low-level structural parser), explicitly not the reader's `Read + Seek` data
interface; `ntfs-forensic` takes raw bytes directly (`audit_record(&[u8])`,
`audit_mft_mirror`, `audit_logfile`) so it sees deleted/overwritten/slack records
that `ntfs-core` would normalize or reject.

The trade-off is duplicated parsing in the cases where the analyzer re-parses raw
structure rather than reusing `-core`. That is accepted deliberately: it is the
price of seeing what a happy-path reader throws away. Naming stays fixed —
reader is always `-core`, analyzer always `-forensic`.

## References

- `CLAUDE.md` — "Crate-structure standard — reader/analyzer split (core/ + forensic/)", "Crate naming grammar" (Pattern A)
- Reference impls: `ewf-forensic` (over `ewf::sections`), `ntfs-forensic` (raw bytes)
