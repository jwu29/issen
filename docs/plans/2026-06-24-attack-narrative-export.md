# Design — Attack-Narrative Export: ATT&CK Overlay + Forensic DOCX

**Status:** design, pre-implementation · **Date:** 2026-06-24

Output issen's correlated attack narrative in two analyst-facing forms:
1. a **MITRE ATT&CK Navigator overlay** (technique heatmap), and
2. a **forensic-grade `.docx`** with diagrams, charts, every statement footnoted to its
   full evidence path, and hotlinked URLs where a source is cited.

Grounded in the fleet docx/reporting standards (`~/.claude/CLAUDE.md`), the
`docx-manipulation` skill, and the existing `issen-report` exporters.

---

## 1. What already exists (reuse, do not rebuild)

- **ATT&CK Navigator layer builder** — `issen-report/src/navigator_output.rs` maps a
  finding's `attack.tXXXX` tags → technique IDs and delegates to the shared, tested
  `forensicnomicon::navigator` layer builder (severity-scored heatmap).
- **Diagrams** — `issen-report/src/mermaid.rs` + `attack_chain.rs` generate Mermaid
  attack-chain diagrams. Also present: STIX (`stix_output.rs`), MISP (`misp.rs`),
  Graphviz (`graphviz.rs`), Attack-Flow-Builder (`afb_output.rs`), crude PDF (`pdf.rs`).
- **The finding/evidence model** — `forensicnomicon::report::Finding { severity, category,
  code, note, source, subjects, evidence(Location: ByteOffset/Lba/Sector/Rva/RecordId/
  Path/Field/Key/Other), context, external_refs(ExternalRef::mitre_attack) }`. Every
  finding already carries **full evidence location + MITRE technique + source** — the raw
  material for both the overlay comments and the docx footnotes.
- **Narrative** — `issen supertimeline --format narrative` already renders the temporal
  attack story; `issen correlate` surfaces cross-artifact Correlated Findings.

**Missing:** CLI exposure of the Navigator layer; a structured full-report export; a real
DOCX exporter. `docx-mcp`'s MCP server is not running, so the available docx tool is the
**`docx-manipulation` skill** (python-docx + the documented footnote / auto-link-cross-ref
algorithms).

---

## 2. Output 1 — ATT&CK Navigator overlay

**CLI:** `issen report <db> --format attack-navigator -o case.layer.json`
(thin format arm → `navigator_output`; no new engine).

**Layer JSON** (Navigator v4.5 schema, `domain = enterprise-attack`):
- `techniques[]`: `{ techniqueID, score (from finding severity → 1..100), color, enabled,
  comment }`, where **`comment` = finding `code` + the full evidence path** (so the overlay
  is self-documenting when an analyst clicks a cell).
- `gradient` + `legendItems` encode the severity scale; multiple findings on one technique
  take the max severity (documented in the layer description).
- Loads directly at <https://mitre-attack.github.io/attack-navigator/>.

**Effort:** ~1 day — a `ReportFormat::AttackNavigator` arm + a call into the existing builder.

---

## 3. Output 2 — Forensic DOCX

### Architecture
Single source of truth: **issen emits the case as structured JSON** (`issen report
--format json` — the full `Report`: findings with evidence `Location`s + MITRE refs +
severity/category/code/note/source, the supertimeline narrative, and the Mermaid
attack-chain source). A **docx generator** (the `docx-manipulation` skill / a shipped
Python template) consumes that JSON and builds the `.docx`.

Rationale: a pure-Rust docx would reinvent footnote/cross-reference/charting machinery
poorly; CLAUDE.md mandates using the docx skill for footnotes + the auto-link cross-ref
pass. The JSON boundary keeps issen medium-agnostic and the docx logic in the tool built
for it.

### Document structure (expert-report shape)
1. **Executive Summary** (BLUF, fits page one — decision/finding/top risks).
2. **Attack narrative** — the supertimeline story, in **expert-witness epistemic layers**:
   observed facts → "consistent with" inferences → legal conclusions handed to the tribunal.
3. **Attack-chain diagram** (rendered Mermaid).
4. **Charts** — severity distribution, timeline density, techniques-per-tactic.
5. **ATT&CK coverage** — techniques observed grouped by tactic (table), each hotlinked.
6. **Findings** — per-finding detail; every claim footnoted.
7. **Appendix** — methodology, evidence inventory, clock-skew caveats.

### Requirement → mechanism (each grounded in a standard)
| Requirement | Mechanism |
|---|---|
| **Every statement → footnote, full path** | each narrative claim carries a footnote rendering the finding's evidence `Location` in full — e.g. `\Device\HarddiskVolume2\Windows\System32\coreupdater.exe · $MFT rec 47291 · $SI 2020-09-19T03:24:06Z`; `Security.evtx rec 1184 · EventID 4624`; `citadeldc01.mem · PID 3724 · VA 0x…`. One renderer per `Location` variant. (`docx-manipulation` skill manages footnotes.) |
| **Hotlinked URLs where required** | MITRE technique → `https://attack.mitre.org/techniques/<ID>/`; cited write-ups; CVEs — via the skill's `add_hyperlink` (CLAUDE.md: **no duplicate URL run**). |
| **Diagrams** | render `mermaid.rs` output via `mmdc` → PNG, embed (CLAUDE.md: **Mermaid, never ASCII box-drawing**; no literal `\n` in node labels). |
| **Charts "as appropriate"** | matplotlib → PNG; honest bar/table only (CLAUDE.md: no false-precision radar/area). |
| **Cross-references** | final **auto-link pass**: `Figure N` / `Item N` / `Section N` → internal hyperlinks across body, tables, **and footnotes**; no dead/self links; verify against the saved file (CLAUDE.md "Auto-Linking In-Text Cross-References" + the skill's algorithm). |
| **Tone / format** | Executive Summary first; **smart curly quotes**; **heading numbers from Word's multilevel list** (never literal digits in heading text); no `## License`. |
| **Epistemics** | "consistent with"/"strongly consistent with", never "confirms"/"proves"; legal characterization → "the Court may draw its own conclusions". |

### Evidence-path footnote: the one new issen-side primitive
A `Location → String` full-path renderer (per variant), reused by both the Navigator
`comment` and the docx footnote, so the overlay and the report cite **identical** evidence
strings. Lives next to the report model (knowledge-layer), tested per variant.

---

## 4. Build phases (strict TDD, separate RED/GREEN commits)
1. **ATT&CK Navigator CLI export** — `--format attack-navigator`; wire `navigator_output`;
   golden-file test of a small layer; validate it loads in Navigator. *(Quick win.)*
2. **`Location` full-path renderer** + **`issen report --format json`** — the structured
   `Report` (findings + evidence paths + MITRE + narrative + Mermaid source). Snapshot test.
3. **DOCX generator** — Python template driven by the `docx-manipulation` skill: sections,
   rendered Mermaid + charts, footnoted statements (full paths), hotlinked URLs, the
   cross-ref auto-link pass, smart quotes + heading numbering, expert-witness phrasing.
   Verify links resolve against the saved file (Doer-Checker). *(Optionally start docx-mcp
   instead; the skill works now.)*

## 5. Open decisions
- **Where the docx generator lives:** a shipped `tools/issen-report-docx.py` (self-contained,
  `cargo`-repo-tracked) vs. an ad-hoc skill invocation per case. Lean: shipped script so the
  output is reproducible and version-controlled.
- **`issen report -o report.docx` one-shot** (issen shells out to the Python generator) vs.
  a documented two-step (`issen report --format json` → generator). Lean: keep them separate
  first (medium-agnostic), add the one-shot convenience later.
- Validate the whole pipeline on the **Szechuan Sauce** case (we have the data + the
  `szechuan-sauce-quickstart.md` answer mapping) as the Doer-Checker real-artifact test.

## 6. References
- `~/.claude/CLAUDE.md` — "Word (.docx) Documents", "Diagrams and Charts", "Expert Witness
  Reports — Three Layers", "Academic Submissions … footnotes", "Writing Style Defaults".
- `~/.claude/skills/docx-manipulation.md` — footnotes + "Auto-Linking In-Text Cross-References".
- `issen/CLAUDE.md` — "The Reporting Model — forensicnomicon::report".
- `issen-report/src/{navigator_output,mermaid,attack_chain}.rs`; `forensicnomicon::navigator`.
