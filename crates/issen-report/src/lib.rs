//! HTML report generator for `Issen`.
//!
//! Produces self-contained HTML reports from forensic timeline data stored
//! in a [`TimelineStore`](issen_timeline::store::TimelineStore). The report
//! includes summary statistics, a sortable events table, and a findings
//! section for scan results.

use std::fmt::Write as FmtWrite;
use std::path::Path;

pub mod afb_output;
pub mod attack_chain;
pub mod graphviz;
pub mod mermaid;
pub mod misp;
pub mod navigator_output;
pub mod pdf;
pub mod stix_output;
pub use afb_output::{
    auto_layout_dag, findings_to_afb, write_afb, AfbCamera, AfbDocument, AfbObject,
};
pub use graphviz::{render_attack_chain_dot, render_attack_chain_png, render_mermaid_png};
pub use misp::{build_misp_event, MispAttribute, MispEvent, MispEventId};
pub use navigator_output::{findings_to_navigator_layer, write_navigator_layer};
pub use pdf::export_pdf;
pub use stix_output::{findings_to_stix_bundle, write_stix_bundle, StixBundle};

pub use attack_chain::{findings_to_attack_chain, tactic_from_tags};
pub use mermaid::{
    render_attack_chain, render_defenses, AttackChainEdge, AttackChainInput, AttackChainNode,
    AttackTactic, DefenseCategory, DefenseInput, DefenseItem,
};

use chrono::{TimeZone, Utc};
use forensicnomicon::report::Severity;
use issen_correlation::correlation::Correlation;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during report generation.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// A `DuckDB` query failed.
    #[error("Database error: {0}")]
    Database(String),

    /// An I/O operation failed (e.g. writing the output file).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization / formatting failed.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<duckdb::Error> for ReportError {
    fn from(e: duckdb::Error) -> Self {
        Self::Database(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for a report.
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Report title shown in the HTML header.
    pub title: String,
    /// Optional case identifier.
    pub case_id: Option<String>,
    /// Optional examiner name.
    pub examiner: Option<String>,
    /// Maximum number of events to include (default 10 000).
    pub max_events: Option<usize>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            title: "Issen Report".to_string(),
            case_id: None,
            examiner: None,
            max_events: Some(10_000),
        }
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A simplified event row for display in the report.
#[derive(Debug, Clone)]
pub struct EventRow {
    /// ISO-8601 timestamp string.
    pub timestamp: String,
    /// Event type label.
    pub event_type: String,
    /// Source artifact type label.
    pub source: String,
    /// Path of the artifact within the evidence.
    pub artifact_path: String,
    /// Human-readable description.
    pub description: String,
    /// Tags associated with the event.
    pub tags: Vec<String>,
}

/// Aggregate statistics for the report summary section.
#[derive(Debug, Clone)]
pub struct ReportSummary {
    /// Total number of events in the timeline.
    pub total_events: usize,
    /// Event counts grouped by source artifact type, sorted descending.
    pub events_by_source: Vec<(String, usize)>,
    /// Event counts grouped by event type, sorted descending.
    pub events_by_type: Vec<(String, usize)>,
    /// Earliest and latest timestamps (if any events exist).
    pub time_range: Option<(String, String)>,
    /// Total number of scan findings.
    pub total_findings: usize,
}

/// A scan finding row for display in the report.
#[derive(Debug, Clone)]
pub struct FindingRow {
    /// Scan engine (e.g. "YARA", "Sigma").
    pub engine: String,
    /// Name of the rule that matched.
    pub rule_name: String,
    /// Severity level (critical / high / medium / low / informational).
    pub severity: String,
    /// Target path or artifact that matched.
    pub target: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// Free-form tags (e.g. Sigma `attack.execution`), used to classify the
    /// finding into an ATT&CK tactic for the attack-chain diagram.
    pub tags: Vec<String>,
}

/// A correlation member event resolved from the `timeline` table for
/// drill-down rendering. Keyed in [`ReportData::member_events`] by `id`.
#[derive(Debug, Clone)]
pub struct CorrEventRow {
    /// The `timeline.id` of this event.
    pub id: u64,
    /// Human-readable timestamp (`timestamp_display`).
    pub timestamp: String,
    /// Event type label.
    pub event_type: String,
    /// Source artifact type label.
    pub source: String,
    /// Path of the artifact within the evidence.
    pub artifact_path: String,
    /// Human-readable description.
    pub description: String,
}

/// All data needed to render a report.
#[derive(Debug, Clone)]
pub struct ReportData {
    /// Configuration used when collecting the report.
    pub config: ReportConfig,
    /// ISO-8601 timestamp of when the report was generated.
    pub generated_at: String,
    /// Event rows to display in the timeline table.
    pub events: Vec<EventRow>,
    /// Summary statistics.
    pub summary: ReportSummary,
    /// Scan findings to display (may be empty).
    pub findings: Vec<FindingRow>,
    /// Cross-artifact correlations — the attack narrative. May be empty.
    pub correlations: Vec<Correlation>,
    /// Correlation member events resolved from the `timeline` table, keyed by
    /// `timeline.id`. Only the members of rendered instances are populated.
    pub member_events: std::collections::HashMap<u64, CorrEventRow>,
}

// ---------------------------------------------------------------------------
// Data collection
// ---------------------------------------------------------------------------

/// Collect report data from a [`TimelineStore`].
///
/// Queries the `DuckDB` database for events and (optionally) scan findings,
/// computes summary statistics, and returns everything packaged as
/// [`ReportData`] ready for rendering.
///
/// # Errors
///
/// Returns [`ReportError::Database`] if any SQL query fails.
#[allow(clippy::cast_possible_truncation)]
pub fn collect_report_data(
    store: &issen_timeline::store::TimelineStore,
    config: ReportConfig,
) -> Result<ReportData, ReportError> {
    let conn = store.connection();
    let generated_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // --- Total event count ---------------------------------------------------
    let total_events: u64 = {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM timeline")?;
        stmt.query_row([], |row| row.get(0))?
    };
    let total_events = total_events as usize;

    // --- Events by source ----------------------------------------------------
    let events_by_source: Vec<(String, usize)> = {
        let mut stmt = conn.prepare(
            "SELECT source, COUNT(*) AS cnt FROM timeline GROUP BY source ORDER BY cnt DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let src: String = row.get(0)?;
            let cnt: u64 = row.get(1)?;
            Ok((src, cnt as usize))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // --- Events by type ------------------------------------------------------
    let events_by_type: Vec<(String, usize)> = {
        let mut stmt = conn.prepare(
            "SELECT event_type, COUNT(*) AS cnt FROM timeline GROUP BY event_type ORDER BY cnt DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let et: String = row.get(0)?;
            let cnt: u64 = row.get(1)?;
            Ok((et, cnt as usize))
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // --- Time range ----------------------------------------------------------
    let time_range: Option<(String, String)> = if total_events > 0 {
        let mut stmt =
            conn.prepare("SELECT MIN(timestamp_display), MAX(timestamp_display) FROM timeline")?;
        stmt.query_row([], |row| {
            let min_ts: String = row.get(0)?;
            let max_ts: String = row.get(1)?;
            Ok(Some((min_ts, max_ts)))
        })?
    } else {
        None
    };

    // --- Event rows (limited) -----------------------------------------------
    let limit = config.max_events.unwrap_or(usize::MAX) as u64;
    let events: Vec<EventRow> = {
        let mut stmt = conn.prepare(
            "SELECT timestamp_display, event_type, source, artifact_path, description, tags
             FROM timeline
             ORDER BY timestamp_ns, record_hash
             LIMIT ?",
        )?;
        let rows = stmt.query_map([limit], |row| {
            let tags_json: Option<String> = row.get(5)?;
            let tags: Vec<String> = tags_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            Ok(EventRow {
                timestamp: row.get(0)?,
                event_type: row.get(1)?,
                source: row.get(2)?,
                artifact_path: row.get(3)?,
                description: row.get(4)?,
                tags,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };

    // --- Findings (if table exists) ------------------------------------------
    let (findings, total_findings) = collect_findings(conn)?;

    // --- Assemble ------------------------------------------------------------
    let summary = ReportSummary {
        total_events,
        events_by_source,
        events_by_type,
        time_range,
        total_findings,
    };

    Ok(ReportData {
        config,
        generated_at,
        events,
        summary,
        findings,
        correlations: Vec::new(),
        member_events: std::collections::HashMap::new(),
    })
}

/// Attempt to read findings from the `scan_findings` table.
///
/// Returns an empty vec if the table does not exist.
#[allow(clippy::cast_possible_truncation)]
fn collect_findings(conn: &duckdb::Connection) -> Result<(Vec<FindingRow>, usize), ReportError> {
    // Check whether the table exists.
    let table_exists: bool = {
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'scan_findings'",
        )?;
        let count: u64 = stmt.query_row([], |row| row.get(0))?;
        count > 0
    };

    if !table_exists {
        return Ok((Vec::new(), 0));
    }

    let total: u64 = {
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM scan_findings")?;
        stmt.query_row([], |row| row.get(0))?
    };

    let mut stmt = conn.prepare(
        "SELECT engine, rule_name, severity, artifact_path, description, tags
         FROM scan_findings
         ORDER BY CASE severity
             WHEN 'critical' THEN 5
             WHEN 'high' THEN 4
             WHEN 'medium' THEN 3
             WHEN 'low' THEN 2
             ELSE 1
         END DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        // `tags` is stored as a JSON-serialized Vec<String>; tolerate NULL and
        // malformed JSON by falling back to an empty tag set.
        let tags_json: Option<String> = row.get(5)?;
        let tags = tags_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default();
        Ok(FindingRow {
            engine: row.get(0)?,
            rule_name: row.get(1)?,
            severity: row.get(2)?,
            target: row.get(3)?,
            description: row.get(4)?,
            tags,
        })
    })?;

    let findings: Vec<FindingRow> = rows.collect::<Result<Vec<_>, _>>()?;

    Ok((findings, total as usize))
}

// ---------------------------------------------------------------------------
// Pure analysis logic (Humble Object: testable without rendering)
// ---------------------------------------------------------------------------

/// A single ATT&CK technique observed under a tactic, graded by its worst
/// observed severity with a hit count.
#[derive(Debug, Clone)]
pub struct TechniqueCell {
    /// Canonical technique id (e.g. `T1543.003`).
    pub id: String,
    /// Worst severity observed across the contributions to this technique.
    pub max_severity: Severity,
    /// Number of contributing correlations/findings.
    pub count: usize,
}

/// One kill-chain tactic column with the techniques observed under it.
#[derive(Debug, Clone)]
pub struct TacticColumn {
    /// Human-readable tactic label (kill-chain ordered upstream).
    pub tactic_label: &'static str,
    /// Techniques observed under this tactic, most-severe first.
    pub techniques: Vec<TechniqueCell>,
}

/// A correlation rule collapsed across all its instances, for the grouped
/// "Correlated Findings" cards.
#[derive(Debug, Clone)]
pub struct RuleGroup {
    /// Scheme-prefixed rule code (e.g. `CORR-MALWARE-PERSIST`).
    pub code: String,
    /// MITRE technique the rule is consistent with, if any.
    pub attack_technique: Option<String>,
    /// Worst severity across this rule's instances.
    pub max_severity: Severity,
    /// Examiner-facing rationale (the rule's note).
    pub note: String,
    /// Total number of instances of this rule.
    pub hit_count: usize,
    /// The instances (each a [`Correlation`]), most-severe/earliest first.
    pub instances: Vec<Correlation>,
}

/// Total ordering rank for a severity (`Info` lowest, `Critical` highest).
#[must_use]
fn severity_rank(_s: Severity) -> u8 {
    0 // RED stub
}

/// Lowercase severity token for CSS classes / display.
#[must_use]
fn severity_token(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
        _ => "info", // cov:unreachable: Severity has exactly five known variants today
    }
}

/// Parse a `scan_findings.severity` token into a [`Severity`].
#[must_use]
fn severity_from_finding_str(_s: &str) -> Option<Severity> {
    None // RED stub
}

/// Format a nanoseconds-since-epoch instant as a readable UTC string.
#[must_use]
fn format_ns(_ns: i64) -> String {
    String::new() // RED stub
}

/// Map a MITRE technique id (e.g. `T1543.003`, `T1110`) to the kill-chain
/// tactic it belongs to for this report's overview. The base technique (before
/// the sub-technique dot) drives the mapping. Unknown ids fall under `Unknown`.
#[must_use]
fn technique_to_tactic(id: &str) -> AttackTactic {
    let base = id.split('.').next().unwrap_or(id).to_ascii_uppercase();
    match base.as_str() {
        // Initial Access
        "T1110" | "T1078" | "T1190" | "T1133" | "T1566" => AttackTactic::InitialAccess,
        // Execution
        "T1059" | "T1106" | "T1053" | "T1204" | "T1569" | "T1047" | "T1105" => {
            AttackTactic::Execution
        }
        // Persistence
        "T1543" | "T1547" | "T1136" | "T1505" | "T1546" | "T1574" => AttackTactic::Persistence,
        // Defense Evasion
        "T1070" | "T1027" | "T1055" | "T1112" | "T1562" | "T1140" => AttackTactic::DefenseEvasion,
        // Command and Control
        "T1071" | "T1095" | "T1573" | "T1090" | "T1102" => AttackTactic::CommandAndControl,
        // Impact
        "T1486" | "T1490" | "T1489" | "T1485" => AttackTactic::Impact,
        _ => AttackTactic::Unknown,
    }
}

/// Kill-chain order for a tactic (lower = earlier). Mirrors `attack_chain.rs`.
#[must_use]
fn tactic_kill_chain_order(t: AttackTactic) -> usize {
    match t {
        AttackTactic::InitialAccess => 0,
        AttackTactic::Execution => 1,
        AttackTactic::Persistence => 2,
        AttackTactic::DefenseEvasion => 3,
        AttackTactic::CommandAndControl => 4,
        AttackTactic::Impact => 5,
        AttackTactic::Unknown => 6,
    }
}

/// Human-readable tactic label.
#[must_use]
fn tactic_overview_label(t: AttackTactic) -> &'static str {
    match t {
        AttackTactic::InitialAccess => "Initial Access",
        AttackTactic::Execution => "Execution",
        AttackTactic::Persistence => "Persistence",
        AttackTactic::DefenseEvasion => "Defense Evasion",
        AttackTactic::CommandAndControl => "Command & Control",
        AttackTactic::Impact => "Impact",
        AttackTactic::Unknown => "Other",
    }
}

/// Extract a technique id from a finding tag such as `attack.t1059.001`.
/// Returns the canonical upper-case `T1059.001`, or `None` for non-technique
/// tags (e.g. tactic tags like `attack.execution`).
#[must_use]
fn finding_tag_technique(tag: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let rest = lower.strip_prefix("attack.")?;
    // A technique tag is `t<digits>` optionally with `.<digits>` sub-techniques.
    let mut chars = rest.chars();
    if chars.next() != Some('t') {
        return None;
    }
    let after_t = &rest[1..];
    // First segment must be all digits.
    let first = after_t.split('.').next().unwrap_or("");
    if first.is_empty() || !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("T{}", &rest[1..]).to_ascii_uppercase())
}

/// Build the ATT&CK overview: tactics in kill-chain order, each with the
/// techniques observed under it (from correlations' `attack_technique` and
/// findings' `attack.tXXXX` tags), every technique graded by its worst
/// severity with a hit count.
#[must_use]
fn attack_overview(_correlations: &[Correlation], _findings: &[FindingRow]) -> Vec<TacticColumn> {
    Vec::new() // RED stub
}

/// Group correlations by rule `code`, ordered by worst severity descending.
#[must_use]
fn group_rules(_correlations: &[Correlation]) -> Vec<RuleGroup> {
    Vec::new() // RED stub
}

/// Derive the page-one key judgment (BLUF) from the correlations. Uses
/// "consistent with" framing and never asserts a verdict.
#[must_use]
fn key_judgment(_correlations: &[Correlation]) -> String {
    String::new() // RED stub
}

// ---------------------------------------------------------------------------
// HTML rendering
// ---------------------------------------------------------------------------

/// Escape a string for safe inclusion in HTML content.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Render [`ReportData`] to a self-contained HTML string.
///
/// The output includes inline CSS and JavaScript; no external resources are
/// referenced so the report can be viewed offline.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_html(data: &ReportData) -> String {
    let mut html = String::with_capacity(64 * 1024);

    // --- Head ----------------------------------------------------------------
    let _ = write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
    --bg: #1a1a2e;
    --surface: #16213e;
    --border: #0f3460;
    --text: #e0e0e0;
    --heading: #e94560;
    --accent: #0f3460;
    --link: #53a8b6;
    --severity-critical: #e94560;
    --severity-high: #ff6b35;
    --severity-medium: #f5a623;
    --severity-low: #7ecec1;
    --severity-info: #8899aa;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
}}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
header {{
    background: var(--surface);
    border-bottom: 3px solid var(--heading);
    padding: 24px 32px;
    margin-bottom: 24px;
}}
header h1 {{ color: var(--heading); font-size: 1.6rem; }}
header .meta {{ color: #8899aa; font-size: 0.85rem; margin-top: 6px; }}
section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 20px; margin-bottom: 20px; }}
section h2 {{ color: var(--heading); font-size: 1.2rem; margin-bottom: 14px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; }}
.stat-card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 14px; text-align: center; }}
.stat-card .value {{ font-size: 1.8rem; font-weight: bold; color: var(--heading); }}
.stat-card .label {{ font-size: 0.8rem; color: #8899aa; text-transform: uppercase; letter-spacing: 0.5px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
th, td {{ padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: var(--bg); color: var(--heading); cursor: pointer; user-select: none; position: sticky; top: 0; }}
th:hover {{ background: var(--accent); }}
td {{ font-family: "SF Mono", "Fira Code", "Consolas", monospace; word-break: break-all; }}
.table-wrapper {{ max-height: 600px; overflow-y: auto; }}
.tag {{ display: inline-block; background: var(--accent); color: var(--text); padding: 1px 6px; border-radius: 3px; font-size: 0.72rem; margin: 1px 2px; }}
.severity-critical {{ color: var(--severity-critical); font-weight: bold; }}
.severity-high {{ color: var(--severity-high); font-weight: bold; }}
.severity-medium {{ color: var(--severity-medium); }}
.severity-low {{ color: var(--severity-low); }}
.severity-informational {{ color: var(--severity-info); }}
.attack-note {{ color: #8899aa; font-size: 0.82rem; margin-bottom: 12px; }}
.attack-chain {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 8px 0; }}
.attack-node {{ padding: 10px 14px; border-radius: 6px; color: #fff; font-weight: bold; font-size: 0.85rem; white-space: nowrap; }}
.attack-arrow {{ color: #8899aa; font-size: 1.3rem; line-height: 1; }}
.attack-initial {{ background: #1a5276; }}
.attack-exec {{ background: #d35400; }}
.attack-persist {{ background: #7d3c98; }}
.attack-evasion {{ background: #1e8449; }}
.attack-c2 {{ background: #0e6655; }}
.attack-impact {{ background: #922b21; }}
.attack-unknown {{ background: #5d6d7e; }}
.attack-mermaid {{ margin-top: 12px; }}
.attack-mermaid summary {{ cursor: pointer; color: var(--link); font-size: 0.82rem; }}
.attack-mermaid pre {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 10px; margin-top: 8px; overflow-x: auto; font-size: 0.75rem; font-family: "SF Mono", "Fira Code", "Consolas", monospace; white-space: pre; }}
.breakdown {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }}
.breakdown-item {{ background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 4px 10px; font-size: 0.82rem; }}
.breakdown-item .count {{ font-weight: bold; color: var(--heading); }}
footer {{ text-align: center; color: #556; font-size: 0.75rem; padding: 16px; }}
#filter {{ width: 100%; padding: 8px 12px; margin-bottom: 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text); font-size: 0.85rem; }}
</style>
</head>
<body>
"#,
        title = html_escape(&data.config.title),
    );

    // --- Header --------------------------------------------------------------
    let _ = write!(
        html,
        r#"<header>
<h1>{title}</h1>
<div class="meta">"#,
        title = html_escape(&data.config.title),
    );

    if let Some(ref case_id) = data.config.case_id {
        let _ = write!(html, "Case: {} &middot; ", html_escape(case_id));
    }
    if let Some(ref examiner) = data.config.examiner {
        let _ = write!(html, "Examiner: {} &middot; ", html_escape(examiner));
    }
    let _ = write!(
        html,
        "Generated: {}</div>\n</header>\n<div class=\"container\">\n",
        html_escape(&data.generated_at),
    );

    // --- Summary section -----------------------------------------------------
    render_summary(&mut html, &data.summary);

    // --- ATT&CK attack-chain (only if findings carry recognized tactics) ------
    let chain = attack_chain::findings_to_attack_chain(&data.findings);
    if !chain.nodes.is_empty() {
        render_attack_chain_section(&mut html, &chain);
    }

    // --- Events table --------------------------------------------------------
    render_events_table(&mut html, &data.events);

    // --- Findings section (only if findings exist) ---------------------------
    if !data.findings.is_empty() {
        render_findings_table(&mut html, &data.findings);
    }

    // --- Footer --------------------------------------------------------------
    let _ = write!(
        html,
        r"</div>
<footer>
Generated by Issen &middot; {generated}
</footer>
",
        generated = html_escape(&data.generated_at),
    );

    // --- Sort script ---------------------------------------------------------
    html.push_str(
        r"<script>
document.querySelectorAll('th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
        const table = th.closest('table');
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const col = parseInt(th.dataset.col, 10);
        const asc = th.dataset.dir !== 'asc';
        th.dataset.dir = asc ? 'asc' : 'desc';
        rows.sort((a, b) => {
            const at = a.children[col].textContent;
            const bt = b.children[col].textContent;
            return asc ? at.localeCompare(bt) : bt.localeCompare(at);
        });
        rows.forEach(r => tbody.appendChild(r));
    });
});
const filterInput = document.getElementById('filter');
if (filterInput) {
    filterInput.addEventListener('input', () => {
        const q = filterInput.value.toLowerCase();
        document.querySelectorAll('#events-tbody tr').forEach(r => {
            r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
        });
    });
}
</script>
</body>
</html>
",
    );

    html
}

/// CSS class for a tactic's coloured attack-chain node.
fn tactic_css_class(tactic: &AttackTactic) -> &'static str {
    match tactic {
        AttackTactic::InitialAccess => "attack-initial",
        AttackTactic::Execution => "attack-exec",
        AttackTactic::Persistence => "attack-persist",
        AttackTactic::DefenseEvasion => "attack-evasion",
        AttackTactic::CommandAndControl => "attack-c2",
        AttackTactic::Impact => "attack-impact",
        AttackTactic::Unknown => "attack-unknown",
    }
}

/// Render the ATT&CK attack-chain section: an inline, self-contained row of
/// colour-coded tactic nodes (ordered by kill-chain phase) plus the
/// [`render_attack_chain`] Mermaid source in a collapsible block.
///
/// The visual chain renders offline with no external resources; the Mermaid
/// source is provided for analysts who want to drop it into other tooling.
fn render_attack_chain_section(html: &mut String, chain: &AttackChainInput) {
    html.push_str("<section>\n<h2>Attack Chain</h2>\n");
    html.push_str(
        "<p class=\"attack-note\">ATT&amp;CK tactics observed in the scan findings, \
         ordered by kill-chain phase. This shows which tactics are present, not a \
         proven causal sequence \u{2014} the analyst draws the conclusions.</p>\n",
    );

    html.push_str("<div class=\"attack-chain\">\n");
    for (i, node) in chain.nodes.iter().enumerate() {
        if i > 0 {
            html.push_str("<div class=\"attack-arrow\">&rarr;</div>\n");
        }
        let _ = writeln!(
            html,
            "<div class=\"attack-node {class}\">{label}</div>",
            class = tactic_css_class(&node.tactic),
            label = html_escape(&node.label),
        );
    }
    html.push_str("</div>\n");

    // Embed the Mermaid source (proves the shared renderer is wired in and gives
    // analysts a copy-pastable diagram). Escaped so it is inert in the page.
    let mermaid = render_attack_chain(chain);
    let _ = write!(
        html,
        "<details class=\"attack-mermaid\">\n<summary>Mermaid source</summary>\n<pre>{}</pre>\n</details>\n",
        html_escape(&mermaid),
    );

    html.push_str("</section>\n");
}

/// Render the summary section into the HTML buffer.
fn render_summary(html: &mut String, summary: &ReportSummary) {
    html.push_str("<section>\n<h2>Summary</h2>\n<div class=\"stat-grid\">\n");

    // Total events card
    let _ = writeln!(
        html,
        "<div class=\"stat-card\"><div class=\"value\">{}</div><div class=\"label\">Total Events</div></div>",
        summary.total_events,
    );

    // Total findings card
    let _ = writeln!(
        html,
        "<div class=\"stat-card\"><div class=\"value\">{}</div><div class=\"label\">Findings</div></div>",
        summary.total_findings,
    );

    // Time range card
    if let Some((ref start, ref end)) = summary.time_range {
        let _ = writeln!(
            html,
            "<div class=\"stat-card\"><div class=\"value\" style=\"font-size:0.9rem\">{} &mdash; {}</div><div class=\"label\">Time Range</div></div>",
            html_escape(start),
            html_escape(end),
        );
    }

    html.push_str("</div>\n");

    // Events by source breakdown
    if !summary.events_by_source.is_empty() {
        html.push_str("<h3 style=\"margin-top:14px;color:#e0e0e0;font-size:0.95rem\">Events by Source</h3>\n<div class=\"breakdown\">\n");
        for (source, count) in &summary.events_by_source {
            let _ = writeln!(
                html,
                "<div class=\"breakdown-item\">{} <span class=\"count\">{}</span></div>",
                html_escape(source),
                count,
            );
        }
        html.push_str("</div>\n");
    }

    // Events by type breakdown
    if !summary.events_by_type.is_empty() {
        html.push_str("<h3 style=\"margin-top:14px;color:#e0e0e0;font-size:0.95rem\">Events by Type</h3>\n<div class=\"breakdown\">\n");
        for (event_type, count) in &summary.events_by_type {
            let _ = writeln!(
                html,
                "<div class=\"breakdown-item\">{} <span class=\"count\">{}</span></div>",
                html_escape(event_type),
                count,
            );
        }
        html.push_str("</div>\n");
    }

    html.push_str("</section>\n");
}

/// Render the events table into the HTML buffer.
fn render_events_table(html: &mut String, events: &[EventRow]) {
    html.push_str("<section>\n<h2>Timeline Events</h2>\n");
    html.push_str("<input type=\"text\" id=\"filter\" placeholder=\"Filter events...\">\n");
    html.push_str("<div class=\"table-wrapper\">\n<table>\n<thead><tr>");

    let headers = ["Timestamp", "Type", "Source", "Path", "Description", "Tags"];
    for (i, hdr) in headers.iter().enumerate() {
        let _ = write!(html, "<th data-col=\"{i}\">{hdr}</th>");
    }
    html.push_str("</tr></thead>\n<tbody id=\"events-tbody\">\n");

    for ev in events {
        let tags_html: String = ev
            .tags
            .iter()
            .map(|t| format!("<span class=\"tag\">{}</span>", html_escape(t)))
            .collect::<Vec<_>>()
            .join(" ");

        let _ = writeln!(
            html,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&ev.timestamp),
            html_escape(&ev.event_type),
            html_escape(&ev.source),
            html_escape(&ev.artifact_path),
            html_escape(&ev.description),
            tags_html,
        );
    }

    html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
}

/// Render the findings table into the HTML buffer.
fn render_findings_table(html: &mut String, findings: &[FindingRow]) {
    html.push_str("<section>\n<h2>Scan Findings</h2>\n");
    html.push_str("<div class=\"table-wrapper\">\n<table>\n<thead><tr>");

    let headers = ["Engine", "Rule", "Severity", "Target", "Description"];
    for (i, hdr) in headers.iter().enumerate() {
        let _ = write!(html, "<th data-col=\"{i}\">{hdr}</th>");
    }
    html.push_str("</tr></thead>\n<tbody>\n");

    for f in findings {
        let sev_class = match f.severity.as_str() {
            "critical" => "severity-critical",
            "high" => "severity-high",
            "medium" => "severity-medium",
            "low" => "severity-low",
            _ => "severity-informational",
        };

        let _ = writeln!(
            html,
            "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&f.engine),
            html_escape(&f.rule_name),
            sev_class,
            html_escape(&f.severity),
            html_escape(&f.target),
            html_escape(&f.description),
        );
    }

    html.push_str("</tbody>\n</table>\n</div>\n</section>\n");
}

// ---------------------------------------------------------------------------
// Convenience: collect + render + write
// ---------------------------------------------------------------------------

/// Generate a self-contained HTML report and write it to a file.
///
/// This is a convenience wrapper that calls [`collect_report_data`] followed
/// by [`render_html`] and writes the result to `output_path`.
///
/// # Errors
///
/// Returns [`ReportError::Database`] if querying the store fails, or
/// [`ReportError::Io`] if writing the output file fails.
pub fn generate_report(
    store: &issen_timeline::store::TimelineStore,
    config: ReportConfig,
    output_path: &Path,
) -> Result<(), ReportError> {
    let data = collect_report_data(store, config)?;
    let html = render_html(&data);
    std::fs::write(output_path, html)?;
    Ok(())
}

/// Collect the case's findings from the timeline DB and write a MITRE ATT&CK
/// **Navigator layer** JSON (a severity-scored technique heatmap) to `output`.
///
/// Each finding's `attack.t<id>` tag becomes a technique cell scored by the
/// finding's severity, so the most-severe observed techniques stand out; the
/// layer loads directly in the ATT&CK Navigator. Findings without a technique
/// tag contribute nothing (they have no matrix cell).
///
/// # Errors
///
/// Returns [`ReportError::Database`] if querying the findings fails, or
/// [`ReportError::Io`] if writing the layer file fails.
pub fn generate_navigator_layer(
    store: &issen_timeline::store::TimelineStore,
    layer_name: &str,
    output: &Path,
) -> Result<(), ReportError> {
    let (findings, _) = collect_findings(store.connection())?;
    std::fs::write(output, findings_to_navigator_layer(&findings, layer_name))?;
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    use issen_core::artifacts::ArtifactType;
    use issen_core::timeline::event::{EventType, TimelineEvent};
    use issen_timeline::findings;
    use issen_timeline::store::TimelineStore;

    // ---- Helpers ------------------------------------------------------------

    fn sample_event(ts_ns: i64, desc: &str, et: EventType, source: ArtifactType) -> TimelineEvent {
        TimelineEvent::new(
            ts_ns,
            format!("2023-11-14T22:13:20.{ts_ns:09}Z"),
            et,
            source,
            "C:/Users/analyst/report.docx".to_string(),
            desc.to_string(),
            "evidence-001".to_string(),
        )
    }

    fn make_store_with_events(events: &[TimelineEvent]) -> TimelineStore {
        let store = TimelineStore::in_memory().expect("create in-memory store");
        for ev in events {
            store.insert_event(ev).expect("insert event");
        }
        store
    }

    fn sample_report_data(events: Vec<EventRow>, findings: Vec<FindingRow>) -> ReportData {
        let total_events = events.len();
        let total_findings = findings.len();

        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for ev in &events {
            *by_source.entry(ev.source.clone()).or_insert(0) += 1;
            *by_type.entry(ev.event_type.clone()).or_insert(0) += 1;
        }
        let mut events_by_source: Vec<(String, usize)> = by_source.into_iter().collect();
        events_by_source.sort_by_key(|x| std::cmp::Reverse(x.1));
        let mut events_by_type: Vec<(String, usize)> = by_type.into_iter().collect();
        events_by_type.sort_by_key(|x| std::cmp::Reverse(x.1));

        let time_range = if events.is_empty() {
            None
        } else {
            Some((
                events.first().expect("first event").timestamp.clone(),
                events.last().expect("last event").timestamp.clone(),
            ))
        };

        ReportData {
            config: ReportConfig::default(),
            generated_at: "2026-03-23T12:00:00Z".to_string(),
            events,
            summary: ReportSummary {
                total_events,
                events_by_source,
                events_by_type,
                time_range,
                total_findings,
            },
            findings,
            correlations: Vec::new(),
            member_events: HashMap::new(),
        }
    }

    // ---- Tests --------------------------------------------------------------

    #[test]
    fn test_report_config_default() {
        let cfg = ReportConfig::default();
        assert_eq!(cfg.title, "Issen Report");
        assert!(cfg.case_id.is_none());
        assert!(cfg.examiner.is_none());
        assert_eq!(cfg.max_events, Some(10_000));
    }

    #[test]
    fn test_render_html_empty() {
        let data = sample_report_data(vec![], vec![]);
        let html = render_html(&data);

        assert!(
            html.contains("<!DOCTYPE html>"),
            "should start with doctype"
        );
        assert!(html.contains("</html>"), "should end with closing html tag");
        assert!(html.contains("Issen Report"), "should contain the title");
        assert!(html.contains("Generated by Issen"), "should contain footer");
        assert!(
            html.contains("Timeline Events"),
            "should contain events section header"
        );
        // With no findings, findings section should NOT appear
        assert!(
            !html.contains("Scan Findings"),
            "should not contain findings section when empty"
        );
    }

    #[test]
    fn test_render_html_with_events() {
        let events = vec![
            EventRow {
                timestamp: "2023-11-14T22:13:20Z".to_string(),
                event_type: "FileCreate".to_string(),
                source: "UsnJournal".to_string(),
                artifact_path: "C:/Users/analyst/report.docx".to_string(),
                description: "File created: report.docx".to_string(),
                tags: vec!["suspicious".to_string()],
            },
            EventRow {
                timestamp: "2023-11-14T22:14:00Z".to_string(),
                event_type: "LogonSuccess".to_string(),
                source: "EventLog".to_string(),
                artifact_path: "Security.evtx".to_string(),
                description: "Logon event for user ADMIN".to_string(),
                tags: vec![],
            },
        ];

        let data = sample_report_data(events, vec![]);
        let html = render_html(&data);

        assert!(html.contains("File created: report.docx"));
        assert!(html.contains("Logon event for user ADMIN"));
        assert!(html.contains("UsnJournal"));
        assert!(html.contains("EventLog"));
        assert!(html.contains("FileCreate"));
        assert!(html.contains("LogonSuccess"));
        assert!(
            html.contains("<span class=\"tag\">suspicious</span>"),
            "should render tags"
        );
    }

    #[test]
    fn test_render_html_with_findings() {
        let findings = vec![
            FindingRow {
                engine: "YARA".to_string(),
                rule_name: "detect_malware".to_string(),
                severity: "critical".to_string(),
                target: "/evidence/malware.exe".to_string(),
                description: "Known malware signature matched".to_string(),
                tags: vec!["attack.execution".to_string()],
            },
            FindingRow {
                engine: "Sigma".to_string(),
                rule_name: "suspicious_login".to_string(),
                severity: "high".to_string(),
                target: "Security.evtx".to_string(),
                description: "Brute force login pattern".to_string(),
                tags: vec!["attack.initial_access".to_string()],
            },
        ];

        let data = sample_report_data(vec![], findings);
        let html = render_html(&data);

        assert!(
            html.contains("Scan Findings"),
            "should contain findings section"
        );
        assert!(html.contains("detect_malware"));
        assert!(html.contains("suspicious_login"));
        assert!(html.contains("severity-critical"));
        assert!(html.contains("severity-high"));
        assert!(html.contains("Known malware signature matched"));
        assert!(html.contains("Brute force login pattern"));
    }

    #[test]
    fn test_render_html_includes_attack_chain_when_tactics_present() {
        let findings = vec![
            FindingRow {
                engine: "Sigma".to_string(),
                rule_name: "exec_rule".to_string(),
                severity: "high".to_string(),
                target: "Security.evtx".to_string(),
                description: "process spawn".to_string(),
                tags: vec!["attack.execution".to_string()],
            },
            FindingRow {
                engine: "Sigma".to_string(),
                rule_name: "logon_rule".to_string(),
                severity: "medium".to_string(),
                target: "Security.evtx".to_string(),
                description: "remote logon".to_string(),
                tags: vec!["attack.initial_access".to_string()],
            },
        ];
        let data = sample_report_data(vec![], findings);
        let html = render_html(&data);

        assert!(
            html.contains("Attack Chain"),
            "should contain an ATT&CK attack-chain section header"
        );
        assert!(html.contains("Initial Access"), "tactic node label present");
        assert!(html.contains("Execution"), "tactic node label present");
        // The Mermaid source from render_attack_chain must be embedded, proving
        // the chain renderer is wired in (self-contained, copy-pastable).
        assert!(
            html.contains("flowchart LR"),
            "should embed the render_attack_chain Mermaid source"
        );
        // Nodes appear in ATT&CK kill-chain order: Initial Access before Execution.
        let ia = html.find("Initial Access").expect("initial access node");
        let ex = html.find(">Execution").or_else(|| html.find("Execution ("));
        let ex = ex.expect("execution node");
        assert!(
            ia < ex,
            "Initial Access should precede Execution in kill-chain order"
        );
    }

    #[test]
    fn test_render_html_no_attack_chain_without_tactics() {
        let findings = vec![FindingRow {
            engine: "YARA".to_string(),
            rule_name: "blob_match".to_string(),
            severity: "low".to_string(),
            target: "/evidence/blob.bin".to_string(),
            description: "generic match".to_string(),
            tags: vec!["malware".to_string()], // no attack.<tactic> tag
        }];
        let data = sample_report_data(vec![], findings);
        let html = render_html(&data);

        assert!(
            !html.contains("Attack Chain"),
            "findings without ATT&CK tactics must not produce an attack-chain section"
        );
    }

    #[test]
    fn test_event_row_from_timeline_event() {
        // Verify the conversion path used in collect_report_data by inserting
        // an event into a store and reading it back as EventRow via collect.
        let ev = sample_event(
            1_700_000_000_000_000_000,
            "Test file created",
            EventType::FileCreate,
            ArtifactType::UsnJournal,
        )
        .with_tag("bookmarked");

        let store = make_store_with_events(&[ev]);
        let data =
            collect_report_data(&store, ReportConfig::default()).expect("collect_report_data");

        assert_eq!(data.events.len(), 1);
        let row = &data.events[0];
        assert_eq!(row.event_type, "FileCreate");
        assert_eq!(row.source, "UsnJournal");
        assert!(row.description.contains("Test file created"));
        assert_eq!(row.tags, vec!["bookmarked"]);
    }

    #[test]
    fn test_report_summary_computation() {
        let events = vec![
            sample_event(
                1000,
                "Event A",
                EventType::FileCreate,
                ArtifactType::UsnJournal,
            ),
            sample_event(
                2000,
                "Event B",
                EventType::FileCreate,
                ArtifactType::UsnJournal,
            ),
            sample_event(
                3000,
                "Event C",
                EventType::LogonSuccess,
                ArtifactType::EventLog,
            ),
        ];

        let store = make_store_with_events(&events);
        let data =
            collect_report_data(&store, ReportConfig::default()).expect("collect_report_data");

        assert_eq!(data.summary.total_events, 3);
        assert_eq!(data.summary.total_findings, 0);

        // Time range should exist
        assert!(data.summary.time_range.is_some());

        // Check by-source counts
        let source_map: HashMap<&str, usize> = data
            .summary
            .events_by_source
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        assert_eq!(source_map.get("UsnJournal"), Some(&2));
        assert_eq!(source_map.get("EventLog"), Some(&1));

        // Check by-type counts
        let type_map: HashMap<&str, usize> = data
            .summary
            .events_by_type
            .iter()
            .map(|(k, v)| (k.as_str(), *v))
            .collect();
        assert_eq!(type_map.get("FileCreate"), Some(&2));
        assert_eq!(type_map.get("LogonSuccess"), Some(&1));
    }

    #[test]
    fn test_render_html_escapes_special_chars() {
        let events = vec![EventRow {
            timestamp: "2023-01-01T00:00:00Z".to_string(),
            event_type: "FileCreate".to_string(),
            source: "UsnJournal".to_string(),
            artifact_path: "C:/test.txt".to_string(),
            description: "<script>alert('XSS')</script> & \"quotes\"".to_string(),
            tags: vec!["tag<>".to_string()],
        }];

        let data = sample_report_data(events, vec![]);
        let html = render_html(&data);

        // The raw dangerous characters must NOT appear unescaped.
        assert!(
            !html.contains("<script>alert"),
            "script tags must be escaped"
        );
        assert!(
            html.contains("&lt;script&gt;alert"),
            "should contain escaped script tag"
        );
        assert!(
            html.contains("&amp; &quot;quotes&quot;"),
            "should escape ampersand and quotes"
        );
        assert!(
            html.contains("tag&lt;&gt;"),
            "should escape tags in tag badges"
        );
    }

    #[test]
    fn test_html_escape_function() {
        assert_eq!(html_escape("hello"), "hello");
        assert_eq!(html_escape("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(html_escape("a & b"), "a &amp; b");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
        assert_eq!(html_escape("it's"), "it&#39;s");
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_collect_report_data_empty_store() {
        let store = TimelineStore::in_memory().expect("create store");
        let data =
            collect_report_data(&store, ReportConfig::default()).expect("collect_report_data");

        assert_eq!(data.summary.total_events, 0);
        assert!(data.events.is_empty());
        assert!(data.findings.is_empty());
        assert!(data.summary.time_range.is_none());
    }

    #[test]
    fn test_collect_report_data_with_findings() {
        let store = TimelineStore::in_memory().expect("create store");

        // Insert an event
        let ev = sample_event(1000, "Test event", EventType::FileCreate, ArtifactType::Mft);
        store.insert_event(&ev).expect("insert event");

        // Create findings table and insert findings
        findings::create_findings_table(store.connection()).expect("create findings table");
        let finding_rows = vec![issen_timeline::findings::FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "/evidence/malware.exe".to_string(),
            engine: "YARA".to_string(),
            severity: "critical".to_string(),
            rule_name: "detect_malware".to_string(),
            description: "Malware detected".to_string(),
            matched_indicator: Some("$bad_string".to_string()),
            tags: "[]".to_string(),
        }];
        findings::insert_findings(store.connection(), &finding_rows).expect("insert findings");

        let data =
            collect_report_data(&store, ReportConfig::default()).expect("collect_report_data");

        assert_eq!(data.summary.total_events, 1);
        assert_eq!(data.summary.total_findings, 1);
        assert_eq!(data.findings.len(), 1);
        assert_eq!(data.findings[0].engine, "YARA");
        assert_eq!(data.findings[0].rule_name, "detect_malware");
        assert_eq!(data.findings[0].severity, "critical");
    }

    #[test]
    fn generate_navigator_layer_writes_attack_layer_from_db_findings() {
        let store = TimelineStore::in_memory().expect("create store");
        findings::create_findings_table(store.connection()).expect("create findings table");
        let finding_rows = vec![issen_timeline::findings::FindingRow {
            evidence_source_id: "case-001".to_string(),
            artifact_path: "Security.evtx".to_string(),
            engine: "Sigma".to_string(),
            severity: "critical".to_string(),
            rule_name: "RDP-BRUTE".to_string(),
            description: "Failed-logon burst".to_string(),
            matched_indicator: None,
            tags: r#"["attack.t1110"]"#.to_string(),
        }];
        findings::insert_findings(store.connection(), &finding_rows).expect("insert findings");

        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        generate_navigator_layer(&store, "case-001", tmp.path()).expect("generate navigator layer");

        let layer = std::fs::read_to_string(tmp.path()).expect("read layer");
        assert!(
            layer.contains(r#""techniqueID": "T1110""#),
            "layer missing technique: {layer}"
        );
        assert!(
            layer.contains(r#""name": "case-001""#),
            "layer missing name: {layer}"
        );
    }

    #[test]
    fn test_collect_report_data_max_events() {
        let store = TimelineStore::in_memory().expect("create store");

        // Insert 20 events
        for i in 0..20 {
            let ev = sample_event(
                i * 1_000_000_000,
                &format!("Event {i}"),
                EventType::FileCreate,
                ArtifactType::UsnJournal,
            );
            store.insert_event(&ev).expect("insert event");
        }

        // Limit to 5
        let config = ReportConfig {
            max_events: Some(5),
            ..ReportConfig::default()
        };
        let data = collect_report_data(&store, config).expect("collect_report_data");

        assert_eq!(data.events.len(), 5, "should respect max_events limit");
        assert_eq!(
            data.summary.total_events, 20,
            "summary should reflect total, not limited"
        );
    }

    #[test]
    fn test_generate_report_writes_file() {
        let store = TimelineStore::in_memory().expect("create store");
        let ev = sample_event(
            1000,
            "File created",
            EventType::FileCreate,
            ArtifactType::Mft,
        );
        store.insert_event(&ev).expect("insert event");

        let dir = tempfile::tempdir().expect("create tmpdir");
        let output_path = dir.path().join("report.html");

        generate_report(&store, ReportConfig::default(), &output_path).expect("generate_report");

        assert!(output_path.exists(), "output file should exist");
        let contents = std::fs::read_to_string(&output_path).expect("read output file");
        assert!(contents.contains("<!DOCTYPE html>"));
        assert!(contents.contains("File created"));
    }

    #[test]
    fn test_render_html_config_metadata() {
        let data = ReportData {
            config: ReportConfig {
                title: "Case 42 Report".to_string(),
                case_id: Some("CASE-042".to_string()),
                examiner: Some("Jane Doe".to_string()),
                max_events: Some(10_000),
            },
            generated_at: "2026-03-23T12:00:00Z".to_string(),
            events: vec![],
            summary: ReportSummary {
                total_events: 0,
                events_by_source: vec![],
                events_by_type: vec![],
                time_range: None,
                total_findings: 0,
            },
            findings: vec![],
            correlations: vec![],
            member_events: HashMap::new(),
        };

        let html = render_html(&data);

        assert!(
            html.contains("Case 42 Report"),
            "should contain custom title"
        );
        assert!(html.contains("CASE-042"), "should contain case ID");
        assert!(html.contains("Jane Doe"), "should contain examiner name");
    }

    // ---- BLUF / progressive-disclosure redesign -----------------------------

    use forensicnomicon::report::Severity;
    use issen_correlation::correlation::{
        Correlation, CorrelationMember, CorrelationRole, CorrelationScope,
    };

    fn corr(
        code: &str,
        sev: Severity,
        technique: Option<&str>,
        first: i64,
        last: i64,
        note: &str,
        members: &[(u64, CorrelationRole)],
    ) -> Correlation {
        let mut c = Correlation::new(code, sev)
            .with_scope(CorrelationScope::SameHost)
            .with_window(first, last)
            .with_note(note);
        if let Some(t) = technique {
            c = c.with_attack_technique(t);
        }
        for (id, role) in members {
            c = c.with_member(CorrelationMember::new(*id, *role));
        }
        c
    }

    fn report_with_correlations(
        correlations: Vec<Correlation>,
        member_events: HashMap<u64, CorrEventRow>,
        findings: Vec<FindingRow>,
    ) -> ReportData {
        let mut d = sample_report_data(vec![], findings);
        d.correlations = correlations;
        d.member_events = member_events;
        d
    }

    fn member_ev(id: u64, ts: &str, et: &str, src: &str, path: &str) -> CorrEventRow {
        CorrEventRow {
            id,
            timestamp: ts.to_string(),
            event_type: et.to_string(),
            source: src.to_string(),
            artifact_path: path.to_string(),
            description: format!("{et} on {path}"),
        }
    }

    // -- ns formatting --------------------------------------------------------

    #[test]
    fn format_ns_renders_readable_utc() {
        // 1_700_000_000_000_000_000 ns = 2023-11-14T22:13:20Z
        let s = format_ns(1_700_000_000_000_000_000);
        assert!(s.starts_with("2023-11-14T22:13:20"), "got {s}");
        assert!(s.ends_with('Z'), "UTC marker: {s}");
    }

    #[test]
    fn format_ns_handles_zero_and_negative() {
        assert!(format_ns(0).starts_with("1970-01-01T00:00:00"));
        // negative / nonsensical input must not panic
        let _ = format_ns(-1);
        let _ = format_ns(i64::MIN);
    }

    // -- severity ranking -----------------------------------------------------

    #[test]
    fn severity_rank_orders_info_lt_critical() {
        assert!(severity_rank(Severity::Info) < severity_rank(Severity::Low));
        assert!(severity_rank(Severity::Low) < severity_rank(Severity::Medium));
        assert!(severity_rank(Severity::Medium) < severity_rank(Severity::High));
        assert!(severity_rank(Severity::High) < severity_rank(Severity::Critical));
    }

    #[test]
    fn severity_from_finding_str_parses_known_tokens() {
        assert_eq!(
            severity_from_finding_str("critical"),
            Some(Severity::Critical)
        );
        assert_eq!(severity_from_finding_str("HIGH"), Some(Severity::High));
        assert_eq!(severity_from_finding_str("medium"), Some(Severity::Medium));
        assert_eq!(severity_from_finding_str("low"), Some(Severity::Low));
        assert_eq!(
            severity_from_finding_str("informational"),
            Some(Severity::Info)
        );
        assert_eq!(severity_from_finding_str("info"), Some(Severity::Info));
        assert_eq!(severity_from_finding_str("nonsense"), None);
    }

    // -- rule grouping --------------------------------------------------------

    #[test]
    fn group_rules_collapses_by_code_and_counts_instances() {
        let corrs = vec![
            corr(
                "CORR-A",
                Severity::Medium,
                Some("T1055"),
                10,
                20,
                "note-a",
                &[],
            ),
            corr(
                "CORR-A",
                Severity::Medium,
                Some("T1055"),
                30,
                40,
                "note-a",
                &[],
            ),
            corr(
                "CORR-B",
                Severity::High,
                Some("T1543.003"),
                5,
                6,
                "note-b",
                &[],
            ),
        ];
        let groups = group_rules(&corrs);
        assert_eq!(groups.len(), 2, "two distinct codes");
        // High severity rule must sort first.
        assert_eq!(groups[0].code, "CORR-B");
        assert_eq!(groups[0].hit_count, 1);
        assert_eq!(groups[0].max_severity, Severity::High);
        assert_eq!(groups[0].attack_technique.as_deref(), Some("T1543.003"));
        assert_eq!(groups[0].note, "note-b");
        assert_eq!(groups[1].code, "CORR-A");
        assert_eq!(groups[1].hit_count, 2, "two CORR-A instances grouped");
    }

    #[test]
    fn group_rules_orders_by_max_severity_desc() {
        let corrs = vec![
            corr("LOW", Severity::Low, None, 1, 2, "", &[]),
            corr("CRIT", Severity::Critical, None, 1, 2, "", &[]),
            corr("MED", Severity::Medium, None, 1, 2, "", &[]),
        ];
        let groups = group_rules(&corrs);
        let codes: Vec<&str> = groups.iter().map(|g| g.code.as_str()).collect();
        assert_eq!(codes, vec!["CRIT", "MED", "LOW"]);
    }

    // -- ATT&CK overview ------------------------------------------------------

    #[test]
    fn attack_overview_groups_techniques_under_kill_chain_tactics() {
        let corrs = vec![
            corr(
                "CORR-PERSIST",
                Severity::High,
                Some("T1543.003"),
                1,
                2,
                "n",
                &[],
            ),
            corr(
                "CORR-PERSIST",
                Severity::High,
                Some("T1543.003"),
                3,
                4,
                "n",
                &[],
            ),
            corr("CORR-BRUTE", Severity::High, Some("T1110"), 5, 6, "n", &[]),
        ];
        let cols = attack_overview(&corrs, &[]);
        // Persistence (T1543.003) and Initial Access (T1110, brute force) present.
        let tactics: Vec<&str> = cols.iter().map(|c| c.tactic_label).collect();
        assert!(tactics.contains(&"Persistence"), "tactics: {tactics:?}");
        // Persistence column should carry T1543.003 with count 2 at High.
        let persist = cols
            .iter()
            .find(|c| c.tactic_label == "Persistence")
            .expect("persistence column");
        let t = persist
            .techniques
            .iter()
            .find(|t| t.id == "T1543.003")
            .expect("T1543.003 cell");
        assert_eq!(t.count, 2);
        assert_eq!(t.max_severity, Severity::High);
    }

    #[test]
    fn attack_overview_includes_finding_attack_tags() {
        let findings = vec![FindingRow {
            engine: "Native".to_string(),
            rule_name: "native-t1059".to_string(),
            severity: "high".to_string(),
            target: "cmd.exe".to_string(),
            description: "cmd".to_string(),
            tags: vec!["attack.t1059.001".to_string()],
        }];
        let cols = attack_overview(&[], &findings);
        let all_ids: Vec<String> = cols
            .iter()
            .flat_map(|c| c.techniques.iter().map(|t| t.id.clone()))
            .collect();
        assert!(
            all_ids.iter().any(|id| id == "T1059.001"),
            "finding technique tag should appear: {all_ids:?}"
        );
    }

    // -- key judgment ---------------------------------------------------------

    #[test]
    fn key_judgment_uses_consistent_with_framing_and_top_technique() {
        let corrs = vec![
            corr(
                "CORR-MALWARE-PERSIST",
                Severity::High,
                Some("T1543.003"),
                1,
                2,
                "n",
                &[],
            ),
            corr(
                "CORR-BRUTEFORCE-LOGON",
                Severity::High,
                Some("T1110"),
                3,
                4,
                "n",
                &[],
            ),
        ];
        let kj = key_judgment(&corrs);
        assert!(kj.contains("consistent with"), "BLUF framing: {kj}");
        assert!(
            !kj.to_lowercase().contains("confirms") && !kj.to_lowercase().contains("proves"),
            "must not assert a verdict: {kj}"
        );
        assert!(
            kj.contains("T1543.003") || kj.contains("T1110"),
            "names a technique: {kj}"
        );
    }

    #[test]
    fn key_judgment_handles_no_correlations() {
        let kj = key_judgment(&[]);
        assert!(
            !kj.is_empty(),
            "must produce some text even with no correlations"
        );
    }

    // -- structural HTML assertions for the new report ------------------------

    #[test]
    fn render_html_executive_summary_appears_first() {
        let corrs = vec![corr(
            "CORR-MALWARE-PERSIST",
            Severity::High,
            Some("T1543.003"),
            1_700_000_000_000_000_000,
            1_700_000_100_000_000_000,
            "service-based persistence note",
            &[
                (1, CorrelationRole::Anchor),
                (2, CorrelationRole::Consequent),
            ],
        )];
        let mut members = HashMap::new();
        members.insert(
            1,
            member_ev(
                1,
                "2023-11-14T22:13:20Z",
                "FileCreate",
                "Mft",
                "C:/evil.exe",
            ),
        );
        members.insert(
            2,
            member_ev(
                2,
                "2023-11-14T22:14:00Z",
                "ServiceInstall",
                "EventLog",
                "Security.evtx",
            ),
        );
        let data = report_with_correlations(corrs, members, vec![]);
        let html = render_html(&data);

        let exec = html
            .find("Executive Summary")
            .expect("exec summary present");
        // The exec summary must precede the appendix and the events sample.
        let appendix = html.find("Appendix").expect("appendix present");
        assert!(
            exec < appendix,
            "Executive Summary must come before Appendix"
        );
        // BLUF judgment text present.
        assert!(
            html.contains("consistent with"),
            "key judgment framing present"
        );
    }

    #[test]
    fn render_html_attack_overview_colors_techniques_by_severity() {
        let corrs = vec![corr(
            "CORR-MALWARE-PERSIST",
            Severity::High,
            Some("T1543.003"),
            1,
            2,
            "n",
            &[],
        )];
        let data = report_with_correlations(corrs, HashMap::new(), vec![]);
        let html = render_html(&data);
        assert!(
            html.contains("ATT&amp;CK Overview"),
            "overview section header"
        );
        assert!(html.contains("T1543.003"), "technique id rendered");
        // technique cell carries a severity class.
        assert!(
            html.contains("sev-cell-high"),
            "severity-colored cell: {}",
            &html[..0.max(0)]
        );
    }

    #[test]
    fn render_html_correlated_findings_are_grouped_cards_with_notes_and_roles() {
        let corrs = vec![
            corr(
                "CORR-MALWARE-PERSIST",
                Severity::High,
                Some("T1543.003"),
                1_700_000_000_000_000_000,
                1_700_000_100_000_000_000,
                "An executable file create followed by a service install is consistent with service-based persistence (T1543.003).",
                &[(1, CorrelationRole::Anchor), (2, CorrelationRole::Consequent)],
            ),
            corr(
                "CORR-MALWARE-PERSIST",
                Severity::High,
                Some("T1543.003"),
                1_700_000_000_000_000_000,
                1_700_000_100_000_000_000,
                "An executable file create followed by a service install is consistent with service-based persistence (T1543.003).",
                &[(1, CorrelationRole::Anchor), (2, CorrelationRole::Consequent)],
            ),
        ];
        let mut members = HashMap::new();
        members.insert(
            1,
            member_ev(
                1,
                "2023-11-14T22:13:20Z",
                "FileCreate",
                "Mft",
                "C:/evil.exe",
            ),
        );
        members.insert(
            2,
            member_ev(
                2,
                "2023-11-14T22:14:00Z",
                "ServiceInstall",
                "EventLog",
                "Security.evtx",
            ),
        );
        let data = report_with_correlations(corrs, members, vec![]);
        let html = render_html(&data);

        assert!(html.contains("Correlated Findings"), "section header");
        assert!(html.contains("CORR-MALWARE-PERSIST"), "rule code rendered");
        assert!(
            html.contains("consistent with service-based persistence"),
            "rule note (rationale) rendered"
        );
        // Drill-down uses <details>.
        assert!(
            html.contains("<details"),
            "progressive disclosure via details"
        );
        // Role badges for member events.
        assert!(html.contains("anchor"), "anchor role badge");
        assert!(html.contains("consequent"), "consequent role badge");
        // Member event detail surfaced.
        assert!(html.contains("C:/evil.exe"), "member event path");
        // Two instances of one rule => ONE card, not two top-level cards.
        let card_count = html.matches("rule-card").count();
        assert!(card_count >= 1, "at least one rule card");
        // The rule must report its 2-instance hit count.
        assert!(html.contains("2"), "hit count rendered");
    }

    #[test]
    fn render_html_appendix_surfaces_medium_findings_and_collapses_info_low() {
        let mut findings = vec![FindingRow {
            engine: "Timestomp".to_string(),
            rule_name: "NTFS-TIMESTOMP-SI-FN-MISMATCH".to_string(),
            severity: "medium".to_string(),
            target: "FileShare/Secret/Beth_Secret.txt".to_string(),
            description: "SI<FN timestamp mismatch".to_string(),
            tags: vec![],
        }];
        // A large pile of Info/Low leads that must be collapsed behind a count.
        for i in 0..500 {
            findings.push(FindingRow {
                engine: "Timestomp".to_string(),
                rule_name: "NTFS-TIMESTOMP-SI-FN-MISMATCH".to_string(),
                severity: "info".to_string(),
                target: format!("C:/win/file{i}.sys"),
                description: "lead".to_string(),
                tags: vec![],
            });
        }
        let data = report_with_correlations(vec![], HashMap::new(), findings);
        let html = render_html(&data);

        assert!(html.contains("Appendix"), "appendix present");
        // The lone medium must be individually visible.
        assert!(html.contains("Beth_Secret.txt"), "medium finding surfaced");
        // The 500 info leads must be collapsed (count shown), not dumped as 500 rows.
        assert!(html.contains("500"), "info/low count surfaced");
        // We must NOT inline a giant events table; the events sample is bounded.
        // (No giant inline dump: total info rows are not all rendered as <tr>.)
    }

    #[test]
    fn render_html_events_sample_is_bounded() {
        // 1000 events but the report only samples a small number inline.
        let events: Vec<EventRow> = (0..1000)
            .map(|i| EventRow {
                timestamp: format!("2023-01-01T00:00:{:02}Z", i % 60),
                event_type: "FileCreate".to_string(),
                source: "Mft".to_string(),
                artifact_path: format!("C:/f{i}.txt"),
                description: format!("event {i}"),
                tags: vec![],
            })
            .collect();
        let mut data = sample_report_data(events, vec![]);
        data.correlations = vec![];
        data.member_events = HashMap::new();
        let html = render_html(&data);
        // The events sample is capped well below 1000 rows.
        let row_count = html.matches("<tr>").count();
        assert!(
            row_count <= 250,
            "events sample must be bounded (<=200 rows + headers), got {row_count}"
        );
    }
}
