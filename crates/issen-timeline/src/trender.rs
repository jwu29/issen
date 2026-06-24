//! One renderer for all typed-query output (Humble Object).
//!
//! The verbs decide *what* to ask ([`crate::tquery`]); this module decides *how*
//! to render — `text` or `json` — so both behave identically. Output is
//! attacker-controlled evidence, so every emitted string is sanitized
//! (control/bidi characters neutralized) and `json` goes through `serde_json`'s
//! correct escaping rather than hand-built strings.

use crate::tquery::QueryResult;

/// A self-describing provenance header attached to every result.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// The case DB path the query ran against.
    pub db_path: String,
    /// One human-readable line per filter applied (e.g. `event-type=LogonSuccess`).
    pub filters: Vec<String>,
}

/// Strip/escape characters that could corrupt a terminal or smuggle a spoofed
/// rendering into a report screenshot: C0/C1 control codes (except tab) and
/// Unicode bidi-override codepoints. Returns a safe display string.
#[must_use]
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let is_bidi = matches!(
            ch,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
        );
        let is_control = (ch.is_control() && ch != '\t') || is_bidi;
        if is_control {
            out.push_str(&format!("\\u{{{:04x}}}", ch as u32));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Render to plain text: a provenance line, the column headers, the rows, and
/// any empty-vs-absent diagnostic.
#[must_use]
pub fn render_text(result: &QueryResult, prov: &Provenance) -> String {
    let mut out = String::new();
    out.push_str(&format!("# db: {}\n", sanitize(&prov.db_path)));
    if prov.filters.is_empty() {
        out.push_str("# filters: (none)\n");
    } else {
        let joined: Vec<String> = prov.filters.iter().map(|f| sanitize(f)).collect();
        out.push_str(&format!("# filters: {}\n", joined.join(" AND ")));
    }
    out.push_str(&format!("# rows: {}\n", result.row_count));

    let headers: Vec<&str> = result.columns.iter().map(|c| c.name.as_str()).collect();
    if !headers.is_empty() {
        out.push_str(&headers.join("\t"));
        out.push('\n');
        for i in 0..result.row_count {
            let cells: Vec<String> = result
                .columns
                .iter()
                .map(|c| sanitize(c.values.get(i).map_or("", |v| v.as_str())))
                .collect();
            out.push_str(&cells.join("\t"));
            out.push('\n');
        }
    }

    out.push_str(&empty_vs_absent(result));
    out
}

/// Render to JSON via `serde_json` (correct escaping by construction). Shape:
/// `{ "db", "filters", "row_count", "rows": [ {col: val, …} ], "field_coverage": {field: bool} }`.
#[must_use]
pub fn render_json(result: &QueryResult, prov: &Provenance) -> String {
    let rows: Vec<serde_json::Value> = (0..result.row_count)
        .map(|i| {
            let mut obj = serde_json::Map::new();
            for c in &result.columns {
                obj.insert(
                    c.name.clone(),
                    serde_json::Value::String(sanitize(c.values.get(i).map_or("", |v| v.as_str()))),
                );
            }
            serde_json::Value::Object(obj)
        })
        .collect();

    let coverage: serde_json::Map<String, serde_json::Value> = result
        .field_populated
        .iter()
        .map(|(name, present)| (name.clone(), serde_json::Value::Bool(*present)))
        .collect();

    let value = serde_json::json!({
        "db": prov.db_path,
        "filters": prov.filters,
        "row_count": result.row_count,
        "rows": rows,
        "field_coverage": coverage,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

/// The empty != absent diagnostic: when a result has zero rows but a filtered
/// field was never populated by any ingested source, say so explicitly.
fn empty_vs_absent(result: &QueryResult) -> String {
    let mut out = String::new();
    if result.row_count == 0 {
        for (field, present) in &result.field_populated {
            if *present {
                out.push_str(&format!(
                    "# note: 0 matches, but field '{field}' IS populated in this case (genuine empty result)\n"
                ));
            } else {
                out.push_str(&format!(
                    "# warning: field '{field}' was NEVER populated by any ingested source — \
                     0 rows means COVERAGE GAP, not a clean finding\n"
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tquery::Column;

    fn result_with(rows: usize, columns: Vec<Column>, fp: Vec<(String, bool)>) -> QueryResult {
        QueryResult {
            columns,
            row_count: rows,
            field_populated: fp,
        }
    }

    #[test]
    fn sanitize_neutralises_bidi_and_control() {
        let evil = "ab\u{202E}cd\u{0007}ef";
        let safe = sanitize(evil);
        assert!(!safe.contains('\u{202E}'));
        assert!(!safe.contains('\u{0007}'));
        assert!(safe.contains("ab"));
    }

    #[test]
    fn text_render_carries_provenance_and_rows() {
        let r = result_with(
            1,
            vec![Column {
                name: "count".into(),
                values: vec!["42".into()],
            }],
            vec![],
        );
        let prov = Provenance {
            db_path: "dc01.duckdb".into(),
            filters: vec!["event-type=LogonSuccess".into()],
        };
        let text = render_text(&r, &prov);
        assert!(text.contains("# db: dc01.duckdb"));
        assert!(text.contains("event-type=LogonSuccess"));
        assert!(text.contains("# rows: 1"));
        assert!(text.contains("42"));
    }

    #[test]
    fn empty_result_distinguishes_populated_from_absent_field() {
        // 0 rows + field present ⇒ genuine empty; 0 rows + field absent ⇒ gap.
        let present = result_with(0, vec![], vec![("ip".into(), true)]);
        let absent = result_with(0, vec![], vec![("service".into(), false)]);
        let prov = Provenance {
            db_path: "x".into(),
            filters: vec![],
        };
        assert!(render_text(&present, &prov).contains("genuine empty result"));
        assert!(render_text(&absent, &prov).contains("COVERAGE GAP"));
    }

    #[test]
    fn json_render_is_valid_and_escaped() {
        let r = result_with(
            1,
            vec![Column {
                name: "user".into(),
                values: vec!["a\"b".into()],
            }],
            vec![("user".into(), true)],
        );
        let prov = Provenance {
            db_path: "x".into(),
            filters: vec![],
        };
        let json = render_json(&r, &prov);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["rows"][0]["user"], "a\"b");
        assert_eq!(parsed["field_coverage"]["user"], true);
    }
}
