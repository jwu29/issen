use std::path::Path;

use anyhow::{Context, Result};
use rt_report::ReportConfig;
use rt_timeline::store::TimelineStore;

/// Run the report command: generate a self-contained HTML report.
pub fn run(
    db_path: &Path,
    output: &Path,
    case_id: Option<&str>,
    examiner: Option<&str>,
    max_events: Option<usize>,
) -> Result<()> {
    let store = TimelineStore::open(db_path)
        .with_context(|| format!("Failed to open database: {}", db_path.display()))?;

    let config = ReportConfig {
        title: case_id
            .map(|id| format!("RapidTriage Report — {id}"))
            .unwrap_or_else(|| "RapidTriage Report".to_string()),
        case_id: case_id.map(String::from),
        examiner: examiner.map(String::from),
        max_events: max_events.or(Some(10_000)),
    };

    rt_report::generate_report(&store, config, output)
        .with_context(|| format!("Failed to generate report: {}", output.display()))?;

    println!("Report written to {}", output.display());
    Ok(())
}
