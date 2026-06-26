//! `issen rules` — list the bundled detection rules ("what detections do you
//! have?"). A read-only inventory of the temporal/correlation rule pack; the
//! detections themselves run automatically inside the bare pipeline.

/// One detection rule, flattened for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    pub id: String,
    pub severity: String,
    pub description: String,
}

/// Gather the bundled detection rules from the temporal rule pack.
#[must_use]
pub fn collect() -> Vec<RuleRow> {
    issen_correlation::temporal_rule::bundled_temporal_rules()
        .into_iter()
        .map(|r| RuleRow {
            id: r.id,
            severity: r.severity,
            description: r.description.unwrap_or_default(),
        })
        .collect()
}

/// Print the bundled detection rules.
///
/// # Errors
/// Currently never errors; returns `Result` for dispatch uniformity.
pub fn run() -> anyhow::Result<()> {
    let rows = collect();
    if rows.is_empty() {
        println!("No detection rules bundled.");
        return Ok(());
    }
    let (rule, sev, desc) = ("RULE", "SEVERITY", "DESCRIPTION");
    println!("{rule:<44}  {sev:<10}  {desc}");
    println!("{}", "-".repeat(100));
    for r in &rows {
        println!("{:<44}  {:<10}  {}", r.id, r.severity, r.description);
    }
    println!("\n{} detection rule(s).", rows.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_bundled_rules_with_ids() {
        let rows = collect();
        assert!(!rows.is_empty(), "there are bundled detection rules");
        assert!(
            rows.iter().all(|r| !r.id.is_empty()),
            "every rule has an id"
        );
    }
}
