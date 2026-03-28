use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.chkrootkit;
    let title = format!(" Chkrootkit Findings ({}) ", data.len());

    let header = Row::new(vec!["Check", "Result", "Infected"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let base_fg = if finding.is_infected {
                Color::Red
            } else {
                Color::default()
            };
            let style = if start + i == app.selected {
                Style::default()
                    .fg(base_fg)
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(base_fg)
            };
            Row::new(vec![
                finding.check_name.clone(),
                finding.result.clone(),
                if finding.is_infected {
                    "YES".to_string()
                } else {
                    "no".to_string()
                },
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(24), // Check
        Constraint::Min(30),    // Result
        Constraint::Length(10), // Infected
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));

    frame.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::data::{CollectionMetadata, InvestigationData};
    use crate::investigation::WorkbenchApp;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use rt_parser_uac::parsers::chkrootkit::ChkrootkitFinding;
    use std::collections::HashMap;

    fn make_data_with_chkrootkit(findings: Vec<ChkrootkitFinding>) -> InvestigationData {
        InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline: Vec::new(),
            mft_tree: None,
            anomaly_index: None,
            network: Vec::new(),
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins: Vec::new(),
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: findings,
            configs: Vec::new(),
            artifact_counts: HashMap::new(),
        }
    }

    #[test]
    fn render_with_data_no_panic() {
        let findings = vec![
            ChkrootkitFinding {
                check_name: "amd".into(),
                result: "not infected".into(),
                is_infected: false,
            },
            ChkrootkitFinding {
                check_name: "bindshell".into(),
                result: "INFECTED".into(),
                is_infected: true,
            },
        ];
        let data = make_data_with_chkrootkit(findings);
        let app = WorkbenchApp::new(data, None);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                draw(frame, &app, area);
            })
            .unwrap();
    }

    #[test]
    fn render_empty_no_panic() {
        let data = make_data_with_chkrootkit(Vec::new());
        let app = WorkbenchApp::new(data, None);
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                draw(frame, &app, area);
            })
            .unwrap();
    }
}
