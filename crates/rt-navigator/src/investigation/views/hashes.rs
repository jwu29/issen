use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.hashes;
    let title = format!(" Hashed Executables ({}) ", data.len());

    let header = Row::new(vec!["Algorithm", "Hash", "Path"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![h.algorithm.clone(), h.hash.clone(), h.path.clone()]).style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(8),  // Algorithm
        Constraint::Length(64), // Hash (SHA-256 max)
        Constraint::Min(20),    // Path
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
    use rt_parser_uac::parsers::hash_execs::HashedExecutable;
    use std::collections::HashMap;

    fn make_data_with_hashes(hashes: Vec<HashedExecutable>) -> InvestigationData {
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
            hashes,
            chkrootkit: Vec::new(),
            configs: Vec::new(),
            artifact_counts: HashMap::new(),
        }
    }

    #[test]
    fn render_with_data_no_panic() {
        let hashes = vec![
            HashedExecutable {
                algorithm: "sha256".into(),
                hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
                path: "/usr/bin/ls".into(),
            },
            HashedExecutable {
                algorithm: "md5".into(),
                hash: "d41d8cd98f00b204e9800998ecf8427e".into(),
                path: "/usr/bin/cat".into(),
            },
        ];
        let data = make_data_with_hashes(hashes);
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
        let data = make_data_with_hashes(Vec::new());
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
