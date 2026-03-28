use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.configs;
    let title = format!(" Config Files ({}) ", data.len());

    let header =
        Row::new(vec!["Path", "Size"]).style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, cfg)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![cfg.path.clone(), format!("{} B", cfg.content.len())]).style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(40),    // Path
        Constraint::Length(12), // Size
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
    use rt_parser_uac::parsers::configs::ConfigFile;
    use std::collections::HashMap;

    fn make_data_with_configs(configs: Vec<ConfigFile>) -> InvestigationData {
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
            chkrootkit: Vec::new(),
            configs,
            artifact_counts: HashMap::new(),
        }
    }

    #[test]
    fn render_with_data_no_panic() {
        let configs = vec![
            ConfigFile {
                path: "/etc/ssh/sshd_config".into(),
                content: "PermitRootLogin no\nPort 22\n".into(),
            },
            ConfigFile {
                path: "/etc/passwd".into(),
                content: "root:x:0:0:root:/root:/bin/bash\n".into(),
            },
        ];
        let data = make_data_with_configs(configs);
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
        let data = make_data_with_configs(Vec::new());
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
