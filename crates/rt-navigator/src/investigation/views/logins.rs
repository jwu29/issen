use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.logins;
    let title = format!(" Login Records ({}) ", data.len());

    let header = Row::new(vec![
        "User", "Terminal", "Source", "Login", "Logout", "Duration",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, record)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                record.user.clone(),
                record.terminal.clone(),
                record.source.clone(),
                record.login_time.as_deref().unwrap_or("-").to_string(),
                record.logout_time.as_deref().unwrap_or("-").to_string(),
                record.duration.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(12), // User
        Constraint::Length(10), // Terminal
        Constraint::Length(16), // Source
        Constraint::Length(20), // Login
        Constraint::Length(20), // Logout
        Constraint::Min(10),    // Duration
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
    use rt_parser_uac::parsers::system::LoginRecord;
    use std::collections::HashMap;

    fn make_data_with_logins(logins: Vec<LoginRecord>) -> InvestigationData {
        InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline: Vec::new(),
            mft_tree: None,
            anomaly_index: None,
            network: Vec::new(),
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins,
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
            artifact_counts: HashMap::new(),
        }
    }

    #[test]
    fn render_with_data_no_panic() {
        let logins = vec![
            LoginRecord {
                user: "root".into(),
                terminal: "pts/0".into(),
                source: "192.168.1.10".into(),
                login_time: Some("Mon Jan  1 00:00".into()),
                logout_time: Some("Mon Jan  1 01:00".into()),
                duration: Some("01:00".into()),
            },
            LoginRecord {
                user: "admin".into(),
                terminal: "tty1".into(),
                source: "".into(),
                login_time: None,
                logout_time: None,
                duration: None,
            },
        ];
        let data = make_data_with_logins(logins);
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
        let data = make_data_with_logins(Vec::new());
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
