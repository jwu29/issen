use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.network;
    let title = format!(" Network Connections ({}) ", data.len());

    let header = Row::new(vec![
        "Proto",
        "Local Addr",
        "Remote Addr",
        "State",
        "PID",
        "Program",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, conn)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                conn.protocol.clone(),
                conn.local_addr.clone(),
                conn.remote_addr.clone(),
                conn.state.clone(),
                conn.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                conn.program.as_deref().unwrap_or("-").to_string(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(6),  // Proto
        Constraint::Length(22), // Local Addr
        Constraint::Length(22), // Remote Addr
        Constraint::Length(12), // State
        Constraint::Length(7),  // PID
        Constraint::Min(15),    // Program
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
    use rt_parser_uac::parsers::network::NetworkConnection;
    use std::collections::HashMap;

    fn make_data_with_network(conns: Vec<NetworkConnection>) -> InvestigationData {
        InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline: Vec::new(),
            mft_tree: None,
            anomaly_index: None,
            network: conns,
            processes: Vec::new(),
            crontabs: Vec::new(),
            logins: Vec::new(),
            packages: Vec::new(),
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
            artifact_counts: HashMap::new(),
        }
    }

    #[test]
    fn render_with_data_no_panic() {
        let conns = vec![
            NetworkConnection {
                protocol: "tcp".into(),
                local_addr: "127.0.0.1:8080".into(),
                remote_addr: "10.0.0.1:443".into(),
                state: "ESTABLISHED".into(),
                pid: Some(1234),
                program: Some("nginx".into()),
            },
            NetworkConnection {
                protocol: "udp".into(),
                local_addr: "0.0.0.0:53".into(),
                remote_addr: "*:*".into(),
                state: "LISTEN".into(),
                pid: None,
                program: None,
            },
        ];
        let data = make_data_with_network(conns);
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
        let data = make_data_with_network(Vec::new());
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
