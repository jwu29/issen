use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.processes;
    let title = format!(" Processes ({}) ", data.len());

    let header = Row::new(vec![
        "PID", "PPID", "User", "CPU%", "MEM%", "Start", "Command",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, proc_info)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                proc_info.pid.to_string(),
                proc_info.ppid.to_string(),
                proc_info.user.clone(),
                proc_info.cpu_pct.as_deref().unwrap_or("-").to_string(),
                proc_info.mem_pct.as_deref().unwrap_or("-").to_string(),
                proc_info.start_time.as_deref().unwrap_or("-").to_string(),
                proc_info.command.clone(),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Length(7),  // PID
        Constraint::Length(7),  // PPID
        Constraint::Length(12), // User
        Constraint::Length(6),  // CPU%
        Constraint::Length(6),  // MEM%
        Constraint::Length(12), // Start
        Constraint::Min(20),    // Command
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
    use rt_parser_uac::parsers::process::ProcessInfo;
    use std::collections::HashMap;

    fn make_data_with_processes(procs: Vec<ProcessInfo>) -> InvestigationData {
        InvestigationData {
            metadata: CollectionMetadata::default(),
            alerts: Vec::new(),
            timeline: Vec::new(),
            mft_tree: None,
            anomaly_index: None,
            network: Vec::new(),
            processes: procs,
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
        let procs = vec![
            ProcessInfo {
                pid: 1,
                ppid: 0,
                user: "root".into(),
                command: "/sbin/init".into(),
                cpu_pct: Some("0.1".into()),
                mem_pct: Some("0.5".into()),
                start_time: Some("Jan01".into()),
            },
            ProcessInfo {
                pid: 1234,
                ppid: 1,
                user: "www-data".into(),
                command: "nginx: worker process".into(),
                cpu_pct: None,
                mem_pct: None,
                start_time: None,
            },
        ];
        let data = make_data_with_processes(procs);
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
        let data = make_data_with_processes(Vec::new());
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
