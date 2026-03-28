use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use crate::investigation::WorkbenchApp;

pub fn draw(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let data = &app.data.packages;
    let title = format!(" Installed Packages ({}) ", data.len());

    let header = Row::new(vec!["Name", "Version", "Manager"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(3) as usize;
    let start = app.scroll_offset;
    let end = (start + visible_height).min(data.len());

    let rows: Vec<Row<'_>> = data[start..end]
        .iter()
        .enumerate()
        .map(|(i, pkg)| {
            let style = if start + i == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                pkg.name.clone(),
                pkg.version.clone(),
                format!("{:?}", pkg.manager),
            ])
            .style(style)
        })
        .collect();

    let widths = [
        Constraint::Min(20),    // Name
        Constraint::Length(15), // Version
        Constraint::Length(8),  // Manager
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
    use rt_parser_uac::parsers::packages::{InstalledPackage, PackageManager};
    use std::collections::HashMap;

    fn make_data_with_packages(packages: Vec<InstalledPackage>) -> InvestigationData {
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
            packages,
            hashes: Vec::new(),
            chkrootkit: Vec::new(),
            configs: Vec::new(),
            artifact_counts: HashMap::new(),
        }
    }

    #[test]
    fn render_with_data_no_panic() {
        let packages = vec![
            InstalledPackage {
                name: "openssl".into(),
                version: "3.0.2-0ubuntu1".into(),
                manager: PackageManager::Dpkg,
            },
            InstalledPackage {
                name: "curl".into(),
                version: "7.81.0-1".into(),
                manager: PackageManager::Rpm,
            },
        ];
        let data = make_data_with_packages(packages);
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
        let data = make_data_with_packages(Vec::new());
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
