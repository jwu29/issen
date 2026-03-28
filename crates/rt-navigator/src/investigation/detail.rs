use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::{WorkbenchApp, WorkbenchView};

/// Render a detail panel for the selected item in the current view.
/// For Timeline, detail is handled in supertimeline.rs directly.
pub fn draw_detail(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    let content = match app.current_view() {
        WorkbenchView::Network => network_detail(app),
        WorkbenchView::Processes => process_detail(app),
        WorkbenchView::Logins => login_detail(app),
        WorkbenchView::Configs => config_detail(app),
        _ => vec![Line::from("Select an item to see details")],
    };

    let detail = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL).title(" Detail "))
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

fn network_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(conn) = app.data.network.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    vec![
        detail_line("Protocol", &conn.protocol),
        detail_line("Local", &conn.local_addr),
        detail_line("Remote", &conn.remote_addr),
        detail_line("State", &conn.state),
        detail_line("PID", &conn.pid.map_or("-".to_string(), |p| p.to_string())),
        detail_line("Program", conn.program.as_deref().unwrap_or("-")),
    ]
}

fn process_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(proc_info) = app.data.processes.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    vec![
        detail_line("User", &proc_info.user),
        detail_line("PID", &proc_info.pid.to_string()),
        detail_line("PPID", &proc_info.ppid.to_string()),
        detail_line("CPU%", proc_info.cpu_pct.as_deref().unwrap_or("-")),
        detail_line("MEM%", proc_info.mem_pct.as_deref().unwrap_or("-")),
        detail_line("Start", proc_info.start_time.as_deref().unwrap_or("-")),
        Line::from(""),
        detail_line("Command", &proc_info.command),
    ]
}

fn login_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(record) = app.data.logins.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    vec![
        detail_line("User", &record.user),
        detail_line("Terminal", &record.terminal),
        detail_line("Source", &record.source),
        detail_line("Login", record.login_time.as_deref().unwrap_or("-")),
        detail_line("Logout", record.logout_time.as_deref().unwrap_or("-")),
        detail_line("Duration", record.duration.as_deref().unwrap_or("-")),
    ]
}

fn config_detail(app: &WorkbenchApp) -> Vec<Line<'static>> {
    let Some(config) = app.data.configs.get(app.selected) else {
        return vec![Line::from("No selection")];
    };
    let preview: String = config.content.chars().take(500).collect();
    vec![
        detail_line("Path", &config.path),
        Line::from(""),
        Line::from(Span::styled(
            "Content preview:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(preview),
    ]
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label}: "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(value.to_string()),
    ])
}
