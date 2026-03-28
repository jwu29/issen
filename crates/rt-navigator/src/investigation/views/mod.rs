pub mod supertimeline;

use ratatui::layout::Rect;
use ratatui::Frame;

use super::{WorkbenchApp, WorkbenchView};

/// Render the current view's list content in the given area.
pub fn draw_view(frame: &mut Frame, app: &WorkbenchApp, area: Rect) {
    match app.current_view() {
        // Dashboard is handled separately by dashboard.rs;
        // MftTree is handled by delegation to existing App.
        WorkbenchView::Dashboard | WorkbenchView::MftTree => {}
        WorkbenchView::Timeline => supertimeline::draw(frame, app, area),
        // Artifact views — will be added in Task 6
        WorkbenchView::Network
        | WorkbenchView::Processes
        | WorkbenchView::Logins
        | WorkbenchView::Packages
        | WorkbenchView::Configs
        | WorkbenchView::Hashes
        | WorkbenchView::Chkrootkit => {
            // Placeholder: render empty block until Task 6 adds these
            let block = ratatui::widgets::Block::default()
                .borders(ratatui::widgets::Borders::ALL)
                .title(format!(" {} (coming soon) ", app.current_view().label()));
            frame.render_widget(block, area);
        }
    }
}
