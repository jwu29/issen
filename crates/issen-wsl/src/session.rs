//! WSL session detection — links Windows wsl.exe PIDs to Linux process trees.

use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct WslSession {
    pub distro: String,
    pub windows_pid: u32,
    pub start_win: DateTime<Utc>,
    pub end_win: Option<DateTime<Utc>>,
}
