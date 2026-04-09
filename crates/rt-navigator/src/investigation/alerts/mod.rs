//! Alert detection heuristics for forensic investigation data.
//!
//! Scans parsed UAC artifacts for indicators of compromise — suspicious
//! network connections, processes running from temp directories, rootkit
//! detections, and misconfigured system files.

mod auth;
mod config;
mod engine;
mod filesystem;
mod integrity;
mod malware;
mod network;
mod persistence;
mod process;
mod types;

pub use engine::{anomalies_to_alerts, detect_alerts};
pub use types::{Alert, AlertInput, AlertSeverity, WindowsEvent};
