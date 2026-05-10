//! HybridScope: Windows+WSL forensic analysis.
//!
//! Provides path normalization, timestamp calibration, WSL session linking,
//! and forensic narrative pattern detection across the three address spaces
//! present in a Windows+WSL2 host: NTFS, DrvFs virtual mount, and ext4-in-VHDX.

pub mod clock;
pub mod fish_history;
pub mod hybrid_path;
pub mod session;
pub mod pattern;
