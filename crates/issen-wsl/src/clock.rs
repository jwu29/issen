//! WSL2 clock calibration and DrvFs timestamp normalization.

/// Which clock produced a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    /// Windows EVTX / NTFS (100ns precision, Windows epoch).
    WindowsHost,
    /// Linux clock inside WSL2 Hyper-V VM (nanosecond precision, Unix epoch).
    WslLinux,
    /// DrvFs-accessed file (1-second precision due to kernel clamping).
    DrvFs,
}

/// WSL2 clock calibration state.
#[derive(Debug, Clone)]
pub struct ClockCalibration {
    /// Measured offset in milliseconds: wsl_time + drift_ms = windows_time.
    drift_ms: i64,
}

impl ClockCalibration {
    pub fn new(_drift_ms: i64) -> Self {
        todo!("implement new")
    }

    pub fn drift_ms(&self) -> i64 {
        todo!("implement drift_ms")
    }

    /// Adjust a WSL nanosecond timestamp to Windows epoch nanoseconds.
    pub fn wsl_to_windows_ns(&self, _wsl_ns: i64) -> i64 {
        todo!("implement wsl_to_windows_ns")
    }

    /// Adjust a WSL timestamp, returning (adjusted_ns, source_tag).
    pub fn adjust_with_source(&self, _wsl_ns: i64, _source: TimestampSource) -> (i64, TimestampSource) {
        todo!("implement adjust_with_source")
    }

    /// Derive calibration from a pair of timestamps for the same event:
    /// `windows_ns` from EVTX, `wsl_ns` from Linux log.
    pub fn from_event_pair(_windows_ns: i64, _wsl_ns: i64) -> Self {
        todo!("implement from_event_pair")
    }

    /// Returns `true` if `ts_ns` looks like a DrvFs-clamped timestamp
    /// (no sub-second component → whole number of seconds).
    pub fn is_likely_drvfs_clamped(_ts_ns: i64) -> bool {
        todo!("implement is_likely_drvfs_clamped")
    }

    /// Returns a (lo, hi) window in nanoseconds around the adjusted timestamp.
    pub fn uncertainty_window_ns(&self, _ts_ns: i64, _uncertainty_ms: i64) -> (i64, i64) {
        todo!("implement uncertainty_window_ns")
    }
}
