//! WSL2 clock calibration and DrvFs timestamp normalization.

/// Which clock produced a timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    WindowsHost,
    WslLinux,
    DrvFs,
}

/// WSL2 clock calibration state.
#[derive(Debug, Clone)]
pub struct ClockCalibration {
    /// Measured offset in milliseconds: wsl_time + drift_ms = windows_time.
    drift_ms: i64,
}

impl ClockCalibration {
    pub fn new(drift_ms: i64) -> Self {
        Self { drift_ms }
    }

    pub fn drift_ms(&self) -> i64 {
        self.drift_ms
    }

    pub fn wsl_to_windows_ns(&self, wsl_ns: i64) -> i64 {
        wsl_ns + self.drift_ms * 1_000_000
    }

    pub fn adjust_with_source(&self, wsl_ns: i64, source: TimestampSource) -> (i64, TimestampSource) {
        (self.wsl_to_windows_ns(wsl_ns), source)
    }

    /// Derive calibration from a pair of timestamps for the same event.
    pub fn from_event_pair(windows_ns: i64, wsl_ns: i64) -> Self {
        let diff_ns = windows_ns - wsl_ns;
        Self { drift_ms: diff_ns / 1_000_000 }
    }

    /// Returns `true` if `ts_ns` has no sub-second component (likely DrvFs clamped).
    pub fn is_likely_drvfs_clamped(ts_ns: i64) -> bool {
        ts_ns % 1_000_000_000 == 0
    }

    /// Returns a (lo, hi) window around the adjusted timestamp.
    pub fn uncertainty_window_ns(&self, ts_ns: i64, uncertainty_ms: i64) -> (i64, i64) {
        let adjusted = self.wsl_to_windows_ns(ts_ns);
        let half = uncertainty_ms * 1_000_000;
        (adjusted - half, adjusted + half)
    }
}
