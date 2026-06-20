//! RED tests for ClockCalibration — WSL2 clock drift and DrvFs timestamp normalization.
//!
//! Two distinct problems:
//! 1. WSL2 VM clock drift: Linux clock in Hyper-V can drift from Windows host.
//! 2. DrvFs timestamp clamping: NTFS 100ns timestamps truncated to 1-second
//!    precision when accessed from WSL (stat() returns whole seconds).


use issen_wsl::clock::{ClockCalibration, TimestampSource};

// ── Test 1: zero drift means timestamps unchanged ────────────────────────────

#[test]
fn zero_drift_no_adjustment() {
    let cal = ClockCalibration::new(0);
    let wsl_ts = 1_000_000_000i64; // 1 second in nanoseconds
    assert_eq!(cal.wsl_to_windows_ns(wsl_ts), wsl_ts);
}

// ── Test 2: positive drift shifts WSL time forward ────────────────────────────

#[test]
fn positive_drift_shifts_forward() {
    // WSL clock is 500ms behind Windows: adjust by +500ms
    let drift_ms = 500i64;
    let cal = ClockCalibration::new(drift_ms);
    let wsl_ts = 1_000_000_000i64;
    let adjusted = cal.wsl_to_windows_ns(wsl_ts);
    assert_eq!(adjusted, wsl_ts + drift_ms * 1_000_000);
}

// ── Test 3: negative drift shifts WSL time backward ──────────────────────────

#[test]
fn negative_drift_shifts_backward() {
    let drift_ms = -200i64;
    let cal = ClockCalibration::new(drift_ms);
    let wsl_ts = 2_000_000_000i64;
    let adjusted = cal.wsl_to_windows_ns(wsl_ts);
    assert_eq!(adjusted, wsl_ts + drift_ms * 1_000_000);
}

// ── Test 4: DrvFs clamping detected when sub-second bits are zero ─────────────

#[test]
fn drvfs_clamping_detected() {
    // A timestamp that is exactly a whole second is suspect (DrvFs clamped).
    let ts_whole_second = 1_716_000_000_000_000_000i64; // exact second in nanos
    assert!(
        ClockCalibration::is_likely_drvfs_clamped(ts_whole_second),
        "timestamp with no sub-second component should be flagged as likely clamped"
    );
}

// ── Test 5: high-resolution timestamp is not clamped ─────────────────────────

#[test]
fn high_res_timestamp_not_clamped() {
    let ts_hires = 1_716_000_000_123_456_789i64; // has nanosecond component
    assert!(
        !ClockCalibration::is_likely_drvfs_clamped(ts_hires),
        "timestamp with sub-second component should not be flagged"
    );
}

// ── Test 6: source tagging ────────────────────────────────────────────────────

#[test]
fn source_tagging_roundtrip() {
    let cal = ClockCalibration::new(100);
    let wsl_ts = 5_000_000_000i64;
    let (adjusted, source) = cal.adjust_with_source(wsl_ts, TimestampSource::WslLinux);
    assert_eq!(source, TimestampSource::WslLinux);
    assert_eq!(adjusted, wsl_ts + 100 * 1_000_000);
}

// ── Test 7: calibration from paired events ────────────────────────────────────

#[test]
fn calibrate_from_event_pair() {
    // Windows observed a WSL process start at t=1000 ms (EVTX)
    // WSL observed the same event at t=900 ms (Linux clock)
    // → WSL is 100ms behind → drift = +100ms
    let windows_ns = 1_000_000_000i64;
    let wsl_ns = 900_000_000i64;
    let cal = ClockCalibration::from_event_pair(windows_ns, wsl_ns);
    assert_eq!(cal.drift_ms(), 100, "drift should be +100ms");
}

// ── Test 8: uncertainty window ────────────────────────────────────────────────

#[test]
fn uncertainty_window_is_symmetric() {
    let cal = ClockCalibration::new(50);
    let (lo, hi) = cal.uncertainty_window_ns(1_000_000_000i64, 200); // 200ms uncertainty
    assert!(lo < 1_000_000_000i64, "low bound should be below nominal");
    assert!(hi > 1_000_000_000i64, "high bound should be above nominal");
    assert_eq!(hi - lo, 400_000_000i64, "window width should be 2×200ms");
}
