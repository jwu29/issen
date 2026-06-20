//! Pure presentation logic for the live ingest display (Humble Object): map a
//! [`ProgressSnapshot`] to display strings. Everything here is deterministic and
//! unit-tested; the indicatif draw shell that calls it stays thin and untested.

#[cfg(test)]
mod tests {
    use super::*;
    use issen_fswalker::progress::{Phase, ProgressSnapshot};
    use std::time::Duration;

    fn snap(phase: Phase, completed: u64, total: u64) -> ProgressSnapshot {
        ProgressSnapshot {
            phase,
            artifacts_total: total,
            artifacts_completed: completed,
            events_emitted: 0,
            bytes_processed: 0,
            errors_encountered: 0,
        }
    }

    #[test]
    fn percent_is_completed_over_total_or_none_when_unknown() {
        assert_eq!(percent(&snap(Phase::Parsing, 100, 400)), Some(25));
        assert_eq!(percent(&snap(Phase::Parsing, 400, 400)), Some(100));
        assert_eq!(
            percent(&snap(Phase::Discovering, 0, 0)),
            None,
            "total unknown"
        );
    }

    #[test]
    fn events_per_sec_rounds_and_guards_zero_elapsed() {
        assert_eq!(events_per_sec(1000, Duration::from_secs(2)), 500);
        assert_eq!(events_per_sec(100, Duration::ZERO), 0, "no divide-by-zero");
    }

    #[test]
    fn eta_extrapolates_rate_or_none_without_one() {
        assert_eq!(
            eta(100, 400, Duration::from_secs(10)),
            Some(Duration::from_secs(30)),
            "100 of 400 in 10s -> 300 left at 10/s -> 30s"
        );
        assert_eq!(eta(0, 400, Duration::from_secs(10)), None, "no rate yet");
        assert_eq!(eta(400, 400, Duration::from_secs(10)), Some(Duration::ZERO));
        assert_eq!(eta(100, 0, Duration::from_secs(10)), None, "total unknown");
    }

    #[test]
    fn humanize_count_compacts_thousands_and_millions() {
        assert_eq!(humanize_count(950), "950");
        assert_eq!(humanize_count(18_400), "18.4k");
        assert_eq!(humanize_count(2_500_000), "2.5M");
    }

    #[test]
    fn humanize_bytes_scales_units() {
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(1_288_490_189), "1.2 GB");
    }

    #[test]
    fn phase_label_is_human_readable() {
        assert_eq!(phase_label(Phase::Queued), "queued");
        assert_eq!(phase_label(Phase::Extracting), "extracting");
        assert_eq!(phase_label(Phase::Parsing), "parsing");
        assert_eq!(phase_label(Phase::Done), "done");
    }

    #[test]
    fn status_line_carries_progress_events_and_errors() {
        let s = ProgressSnapshot {
            phase: Phase::Parsing,
            artifacts_total: 417,
            artifacts_completed: 312,
            events_emitted: 18_400,
            bytes_processed: 0,
            errors_encountered: 3,
        };
        let line = status_line(&s, Duration::from_secs(36));
        assert!(line.contains("312/417"), "got: {line}");
        assert!(line.contains("74%"), "got: {line}");
        assert!(line.contains("18.4k"), "got: {line}");
        assert!(line.contains("3 error"), "got: {line}");
    }

    #[test]
    fn status_line_during_discovery_shows_no_bogus_percent() {
        let s = snap(Phase::Discovering, 0, 0);
        let line = status_line(&s, Duration::from_secs(2));
        assert!(line.contains("discovering"), "got: {line}");
        assert!(
            !line.contains('%'),
            "no percent before the total is known: {line}"
        );
    }
}
