//! NTFS `$LogFile` transaction-journal integrity parser for Issen.
//!
//! Wraps `ntfs-forensic::audit_logfile`, which flags journal-clearing indicators
//! (missing restart areas / page gaps — consistent with `$LogFile` having been
//! wiped to destroy NTFS transaction history). Each finding becomes an Integrity
//! event. Findings are observations ("consistent with clearing"), never a tamper
//! verdict — the analyst/tribunal concludes.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use issen_core::artifacts::ArtifactType;
use issen_core::classify;
use issen_core::error::RtError;
use issen_core::plugin::registry::ParserRegistration;
use issen_core::plugin::selector as sel;
use issen_core::plugin::traits::{
    DataSource, EventEmitter, ForensicParser, ParseCompletion, ParseStats, ParserCapabilities,
};
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Audit raw `$LogFile` bytes into Integrity [`TimelineEvent`]s — one per
/// journal-clearing finding `ntfs-forensic` reports. Bytes that parse cleanly
/// (no clearing indicators) yield no events.
pub fn parse_logfile_bytes(bytes: &[u8], source_id: &str) -> Vec<TimelineEvent> {
    ntfs_forensic::audit_logfile(bytes)
        .into_iter()
        .map(|anomaly| {
            TimelineEvent::new(
                0,
                String::new(),
                EventType::Other("integrity".into()),
                ArtifactType::LogFile,
                "$LogFile".to_string(),
                format!(
                    "$LogFile integrity: {} — consistent with the NTFS transaction \
                     journal having been cleared",
                    anomaly.code()
                ),
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::Integrity)
            .with_tag("integrity")
            .with_metadata("code", serde_json::json!(anomaly.code()))
            .with_metadata(
                "severity",
                serde_json::json!(format!("{:?}", anomaly.severity())),
            )
        })
        .collect()
}

/// `$LogFile` integrity parser.
pub struct LogFileParser;

impl ForensicParser for LogFileParser {
    // The trait mandates `-> &str`; the literal bound is unavoidable.
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "$LogFile Parser"
    }

    fn supported_artifacts(&self) -> &[ArtifactType] {
        &[ArtifactType::LogFile]
    }

    fn parse(
        &self,
        input: &dyn DataSource,
        emitter: &dyn EventEmitter,
    ) -> Result<ParseStats, RtError> {
        let mut stats = ParseStats::new();
        let len = input.len();
        if len == 0 {
            stats.completion = ParseCompletion::Unsupported;
            return Ok(stats);
        }
        let mut bytes = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
        let mut off = 0u64;
        while off < len {
            let n = input.read_at(off, &mut bytes[off as usize..])?;
            if n == 0 {
                break;
            }
            off += n as u64;
        }
        stats.bytes_processed = off;
        let events = parse_logfile_bytes(&bytes[..off as usize], "logfile-evidence");
        stats.events_emitted = events.len() as u64;
        if !events.is_empty() {
            emitter.emit_batch(events)?;
        }
        stats.completion = ParseCompletion::Complete;
        Ok(stats)
    }

    fn capabilities(&self) -> ParserCapabilities {
        ParserCapabilities {
            // $LogFile defaults to 64 MiB; allow headroom.
            max_memory_bytes: Some(128 * 1024 * 1024),
            streaming: false,
            deterministic: true,
        }
    }
}

inventory::submit! {
    ParserRegistration { create: || Box::new(LogFileParser), selector: sel::ArtifactSelector {
            artifact_type: ArtifactType::LogFile,
            matches: classify::logfile,
            priority: 95,
            disk_sources: &[sel::DiskSource::Ntfs(sel::NtfsLoc::FixedPath(r"\$LogFile"))],
            cost: sel::CostTier::Default,
        } }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn cleared_logfile_yields_integrity_event() {
        // A $LogFile with no restart area (degenerate case: empty) is consistent
        // with the journal having been cleared.
        let events = parse_logfile_bytes(&[], "ev");
        assert_eq!(events.len(), 1, "one clearing finding -> one event");
        let e = &events[0];
        assert_eq!(
            e.activity_category,
            Some(issen_core::ActivityCategory::Integrity),
            "a journal-clearing finding is an Integrity observation"
        );
        assert!(
            e.description.contains("NTFS-LOGFILE-CLEARED"),
            "got: {}",
            e.description
        );
        assert!(
            e.metadata.iter().any(|(k, _)| k == "code"),
            "must carry the finding code"
        );
    }

    #[test]
    fn valid_logfile_yields_no_events() {
        // A $LogFile with a real restart-area page (RSTR) is not cleared.
        let mut page = vec![0u8; 0x1000];
        page[0..4].copy_from_slice(b"RSTR");
        page[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
        page[0x20..0x24].copy_from_slice(&4096u32.to_le_bytes());
        page[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        assert!(
            parse_logfile_bytes(&page, "ev").is_empty(),
            "a $LogFile with a restart area must not be flagged cleared"
        );
    }

    #[test]
    fn supported_artifact_is_logfile() {
        assert_eq!(
            LogFileParser.supported_artifacts(),
            &[ArtifactType::LogFile]
        );
    }
}
