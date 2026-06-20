//! LNK (Shell Link) header parsing for Windows `.lnk` files.
//!
//! Parses the fixed 76-byte Shell Link header and emits up to three
//! [`TimelineEvent`]s (one per non-zero FILETIME timestamp).
//!
//! Header layout (all values little-endian):
//!
//! | Offset | Size | Field          |
//! |--------|------|----------------|
//! | 0      | 4    | Signature      | `0x4C 0x00 0x00 0x00`
//! | 4      | 16   | LinkCLSID      | (skipped)
//! | 20     | 4    | LinkFlags      |
//! | 24     | 4    | FileAttributes |
//! | 28     | 8    | CreationTime   | FILETIME (u64 LE)
//! | 36     | 8    | AccessTime     | FILETIME (u64 LE)
//! | 44     | 8    | WriteTime      | FILETIME (u64 LE)
//! | 52     | 4    | FileSize       |
//! | 56     | 4    | IconIndex      |
//! | 60     | 4    | ShowCommand    |
//! | 64     | 2    | HotKey         |

use std::path::Path;

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Human label for a `VolumeID` DriveType ([MS-SHLLINK] §2.3.1).
fn drive_type_label(dt: u32) -> &'static str {
    match dt {
        1 => "NO_ROOT_DIR",
        2 => "REMOVABLE",
        3 => "FIXED",
        4 => "REMOTE",
        5 => "CDROM",
        6 => "RAMDISK",
        _ => "UNKNOWN",
    }
}

/// Parse a Windows LNK (Shell Link) file and return [`TimelineEvent`]s.
///
/// Emits up to three events:
/// - [`EventType::FileCreate`] from `CreationTime` (skipped if zero)
/// - [`EventType::FileAccess`] from `AccessTime` (skipped if zero)
/// - [`EventType::FileModify`] from `WriteTime` (skipped if zero)
///
/// Returns `Ok(vec![])` for:
/// - Files shorter than 76 bytes.
/// - Files whose first four bytes are not the LNK signature.
///
/// # Errors
/// Returns `Err` only on unrecoverable I/O failures.
pub fn parse_lnk(path: &Path, source_id: &str) -> anyhow::Result<Vec<TimelineEvent>> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    Ok(parse_lnk_bytes(&raw, &path.to_string_lossy(), source_id))
}

/// Parse LNK header bytes into timeline events.
///
/// The byte-level core shared by the path-based [`parse_lnk`] and the
/// `ForensicParser` trait impl (which reads bytes from a `DataSource` and has no
/// file path of its own). `artifact_path` labels the events and supplies the
/// display filename; `source_id` tags their source. A too-short buffer or a bad
/// signature yields no events (never an error).
#[must_use]
pub fn parse_lnk_bytes(raw: &[u8], artifact_path: &str, source_id: &str) -> Vec<TimelineEvent> {
    let Some(link) = lnk_core::parse_shell_link(raw) else {
        return vec![];
    };
    let h = &link.header;
    let info = link.link_info.as_ref();

    let filename = Path::new(artifact_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.lnk");

    // The target the shortcut points to — the primary forensic value the old
    // header-only parser dropped. Prefer the LinkInfo local base path, then the
    // StringData relative path, then the reconstructed PIDL path.
    let target = info
        .and_then(|i| i.local_base_path.clone())
        .or_else(|| link.string_data.relative_path.clone())
        .or_else(|| link.link_target_idlist.as_ref().and_then(|t| t.path.clone()));

    let description = match &target {
        Some(t) => format!("LNK shortcut {filename} \u{2192} {t}"),
        None => format!("LNK shortcut: {filename}"),
    };

    // Metadata shared by every emitted event.
    let mut meta: Vec<(&str, serde_json::Value)> = vec![
        ("file_size", serde_json::json!(h.file_size)),
        ("link_flags", serde_json::json!(format!("0x{:08X}", h.link_flags))),
        (
            "file_attributes",
            serde_json::json!(format!("0x{:08X}", h.file_attributes)),
        ),
    ];
    if let Some(t) = &target {
        meta.push(("target_path", serde_json::json!(t)));
    }
    if let Some(v) = info.and_then(|i| i.volume_id.as_ref()) {
        meta.push((
            "drive_serial",
            serde_json::json!(format!("0x{:08X}", v.drive_serial_number)),
        ));
        meta.push(("drive_type", serde_json::json!(drive_type_label(v.drive_type))));
        if let Some(label) = &v.volume_label {
            meta.push(("volume_label", serde_json::json!(label)));
        }
    }

    let timestamps = [
        (h.creation_time, EventType::FileCreate),
        (h.access_time, EventType::FileAccess),
        (h.write_time, EventType::FileModify),
    ];
    let mut events = Vec::with_capacity(3);
    for (secs, event_type) in timestamps {
        if secs == 0 {
            continue;
        }
        let ts_ns = secs.saturating_mul(1_000_000_000);
        let mut event = TimelineEvent::new(
            ts_ns,
            String::new(),
            event_type,
            ArtifactType::Lnk,
            artifact_path.to_string(),
            description.clone(),
            source_id.to_string(),
        )
        .with_activity_category(issen_core::ActivityCategory::FileSystemActivity);
        for (k, value) in &meta {
            event = event.with_metadata(*k, value.clone());
        }
        events.push(event);
    }
    events
}
