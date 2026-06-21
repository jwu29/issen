//! Jump List parsing for Issen — `*.automaticDestinations-ms` (OLE/CFB, a DestList
//! MRU of recent items + embedded LNK sub-streams) and `*.customDestinations-ms`
//! (flat, pinned/custom items). Decoding is delegated to `lnk-core`'s readers; each
//! entry becomes a `FileSystemActivity` [`TimelineEvent`] — the per-application
//! recent/pinned file history that survives the target file's deletion.

use issen_core::artifacts::ArtifactType;
use issen_core::timeline::event::{EventType, TimelineEvent};

/// Parse Jump List bytes (dispatching on the filename suffix) into timeline
/// events: one `FileAccess` event per recorded entry. The AppID (from the DestList
/// header, else the filename stem — real files are named by the AppID hash) is
/// resolved to an application name via `forensicnomicon::jumplist::appid_name`.
/// Unrecognized / unparseable input yields an empty vec.
#[must_use]
pub fn parse_jumplist_bytes(raw: &[u8], filename: &str, source_id: &str) -> Vec<TimelineEvent> {
    let lower = filename.to_ascii_lowercase();
    let jl = if lower.ends_with(".automaticdestinations-ms") {
        lnk_core::parse_automatic_destinations(raw, Some(filename))
    } else if lower.ends_with(".customdestinations-ms") {
        lnk_core::parse_custom_destinations(raw, Some(filename))
    } else {
        None
    };
    let Some(jl) = jl else {
        return Vec::new();
    };

    let app_id = jl
        .app_id
        .clone()
        .or_else(|| filename.rsplit_once('.').map(|(stem, _)| stem.to_string()));
    let app_name = app_id
        .as_deref()
        .and_then(forensicnomicon::jumplist::appid_name);
    let kind = format!("{:?}", jl.kind);

    jl.entries
        .iter()
        .filter_map(|e| {
            // Target: the DestList path, else the embedded LNK's resolved target.
            let target = e
                .destlist
                .as_ref()
                .map(|d| d.path.clone())
                .filter(|p| !p.is_empty())
                .or_else(|| {
                    e.link
                        .link_info
                        .as_ref()
                        .and_then(|i| i.local_base_path.clone())
                })
                .or_else(|| e.link.string_data.relative_path.clone())?;

            let (ts_ns, ts_display) = match e.destlist.as_ref() {
                Some(d) if d.last_access > 0 => (
                    d.last_access.saturating_mul(1_000_000_000),
                    chrono::DateTime::from_timestamp(d.last_access, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default(),
                ),
                _ => (0, String::new()),
            };

            let description = match &app_name {
                Some(a) => format!("Jump List [{a}]: {target}"),
                None => format!("Jump List: {target}"),
            };
            let mut event = TimelineEvent::new(
                ts_ns,
                ts_display,
                EventType::FileAccess,
                ArtifactType::JumpLists,
                filename.to_string(),
                description,
                source_id.to_string(),
            )
            .with_activity_category(issen_core::ActivityCategory::FileSystemActivity)
            .with_tag("jumplist")
            .with_metadata("target_path", serde_json::json!(target))
            .with_metadata("jumplist_kind", serde_json::json!(kind));
            if let Some(a) = &app_id {
                event = event.with_metadata("app_id", serde_json::json!(a));
            }
            if let Some(a) = &app_name {
                event = event.with_metadata("app_name", serde_json::json!(a));
            }
            if let Some(d) = &e.destlist {
                event = event
                    .with_metadata("hostname", serde_json::json!(d.hostname))
                    .with_metadata("entry_number", serde_json::json!(d.entry_number))
                    .with_metadata("pinned", serde_json::json!(d.pinned));
                if let Some(ac) = d.access_count {
                    event = event.with_metadata("access_count", serde_json::json!(ac));
                }
            }
            // The embedded LNK's `TrackerDataBlock` birth-droid: the origin machine
            // (NetBIOS) + the MAC from the birth-droid object UUID-v1 node — the
            // machine where the recent file was *created*, a cross-machine origin
            // signal distinct from the recording `hostname`.
            if let Some(tracker) = &e.link.tracker {
                let mut tracker_meta: Vec<(&'static str, serde_json::Value)> = Vec::new();
                crate::parser::push_tracker_meta(&mut tracker_meta, tracker);
                for (k, v) in tracker_meta {
                    event = event.with_metadata(k, v);
                }
            }
            Some(event)
        })
        .collect()
}
