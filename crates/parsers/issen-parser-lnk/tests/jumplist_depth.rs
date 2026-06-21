//! Jump List parser-depth regression (Track 2 / un-darkening `ArtifactType::JumpLists`).
//!
//! Jump Lists are per-application recent/pinned file history — RecentDocs-equivalent
//! evidence that survives the target file's deletion. lnk-core decodes both forms;
//! the wrapper must surface each entry's target + origin.
//!
//! Real captured Jump Lists from DC01 (DFIR Madness "Stolen Szechuan Sauce").
//! `9b9cdc69c1c24e2b.automaticDestinations-ms` (Notepad AppID): five DestList
//! entries for secret files under `C:\FileShare\Secret\`, recorded on host
//! `citadel-dc01`. `28c8b86deab549a1.customDestinations-ms` (Internet Explorer
//! AppID): custom-destination entries targeting `iexplore.exe`.

use issen_parser_lnk::jumplist::parse_jumplist_bytes;

const AUTO: &[u8] = include_bytes!("data/9b9cdc69c1c24e2b.automaticDestinations-ms");
const CUSTOM: &[u8] = include_bytes!("data/28c8b86deab549a1.customDestinations-ms");
const AUTO_NAME: &str = "9b9cdc69c1c24e2b.automaticDestinations-ms";
const CUSTOM_NAME: &str = "28c8b86deab549a1.customDestinations-ms";

fn searchable(events: &[issen_core::timeline::event::TimelineEvent]) -> String {
    events
        .iter()
        .flat_map(|e| {
            std::iter::once(e.description.clone())
                .chain(e.metadata.iter().map(|(k, v)| format!("{k}={v}")))
        })
        .collect::<Vec<_>>()
        .join("  ")
}

#[test]
fn automatic_destinations_surfaces_recent_file_and_origin() {
    let events = parse_jumplist_bytes(AUTO, AUTO_NAME, "ev");
    assert!(
        !events.is_empty(),
        "the Jump List parses to at least one event"
    );
    let blob = searchable(&events);
    assert!(
        blob.contains("Szechuan Sauce.txt"),
        "must surface the recent-file target the Jump List records; got: {blob}"
    );
    assert!(
        blob.to_lowercase().contains("citadel-dc01"),
        "must surface the recording host (a cross-machine origin signal); got: {blob}"
    );
}

#[test]
fn automatic_destinations_marks_pinned_state() {
    let events = parse_jumplist_bytes(AUTO, AUTO_NAME, "ev");
    let blob = searchable(&events).to_lowercase();
    assert!(
        blob.contains("pinned"),
        "must surface the pinned state (pinned items are deliberately retained); got: {blob}"
    );
}

#[test]
fn custom_destinations_surfaces_target() {
    let events = parse_jumplist_bytes(CUSTOM, CUSTOM_NAME, "ev");
    assert!(
        !events.is_empty(),
        "the custom Jump List parses to at least one event"
    );
    let blob = searchable(&events);
    assert!(
        blob.contains("iexplore.exe"),
        "must surface the custom-destination target; got: {blob}"
    );
}
