//! Parser-depth regression (Track 2): the prefetch parser must surface the
//! LOADED-FILE LIST the owned `prefetch-core` already decodes — the DLLs and
//! other files a traced run touched — not merely their COUNT.
//!
//! The loaded-file list is the forensic payload of a `.pf`: it shows which
//! libraries an implant pulled in (anti-analysis, injection, network stacks),
//! and a path ending in the executable name is the program's own on-disk
//! origin. Reporting "51 files" throws that evidence away.
//!
//! Fixture `COREUPDATER.EXE-157C54BB.pf` is the real Stolen-Szechuan-Sauce
//! Meterpreter implant; its 51 loaded files include `NTDLL.DLL` and the Winsock
//! network stack `WS2_32.DLL`. Those strings can ONLY appear in the events if
//! the full list is surfaced (the executable's own name is excluded as an oracle
//! here — it already appears in the description independently of the list).

use issen_parser_prefetch::parser::events_from_bytes;

const COREUPDATER: &[u8] = include_bytes!("data/COREUPDATER.EXE-157C54BB.pf");

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
fn surfaces_loaded_file_list_not_just_count() {
    let events = events_from_bytes(COREUPDATER, "ev");
    assert!(
        !events.is_empty(),
        "the real prefetch parses to at least one event"
    );
    let blob = searchable(&events).to_uppercase();
    assert!(
        blob.contains("NTDLL.DLL"),
        "must surface the LOADED-FILE LIST (the DLLs a run touched), not just the \
         count; expected a path ending in NTDLL.DLL; got: {blob}"
    );
}

#[test]
fn surfaces_network_stack_dll_from_loaded_files() {
    // WS2_32.DLL (Winsock) is the implant's network stack — present only if the
    // full loaded-file list is surfaced, and forensically the point of the list.
    let events = events_from_bytes(COREUPDATER, "ev");
    let blob = searchable(&events).to_uppercase();
    assert!(
        blob.contains("WS2_32.DLL"),
        "the loaded-file list must surface the network-stack DLL the implant \
         loaded (WS2_32.DLL); got: {blob}"
    );
}
