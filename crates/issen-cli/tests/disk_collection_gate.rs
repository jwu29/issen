//! Disk-collection completeness gate (issen #114).
//!
//! `reachability_gate` proves advertised↔classified; `producer_coverage` proves
//! every classified type has a parser. Neither checks the COLLECTION layer — the
//! step that pulls artifact bytes off a raw NTFS disk image. This gate closes
//! that gap: every `ArtifactType` the filename classifier can DISCOVER must also
//! be COLLECTED by `issen_disk::extract_triage`'s allow-lists — or be on an
//! explicit EXEMPT list with a stated reason.
//!
//! A classified-but-uncollected type is the dark-on-disk bug class: live on
//! loose-file / KAPE ingest (the walker classifies every file) yet silently
//! producing nothing on a raw E01, because the hand-maintained `WINDOWS_*`
//! extraction lists never pulled its bytes. That is exactly how `.lnk`, `$I`,
//! and `setupapi.dev.log` went dark on disk images while their parsers existed,
//! were registered, anchored, and classified.
//!
//! Method: the COLLECTED set is derived at runtime by running the real
//! `WINDOWS_*` extraction targets through `detect_artifact_type`; the CLASSIFIED
//! set is scraped from the classifier body. The diff, minus EXEMPT, must be
//! empty.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use issen_disk::{
    WINDOWS_TRIAGE_GLOBS, WINDOWS_TRIAGE_PATHS, WINDOWS_TRIAGE_STREAMS, WINDOWS_USER_FILES,
    WINDOWS_USER_LNK_DIRS,
};
use issen_fswalker::orchestrator::detect_artifact_type;

/// Types the filename classifier can discover but that disk-image triage
/// intentionally does NOT collect — each with the reason it is exempt:
/// - `Pe`: cost policy — carving every executable off an image is too expensive;
///   PE collection is opt-in, not part of default triage.
/// - `SystemInfo` / `LoginHistory` / `CrontabConfig`: Linux/macOS artifacts.
///   `extract_triage` walks NTFS only; there is no ext4/APFS extraction path yet.
const EXEMPT: &[&str] = &["Pe", "SystemInfo", "LoginHistory", "CrontabConfig"];

/// The `ArtifactType` variant names `detect_artifact_type` can return, scraped
/// from its body (it is a pure path→type function; no parser registry needed).
fn classified_types() -> BTreeSet<String> {
    let src =
        std::fs::read_to_string(workspace_root().join("crates/issen-fswalker/src/orchestrator.rs"))
            .expect("read orchestrator.rs");
    let start = src
        .find("fn detect_artifact_type")
        .expect("classifier present");
    let body = &src[start..];
    let end = body[1..]
        .find("\nfn ")
        .or_else(|| body[1..].find("\npub fn "))
        .map_or(body.len(), |i| i + 1);
    let mut out = BTreeSet::new();
    let mut rest = &body[..end];
    while let Some(i) = rest.find("ArtifactType::") {
        rest = &rest[i + "ArtifactType::".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// The `ArtifactType`s actually COLLECTED off an NTFS image, derived by running
/// every real `WINDOWS_*` extraction target through the classifier.
fn collected_types() -> BTreeSet<String> {
    let mut paths: Vec<String> = Vec::new();
    for p in WINDOWS_TRIAGE_PATHS {
        paths.push((*p).to_string());
    }
    for g in WINDOWS_TRIAGE_GLOBS {
        paths.push(format!(r"{}\sample{}", g.dir, g.suffix));
    }
    for c in WINDOWS_USER_FILES {
        paths.push(format!(r"\Users\u\{c}"));
    }
    for rel in WINDOWS_USER_LNK_DIRS {
        paths.push(format!(r"\Users\u\{rel}\sample.lnk"));
    }
    for (p, _stream) in WINDOWS_TRIAGE_STREAMS {
        paths.push((*p).to_string());
    }
    // Code sweeps not expressible as a const: the per-SID `$Recycle.Bin\$I*`.
    paths.push(r"\$Recycle.Bin\S-1-5-21-1-1-1-500\$ISAMPLE.txt".to_string());

    // Extraction writes a `/`-separated temp tree, so the classifier sees real
    // basenames. Mirror that: a `\`-path on a Unix host would not split, making
    // `file_name()` return the whole string and breaking every exact-name arm.
    paths
        .iter()
        .filter_map(|p| {
            let unix = format!("/img/{}", p.replace('\\', "/").trim_start_matches('/'));
            detect_artifact_type(Path::new(&unix)).map(|t| format!("{t:?}"))
        })
        .collect()
}

fn workspace_root() -> PathBuf {
    // crates/issen-cli → repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_classified_windows_artifact_is_collected_on_the_disk_path() {
    let classified = classified_types();
    let collected = collected_types();
    let exempt: BTreeSet<String> = EXEMPT.iter().map(|s| (*s).to_string()).collect();

    let dark: Vec<String> = classified
        .difference(&collected)
        .filter(|t| !exempt.contains(*t))
        .cloned()
        .collect();

    assert!(
        dark.is_empty(),
        "ArtifactType(s) the classifier discovers but `extract_triage` never \
         collects off an NTFS image, and which are not on the EXEMPT list: {dark:?}.\n\
         These parsers are LIVE on loose-file ingest but DARK on raw disk images. \
         Either add the artifact's path/glob to the WINDOWS_* lists in \
         crates/issen-disk/src/lib.rs, or add the type to EXEMPT with a reason."
    );
}
