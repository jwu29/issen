//! Reachability gate (issen #114) — the reverse of `producer_coverage`.
//!
//! `producer_coverage` proves every type the classifier *emits* has a parser.
//! This proves the other direction: every `ArtifactType` a registered parser
//! *advertises* (`supported_artifacts`) is reachable — i.e. `detect_artifact_type`
//! can classify some file to it — or is on an explicit EXEMPT list (types routed
//! by a path other than filesystem discovery). A parser advertising an
//! unclassified, non-exempt type is wired-but-unreachable: discovery never feeds
//! it, so it silently produces nothing end-to-end (the gap that hid the inert
//! lnk/auth.log wirings — green unit tests, zero events on real ingest).
//!
//! Static (the `inventory` registry is empty outside the `issen` binary): the
//! advertised set is scraped from `supported_artifacts()` across the parser
//! crates; the classified set from `detect_artifact_type`'s body.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Types advertised by a parser but intentionally NOT reached via
/// `detect_artifact_type` filename classification — routed another way:
/// - `BiomeMenuItem`: produced by the dedicated `issen biome` command.
/// - `Shellbags`: derived from registry hives (already classified as `Registry`),
///   not from a standalone shellbags file.
const EXEMPT: &[&str] = &["BiomeMenuItem", "Shellbags"];

fn concat_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            concat_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = fs::read_to_string(&path) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
}

/// `ArtifactType` variants `detect_artifact_type` can return.
fn classified_types(workspace: &Path) -> BTreeSet<String> {
    let src = fs::read_to_string(workspace.join("crates/issen-fswalker/src/orchestrator.rs"))
        .expect("read orchestrator.rs");
    let start = src
        .find("fn detect_artifact_type")
        .expect("classifier present");
    let after = &src[start..];
    let end = after[1..]
        .find("\nfn ")
        .or_else(|| after[1..].find("\npub fn "))
        .map_or(after.len(), |i| i + 1);
    extract_types(&after[..end])
}

/// `ArtifactType` variants any parser advertises via `supported_artifacts`.
fn advertised_types(workspace: &Path) -> BTreeSet<String> {
    let mut src = String::new();
    concat_rs(&workspace.join("crates/parsers"), &mut src);
    let mut types = BTreeSet::new();
    // Each `fn supported_artifacts(...) -> &[ArtifactType] { &[ ... ] }` body.
    for piece in src.split("fn supported_artifacts").skip(1) {
        // bound to the function body's first `{ ... }` end-ish — cheap heuristic:
        // take up to the next `fn ` to avoid bleeding into siblings.
        let body = &piece[..piece.find("\n    fn ").unwrap_or(piece.len().min(400))];
        types.extend(extract_types(body));
    }
    types
}

fn extract_types(s: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for p in s.split("ArtifactType::").skip(1) {
        let name: String = p.chars().take_while(char::is_ascii_alphanumeric).collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

#[test]
fn every_advertised_type_is_reachable_or_exempt() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let advertised = advertised_types(&workspace);
    let classified = classified_types(&workspace);
    let exempt: BTreeSet<String> = EXEMPT.iter().map(|s| (*s).to_string()).collect();

    assert!(
        !advertised.is_empty() && !classified.is_empty(),
        "scrape produced empty sets — the source parse broke"
    );

    let unreachable: Vec<&String> = advertised
        .iter()
        .filter(|t| !classified.contains(*t) && !exempt.contains(*t))
        .collect();

    assert!(
        unreachable.is_empty(),
        "parser(s) advertise ArtifactType(s) that detect_artifact_type never \
         classifies, so discovery never routes a file to them — wired-but-\
         unreachable: {unreachable:?}. Classify the file in detect_artifact_type, \
         or (if routed another way) add the type to EXEMPT with a note."
    );
}

#[test]
fn gate_has_teeth() {
    // The classifier must really emit several types and the parsers advertise
    // them — otherwise the gate passes vacuously.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let classified = classified_types(&workspace);
    let advertised = advertised_types(&workspace);
    assert!(
        classified.contains("LoginHistory") && classified.contains("Lnk"),
        "classifier should emit the just-added LoginHistory/Lnk types"
    );
    assert!(
        advertised.contains("SystemInfo") && advertised.contains("CrontabConfig"),
        "the linux/macos parsers should advertise SystemInfo/CrontabConfig"
    );
}
