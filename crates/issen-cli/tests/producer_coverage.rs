//! Producer-coverage gate (issen #114, mode-6A silent-omission killer).
//!
//! Every `ArtifactType` the classifier (`issen_fswalker::orchestrator::
//! detect_artifact_type`) can emit MUST be supported by at least one parser —
//! declared in that parser's `supported_artifacts()`. Otherwise artifacts of
//! that type are *discovered but never parsed*, and silently vanish from the
//! timeline (e.g. a classifier gains a type, or a parser is removed/retyped).
//!
//! This is the runtime complement to `link_completeness` (which guards that
//! parser crates are *registered* into the binary): here we guard that every
//! *classified* type has a *producer*.
//!
//! Checked statically because the `inventory` registry is empty outside the
//! `issen` binary (force-links live in `main.rs`, so an integration test sees
//! `all_parsers() == 0`). The classified set is *derived from the classifier
//! source* so the gate can never drift from `detect_artifact_type`, and each
//! type must appear in some `crates/parsers/issen-parser-*` source.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn read_all_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            read_all_rs(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = fs::read_to_string(&path) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
}

/// The `ArtifactType` variants `detect_artifact_type` references, parsed from
/// its function body so the gate stays in lockstep with the classifier.
fn classified_types(workspace: &Path) -> BTreeSet<String> {
    let src = fs::read_to_string(workspace.join("crates/issen-fswalker/src/orchestrator.rs"))
        .expect("read orchestrator.rs");
    let start = src
        .find("fn detect_artifact_type")
        .expect("classifier function present");
    let after = &src[start..];
    // Body ends at the next top-level `fn`/`pub fn` (skip char 0 so we don't
    // match this function's own signature).
    let end = after[1..]
        .find("\nfn ")
        .or_else(|| after[1..].find("\npub fn "))
        .map_or(after.len(), |i| i + 1);
    let body = &after[..end];

    let mut types = BTreeSet::new();
    for piece in body.split("ArtifactType::").skip(1) {
        let name: String = piece
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        if !name.is_empty() {
            types.insert(name);
        }
    }
    types
}

#[test]
fn every_classified_artifact_type_has_a_producing_parser() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let classified = classified_types(&workspace);
    assert!(
        !classified.is_empty(),
        "derived zero classified types — the classifier-source parse broke"
    );

    let mut parser_src = String::new();
    read_all_rs(&workspace.join("crates/parsers"), &mut parser_src);

    let missing: Vec<&String> = classified
        .iter()
        .filter(|t| !parser_src.contains(&format!("ArtifactType::{t}")))
        .collect();

    assert!(
        missing.is_empty(),
        "classified ArtifactType(s) with NO producing parser — artifacts of \
         these types are discovered but never parsed (silent timeline drop): {missing:?}. \
         Add a parser advertising the type in supported_artifacts(), or stop \
         classifying it in detect_artifact_type."
    );
}

/// Teeth check: prove the gate would actually flag a gap. A real classified type
/// (`Srum`) is found among the parser sources, while a sentinel type no parser
/// could ever declare is not — so a classified-but-unproduced type fails the
/// gate rather than passing vacuously.
#[test]
fn gate_distinguishes_produced_from_unproduced_types() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut parser_src = String::new();
    read_all_rs(&workspace.join("crates/parsers"), &mut parser_src);

    assert!(
        parser_src.contains("ArtifactType::Srum"),
        "a really-produced type must be found (else the gate over-reports)"
    );
    assert!(
        !parser_src.contains("ArtifactType::Zztotallybogussentinel"),
        "an unproduced type must be absent (so the gate's filter has teeth)"
    );
}
