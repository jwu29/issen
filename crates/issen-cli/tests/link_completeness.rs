//! Link-completeness drift gate (issen #114 mode-2 silent-omission killer; M3).
//!
//! The parser link-anchor set is no longer hand-written under `issen-cli/src` —
//! it is owned by the `issen-parsers` aggregator, whose `build.rs` emits one real
//! `extern crate <dep> as _;` per `[dependencies]` entry. So "is this parser
//! linked?" is now answered by two complementary checks:
//!
//! 1. **Aggregator completeness (static):** every `issen-parser-*` workspace
//!    member MUST be a direct dependency of `issen-parsers` (and therefore
//!    anchored), or carry an annotated `NOT_AGGREGATED` exemption. A member that
//!    is neither is dark — its `inventory::submit!` is dead-code-eliminated and it
//!    never runs in `run_auto`/the supertimeline.
//! 2. **Runtime smoke (dynamic):** with `issen_cli` linked, the live
//!    `all_parsers()` registry is non-empty and contains known *multi*-
//!    registration parser names — proving the gate counts parser **registrations**
//!    (one crate, here, registers four) and that the aggregator anchor chain
//!    actually reaches a library-linked harness.
//!
//! This file links `issen_cli` (the root anchor) so the inventory is populated;
//! a bare crate dependency would leave `all_parsers()` empty.

#![allow(clippy::unwrap_used, clippy::expect_used)]

extern crate issen_cli as _;

use std::fs;
use std::path::{Path, PathBuf};

use issen_core::plugin::registry::all_parsers;

/// `issen-parser-*` workspace members intentionally NOT made deps of the
/// `issen-parsers` aggregator. Each entry MUST carry a reason — excluding a
/// parser from the aggregator is a deliberate, reviewed act, never an accident.
const NOT_AGGREGATED: &[(&str, &str)] = &[(
    "issen-parser-biome",
    "Linked into issen-cli via a direct `commands::biome::run` reference \
         (a real code path, not just an anchor), so it does not need an \
         aggregator anchor; it stays a direct issen-cli dependency.",
)];

/// Workspace root (two levels up from `crates/issen-cli`).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Direct normal deps declared under `[dependencies]` in a crate's manifest.
fn manifest_dep_names(manifest: &Path) -> Vec<String> {
    let text =
        fs::read_to_string(manifest).unwrap_or_else(|e| panic!("read {}: {e}", manifest.display()));
    let value: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("parse {}: {e}", manifest.display()));
    value
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default()
}

/// Every `issen-parser-*` directory under `crates/parsers`.
fn parser_members(root: &Path) -> Vec<String> {
    let mut members: Vec<String> = fs::read_dir(root.join("crates/parsers"))
        .expect("read crates/parsers")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("issen-parser-"))
        .collect();
    members.sort();
    members
}

#[test]
fn every_parser_crate_is_aggregated_or_exempt() {
    let root = workspace_root();
    let aggregator_deps = manifest_dep_names(&root.join("crates/issen-parsers/Cargo.toml"));
    let exempt: Vec<&str> = NOT_AGGREGATED.iter().map(|(c, _)| *c).collect();

    let dark: Vec<String> = parser_members(&root)
        .into_iter()
        .filter(|m| !aggregator_deps.contains(m) && !exempt.contains(&m.as_str()))
        .collect();

    assert!(
        dark.is_empty(),
        "these parser crates are neither a dependency of `issen-parsers` (so they \
         get no generated link anchor) nor an annotated NOT_AGGREGATED exemption — \
         their inventory registrations are dead-code-eliminated and they will NEVER \
         run in run_auto/supertimeline (mode-2 silent omission). Add them to \
         crates/issen-parsers/Cargo.toml or add a reasoned NOT_AGGREGATED entry: {dark:?}"
    );
}

#[test]
fn aggregator_has_no_phantom_parser_deps() {
    // The aggregator must not declare a parser dep that has no workspace member
    // (a typo or a removed crate would leave a stale anchor that fails to build,
    // but guard the manifest directly for a clearer diagnostic).
    let root = workspace_root();
    let members = parser_members(&root);
    let phantom: Vec<String> = manifest_dep_names(&root.join("crates/issen-parsers/Cargo.toml"))
        .into_iter()
        .filter(|d| d.starts_with("issen-parser-") && !members.contains(d))
        .collect();
    assert!(
        phantom.is_empty(),
        "`issen-parsers` declares parser deps with no matching crates/parsers member: {phantom:?}"
    );
}

#[test]
fn live_registry_counts_registrations_not_crates() {
    // Runtime complement: the aggregator anchor chain must actually reach this
    // library-linked harness. A crate-count gate would be WRONG — issen-parser-
    // linux registers FOUR parsers and issen-parser-macos TWO — so we assert the
    // live registry contains the individual multi-registration *names*, proving
    // we count registrations, and that the anchor for that one crate links all of
    // its submissions.
    let names: Vec<String> = all_parsers().iter().map(|p| p.name().to_string()).collect();

    assert!(
        !names.is_empty(),
        "all_parsers() is empty — the issen_cli root anchor / aggregator chain is \
         broken and no parser registration reached this harness"
    );

    // The four distinct registrations from the single issen-parser-linux crate.
    for expected in [
        "Linux Auth Log Parser",
        "Linux Syslog Parser",
        "Linux Cron Log Parser",
        "Linux Bash History Parser",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "live registry missing multi-registration parser {expected:?} — the \
             issen-parser-linux anchor did not link all of its inventory submissions \
             (have: {names:?})"
        );
    }
}
