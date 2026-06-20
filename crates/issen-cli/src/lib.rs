#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::format_push_string,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::redundant_closure_for_method_calls,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::uninlined_format_args,
    clippy::elidable_lifetime_names,
    clippy::match_same_arms,
    clippy::return_self_not_must_use,
    clippy::single_match_else,
    clippy::unnested_or_patterns,
    clippy::field_reassign_with_default,
    clippy::inefficient_to_string,
    clippy::manual_strip,
    clippy::redundant_else,
    clippy::trim_split_whitespace,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::unused_self,
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::missing_fields_in_debug,
    clippy::result_unit_err,
    clippy::unreadable_literal,
    clippy::manual_contains,
    clippy::unnecessary_literal_bound
)]
//! rt-cli library entry point.
//!
//! Exposes the built-in parser modules so that integration test binaries
//! can link them and trigger their `inventory::submit!` registrations.

// Force-link the external parser crates so their `inventory::submit!`
// registrations are pulled into the binary (and the lib test harness).
extern crate issen_parser_registry as _;

pub mod commands;
pub mod parsers;
pub mod scanning;

#[cfg(test)]
mod parser_registration_tests {
    use issen_core::artifacts::ArtifactType;
    use issen_core::plugin::registry::all_parsers;

    #[test]
    fn all_parsers_includes_a_registry_parser() {
        // issen-parser-registry must be linked + inventory-registered so registry
        // hives are actually parsed during ingest (A2 link).
        let has_registry = all_parsers()
            .iter()
            .any(|p| p.supported_artifacts().contains(&ArtifactType::Registry));
        assert!(
            has_registry,
            "no registered parser supports ArtifactType::Registry — the crate is not linked"
        );
    }

    #[test]
    fn library_linked_registry_is_complete_not_just_registry() {
        // L1: the LIBRARY (not only the binary) must force-link every parser, or any
        // library-linked harness — lib unit tests, `tests/*.rs` using `use issen_cli`,
        // external consumers — sees an incomplete registry. This is the lib/bin skew
        // the supertimeline bug exposed. A lib unit test's link set == the library's
        // anchors, so it fails here until L1 moves all anchors into lib.rs.
        let supported: std::collections::HashSet<ArtifactType> = all_parsers()
            .iter()
            .flat_map(|p| p.supported_artifacts().iter().copied())
            .collect();
        for t in [
            ArtifactType::Registry,
            ArtifactType::Mft,
            ArtifactType::UsnJournal,
            ArtifactType::Lnk,
            ArtifactType::Prefetch,
            ArtifactType::Amcache,
            ArtifactType::EventLog,
        ] {
            assert!(
                supported.contains(&t),
                "library-linked registry missing a producer for {t:?} — force-link \
                 anchors must live in lib.rs, not only main.rs (L1)"
            );
        }
    }
}
