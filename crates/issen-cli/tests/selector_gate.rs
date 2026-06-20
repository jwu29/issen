//! Selector consistency gate (issen #114, Stage 1).
//!
//! Every registered parser must declare an [`ArtifactSelector`] whose
//! `artifact_type` is one the parser advertises via `supported_artifacts()`.
//! This is the Stage-1 contract: the single-source-of-truth selector exists and
//! is internally consistent, before Stage 2 derives classification from it.
//!
//! Runtime gate over the real `inventory` (not text-scraping): `use issen_cli`
//! force-links the anchor lib so every parser crate's `inventory::submit!` fires,
//! and an under-population guard fails loudly if the anchors are ever dropped
//! from the test binary (which would otherwise let this gate false-pass).

use issen_cli as _;
use issen_core::plugin::registry::ParserRegistration;

#[test]
fn every_parser_declares_a_consistent_selector() {
    let regs: Vec<&ParserRegistration> =
        inventory::iter::<ParserRegistration>.into_iter().collect();
    assert!(
        regs.len() >= 25,
        "parser inventory under-populated ({}) — the issen-cli anchors were dropped from this \
         test binary, so the gate cannot see the parsers it must check",
        regs.len()
    );

    let mut missing = Vec::new();
    let mut inconsistent = Vec::new();
    for reg in regs {
        let parser = (reg.create)();
        let name = parser.name();
        match &reg.selector {
            None => missing.push(name.to_string()),
            Some(sel) => {
                if !parser.supported_artifacts().contains(&sel.artifact_type) {
                    inconsistent.push(format!(
                        "{name}: selector type {:?} not in supported_artifacts {:?}",
                        sel.artifact_type,
                        parser.supported_artifacts()
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "parsers with no ArtifactSelector (Stage 1 incomplete): {missing:?}"
    );
    assert!(
        inconsistent.is_empty(),
        "selector artifact_type not advertised by the parser: {inconsistent:?}"
    );
}
