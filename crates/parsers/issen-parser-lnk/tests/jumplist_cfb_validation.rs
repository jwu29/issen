#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Provenance check for the real captured Jump List fixtures (DC01, DFIR Madness
//! "Stolen Szechuan Sauce"). Confirms — via the published `cfb-forensic` crate —
//! that the `.automaticDestinations-ms` capture is a genuine OLE/CFB compound
//! file and the `.customDestinations-ms` capture is the non-CFB flat custom
//! format. This is the "is it really a real OLE/CFB artifact" Doer-Checker gate,
//! independent of issen's own `lnk-core` decode path.

use std::path::PathBuf;

fn data(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name);
    std::fs::read(p).unwrap()
}

#[test]
fn automatic_destinations_is_real_ole_cfb() {
    let bytes = data("9b9cdc69c1c24e2b.automaticDestinations-ms");
    // `cfb-forensic::live_entry_names` returns `None` if the `cfb` crate cannot
    // open the bytes as a compound file at all — so `Some(..)` is the published
    // crate vouching the bytes are a valid OLE/CFB structure.
    let names = cfb_forensic::live_entry_names(&bytes)
        .expect("automaticDestinations-ms must be a valid OLE/CFB compound file");
    assert!(
        names.iter().any(|n| n == "DestList"),
        "a real AutomaticDestinations Jump List carries a DestList stream; got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "Root Entry"),
        "every CFB compound file has a Root Entry; got {names:?}"
    );
}

#[test]
fn custom_destinations_is_not_cfb() {
    let bytes = data("28c8b86deab549a1.customDestinations-ms");
    // The custom form is a flat, non-CFB layout — `cfb` cannot open it.
    assert!(
        cfb_forensic::live_entry_names(&bytes).is_none(),
        "customDestinations-ms is the flat non-CFB format, not an OLE compound file"
    );
}
