//! Built-in parser registrations.
//!
//! The former in-crate MFT and USN Journal parsers were removed in favor of the
//! `issen-parser-*` plugin crates, which self-register via `inventory::submit!`
//! at link time (see the `extern crate … as _;` anchors in `lib.rs`).
