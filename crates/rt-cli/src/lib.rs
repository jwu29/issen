//! rt-cli library entry point.
//!
//! Exposes the built-in parser modules so that integration test binaries
//! can link them and trigger their `inventory::submit!` registrations.

pub mod parsers;
