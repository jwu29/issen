//! PE (Portable Executable) parser and forensic detector for Issen.
//!
//! Accepts raw `&[u8]` bytes. Medium-agnostic: works equally from a disk file,
//! an extracted memory region, or a carved AFF4 stream.

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
)]

pub mod detections;
pub mod parser;

pub use detections::{detect_all, PeDetection, PeDetectionKind};
pub use parser::{parse_pe, PeError, PeInfo, PeSection};
