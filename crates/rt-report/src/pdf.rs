//! PDF export for RapidTriage HTML reports.
//!
//! Converts an HTML report string to a minimal single-page PDF by stripping
//! HTML tags and writing the plain text with `printpdf` using a built-in font.
//! No external binaries or system dependencies are required.

use std::path::Path;

/// Export an HTML string as a PDF file at `output_path`.
///
/// HTML tags are stripped to plain text before writing. The output is a valid
/// PDF/X-3 document using Helvetica (a PDF built-in font), so no font files
/// need to be shipped alongside the binary.
///
/// # Errors
///
/// Returns an error if `output_path` cannot be written, or if PDF generation
/// fails internally.
pub fn export_pdf(_html: &str, _output_path: &Path) -> anyhow::Result<()> {
    todo!("implement export_pdf")
}

// ---------------------------------------------------------------------------
// Helpers (stubs until GREEN)
// ---------------------------------------------------------------------------

/// Strip HTML tags from a string, returning plain text.
fn strip_html(_html: &str) -> String {
    todo!("implement strip_html")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    const SIMPLE_HTML: &str = r#"<!DOCTYPE html>
<html><head><title>Test Report</title></head>
<body><h1>RapidTriage Report</h1>
<p>Event count: <strong>42</strong></p>
</body></html>"#;

    /// export_pdf must create a non-empty file at the given path.
    #[test]
    fn export_pdf_creates_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("report.pdf");

        export_pdf(SIMPLE_HTML, &out).expect("export_pdf should succeed");

        assert!(out.exists(), "output file should exist after export_pdf");
        let meta = std::fs::metadata(&out).expect("metadata");
        assert!(meta.len() > 0, "output file should be non-empty");
    }

    /// The first four bytes of a valid PDF must be `%PDF`.
    #[test]
    fn export_pdf_file_starts_with_pdf_magic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("report.pdf");

        export_pdf(SIMPLE_HTML, &out).expect("export_pdf should succeed");

        let mut f = std::fs::File::open(&out).expect("open output");
        let mut magic = [0u8; 4];
        f.read_exact(&mut magic).expect("read magic bytes");
        assert_eq!(&magic, b"%PDF", "file must start with PDF magic bytes");
    }

    /// Calling export_pdf with an empty HTML string must not panic.
    #[test]
    fn export_pdf_empty_html_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("empty.pdf");

        export_pdf("", &out).expect("export_pdf with empty html should succeed");

        assert!(out.exists(), "output file should exist for empty html input");
    }
}
