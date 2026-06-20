//! PE binary parser: `parse_pe(&[u8]) -> Result<PeInfo, PeError>`.

use std::path::Path;

/// All forensically-relevant fields extracted from a PE binary.
#[derive(Debug, Clone)]
pub struct PeInfo {
    /// COFF machine type (e.g. 0x8664 = AMD64).
    pub machine: u16,
    /// Compile timestamp from COFF header (Unix seconds; 0 if absent or zeroed).
    pub compile_timestamp: u32,
    /// True if the PE has the DLL characteristic flag set.
    pub is_dll: bool,
    /// Flat list of imported symbol names from all import descriptors.
    pub imports: Vec<String>,
    /// Section table with per-section entropy.
    pub sections: Vec<PeSection>,
    /// ASCII and UTF-16LE strings (≥ 6 printable chars) extracted from all sections.
    pub strings: Vec<String>,
}

/// A single PE section with computed Shannon entropy.
#[derive(Debug, Clone)]
pub struct PeSection {
    /// Section name (8 bytes, null-terminated, UTF-8 best-effort).
    pub name: String,
    /// Virtual size in bytes.
    pub virtual_size: u32,
    /// Size of raw data on disk.
    pub raw_size: u32,
    /// Shannon entropy of the raw section data (0.0 – 8.0).
    pub entropy: f32,
    /// True when IMAGE_SCN_MEM_EXECUTE is set.
    pub is_executable: bool,
    /// True when IMAGE_SCN_MEM_WRITE is set.
    pub is_writable: bool,
}

/// Errors returned by [`parse_pe`].
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("not a PE file: missing MZ or PE signature")]
    NotPe,
    #[error("PE parse error: {0}")]
    Parse(String),
}

/// Parse a PE binary from raw bytes.
///
/// Returns `PeError::NotPe` for non-PE inputs (empty, wrong magic, truncated).
/// Returns `PeError::Parse` for structurally invalid PEs that pass the magic check.
pub fn parse_pe(bytes: &[u8]) -> Result<PeInfo, PeError> {
    use forensicnomicon::heuristics::pe::MZ_MAGIC;
    use goblin::pe::PE;

    if bytes.len() < 2 || bytes[0..2] != MZ_MAGIC {
        return Err(PeError::NotPe);
    }

    let pe = PE::parse(bytes).map_err(|e| PeError::Parse(e.to_string()))?;

    let machine = pe.header.coff_header.machine;
    let compile_timestamp = pe.header.coff_header.time_date_stamp;
    let is_dll = pe.is_lib;

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|imp| imp.name.to_string())
        .collect();

    let sections = pe
        .sections
        .iter()
        .map(|sec| {
            let name = String::from_utf8_lossy(&sec.name)
                .trim_end_matches('\0')
                .to_string();
            let offset = sec.pointer_to_raw_data as usize;
            let size = sec.size_of_raw_data as usize;
            let section_data = bytes
                .get(offset..offset.saturating_add(size))
                .unwrap_or(&[]);
            let entropy = compute_entropy(section_data);
            let is_executable = sec.characteristics & 0x2000_0000 != 0;
            let is_writable = sec.characteristics & 0x8000_0000 != 0;
            PeSection {
                name,
                virtual_size: sec.virtual_size,
                raw_size: sec.size_of_raw_data,
                entropy,
                is_executable,
                is_writable,
            }
        })
        .collect();

    let strings = extract_strings(bytes, 6);

    Ok(PeInfo {
        machine,
        compile_timestamp,
        is_dll,
        imports,
        sections,
        strings,
    })
}

/// Parse a PE binary from a file path.
///
/// Reads the file into memory and calls [`parse_pe`].
pub fn parse_pe_path(path: &Path) -> Result<PeInfo, PeError> {
    let bytes = std::fs::read(path).map_err(|e| PeError::Parse(e.to_string()))?;
    parse_pe(&bytes)
}

/// Shannon entropy over byte values (0.0 – 8.0).
pub(crate) fn compute_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy = 0.0_f32;
    for &count in &freq {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Extract ASCII strings of at least `min_len` printable chars from `bytes`.
///
/// Also scans for UTF-16LE strings (alternating printable byte / 0x00).
fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut results = Vec::new();

    // ASCII pass
    let mut current = String::new();
    for &b in bytes {
        if (0x20..0x7F).contains(&b) {
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                results.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push(current);
    }

    // UTF-16LE pass: every other byte is 0x00
    let mut current16 = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let lo = bytes[i];
        let hi = bytes[i + 1];
        if hi == 0 && (0x20..0x7F).contains(&lo) {
            current16.push(lo as char);
            i += 2;
        } else {
            if current16.len() >= min_len {
                results.push(current16.clone());
            }
            current16.clear();
            i += 1;
        }
    }
    if current16.len() >= min_len {
        results.push(current16);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE32+ (x64) binary with zero sections and no imports.
    fn make_minimal_pe_x64(timestamp: u32) -> Vec<u8> {
        let mut pe = vec![0u8; 512]; // plenty of room, SizeOfHeaders = 0x200

        // DOS header
        pe[0] = b'M'; pe[1] = b'Z';
        // e_lfanew at offset 0x3C → PE header starts at 0x40
        pe[0x3C] = 0x40;

        // PE signature at 0x40
        pe[0x40] = b'P'; pe[0x41] = b'E';

        // COFF header at 0x44
        // Machine: AMD64 = 0x8664 (little-endian)
        pe[0x44] = 0x64; pe[0x45] = 0x86;
        // NumberOfSections = 0
        // TimeDateStamp at 0x48
        pe[0x48..0x4C].copy_from_slice(&timestamp.to_le_bytes());
        // SizeOfOptionalHeader = 0xF0 = 240 at 0x54
        pe[0x54] = 0xF0;
        // Characteristics = 0x0022 at 0x56
        pe[0x56] = 0x22;

        // Optional header (PE32+) starts at 0x58
        // Magic = 0x020B at 0x58
        pe[0x58] = 0x0B; pe[0x59] = 0x02;
        // ImageBase (u64) at 0x58+24 = 0x70: 0x0000000000400000
        pe[0x70] = 0x00; pe[0x71] = 0x00; pe[0x72] = 0x40;
        // SectionAlignment (u32) at 0x58+32 = 0x78: 0x1000
        pe[0x78] = 0x00; pe[0x79] = 0x10;
        // FileAlignment (u32) at 0x58+36 = 0x7C: 0x200
        pe[0x7C] = 0x00; pe[0x7D] = 0x02;
        // MajorSubsystemVersion at 0x58+48 = 0x88: 6
        pe[0x88] = 0x06;
        // SizeOfImage (u32) at 0x58+56 = 0x90: 0x1000
        pe[0x90] = 0x00; pe[0x91] = 0x10;
        // SizeOfHeaders (u32) at 0x58+60 = 0x94: 0x200
        pe[0x94] = 0x00; pe[0x95] = 0x02;
        // Subsystem at 0x58+68 = 0x9C: 2 (GUI)
        pe[0x9C] = 0x02;
        // SizeOfStackReserve (u64) at 0x58+72 = 0xA0: 0x100000
        pe[0xA0] = 0x00; pe[0xA1] = 0x00; pe[0xA2] = 0x10;
        // SizeOfStackCommit (u64) at 0x58+80 = 0xA8: 0x1000
        pe[0xA8] = 0x00; pe[0xA9] = 0x10;
        // SizeOfHeapReserve (u64) at 0x58+88 = 0xB0: 0x100000
        pe[0xB0] = 0x00; pe[0xB1] = 0x00; pe[0xB2] = 0x10;
        // SizeOfHeapCommit (u64) at 0x58+96 = 0xB8: 0x1000
        pe[0xB8] = 0x00; pe[0xB9] = 0x10;
        // NumberOfRvaAndSizes (u32) at 0x58+108 = 0xC4: 16
        pe[0xC4] = 0x10;

        pe
    }

    // ── parse_pe rejection tests ──────────────────────────────────────────────

    #[test]
    fn parse_pe_rejects_empty() {
        assert!(matches!(parse_pe(&[]), Err(PeError::NotPe)));
    }

    #[test]
    fn parse_pe_rejects_random_bytes() {
        assert!(parse_pe(b"this is not a PE file at all").is_err());
    }

    #[test]
    fn parse_pe_rejects_elf_magic() {
        // ELF magic: 0x7F 'E' 'L' 'F'
        let elf = [0x7F, b'E', b'L', b'F', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_pe(&elf).is_err());
    }

    #[test]
    fn parse_pe_rejects_truncated_mz() {
        assert!(parse_pe(b"MZ").is_err());
    }

    // ── parse_pe success tests ────────────────────────────────────────────────

    #[test]
    fn parse_pe_accepts_minimal_x64() {
        let bytes = make_minimal_pe_x64(0x5F00_0000);
        let result = parse_pe(&bytes);
        assert!(result.is_ok(), "minimal PE should parse: {result:?}");
    }

    #[test]
    fn parse_pe_extracts_machine_amd64() {
        let bytes = make_minimal_pe_x64(0);
        let pe = parse_pe(&bytes).expect("should parse");
        assert_eq!(pe.machine, 0x8664, "machine must be AMD64");
    }

    #[test]
    fn parse_pe_extracts_compile_timestamp() {
        let ts: u32 = 0x5F00_ABCD;
        let bytes = make_minimal_pe_x64(ts);
        let pe = parse_pe(&bytes).expect("should parse");
        assert_eq!(pe.compile_timestamp, ts);
    }

    #[test]
    fn parse_pe_minimal_has_no_imports() {
        let bytes = make_minimal_pe_x64(0);
        let pe = parse_pe(&bytes).expect("should parse");
        assert!(pe.imports.is_empty(), "minimal PE has no import table");
    }

    #[test]
    fn parse_pe_minimal_has_no_sections() {
        let bytes = make_minimal_pe_x64(0);
        let pe = parse_pe(&bytes).expect("should parse");
        assert!(pe.sections.is_empty(), "minimal PE has zero sections");
    }

    // ── parse_pe_path test ────────────────────────────────────────────────────

    #[test]
    fn parse_pe_path_nonexistent_returns_err() {
        let result = parse_pe_path(std::path::Path::new("/nonexistent/rbcw.exe"));
        assert!(result.is_err());
    }
}
