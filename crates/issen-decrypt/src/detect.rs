//! Magic-signature detection for the three FDE formats that HAVE a magic.
//!
//! VeraCrypt is deliberately absent: its header is indistinguishable from random
//! bytes by design (plausible deniability), so it is never detected by probe —
//! it is only ever confirmed by a successful try-unlock (see
//! [`crate::detect_and_unlock`]).
//!
//! Signature facts (verified against each FDE core crate's own parser):
//! - **BitLocker**: 8 bytes at offset 3 — `-FVE-FS-` (Windows) or `MSWIN4.1`
//!   (BitLocker To Go on FAT). (`bitlocker-core` `header::SIG_FVE` / `SIG_TO_GO`.)
//! - **LUKS**: 6 bytes `"LUKS\xba\xbe"` at offset 0, shared by LUKS1 and LUKS2
//!   (the version u16 at offset 6 distinguishes them). (`luks-core` `LUKS_MAGIC`.)
//! - **FileVault / CoreStorage**: the ASCII `"CS"` (little-endian `0x5343`) at
//!   offset 88 of the 512-byte physical volume header.
//!   (`filevault-core` `volume_header::CS_SIGNATURE_LE`.)

use issen_core::plugin::traits::DataSource;

use crate::FdeFormat;

/// BitLocker `-FVE-FS-` volume signature (offset 3, 8 bytes).
const BDE_SIG_FVE: [u8; 8] = *b"-FVE-FS-";
/// BitLocker To Go `MSWIN4.1` volume signature (offset 3, 8 bytes).
const BDE_SIG_TO_GO: [u8; 8] = *b"MSWIN4.1";
/// Byte offset of the BitLocker volume signature.
const BDE_SIG_OFFSET: u64 = 3;

/// LUKS magic `"LUKS\xba\xbe"` (offset 0, 6 bytes; LUKS1 and LUKS2 share it).
const LUKS_MAGIC: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];

/// CoreStorage `"CS"` signature bytes (offset 88).
const CS_SIG: [u8; 2] = *b"CS";
/// Byte offset of the CoreStorage signature within the 512-byte header.
const CS_SIG_OFFSET: u64 = 88;

/// Probe `source` for a BitLocker, LUKS, or FileVault magic signature.
///
/// Returns the detected [`FdeFormat`], or `None` for VeraCrypt (no magic) and
/// for plaintext / unrecognized data. A short read is treated as "signature
/// absent" — never a panic (the source may be smaller than any header).
#[must_use]
pub fn detect_fde(_source: &dyn DataSource) -> Option<FdeFormat> {
    // RED stub — no detection yet.
    let _ = (
        BDE_SIG_OFFSET,
        &BDE_SIG_FVE,
        &BDE_SIG_TO_GO,
        &LUKS_MAGIC,
        CS_SIG_OFFSET,
        &CS_SIG,
    );
    None
}

/// Read exactly `magic.len()` bytes at `offset` and compare. A read that returns
/// fewer bytes than the magic (EOF / tiny source) or an I/O error means the
/// signature is absent — the probe never propagates an error, it just declines.
fn has_signature(source: &dyn DataSource, offset: u64, magic: &[u8]) -> bool {
    let mut buf = vec![0u8; magic.len()];
    match source.read_at(offset, &mut buf) {
        Ok(n) if n == magic.len() => buf == magic,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use issen_core::error::RtError;

    struct MemSource(Vec<u8>);

    impl DataSource for MemSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
            let offset = offset as usize;
            if offset >= self.0.len() {
                return Ok(0);
            }
            let available = self.0.len() - offset;
            let to_read = buf.len().min(available);
            buf[..to_read].copy_from_slice(&self.0[offset..offset + to_read]);
            Ok(to_read)
        }
    }

    fn bde_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[3..11].copy_from_slice(b"-FVE-FS-");
        h
    }

    fn bde_to_go_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[3..11].copy_from_slice(b"MSWIN4.1");
        h
    }

    fn luks1_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[0..6].copy_from_slice(&LUKS_MAGIC);
        h[6..8].copy_from_slice(&1u16.to_be_bytes()); // version 1
        h
    }

    fn luks2_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[0..6].copy_from_slice(&LUKS_MAGIC);
        h[6..8].copy_from_slice(&2u16.to_be_bytes()); // version 2
        h
    }

    fn cs_header() -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[88..90].copy_from_slice(b"CS");
        h
    }

    fn detect(bytes: Vec<u8>) -> Option<FdeFormat> {
        detect_fde(&MemSource(bytes))
    }

    #[test]
    fn detects_bitlocker() {
        assert_eq!(detect(bde_header()), Some(FdeFormat::BitLocker));
        assert_eq!(detect(bde_to_go_header()), Some(FdeFormat::BitLocker));
    }

    #[test]
    fn detects_luks1_and_luks2() {
        assert_eq!(detect(luks1_header()), Some(FdeFormat::Luks));
        assert_eq!(detect(luks2_header()), Some(FdeFormat::Luks));
    }

    #[test]
    fn detects_filevault() {
        assert_eq!(detect(cs_header()), Some(FdeFormat::FileVault));
    }

    #[test]
    fn random_bytes_are_none() {
        assert_eq!(detect(vec![0u8; 512]), None);
        assert_eq!(detect((0..=255u8).cycle().take(512).collect()), None);
    }

    #[test]
    fn tiny_source_is_none_not_panic() {
        assert_eq!(detect(vec![]), None);
        assert_eq!(detect(vec![b'L', b'U']), None);
        assert_eq!(detect(vec![0u8; 4]), None);
    }
}
