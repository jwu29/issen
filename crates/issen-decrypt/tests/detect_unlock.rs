//! Hermetic tests for the FDE bridge: magic detection over hand-built headers
//! and credential-agnostic unlock dispatch (unsupported-credential guards).
//!
//! A magic signature at a known offset is legitimate to construct — it is NOT a
//! fabricated decodable ciphertext. Real unlock is validated by the env-gated
//! oracle tests in `oracle.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;
use issen_decrypt::{detect_and_unlock, detect_fde, unlock, Credential, DecryptError, FdeFormat};

/// A byte-slice DataSource for building synthetic headers.
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

const LUKS_MAGIC: [u8; 6] = [b'L', b'U', b'K', b'S', 0xba, 0xbe];

fn bde_header() -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[3..11].copy_from_slice(b"-FVE-FS-");
    h
}

fn luks_header(version: u16) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[0..6].copy_from_slice(&LUKS_MAGIC);
    h[6..8].copy_from_slice(&version.to_be_bytes());
    h
}

fn cs_header() -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[88..90].copy_from_slice(b"CS");
    h
}

#[test]
fn detect_bitlocker_by_signature() {
    assert_eq!(
        detect_fde(&MemSource(bde_header())),
        Some(FdeFormat::BitLocker)
    );
}

#[test]
fn detect_luks_v1_and_v2() {
    assert_eq!(
        detect_fde(&MemSource(luks_header(1))),
        Some(FdeFormat::Luks)
    );
    assert_eq!(
        detect_fde(&MemSource(luks_header(2))),
        Some(FdeFormat::Luks)
    );
}

#[test]
fn detect_filevault_by_signature() {
    assert_eq!(
        detect_fde(&MemSource(cs_header())),
        Some(FdeFormat::FileVault)
    );
}

#[test]
fn detect_random_is_none() {
    assert_eq!(detect_fde(&MemSource(vec![0u8; 512])), None);
    assert_eq!(
        detect_fde(&MemSource((0..=255u8).cycle().take(1024).collect())),
        None
    );
}

#[test]
fn detect_veracrypt_returns_none_no_magic() {
    // VeraCrypt has no magic by design — detect never claims it.
    let random: Vec<u8> = (0..512u32).map(|i| (i * 7 % 251) as u8).collect();
    assert_eq!(detect_fde(&MemSource(random)), None);
}

#[test]
fn unlock_rejects_startup_key_for_luks() {
    let src: Box<dyn DataSource> = Box::new(MemSource(luks_header(1)));
    let err = unlock(src, FdeFormat::Luks, &Credential::StartupKey(vec![0u8; 32])).unwrap_err();
    assert!(matches!(
        err,
        DecryptError::UnsupportedCredential {
            format: FdeFormat::Luks,
            credential: "StartupKey"
        }
    ));
}

#[test]
fn unlock_rejects_pim_for_bitlocker() {
    let src: Box<dyn DataSource> = Box::new(MemSource(bde_header()));
    let cred = Credential::Pim {
        password: "x".to_string(),
        pim: 1,
    };
    let err = unlock(src, FdeFormat::BitLocker, &cred).unwrap_err();
    assert!(matches!(
        err,
        DecryptError::UnsupportedCredential {
            format: FdeFormat::BitLocker,
            ..
        }
    ));
}

#[test]
fn unlock_rejects_clear_key_for_filevault() {
    let src: Box<dyn DataSource> = Box::new(MemSource(cs_header()));
    let err = unlock(src, FdeFormat::FileVault, &Credential::ClearKey).unwrap_err();
    assert!(matches!(
        err,
        DecryptError::UnsupportedCredential {
            format: FdeFormat::FileVault,
            ..
        }
    ));
}

#[test]
fn detect_and_unlock_plaintext_is_ok_none() {
    // Random bytes: no magic, and a VeraCrypt try-unlock with a password fails,
    // so the source is reported as "no FDE" (Ok(None)) — not an error.
    let bytes: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
    let factory = move || -> Box<dyn DataSource> { Box::new(MemSource(bytes.clone())) };
    let cred = Credential::Password("whatever".to_string());
    let result = detect_and_unlock(factory, &cred).expect("no I/O error");
    assert!(result.is_none(), "plaintext must be Ok(None)");
}

#[test]
fn detect_and_unlock_detected_bitlocker_wrong_password_is_loud_err() {
    // A header WITH the BitLocker magic but no real metadata: detection
    // succeeds, unlock fails — and that failure must be a loud Err, never
    // Ok(None) masquerading as plaintext (fail-loud).
    let header = bde_header();
    let factory = move || -> Box<dyn DataSource> { Box::new(MemSource(header.clone())) };
    let cred = Credential::Password("wrong".to_string());
    let result = detect_and_unlock(factory, &cred);
    assert!(
        matches!(
            result,
            Err(DecryptError::Unlock {
                format: FdeFormat::BitLocker,
                ..
            })
        ),
        "a detected-but-unlockable volume must be a loud Err, got {result:?}"
    );
}
