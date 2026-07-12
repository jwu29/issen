//! Tier-1/Tier-2 oracle tests: unlock the real FDE oracle images *through the
//! issen-decrypt bridge* and confirm the first decrypted sector matches the
//! same known-good SHA-256 each FDE core crate validates against its own
//! reference tool (pybde / cryptsetup / libfvde). This proves the bridge
//! (DataSource → Read+Seek adapter → detect → unlock → DecryptedSource read_at)
//! is transparent end-to-end, not just the underlying crate.
//!
//! Env-gated on the SAME env vars the FDE crates use — skips cleanly when unset:
//!   BDE_ORACLE_IMAGE  (bitlocker `bdetogo.raw`, password "bde-TEST")
//!   LUKS1_ORACLE      (luks `luks1.img`,        passphrase "luks-TEST")
//!   VC_ORACLE         (veracrypt `vc_1-sha512-xts-aes`, password "aaaaaaaaaaaa")
//!   FVDE_ORACLE_IMAGE (filevault `fvde_cs_p1.raw`, password "fvde-TEST")

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;
use issen_decrypt::{detect_and_unlock, detect_fde, unlock, Credential, FdeFormat};
use sha2::{Digest, Sha256};

/// A whole-file DataSource (reads the oracle image into memory once). The oracle
/// images are ≤64 MiB, so this is fine for a test.
struct FileSource(Vec<u8>);

impl FileSource {
    fn load(path: &str) -> Self {
        FileSource(fs::read(path).expect("read oracle image"))
    }
}

impl DataSource for FileSource {
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

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

#[test]
fn bitlocker_bridge_matches_pybde() {
    let Some(path) = env_path("BDE_ORACLE_IMAGE") else {
        eprintln!("BDE_ORACLE_IMAGE unset — skipping BitLocker bridge oracle");
        return;
    };
    let path = path.to_string_lossy().into_owned();
    let bytes = fs::read(&path).expect("read image");

    // detect must recognize BitLocker.
    assert_eq!(
        detect_fde(&FileSource(bytes.clone())),
        Some(FdeFormat::BitLocker)
    );

    // unlock through the bridge and read the first decrypted sector.
    let src: Box<dyn DataSource> = Box::new(FileSource(bytes.clone()));
    let decrypted = unlock(
        src,
        FdeFormat::BitLocker,
        &Credential::Password("bde-TEST".to_string()),
    )
    .expect("unlock bdetogo.raw through bridge");

    let mut sector = [0u8; 512];
    let n = decrypted
        .read_at(0, &mut sector)
        .expect("read decrypted sector");
    assert_eq!(n, 512);
    assert_eq!(
        sha256_hex(&sector),
        "139b857c537e341ceb98bcfde2d31825efcf4b0c0281dd66672e954b34ed28f3",
        "decrypted sector 0 must match pybde ground truth"
    );

    // detect_and_unlock end-to-end (magic path).
    let factory = move || -> Box<dyn DataSource> { Box::new(FileSource(bytes.clone())) };
    let via = detect_and_unlock(factory, &Credential::Password("bde-TEST".to_string()))
        .expect("detect_and_unlock")
        .expect("Some(decrypted)");
    let mut s2 = [0u8; 512];
    via.read_at(0, &mut s2).expect("read");
    assert_eq!(
        sha256_hex(&s2),
        "139b857c537e341ceb98bcfde2d31825efcf4b0c0281dd66672e954b34ed28f3"
    );
}

#[test]
fn luks1_bridge_matches_cryptsetup() {
    let Some(path) = env_path("LUKS1_ORACLE") else {
        eprintln!("LUKS1_ORACLE unset — skipping LUKS1 bridge oracle");
        return;
    };
    let src = FileSource::load(&path.to_string_lossy());
    assert_eq!(detect_fde(&src), Some(FdeFormat::Luks));

    let boxed: Box<dyn DataSource> = Box::new(FileSource::load(&path.to_string_lossy()));
    let decrypted = unlock(
        boxed,
        FdeFormat::Luks,
        &Credential::Password("luks-TEST".to_string()),
    )
    .expect("unlock luks1.img through bridge");

    let mut sector = [0u8; 512];
    let n = decrypted
        .read_at(0, &mut sector)
        .expect("read decrypted sector");
    assert_eq!(n, 512);
    assert_eq!(
        sha256_hex(&sector),
        "c9d8e3352f9f790d8b0be13cb1c18ed7963009888be04acc065ee5efbd934076",
        "decrypted LBA 0 must match cryptsetup ground truth"
    );
}

#[test]
fn veracrypt_bridge_matches_cryptsetup() {
    let Some(path) = env_path("VC_ORACLE") else {
        eprintln!("VC_ORACLE unset — skipping VeraCrypt bridge oracle");
        return;
    };
    // VeraCrypt is magicless — detect returns None, so this exercises the
    // deniable try-unlock fallback in detect_and_unlock.
    let src = FileSource::load(&path.to_string_lossy());
    assert_eq!(detect_fde(&src), None, "VeraCrypt has no magic");

    let bytes = fs::read(path.to_string_lossy().as_ref()).expect("read");
    let factory = move || -> Box<dyn DataSource> { Box::new(FileSource(bytes.clone())) };
    let decrypted = detect_and_unlock(factory, &Credential::Password("aaaaaaaaaaaa".to_string()))
        .expect("detect_and_unlock")
        .expect("VeraCrypt try-unlock must succeed");
    assert_eq!(decrypted.format(), FdeFormat::VeraCrypt);

    let mut sector = [0u8; 512];
    let n = decrypted
        .read_at(0, &mut sector)
        .expect("read decrypted sector");
    assert_eq!(n, 512);
    assert_eq!(
        sha256_hex(&sector),
        "76a9e8419a1e688732c03236e01e564c6b3660c0bcdc4561eb05e1d1de8ff8fa",
        "decrypted data-area LBA 0 must match cryptsetup ground truth"
    );
}

#[test]
fn filevault_bridge_matches_libfvde() {
    let Some(path) = env_path("FVDE_ORACLE_IMAGE") else {
        eprintln!("FVDE_ORACLE_IMAGE unset — skipping FileVault bridge oracle");
        return;
    };
    let src = FileSource::load(&path.to_string_lossy());
    assert_eq!(detect_fde(&src), Some(FdeFormat::FileVault));

    let boxed: Box<dyn DataSource> = Box::new(FileSource::load(&path.to_string_lossy()));
    let decrypted = unlock(
        boxed,
        FdeFormat::FileVault,
        &Credential::Password("fvde-TEST".to_string()),
    )
    .expect("unlock fvde_cs_p1.raw through bridge");

    let mut sector = [0u8; 512];
    let n = decrypted
        .read_at(0, &mut sector)
        .expect("read decrypted sector");
    assert_eq!(n, 512);
    assert_eq!(
        sha256_hex(&sector),
        "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560",
        "decrypted LV offset 0 must match libfvde ground truth"
    );
}
