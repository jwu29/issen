//! [`DecryptedSource`] — an issen [`DataSource`] backed by an unlocked FDE volume.
//!
//! Each FDE core crate hands back a distinct unlocked-volume type, all generic
//! over the reader `R` (here always [`DataSourceReader`]). Their plaintext
//! `read_at` takes `&mut self`, so the volume lives behind a [`Mutex`] to satisfy
//! `DataSource::read_at(&self, …)`.
//!
//! `source_path()` returns `None`: the decrypted view is synthetic — it has no
//! file on disk — so path-needing parsers degrade gracefully (per the
//! `DataSource` trait contract).

use std::sync::Mutex;

use bitlocker::DecryptedVolume as BdeVolume;
use filevault::volume::DecryptedVolume as FvdeVolume;
use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;
use luks::DecryptedPayload as LuksPayload;
use veracrypt::DecryptedVolume as VeraVolume;

use crate::adapter::DataSourceReader;

/// The unlocked volume, one variant per FDE format.
///
/// BitLocker / LUKS / VeraCrypt expose a fill-style `read_at` returning
/// `Result<()>` (zero past end); FileVault's returns the byte count. The
/// [`DecryptedSource`] read path normalizes both to the `DataSource` contract
/// (bytes-read count, clamped at the logical end).
enum UnlockedVolume {
    // Boxed: the four decryptor states differ widely in size (VeraCrypt/LUKS
    // carry Vec master keys + cipher chains), so box each to keep the enum small
    // and avoid `clippy::large_enum_variant`.
    BitLocker(Box<BdeVolume<DataSourceReader>>),
    Luks(Box<LuksPayload<DataSourceReader>>),
    VeraCrypt(Box<VeraVolume<DataSourceReader>>),
    FileVault(Box<FvdeVolume<DataSourceReader>>),
}

impl UnlockedVolume {
    /// Logical size of the decrypted view in bytes.
    fn len(&self) -> u64 {
        match self {
            UnlockedVolume::BitLocker(v) => v.volume_size(),
            UnlockedVolume::Luks(v) => v.payload_size(),
            UnlockedVolume::VeraCrypt(v) => v.data_size(),
            UnlockedVolume::FileVault(v) => v.size(),
        }
    }
}

/// A decrypted, plaintext [`DataSource`] over an unlocked FDE volume.
///
/// Produced by [`crate::unlock`] / [`crate::detect_and_unlock`]. Reads are
/// delegated to the underlying decryptor; the caller sees ordinary plaintext
/// bytes with no knowledge of the encryption beneath.
pub struct DecryptedSource {
    volume: Mutex<UnlockedVolume>,
    len: u64,
    format: crate::FdeFormat,
}

impl std::fmt::Debug for DecryptedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit the volume internals (keys, reader) — a Debug of a
        // decrypted source must never leak key material.
        f.debug_struct("DecryptedSource")
            .field("format", &self.format)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl DecryptedSource {
    /// The FDE format that was unlocked to produce this source.
    #[must_use]
    pub fn format(&self) -> crate::FdeFormat {
        self.format
    }

    fn new(volume: UnlockedVolume, format: crate::FdeFormat) -> Self {
        let len = volume.len();
        Self {
            volume: Mutex::new(volume),
            len,
            format,
        }
    }
}

// Constructors used by the unlock dispatcher (kept in this module so the
// `UnlockedVolume` enum can stay private to the crate's read path).
impl DecryptedSource {
    pub(crate) fn from_bitlocker(v: BdeVolume<DataSourceReader>) -> Self {
        Self::new(
            UnlockedVolume::BitLocker(Box::new(v)),
            crate::FdeFormat::BitLocker,
        )
    }

    pub(crate) fn from_luks(v: LuksPayload<DataSourceReader>) -> Self {
        Self::new(UnlockedVolume::Luks(Box::new(v)), crate::FdeFormat::Luks)
    }

    pub(crate) fn from_veracrypt(v: VeraVolume<DataSourceReader>) -> Self {
        Self::new(
            UnlockedVolume::VeraCrypt(Box::new(v)),
            crate::FdeFormat::VeraCrypt,
        )
    }

    pub(crate) fn from_filevault(v: FvdeVolume<DataSourceReader>) -> Self {
        Self::new(
            UnlockedVolume::FileVault(Box::new(v)),
            crate::FdeFormat::FileVault,
        )
    }
}

impl DataSource for DecryptedSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        // Clamp to the logical end so the fill-style decryptors don't pad past
        // EOF into the returned count; the byte-count-returning one (FileVault)
        // already clamps, so this is a no-op there.
        let available = self.len - offset;
        let want = (buf.len() as u64).min(available) as usize;
        let slice = &mut buf[..want];

        let mut guard = self
            .volume
            .lock()
            .map_err(|_| RtError::InvalidData("decrypted-volume mutex poisoned".to_string()))?;

        match &mut *guard {
            UnlockedVolume::BitLocker(v) => v
                .read_at(offset, slice)
                .map_err(|e| RtError::InvalidData(format!("bitlocker read: {e}")))?,
            UnlockedVolume::Luks(v) => v
                .read_at(offset, slice)
                .map_err(|e| RtError::InvalidData(format!("luks read: {e}")))?,
            UnlockedVolume::VeraCrypt(v) => v
                .read_at(offset, slice)
                .map_err(|e| RtError::InvalidData(format!("veracrypt read: {e}")))?,
            UnlockedVolume::FileVault(v) => {
                let n = v
                    .read_at(offset, slice)
                    .map_err(|e| RtError::InvalidData(format!("filevault read: {e}")))?;
                return Ok(n);
            }
        }
        Ok(want)
    }

    fn source_path(&self) -> Option<&std::path::Path> {
        None
    }
}
