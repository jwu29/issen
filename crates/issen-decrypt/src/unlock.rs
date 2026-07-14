//! Credential-agnostic unlock dispatch.
//!
//! [`unlock`] bridges an issen [`DataSource`] to whatever `Read + Seek` the
//! target FDE crate wants (via [`DataSourceReader`]) and dispatches the supplied
//! [`Credential`] to the matching crate function. [`detect_and_unlock`] adds the
//! magic-probe → unlock → deniable-VeraCrypt-fallback flow.

use bitlocker::BitLockerVolume;
use filevault::FileVaultVolume;
use issen_core::plugin::traits::DataSource;
use luks::LuksVolume;
use veracrypt::VeraVolume;

use crate::adapter::DataSourceReader;
use crate::{Credential, DecryptError, DecryptedSource, FdeFormat};

/// Unlock `source` as `format` using `credential`, returning a decrypted
/// [`DataSource`].
///
/// The credential must be one the format accepts; an unaccepted pairing
/// (e.g. a [`Credential::StartupKey`] against LUKS) is a loud
/// [`DecryptError::UnsupportedCredential`], never a silent wrong answer. A wrong
/// password / recovery key surfaces as [`DecryptError::Unlock`].
///
/// # Errors
/// - [`DecryptError::UnsupportedCredential`] if `credential` is not valid for
///   `format`.
/// - [`DecryptError::Unlock`] if the underlying decryptor rejects the credential
///   or the volume.
pub fn unlock(
    source: Box<dyn DataSource>,
    format: FdeFormat,
    credential: &Credential,
) -> Result<DecryptedSource, DecryptError> {
    let reader = DataSourceReader::new(source);
    match format {
        FdeFormat::BitLocker => unlock_bitlocker(reader, credential),
        FdeFormat::Luks => unlock_luks(reader, credential),
        FdeFormat::VeraCrypt => unlock_veracrypt(reader, credential),
        FdeFormat::FileVault => unlock_filevault(reader, credential),
    }
}

fn unlock_bitlocker(
    reader: DataSourceReader,
    credential: &Credential,
) -> Result<DecryptedSource, DecryptError> {
    let unlock_err = |e: bitlocker::BdeError| DecryptError::Unlock {
        format: FdeFormat::BitLocker,
        message: e.to_string(),
    };
    let vol = match credential {
        Credential::Password(pw) => {
            BitLockerVolume::unlock_with_password(reader, pw).map_err(unlock_err)?
        }
        Credential::RecoveryPassword(rp) => {
            BitLockerVolume::unlock_with_recovery_password(reader, rp).map_err(unlock_err)?
        }
        Credential::StartupKey(bek) => {
            BitLockerVolume::unlock_with_startup_key(reader, bek).map_err(unlock_err)?
        }
        Credential::ClearKey => BitLockerVolume::unlock_clear_key(reader).map_err(unlock_err)?,
        Credential::Pim { .. } => {
            return Err(DecryptError::UnsupportedCredential {
                format: FdeFormat::BitLocker,
                credential: credential.variant_name(),
            });
        }
    };
    Ok(DecryptedSource::from_bitlocker(vol))
}

fn unlock_luks(
    reader: DataSourceReader,
    credential: &Credential,
) -> Result<DecryptedSource, DecryptError> {
    // LUKS accepts only a passphrase; auto-detects LUKS1 vs LUKS2 by header.
    let Credential::Password(pw) = credential else {
        return Err(DecryptError::UnsupportedCredential {
            format: FdeFormat::Luks,
            credential: credential.variant_name(),
        });
    };
    let vol = LuksVolume::unlock_with_passphrase(reader, pw.as_bytes()).map_err(|e| {
        DecryptError::Unlock {
            format: FdeFormat::Luks,
            message: e.to_string(),
        }
    })?;
    Ok(DecryptedSource::from_luks(vol))
}

fn unlock_veracrypt(
    reader: DataSourceReader,
    credential: &Credential,
) -> Result<DecryptedSource, DecryptError> {
    let unlock_err = |e: veracrypt::VeraError| DecryptError::Unlock {
        format: FdeFormat::VeraCrypt,
        message: e.to_string(),
    };
    let vol = match credential {
        Credential::Password(pw) => {
            VeraVolume::unlock_with_password(reader, pw.as_bytes()).map_err(unlock_err)?
        }
        Credential::Pim { password, pim } => {
            VeraVolume::unlock_with_pim(reader, password.as_bytes(), *pim).map_err(unlock_err)?
        }
        _ => {
            return Err(DecryptError::UnsupportedCredential {
                format: FdeFormat::VeraCrypt,
                credential: credential.variant_name(),
            });
        }
    };
    Ok(DecryptedSource::from_veracrypt(vol))
}

fn unlock_filevault(
    reader: DataSourceReader,
    credential: &Credential,
) -> Result<DecryptedSource, DecryptError> {
    let Credential::Password(pw) = credential else {
        return Err(DecryptError::UnsupportedCredential {
            format: FdeFormat::FileVault,
            credential: credential.variant_name(),
        });
    };
    let vol =
        FileVaultVolume::unlock_with_password(reader, pw).map_err(|e| DecryptError::Unlock {
            format: FdeFormat::FileVault,
            message: e.to_string(),
        })?;
    Ok(DecryptedSource::from_filevault(vol.into_decrypted()))
}

/// Detect the FDE format of `source` and unlock it with `credential`.
///
/// Flow:
/// 1. Probe magics ([`crate::detect_fde`]). A recognized volume is unlocked with
///    `credential` — a wrong credential is a loud [`DecryptError`], never
///    `Ok(None)` (a detected-but-unlockable volume must not masquerade as
///    plaintext).
/// 2. No magic ⇒ try VeraCrypt (deniable, magicless): if it unlocks, it *was*
///    VeraCrypt.
/// 3. Otherwise it is plaintext / an unsupported format ⇒ `Ok(None)`.
///
/// A `probe` copy of the source is needed for the magic read and a fresh owned
/// `source` for the unlock, so this takes a factory that yields an owned
/// [`DataSource`] on demand. This keeps the crate credential-agnostic and lets
/// the caller decide how the bytes are backed (file, mmap, byte slice).
///
/// # Cost of the VeraCrypt fallback
/// When no magic is present, step 2 attempts a VeraCrypt unlock — and VeraCrypt
/// detection *is* a KDF brute-force (up to five PBKDF2 PRFs at ~500k iterations
/// each × several cipher chains). On a genuinely plaintext source at or above
/// VeraCrypt's minimum header size this runs the full brute-force before
/// declining, which is seconds of CPU. A caller that routes many
/// known-plaintext sources through this function should gate the VeraCrypt try
/// (e.g. only call it when a VeraCrypt volume is plausible) rather than pay the
/// KDF cost per source. Sources below the VeraCrypt header size decline
/// instantly.
///
/// # Errors
/// [`DecryptError::Unlock`] if a detected volume — or a magicless VeraCrypt
/// try — fails to unlock with the given credential.
pub fn detect_and_unlock<F>(
    mut source_factory: F,
    credential: &Credential,
) -> Result<Option<DecryptedSource>, DecryptError>
where
    F: FnMut() -> Box<dyn DataSource>,
{
    let probe = source_factory();
    if let Some(format) = crate::detect_fde(probe.as_ref()) {
        // Detected: a failure here is fail-loud, not "plaintext".
        return unlock(source_factory(), format, credential).map(Some);
    }

    // No magic. It could be VeraCrypt (deniable) or genuine plaintext.
    match unlock(source_factory(), FdeFormat::VeraCrypt, credential) {
        Ok(decrypted) => Ok(Some(decrypted)),
        Err(DecryptError::UnsupportedCredential { .. }) => {
            // The credential can't even be a VeraCrypt attempt (e.g. a startup
            // key): there is no FDE we can act on, so treat as plaintext.
            Ok(None)
        }
        Err(DecryptError::Unlock { .. }) => {
            // VeraCrypt try failed ⇒ not a VeraCrypt volume we can open ⇒ the
            // source is plaintext (or an FDE we don't support / wrong cred for a
            // magicless format). Degrade to "no FDE".
            Ok(None)
        }
        Err(e @ DecryptError::Io(_)) => Err(e),
    }
}
