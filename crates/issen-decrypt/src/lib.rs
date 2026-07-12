//! # issen-decrypt — the fleet's full-disk-encryption bridge for Issen
//!
//! Credential-agnostic **detect + unlock** of the four full-disk-encryption
//! formats the fleet decrypts — BitLocker, LUKS, VeraCrypt, FileVault — yielding
//! a plaintext [`issen_core::plugin::traits::DataSource`] the disk pipeline can
//! read as if the volume were never encrypted.
//!
//! This crate is the *capability bridge only*: it accepts a [`Credential`]
//! handed in by a caller and stops there. How a passphrase or recovery key
//! reaches the code from a user is a separate concern (owned by the
//! credential-supply design), deliberately out of scope here.
//!
//! ## Detect
//! [`detect_fde`] probes header magics for BitLocker (`-FVE-FS-` / `MSWIN4.1` at
//! offset 3), LUKS (`LUKS\xba\xbe` at offset 0, LUKS1 + LUKS2), and FileVault /
//! CoreStorage (`CS` at offset 88). It returns `None` for VeraCrypt — which has
//! no magic by design (deniability) — and for plaintext.
//!
//! ## Unlock
//! [`unlock`] dispatches a [`Credential`] to the matching decryptor.
//! [`detect_and_unlock`] runs the full flow: magic-probe → unlock, falling back
//! to a VeraCrypt try-unlock when no magic is present. A *detected* volume that
//! will not open with the credential is a loud [`DecryptError`] — it never
//! masquerades as plaintext (`Ok(None)`).
//!
//! ```no_run
//! use issen_decrypt::{detect_and_unlock, Credential};
//! use issen_core::plugin::traits::DataSource;
//!
//! # fn demo(make_source: impl FnMut() -> Box<dyn DataSource>) -> Result<(), Box<dyn std::error::Error>> {
//! let cred = Credential::Password("bde-TEST".to_string());
//! if let Some(plaintext) = detect_and_unlock(make_source, &cred)? {
//!     let mut sector = [0u8; 512];
//!     plaintext.read_at(0, &mut sector)?;
//! }
//! # Ok(())
//! # }
//! ```

mod adapter;
mod detect;
mod error;
mod source;
mod unlock;

pub use detect::detect_fde;
pub use error::DecryptError;
pub use source::DecryptedSource;
pub use unlock::{detect_and_unlock, unlock};

/// A full-disk-encryption format this bridge can detect and/or unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdeFormat {
    /// Microsoft BitLocker Drive Encryption (BDE), incl. BitLocker To Go.
    BitLocker,
    /// Linux Unified Key Setup (LUKS1 and LUKS2).
    Luks,
    /// VeraCrypt / TrueCrypt (magicless — detected only by try-unlock).
    VeraCrypt,
    /// Apple CoreStorage / FileVault 2 (FVDE).
    FileVault,
}

impl std::fmt::Display for FdeFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            FdeFormat::BitLocker => "BitLocker",
            FdeFormat::Luks => "LUKS",
            FdeFormat::VeraCrypt => "VeraCrypt",
            FdeFormat::FileVault => "FileVault",
        };
        f.write_str(name)
    }
}

/// A credential to unlock an FDE volume, format-agnostic at the call site.
///
/// Each variant maps to a specific unlock function of the target FDE crate;
/// pairing a variant with a format that does not accept it is a loud
/// [`DecryptError::UnsupportedCredential`]. New variants are added only as the
/// underlying crates require.
#[derive(Debug, Clone)]
pub enum Credential {
    /// A user passphrase / password.
    ///
    /// BitLocker password protector, LUKS passphrase, VeraCrypt password,
    /// FileVault password.
    Password(String),
    /// A BitLocker 48-digit recovery password (recovery protector).
    RecoveryPassword(String),
    /// The raw bytes of a BitLocker `.BEK` startup-key file (startup-key
    /// protector).
    StartupKey(Vec<u8>),
    /// A VeraCrypt password with a Personal Iterations Multiplier.
    Pim {
        /// The passphrase.
        password: String,
        /// The PIM value.
        pim: u32,
    },
    /// No credential — a BitLocker clear-key protector (protection suspended),
    /// which stores the volume key unprotected.
    ClearKey,
}

impl Credential {
    /// A stable, human-readable name for the variant, used in error messages.
    #[must_use]
    pub fn variant_name(&self) -> &'static str {
        match self {
            Credential::Password(_) => "Password",
            Credential::RecoveryPassword(_) => "RecoveryPassword",
            Credential::StartupKey(_) => "StartupKey",
            Credential::Pim { .. } => "Pim",
            Credential::ClearKey => "ClearKey",
        }
    }
}
