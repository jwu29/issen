//! Error type for the FDE bridge.

use thiserror::Error;

/// A failure while detecting or unlocking a full-disk-encryption volume.
///
/// Wrong-credential and format-parse failures from the underlying FDE crates
/// surface here as [`DecryptError::Unlock`] (fail-loud): a *detected* volume that
/// will not unlock is never silently reported as plaintext.
#[derive(Debug, Error)]
pub enum DecryptError {
    /// Reading the source (header probe or the FDE crate's own I/O) failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The underlying FDE crate rejected the credential or the volume.
    ///
    /// Carries the format that was attempted and the crate's own error text, so
    /// the caller sees *what* failed and *why* — never an opaque "unlock failed".
    #[error("{format} unlock failed: {message}")]
    Unlock {
        /// Which FDE decryptor was dispatched.
        format: crate::FdeFormat,
        /// The underlying crate's error rendered as text.
        message: String,
    },

    /// The supplied [`crate::Credential`] variant is not accepted by the target
    /// format (e.g. a startup key handed to LUKS, which has no such protector).
    #[error("{format} does not accept the {credential} credential")]
    UnsupportedCredential {
        /// Which FDE decryptor was targeted.
        format: crate::FdeFormat,
        /// The credential variant name that was rejected.
        credential: &'static str,
    },
}
