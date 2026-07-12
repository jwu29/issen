//! Credential-agnostic unlock dispatch (RED stub — see GREEN for the real
//! bridge).

use issen_core::plugin::traits::DataSource;

use crate::{Credential, DecryptError, DecryptedSource, FdeFormat};

/// Unlock `source` as `format` using `credential`. RED stub: not implemented.
///
/// # Errors
/// Always errors in the stub.
pub fn unlock(
    _source: Box<dyn DataSource>,
    format: FdeFormat,
    _credential: &Credential,
) -> Result<DecryptedSource, DecryptError> {
    Err(DecryptError::Unlock {
        format,
        message: "RED stub — unlock not implemented".to_string(),
    })
}

/// Detect and unlock. RED stub: always reports no FDE.
///
/// # Errors
/// Never errors in the stub.
pub fn detect_and_unlock<F>(
    mut _source_factory: F,
    _credential: &Credential,
) -> Result<Option<DecryptedSource>, DecryptError>
where
    F: FnMut() -> Box<dyn DataSource>,
{
    Ok(None)
}
