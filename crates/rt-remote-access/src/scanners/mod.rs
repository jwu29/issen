pub mod builtin_remote;

use crate::model::{Finding, RemoteAccessCategory};
use crate::providers::ArtifactProvider;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scanner error: {0}")]
    Internal(String),
}

pub trait CategoryScanner: Send + Sync {
    fn category(&self) -> RemoteAccessCategory;
    fn scan(&self, provider: &dyn ArtifactProvider) -> Result<Vec<Finding>, ScanError>;
}
