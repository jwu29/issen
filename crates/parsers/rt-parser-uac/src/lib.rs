pub mod extract;
pub mod parsers;
pub mod probe;

use std::path::Path;

use rt_core::error::RtError;
use rt_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// UAC (Unix Artifact Collector) collection format handler.
///
/// Recognizes `.tar.gz` files containing `uac.log` and standard UAC directories.
pub struct UacProvider;

impl CollectionProvider for UacProvider {
    fn name(&self) -> &'static str {
        "UAC"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        probe::probe_uac(path)
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        let tempdir = rt_unpack::tempdir::create_extraction_dir()?;
        let (entries, metadata) = extract::extract_uac(path, tempdir.path())?;
        Ok(CollectionManifest::new(
            "UAC".into(),
            tempdir,
            entries,
            metadata,
        ))
    }
}

inventory::submit!(rt_unpack::registry::ProviderRegistration {
    create: || Box::new(UacProvider),
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uac_provider_name() {
        assert_eq!(UacProvider.name(), "UAC");
    }
}
