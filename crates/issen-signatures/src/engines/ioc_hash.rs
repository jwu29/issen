//! Hash-based IOC matching for the scanning engine.
//!
//! The hash *store* (multi-algorithm known-good/known-bad set with text/CSV
//! loaders) is the fleet's one hash-lookup capability and lives in
//! [`forensic_hashdb::feed`] — re-exported here so the scanning engine keeps its
//! import path (ADR-0011: consolidate hash lookup on forensic-hashdb). This
//! module now owns only the issen-specific piece: computing a file's digest.

pub use forensic_hashdb::feed::{HashAlgorithm, HashFeed, HashMatch};

/// Compute SHA-256 of a byte slice, returning lowercase hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute MD5 of a byte slice, returning lowercase hex.
#[must_use]
pub fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{md5_hex, sha256_hex};

    #[test]
    fn sha256_hex_of_empty_is_the_known_digest() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn md5_hex_of_empty_is_the_known_digest() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
