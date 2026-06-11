//! Derive a stable super-timeline epoch label from a forensicnomicon `[H]` ordering key.
//!
//! The DuckDB epoch dimension (#45) tags each snapshot's timeline with a string epoch.
//! Before this seam those strings were ad-hoc (`"snap-T1"`); `epoch_label_for` derives
//! them from the canonical [`LsnKind`](forensicnomicon::history::epoch::LsnKind) ordering
//! key, so a WAL commit's epoch is its salt-qualified position, an ESE state's epoch is
//! its LSN, and so on — principled, deterministic, and distinct whenever the underlying
//! states differ. The mapping is general across every `LsnKind` variant (no special case);
//! a future variant falls through to a namespaced catch-all rather than colliding silently.

use forensicnomicon::history::epoch::LsnKind;

/// Lower-hex encode bytes (no allocation-heavy deps; the keys are ≤ 16 bytes).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A deterministic, source-namespaced epoch label for one `[H]` ordering key.
///
/// Distinct states map to distinct labels; equal states map to equal labels. For SQLite
/// WAL the label is salt-qualified, so a checkpoint reset (which renumbers frames) never
/// collapses two generations onto one epoch.
pub fn epoch_label_for(lsn: &LsnKind) -> String {
    let _ = lsn;
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_epoch_label_is_salt_qualified() {
        let a = epoch_label_for(&LsnKind::SqliteWalFrame {
            salt1: 0xDEAD_BEEF,
            salt2: 0x0BAD_F00D,
            frame_seq: 1,
            commit_seq: 0,
        });
        // Same commit position but a DIFFERENT salt epoch ⇒ a DIFFERENT label: a
        // checkpoint reset must not collapse two generations onto one epoch.
        let b = epoch_label_for(&LsnKind::SqliteWalFrame {
            salt1: 0xDEAD_BEF0,
            salt2: 0x0BAD_F00D,
            frame_seq: 1,
            commit_seq: 0,
        });
        assert_ne!(a, b);
        assert!(a.starts_with("wal:"));
        // Deterministic.
        assert_eq!(
            a,
            epoch_label_for(&LsnKind::SqliteWalFrame {
                salt1: 0xDEAD_BEEF,
                salt2: 0x0BAD_F00D,
                frame_seq: 1,
                commit_seq: 0,
            })
        );
    }

    #[test]
    fn distinct_sources_get_distinct_namespaced_labels() {
        assert!(epoch_label_for(&LsnKind::EseLsn(42)).starts_with("ese:"));
        assert!(epoch_label_for(&LsnKind::UsnRecord { usn: 7 }).starts_with("usn:"));
        assert!(epoch_label_for(&LsnKind::GitCommitSha("abc123".into())).starts_with("git:"));
        // A byte-valued key is hex-encoded, not lossy.
        let vss = epoch_label_for(&LsnKind::VssShadowSetId([0xAB; 16]));
        assert!(vss.starts_with("vss:") && vss.contains("abab"));
    }
}
