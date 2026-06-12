//! Tier-A correlation rules (capstone task #37, plan v4 §5.2 / v5 §7.2).
//!
//! Three high-value disk/EVTX rules expressed for the ordered-window
//! [`evaluate`](crate::evaluator::evaluate) engine plus the precision guards the
//! plan mandates. The engine joins an anchor to a consequent on an *exact*
//! shared [`EntityRef`], within a window, under a host/dump scope. Two of the
//! three rules carry guards that exact-entity equality alone cannot express, so
//! this module supplies them as named, tested helpers:
//!
//! - **`CORR-MALWARE-RELOCATE`** — joins file events on the file *basename* (a
//!   create in a user/temp dir, then a rename into a system dir). The basename
//!   join is achieved by normalizing the join entity ([`basename_entity`]); the
//!   "moved out of user space into a system dir" guard is a candidate filter
//!   ([`relocate::is_user_writable_path`] / [`relocate::is_system_path`]).
//! - **`CORR-MALWARE-PERSIST`** — joins an executable's file create to a 7045
//!   `ServiceInstall` naming that image, on the image *stem* ([`stem_entity`]).
//! - **`CORR-COPY-DELETE`** — a delete and a near-identical copy within a
//!   window. Its token-set / subtree / extension / size guards and its
//!   either-order semantics are *not* an ordered-exact-entity shape, so the
//!   rule is matched by a dedicated guard function
//!   ([`copy_delete::copy_delete_pairs`]) that emits the same [`Correlation`]
//!   type — it is a rule-specific matcher, not a second generic evaluator.
//!
//! Findings are observations: every note says "consistent with" and never a
//! verdict. The [`tests::no_rule_note_asserts_a_verdict`] test enforces this.

use issen_core::timeline::event::EntityRef;

use crate::evaluator::RuleSpec;

pub mod copy_delete;
pub mod persist;
pub mod relocate;

/// The basename component of a Windows or POSIX path (the part after the last
/// `\\` or `/`). Returns the whole string when there is no separator.
#[must_use]
pub fn basename(path: &str) -> &str {
    let cut = path.rfind(['\\', '/']).map_or(0, |i| i + 1);
    &path[cut..]
}

/// The directory component of a path (everything before the basename), with the
/// trailing separator removed. Empty when the path has no separator.
#[must_use]
pub fn parent_dir(path: &str) -> &str {
    match path.rfind(['\\', '/']) {
        Some(i) => &path[..i],
        None => "",
    }
}

/// The stem of a path: its basename with a single trailing extension removed
/// (`C:/x/coreupdater.exe` -> `coreupdater`). A leading dot is preserved
/// (`.bashrc` -> `.bashrc`).
#[must_use]
pub fn stem(path: &str) -> &str {
    let base = basename(path);
    match base.rfind('.') {
        Some(0) | None => base,
        Some(i) => &base[..i],
    }
}

/// The lowercased extension of a path, without the dot (`x.EXE` -> `exe`).
/// Empty when the basename has no extension.
#[must_use]
pub fn extension(path: &str) -> String {
    let base = basename(path);
    match base.rfind('.') {
        Some(0) | None => String::new(),
        Some(i) => base[i + 1..].to_ascii_lowercase(),
    }
}

/// Normalize a file path into a basename join entity, so the exact-equality
/// engine join fires across two different full paths that share a name.
#[must_use]
pub fn basename_entity(path: &str) -> EntityRef {
    EntityRef::FilePath(basename(path).to_ascii_lowercase())
}

/// Normalize a file path into a stem join entity (extension dropped), so a file
/// event and a service-image event join on the image stem.
#[must_use]
pub fn stem_entity(path: &str) -> EntityRef {
    EntityRef::FilePath(stem(path).to_ascii_lowercase())
}

/// The bundled Tier-A ordered-window rules.
///
/// Only the rules whose full semantics the ordered engine can express appear
/// here: `CORR-MALWARE-RELOCATE` and `CORR-MALWARE-PERSIST`. `CORR-COPY-DELETE`
/// is a non-ordered, multi-guard pairing and is produced by
/// [`copy_delete::copy_delete_pairs`] instead — it has no `RuleSpec` form.
#[must_use]
pub fn tier_a_rules() -> Vec<RuleSpec> {
    vec![relocate::relocate_rule(), persist::persist_rule()]
}

#[cfg(test)]
pub(crate) mod testkit {
    use issen_core::timeline::event::EntityRef;

    use crate::evaluator::{EventSource, EventView};

    /// A synthetic event for Tier-A rule unit tests.
    #[derive(Debug, Clone)]
    pub struct TestEvent {
        pub id: u64,
        pub ts: i64,
        pub event_type: String,
        pub entity_refs: Vec<EntityRef>,
        pub host: Option<String>,
        pub source: EventSource,
    }

    impl TestEvent {
        pub fn new(id: u64, ts: i64, event_type: &str, host: &str, source: EventSource) -> Self {
            Self {
                id,
                ts,
                event_type: event_type.to_string(),
                entity_refs: Vec::new(),
                host: Some(host.to_string()),
                source,
            }
        }

        #[must_use]
        pub fn with_entity(mut self, e: EntityRef) -> Self {
            self.entity_refs.push(e);
            self
        }
    }

    impl EventView for TestEvent {
        fn id(&self) -> u64 {
            self.id
        }
        fn timestamp_ns(&self) -> i64 {
            self.ts
        }
        fn event_type(&self) -> &str {
            &self.event_type
        }
        fn entity_refs(&self) -> &[EntityRef] {
            &self.entity_refs
        }
        fn hostname(&self) -> Option<&str> {
            self.host.as_deref()
        }
        fn source(&self) -> EventSource {
            self.source
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_handles_both_separators_and_bare_names() {
        assert_eq!(basename("C:\\Windows\\System32\\evil.exe"), "evil.exe");
        assert_eq!(basename("/tmp/evil.exe"), "evil.exe");
        assert_eq!(basename("evil.exe"), "evil.exe");
    }

    #[test]
    fn parent_dir_strips_the_basename() {
        assert_eq!(parent_dir("C:\\Users\\beth\\a.txt"), "C:\\Users\\beth");
        assert_eq!(parent_dir("/home/beth/a.txt"), "/home/beth");
        assert_eq!(parent_dir("a.txt"), "");
    }

    #[test]
    fn stem_drops_one_extension_and_preserves_dotfiles() {
        assert_eq!(stem("C:/x/coreupdater.exe"), "coreupdater");
        assert_eq!(stem("archive.tar.gz"), "archive.tar");
        assert_eq!(stem(".bashrc"), ".bashrc");
        assert_eq!(stem("noext"), "noext");
    }

    #[test]
    fn extension_is_lowercased_without_dot() {
        assert_eq!(extension("X.EXE"), "exe");
        assert_eq!(extension("a.tar.gz"), "gz");
        assert_eq!(extension("noext"), "");
        assert_eq!(extension(".bashrc"), "");
    }

    #[test]
    fn entity_normalizers_lowercase_for_a_robust_join() {
        assert_eq!(
            basename_entity("C:\\Windows\\System32\\Evil.EXE"),
            EntityRef::FilePath("evil.exe".to_string())
        );
        assert_eq!(
            stem_entity("C:/Users/beth/CoreUpdater.exe"),
            EntityRef::FilePath("coreupdater".to_string())
        );
    }

    #[test]
    fn registry_carries_both_ordered_rules() {
        let codes: Vec<&str> = tier_a_rules().iter().map(|r| r.code).collect();
        assert!(codes.contains(&"CORR-MALWARE-RELOCATE"));
        assert!(codes.contains(&"CORR-MALWARE-PERSIST"));
    }

    /// Epistemics gate (plan v5 §7.5): every Tier-A note is an observation, not
    /// a verdict. It must say "consistent with" and must never assert proof.
    #[test]
    fn no_rule_note_asserts_a_verdict() {
        let forbidden =
            regex_like(&["confirm", "prove", "proof", "exceed", "undoubtedly", "certainly"]);

        let mut notes: Vec<&str> = tier_a_rules().iter().map(|r| r.note).collect();
        notes.push(copy_delete::COPY_DELETE_NOTE);

        for note in notes {
            let lower = note.to_ascii_lowercase();
            assert!(
                lower.contains("consistent with"),
                "note must hedge with 'consistent with': {note:?}"
            );
            for needle in &forbidden {
                assert!(
                    !lower.contains(needle),
                    "note must not assert a verdict ({needle:?}): {note:?}"
                );
            }
        }
    }

    /// Lowercased forbidden substrings — a deliberately simple matcher (no regex
    /// dependency) covering the plan's `confirm|prove|proof|exceed|undoubtedly|
    /// certainly` family by stem.
    fn regex_like(stems: &[&str]) -> Vec<String> {
        stems.iter().map(|s| s.to_ascii_lowercase()).collect()
    }
}
