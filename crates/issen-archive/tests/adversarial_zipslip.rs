//! INDEPENDENT adversarial verification of the zip-slip / path-traversal
//! security invariant — authored by the verifier, not the implementer.
//!
//! Hostile zip carries THREE escape vectors at once:
//!   1. a `../../` parent-traversal entry,
//!   2. an absolute-path entry (`/tmp/...`-style),
//!   3. a symlink entry whose target points outside the extraction dir.
//!
//! Method: build a parent tempdir holding the extraction `dest` PLUS sentinel
//! siblings, snapshot the parent tree byte-for-byte (path -> raw content bytes,
//! a symlink target, or a dir marker) BEFORE extraction, extract, then assert
//! the parent is byte-for-byte unchanged OUTSIDE `dest`. Anything new/changed
//! outside `dest` is an escape. Storing the RAW bytes (not a hash) makes the
//! comparison a true byte-for-byte equality with no collision surface.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use issen_archive::extract::extract_zip;

/// A node fingerprint: its kind plus the bytes that distinguish it (file
/// content / symlink target / nothing for a dir).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    File(Vec<u8>),
    Symlink(String),
    Dir,
}

/// Snapshot every path under `root` recursively to a byte-for-byte fingerprint
/// map. Used to prove invariance of everything OUTSIDE the dest dir.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Node> {
    let mut map = BTreeMap::new();
    walk(root, &mut map);
    map
}

fn walk(dir: &Path, map: &mut BTreeMap<PathBuf, Node>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let ft = e.file_type().unwrap();
        if ft.is_symlink() {
            let target = std::fs::read_link(&p)
                .map(|t| t.to_string_lossy().to_string())
                .unwrap_or_default();
            map.insert(p, Node::Symlink(target));
        } else if ft.is_dir() {
            map.insert(p.clone(), Node::Dir);
            walk(&p, map);
        } else {
            let bytes = std::fs::read(&p).unwrap_or_default();
            map.insert(p, Node::File(bytes));
        }
    }
}

fn make_hostile_zip(path: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default();

    // 1. parent-traversal regular file
    zip.start_file("../../parent-escaped.txt", opts).unwrap();
    zip.write_all(b"PWNED-PARENT").unwrap();

    // 2. absolute-path regular file (forward-slash absolute)
    zip.start_file("/abs-escaped.txt", opts).unwrap();
    zip.write_all(b"PWNED-ABS").unwrap();

    // 2b. nested traversal that normalizes outside via a/../..
    zip.start_file("a/../../mixed-escaped.txt", opts).unwrap();
    zip.write_all(b"PWNED-MIXED").unwrap();

    // 3. symlink whose TARGET points outside the dest (../../). Even with a safe
    //    NAME, if extraction materialized a real symlink and later followed it,
    //    a subsequent entry could write through it. The name is also hostile-ish
    //    but kept inside dest to isolate the symlink-target vector.
    zip.add_symlink("evil-link", "../../symlink-target-outside", opts)
        .unwrap();

    // 3b. a symlink with a traversal NAME as well
    zip.add_symlink("../../link-escaped", "/etc/passwd", opts)
        .unwrap();

    // a genuinely safe entry to prove extraction still works
    zip.start_file("safe/keep.txt", opts).unwrap();
    zip.write_all(b"good").unwrap();

    zip.finish().unwrap();
}

#[test]
fn hostile_zip_leaves_parent_byte_for_byte_unchanged_outside_dest() {
    let parent = tempfile::tempdir().unwrap();

    // dest sits inside parent; sentinel siblings represent pre-existing host
    // files the attacker would try to clobber.
    let dest = parent.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::write(parent.path().join("sentinel-A.txt"), b"original-A").unwrap();
    let sib = parent.path().join("sibling");
    std::fs::create_dir_all(&sib).unwrap();
    std::fs::write(sib.join("sentinel-B.txt"), b"original-B").unwrap();
    // A pre-existing file at the exact name the symlink target would resolve to,
    // to detect a clobber-through-symlink.
    std::fs::write(
        parent.path().join("symlink-target-outside"),
        b"untouched-target",
    )
    .unwrap();

    let zip_path = parent.path().join("evil.zip");
    make_hostile_zip(&zip_path);

    // Snapshot EVERYTHING under parent EXCEPT dest (dest is allowed to change)
    // and except the zip itself (created above, stable).
    let snap_before = snapshot(parent.path());

    let report = extract_zip(&zip_path, &dest).expect("extraction must not error");

    let snap_after = snapshot(parent.path());

    // Compute escape: any path outside dest that is new or whose fingerprint
    // changed. dest subtree is excluded.
    let mut escapes: Vec<(PathBuf, String)> = Vec::new();
    for (p, fp_after) in &snap_after {
        if p.starts_with(&dest) {
            continue;
        }
        match snap_before.get(p) {
            None => escapes.push((p.clone(), format!("NEW {fp_after:?}"))),
            Some(fp_before) if fp_before != fp_after => {
                escapes.push((p.clone(), format!("CHANGED {fp_before:?} -> {fp_after:?}")));
            }
            _ => {}
        }
    }
    // Also catch deletions outside dest.
    for (p, fp_before) in &snap_before {
        if p.starts_with(&dest) {
            continue;
        }
        if !snap_after.contains_key(p) {
            escapes.push((p.clone(), format!("DELETED {fp_before:?}")));
        }
    }

    assert!(
        escapes.is_empty(),
        "SECURITY VIOLATION: extraction escaped dest. Mutations outside dest:\n{escapes:#?}\nrefused={:?}",
        report.refused
    );

    // Positive controls: sentinels intact, traversal entries refused & recorded.
    assert_eq!(
        std::fs::read(parent.path().join("sentinel-A.txt")).unwrap(),
        b"original-A"
    );
    assert_eq!(
        std::fs::read(parent.path().join("symlink-target-outside")).unwrap(),
        b"untouched-target",
        "symlink target file must NOT be clobbered"
    );
    assert!(
        !parent.path().join("parent-escaped.txt").exists(),
        "parent-traversal file escaped"
    );
    assert!(
        !parent.path().join("mixed-escaped.txt").exists(),
        "a/../.. traversal escaped"
    );
    // The traversal-named entries must be REFUSED and recorded (fail-loud).
    assert!(
        report.refused.iter().any(|n| n.contains("parent-escaped")),
        "parent traversal must be recorded as refused; got {:?}",
        report.refused
    );
    assert!(
        report.refused.iter().any(|n| n.contains("abs-escaped")),
        "absolute path must be recorded as refused; got {:?}",
        report.refused
    );

    // The safe entry was written inside dest.
    assert_eq!(std::fs::read(dest.join("safe/keep.txt")).unwrap(), b"good");

    // Document how the symlink entry was handled: a real symlink that points
    // outside dest is itself an escape primitive even if no file is written
    // through it yet. If the extractor materialized a dangling-or-escaping
    // symlink INSIDE dest, flag it loudly.
    let link_in_dest = dest.join("evil-link");
    if let Ok(meta) = std::fs::symlink_metadata(&link_in_dest) {
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&link_in_dest).unwrap();
            // A symlink whose target escapes dest is a latent escape vector.
            assert!(
                !target.to_string_lossy().contains(".."),
                "RESIDUAL RISK: a symlink escaping dest was materialized: {target:?} \
                 (TOCTOU follow-through could write outside dest on a later pass)"
            );
        }
    }
}

/// A zip symlink entry is REFUSED outright — `extract_zip` explicitly rejects
/// symlink entries (matching `extract_tar`), so no file (inert or otherwise) is
/// created for it and it is recorded in the refused list (fail-loud). Containment
/// is now a property of THIS code, not of how the zip crate happens to materialize
/// links — a future "preserve symlinks" change in the dependency cannot reintroduce
/// an escaping symlink primitive because we never write the entry at all.
#[test]
fn zip_symlink_entry_is_refused_not_written() {
    let parent = tempfile::tempdir().unwrap();
    let dest = parent.path().join("dest");
    std::fs::create_dir_all(&dest).unwrap();
    let zp = parent.path().join("s.zip");
    {
        let f = std::fs::File::create(&zp).unwrap();
        let mut z = zip::ZipWriter::new(f);
        let o = zip::write::SimpleFileOptions::default();
        z.add_symlink("evil-link", "../../outside", o).unwrap();
        z.finish().unwrap();
    }
    let report = extract_zip(&zp, &dest).unwrap();
    assert!(
        !dest.join("evil-link").exists(),
        "a symlink entry must not be written at all"
    );
    assert!(
        report.refused.iter().any(|r| r.contains("evil-link")),
        "the symlink entry must be recorded as refused (fail-loud); got {:?}",
        report.refused
    );
}

// Verifier-driven 7z extraction against a FIXED on-disk archive built by the
// system 7z. Env-gated: ISSEN_7Z_IN points at the .7z, ISSEN_7Z_OUT at an
// empty dir to extract into. The shell harness then diffs OUT against the
// system-7z extraction independently (true independent oracle).
#[test]
fn verifier_extract_7z_to_fixed_dir() {
    let (Ok(inp), Ok(out)) = (std::env::var("ISSEN_7Z_IN"), std::env::var("ISSEN_7Z_OUT")) else {
        eprintln!("skip: ISSEN_7Z_IN / ISSEN_7Z_OUT not set");
        return;
    };
    let report = issen_archive::extract::extract_7z(Path::new(&inp), Path::new(&out)).unwrap();
    eprintln!(
        "VERIFIER_7Z written={} refused={:?}",
        report.written, report.refused
    );
    assert_eq!(report.refused.len(), 0);
}

// Verifier-driven REAL-zip extraction to a fixed dir for independent diffing
// against system 7z. Env-gated.
#[test]
fn verifier_extract_zip_to_fixed_dir() {
    let (Ok(inp), Ok(out)) = (
        std::env::var("ISSEN_ZIP_IN"),
        std::env::var("ISSEN_ZIP_OUT"),
    ) else {
        eprintln!("skip: ISSEN_ZIP_IN / ISSEN_ZIP_OUT not set");
        return;
    };
    let report = extract_zip(Path::new(&inp), Path::new(&out)).unwrap();
    eprintln!(
        "VERIFIER_ZIP written={} refused={:?}",
        report.written, report.refused
    );
}
