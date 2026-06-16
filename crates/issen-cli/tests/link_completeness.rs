//! Link-completeness gate (issen #114, mode-2 silent-omission killer).
//!
//! Every `issen-parser-*` workspace crate must be linked into the `issen`
//! binary, or the linker drops its `inventory::submit!` registration and the
//! parser silently never runs in `run_auto` / the supertimeline — exactly how
//! mft/usnjrnl/pe/lnk/linux/macos/setupapi and the #113 winreg parsers went
//! dark. A crate is "linked" iff some non-test source file under `issen-cli/src`
//! names it (an `extern crate issen_parser_x;` force-link, or any direct
//! `issen_parser_x::…` reference). A `[dependency]` alone is NOT enough.
//!
//! Intentional exclusions go in `NOT_INVENTORY_LINKED` with a written reason —
//! excluding a parser must be a deliberate, reviewed act, never an accident.

use std::fs;
use std::path::{Path, PathBuf};

/// Parser crates intentionally NOT linked into the run_auto inventory path.
/// Each entry MUST carry a reason. Empty today: every parser belongs in the one
/// all-encompassing supertimeline.
const NOT_INVENTORY_LINKED: &[(&str, &str)] = &[];

fn collect_src_text(dir: &Path, out: &mut String) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_src_text(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            if let Ok(text) = fs::read_to_string(&path) {
                out.push_str(&text);
                out.push('\n');
            }
        }
    }
}

#[test]
fn every_parser_crate_is_linked_into_the_binary() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")); // crates/issen-cli
    let parsers_dir = manifest_dir.join("..").join("parsers");
    let src_dir = manifest_dir.join("src");

    let mut src = String::new();
    collect_src_text(&src_dir, &mut src);

    let mut members: Vec<String> = fs::read_dir(&parsers_dir)
        .expect("read crates/parsers")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("issen-parser-"))
        .collect();
    members.sort();

    let allow: Vec<&str> = NOT_INVENTORY_LINKED.iter().map(|(c, _)| *c).collect();

    let dark: Vec<String> = members
        .into_iter()
        .filter(|m| !allow.contains(&m.as_str()))
        .filter(|m| {
            let ident = m.replace('-', "_"); // issen-parser-mft -> issen_parser_mft
            !src.contains(&ident)
        })
        .collect();

    assert!(
        dark.is_empty(),
        "these parser crates are linked into nothing and will NEVER run in \
         run_auto/supertimeline (mode-2 silent omission); force-link them in \
         issen-cli/src/main.rs or add an annotated NOT_INVENTORY_LINKED entry: {dark:?}"
    );
}
