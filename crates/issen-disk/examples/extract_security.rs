//! One-off: carve the `SECURITY` registry hive from an E01 to a named output.
//! Usage: extract_security <image.E01> <out-file>
#![allow(clippy::unwrap_used, clippy::expect_used)]
use issen_disk::{extract_dir_suffix, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let src = EwfDataSource::open(std::path::Path::new(&a[1])).expect("open");
    for w in find_ntfs_partitions(&src).expect("parts") {
        let Ok(files) = extract_dir_suffix(&src, w, r"\Windows\System32\config", "SECURITY") else {
            continue;
        };
        for f in files {
            std::fs::write(&a[2], &f.data).unwrap();
            println!("wrote {} ({} bytes) from {}", a[2], f.data.len(), f.path);
        }
    }
}
