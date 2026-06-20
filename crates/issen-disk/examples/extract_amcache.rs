//! One-off: carve `Amcache.hve` from an E01 to an output dir.
//! Usage: extract_amcache <image.E01> <out-dir>
#![allow(clippy::unwrap_used, clippy::expect_used)]
use issen_disk::{extract_dir_suffix, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let src = EwfDataSource::open(std::path::Path::new(&a[1])).expect("open");
    for w in find_ntfs_partitions(&src).expect("parts") {
        let Ok(files) =
            extract_dir_suffix(&src, w, r"\Windows\AppCompat\Programs", "Amcache.hve")
        else {
            continue;
        };
        for f in files {
            let out = format!("{}/Amcache.hve", a[2]);
            std::fs::write(&out, &f.data).unwrap();
            println!("wrote {} ({} bytes) from {}", out, f.data.len(), f.path);
        }
    }
}
