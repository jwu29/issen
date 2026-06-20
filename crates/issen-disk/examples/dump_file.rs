//! One-off: dump every file ending in `suffix` from an NTFS dir in an E01 to /tmp.
//! Usage: dump_file <image.E01> <ntfs-dir> <suffix> <out-dir>
// A throwaway debugging example: unwrap/expect on argv are intentional brevity.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use issen_disk::{extract_dir_suffix, find_ntfs_partitions};
use issen_ewf::EwfDataSource;
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let src = EwfDataSource::open(std::path::Path::new(&a[1])).expect("open");
    for w in find_ntfs_partitions(&src).expect("parts") {
        let Ok(files) = extract_dir_suffix(&src, w, &a[2], &a[3]) else {
            continue;
        };
        for f in files {
            let name = f.path.rsplit(['\\', '/']).next().unwrap_or("x");
            let out = format!("{}/{}", a[4], name);
            std::fs::write(&out, &f.data).unwrap();
            println!("wrote {} ({} bytes)", out, f.data.len());
        }
    }
}
