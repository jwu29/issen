//! One-off: carve every user's `UsrClass.dat` from an E01 to an output dir.
//! Usage: extract_usrclass <image.E01> <out-dir>
#![allow(clippy::unwrap_used, clippy::expect_used)]
use issen_disk::{extract_per_subdir, find_ntfs_partitions};
use issen_ewf::EwfDataSource;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let src = EwfDataSource::open(std::path::Path::new(&a[1])).expect("open");
    for w in find_ntfs_partitions(&src).expect("parts") {
        let child = r"AppData\Local\Microsoft\Windows\UsrClass.dat";
        let files = match extract_per_subdir(&src, w, r"\Users", child) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for f in files {
            let user = f.path.split('\\').nth(2).unwrap_or("unknown");
            let out = format!("{}/UsrClass-{}.dat", a[2], user);
            std::fs::write(&out, &f.data).unwrap();
            println!("wrote {} ({} bytes) from {}", out, f.data.len(), f.path);
        }
    }
}
