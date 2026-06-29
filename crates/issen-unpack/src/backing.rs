//! Centralized bounded backing for a disk-image container that may live loose on
//! disk OR inside an archive (zip / 7z / tar.gz / tar.bz2 / dar).
//!
//! The RAM-vs-temp spill decision for a *compressed* image entry is governed by
//! an adaptive budget (this module's pure core, [`ram_threshold`]) plus a
//! streaming spooled buffer that rolls over on the *actual* decompressed bytes
//! (bomb-safe, independent of the entry's declared size). A `zip` `Stored` entry
//! never reaches the spill path — it is read in place (zero copy).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::SpooledTempFile;

/// A seekable, thread-safe byte source a container reader can sit on: an in-place
/// window over an archive file, an in-RAM buffer, or a disk-backed temp spill.
/// One canonical definition for the whole fleet (each container's `open_reader`
/// accepts `Box<dyn ReadSeekSend>`).
pub trait ReadSeekSend: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> ReadSeekSend for T {}

/// One mebibyte, in bytes.
const MIB: u64 = 1024 * 1024;
/// One gibibyte, in bytes.
const GIB: u64 = 1024 * 1024 * 1024;

/// Floor on the per-image RAM-residency threshold: below this, spilling a tiny
/// entry costs more in filesystem overhead than the RAM it would save.
const THRESHOLD_FLOOR: u64 = 64 * MIB;
/// Ceiling: above the parser's typical working set, holding more of an image
/// resident buys nothing (a multi-GB image is read in scattered fragments), so
/// spill instead of committing more RAM.
const THRESHOLD_CEILING: u64 = GIB;
/// Denominator of the fraction of *available* RAM we commit to resident images;
/// the remaining 3/4 is left for issen's own growth (DuckDB / correlate) + OS.
const RAM_COMMIT_DENOMINATOR: u64 = 4;

/// Resource snapshot gathered once per ingest, used to size the per-image
/// RAM-residency threshold. All byte counts are bytes. The platform probing that
/// fills this in is a thin shell ([`probe_spill_plan`]); this struct keeps the
/// budget math pure and testable.
#[derive(Debug, Clone, Copy)]
pub struct SpillPlan {
    /// Currently available (free + reclaimable) RAM, in bytes.
    pub available_ram: u64,
    /// Planned concurrent decompressions (sources × worker cap). Treated as 1 if
    /// zero.
    pub concurrency: usize,
    /// Explicit operator override (`ISSEN_ARCHIVE_SPILL_THRESHOLD`), in bytes;
    /// when set it wins outright, unclamped, for deterministic environments.
    pub env_override: Option<u64>,
}

/// Per-image RAM-residency threshold in bytes: a decompressed image strictly
/// smaller than this stays in a RAM buffer; at or above it, it spills to a
/// disk-backed temp file.
///
/// The budget is `1/4 of available RAM`, split across the planned concurrency,
/// clamped to `[64 MiB, 1 GiB]`. An `env_override` bypasses the formula entirely.
#[must_use]
pub fn ram_threshold(plan: &SpillPlan) -> u64 {
    // An explicit operator override wins outright (deterministic environments).
    if let Some(n) = plan.env_override {
        return n;
    }
    let concurrency = plan.concurrency.max(1) as u64;
    // 1/4 of available RAM, split across the planned concurrent decompressions.
    // Divide before multiplying is unnecessary here (denominator only), and the
    // budget can't overflow u64 for any real RAM size.
    let budget = plan.available_ram / RAM_COMMIT_DENOMINATOR;
    let per_image = budget / concurrency;
    per_image.clamp(THRESHOLD_FLOOR, THRESHOLD_CEILING)
}

/// A positioned, read-only window `[base, base + len)` over a shared archive
/// file — lets a container reader sit directly on a `Stored` (uncompressed) zip
/// entry with zero copy. Positioned reads (no `&mut` on the file), so `Send +
/// Sync`. This is the one canonical copy (the per-container duplicates fold into
/// it).
#[derive(Debug)]
pub struct SubRangeReader {
    file: Arc<File>,
    base: u64,
    len: u64,
    pos: u64,
}

impl SubRangeReader {
    /// Window `[base, base + len)` over `file`.
    #[must_use]
    pub fn new(file: Arc<File>, base: u64, len: u64) -> Self {
        Self {
            file,
            base,
            len,
            pos: 0,
        }
    }
}

impl Read for SubRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let to_read = (buf.len() as u64).min(remaining) as usize;
        #[cfg(unix)]
        let n = {
            use std::os::unix::fs::FileExt;
            self.file
                .read_at(&mut buf[..to_read], self.base + self.pos)?
        };
        #[cfg(windows)]
        let n = {
            use std::os::windows::fs::FileExt;
            self.file
                .seek_read(&mut buf[..to_read], self.base + self.pos)?
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SubRangeReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(n) => self.pos as i64 + n,
            SeekFrom::End(n) => self.len as i64 + n,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

/// Stream every byte of `src` into a spooled buffer that stays in RAM until it
/// exceeds `ram_threshold` bytes, then rolls over to a disk-backed temp file in
/// `dir`. Returns the buffer seeked to the start. Bounded: `io::copy` streams
/// through a fixed buffer, so RAM never holds the whole decompressed image once
/// it has rolled over. `max_bytes` caps the output (decompression-bomb guard) —
/// exceeding it is an error, not a silent truncation.
///
/// # Errors
/// I/O failure, or `src` produces more than `max_bytes` (possible bomb).
pub fn spill_from<R: Read>(
    src: R,
    ram_threshold: u64,
    max_bytes: u64,
    dir: &Path,
) -> io::Result<SpooledTempFile> {
    let threshold = usize::try_from(ram_threshold).unwrap_or(usize::MAX);
    let mut spool = tempfile::spooled_tempfile_in(threshold, dir);
    // Read at most max_bytes + 1 so an overrun is detectable without consuming
    // the whole (possibly bomb-sized) stream.
    let mut limited = src.take(max_bytes.saturating_add(1));
    let written = io::copy(&mut limited, &mut spool)?;
    if written > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("decompressed output exceeds cap of {max_bytes} bytes (possible bomb)"),
        ));
    }
    spool.seek(SeekFrom::Start(0))?;
    Ok(spool)
}

/// Choose the first writable, **non-tmpfs** directory from `candidates` in order
/// (storage-backed before in-memory), falling back to any writable candidate.
/// Pure: filesystem facts are injected via the predicates, so the
/// prefer-storage-over-RAM logic is testable without real mounts.
fn select_storage_dir(
    candidates: &[PathBuf],
    writable: &dyn Fn(&Path) -> bool,
    is_tmpfs: &dyn Fn(&Path) -> bool,
) -> Option<PathBuf> {
    // Prefer a writable, storage-backed directory in priority order.
    if let Some(d) = candidates
        .iter()
        .find(|c| writable(c) && !is_tmpfs(c))
        .cloned()
    {
        return Some(d);
    }
    // Nothing storage-backed: a writable tmpfs beats failing outright.
    candidates.iter().find(|c| writable(c)).cloned()
}

/// Resolve a disk-backed temp directory for spilling decompressed images,
/// preferring storage-backed mounts over RAM-backed tmpfs — the OS default temp
/// dir is often tmpfs (tempfile's own docs warn of this), and spilling there
/// would silently defeat the bounded-RAM goal. Honors `ISSEN_SPILL_DIR`.
#[must_use]
pub fn storage_backed_temp_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("ISSEN_SPILL_DIR") {
        return PathBuf::from(d);
    }
    let candidates = [
        PathBuf::from("/var/tmp"), // Linux: persistent, disk-backed
        std::env::temp_dir(),      // macOS: disk-backed ($TMPDIR); Linux: often tmpfs
        PathBuf::from("/tmp"),
    ];
    select_storage_dir(&candidates, &dir_is_writable, &dir_is_tmpfs)
        .unwrap_or_else(std::env::temp_dir)
}

/// True if a temp file can actually be created in `dir` right now.
fn dir_is_writable(dir: &Path) -> bool {
    dir.is_dir() && tempfile::Builder::new().tempfile_in(dir).is_ok()
}

/// True if `dir` lives on a RAM-backed filesystem (tmpfs/ramfs). Reads
/// `/proc/mounts` (absent off Linux → `false`, which is correct: macOS/Windows
/// default temp dirs are disk-backed).
fn dir_is_tmpfs(dir: &Path) -> bool {
    let canon = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    std::fs::read_to_string("/proc/mounts")
        .ok()
        .and_then(|m| fstype_for_path(&m, &canon).map(str::to_owned))
        .is_some_and(|fs| fs == "tmpfs" || fs == "ramfs")
}

/// Filesystem type of the mount containing `target`, from `/proc/mounts` text:
/// the longest mount-point that is a path-prefix of `target`. Pure, so the
/// longest-prefix selection is testable without real mounts.
fn fstype_for_path<'a>(mounts: &'a str, target: &Path) -> Option<&'a str> {
    let mut best: Option<(&str, &str)> = None; // (mount_point, fstype)
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (_dev, mount_point, fstype) = (fields.next(), fields.next(), fields.next());
        if let (Some(mp), Some(fs)) = (mount_point, fstype) {
            if target.starts_with(mp) && best.is_none_or(|(b, _)| mp.len() > b.len()) {
                best = Some((mp, fs));
            }
        }
    }
    best.map(|(_, fs)| fs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(available_ram: u64, concurrency: usize) -> SpillPlan {
        SpillPlan {
            available_ram,
            concurrency,
            env_override: None,
        }
    }

    #[test]
    fn env_override_wins_unclamped() {
        // Override is an explicit operator choice — honored literally, even
        // outside the [floor, ceiling] band, regardless of RAM/concurrency.
        let p = SpillPlan {
            available_ram: 64 * GIB,
            concurrency: 100,
            env_override: Some(5 * GIB),
        };
        assert_eq!(ram_threshold(&p), 5 * GIB);
        let p2 = SpillPlan {
            available_ram: 1 * GIB,
            concurrency: 1,
            env_override: Some(16 * MIB),
        };
        assert_eq!(ram_threshold(&p2), 16 * MIB);
    }

    #[test]
    fn shrinks_as_concurrency_grows() {
        // 8 GiB available: /4 = 2 GiB budget; ÷concurrency lands in-band.
        let four = ram_threshold(&plan(8 * GIB, 4)); // 512 MiB
        let eight = ram_threshold(&plan(8 * GIB, 8)); // 256 MiB
        assert_eq!(four, 512 * MIB);
        assert_eq!(eight, 256 * MIB);
        assert!(eight < four, "more sources → smaller per-image budget");
    }

    #[test]
    fn grows_with_available_ram() {
        let lo = ram_threshold(&plan(2 * GIB, 2)); // 0.25*2G/2 = 256 MiB
        let hi = ram_threshold(&plan(8 * GIB, 2)); // 0.25*8G/2 = 1 GiB (ceiling)
        assert_eq!(lo, 256 * MIB);
        assert_eq!(hi, GIB);
        assert!(hi > lo, "more available RAM → larger per-image budget");
    }

    #[test]
    fn clamps_to_floor_on_scarce_ram() {
        // 1 GiB available, 4 sources: 0.25*1G/4 = 64 MiB exactly; 512 MiB box
        // would compute 32 MiB → clamped up to the 64 MiB floor.
        assert_eq!(ram_threshold(&plan(1 * GIB, 4)), 64 * MIB);
        assert_eq!(ram_threshold(&plan(512 * MIB, 4)), 64 * MIB);
    }

    #[test]
    fn clamps_to_ceiling_on_abundant_ram() {
        // 64 GiB available, single source: 16 GiB budget → capped at 1 GiB.
        assert_eq!(ram_threshold(&plan(64 * GIB, 1)), GIB);
    }

    #[test]
    fn zero_concurrency_treated_as_one() {
        assert_eq!(
            ram_threshold(&plan(8 * GIB, 0)),
            ram_threshold(&plan(8 * GIB, 1))
        );
    }

    fn tmp_file_with(bytes: &[u8]) -> (tempfile::NamedTempFile, Arc<File>) {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        let reopened = Arc::new(f.reopen().unwrap());
        (f, reopened)
    }

    #[test]
    fn sub_range_reads_only_its_window() {
        let data: Vec<u8> = (0u8..=255).collect();
        let (_keep, file) = tmp_file_with(&data);
        let mut sr = SubRangeReader::new(file, 20, 10); // bytes 20..30
        let mut buf = vec![0u8; 16];
        let n = sr.read(&mut buf).unwrap();
        assert_eq!(n, 10, "clamped to window length");
        assert_eq!(&buf[..10], &data[20..30]);
        assert_eq!(sr.read(&mut buf).unwrap(), 0, "EOF at window end");
    }

    #[test]
    fn sub_range_seek_is_window_relative() {
        let data: Vec<u8> = (0u8..=255).collect();
        let (_keep, file) = tmp_file_with(&data);
        let mut sr = SubRangeReader::new(file, 100, 50);
        sr.seek(SeekFrom::Start(5)).unwrap();
        let mut buf = [0u8; 1];
        sr.read(&mut buf).unwrap();
        assert_eq!(buf[0], data[105], "offset 5 in window = byte base+5");
        assert_eq!(sr.seek(SeekFrom::End(0)).unwrap(), 50, "End = window len");
    }

    #[test]
    fn sub_range_is_read_seek_send_sync() {
        fn assert_rss<T: ReadSeekSend>() {}
        assert_rss::<SubRangeReader>();
    }

    #[test]
    fn spill_below_threshold_stays_in_ram() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0xABu8; 100];
        let mut spool = spill_from(&payload[..], 1000, 1 << 20, dir.path()).unwrap();
        assert!(!spool.is_rolled(), "100 B under 1000 B threshold → in RAM");
        let mut got = Vec::new();
        spool.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn spill_above_threshold_rolls_to_temp() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0xCDu8; 10_000];
        let mut spool = spill_from(&payload[..], 100, 1 << 20, dir.path()).unwrap();
        assert!(
            spool.is_rolled(),
            "10 kB over 100 B threshold → spilled to disk"
        );
        let mut got = Vec::new();
        spool.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload, "spilled bytes round-trip identically");
    }

    #[test]
    fn spill_rejects_output_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let payload = vec![0u8; 10_000];
        let result = spill_from(&payload[..], 1 << 20, 100, dir.path());
        assert!(
            result.is_err(),
            "output exceeding max_bytes must error (bomb guard)"
        );
    }

    #[test]
    fn select_storage_dir_prefers_non_tmpfs() {
        let cands = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
        let writable = |_: &Path| true;
        let is_tmpfs = |p: &Path| p == Path::new("/tmp");
        assert_eq!(
            select_storage_dir(&cands, &writable, &is_tmpfs),
            Some(PathBuf::from("/var/tmp")),
            "skip the writable-but-tmpfs /tmp for storage-backed /var/tmp"
        );
    }

    #[test]
    fn select_storage_dir_falls_back_to_tmpfs_when_only_option() {
        let cands = vec![PathBuf::from("/tmp")];
        assert_eq!(
            select_storage_dir(&cands, &|_| true, &|_| true),
            Some(PathBuf::from("/tmp")),
            "tmpfs beats failing entirely"
        );
    }

    #[test]
    fn select_storage_dir_none_when_nothing_writable() {
        assert_eq!(
            select_storage_dir(&[PathBuf::from("/nope")], &|_| false, &|_| false),
            None
        );
    }

    #[test]
    fn fstype_picks_longest_mount_prefix() {
        let mounts = "\
sysfs /sys sysfs rw 0 0
/dev/sda1 / ext4 rw 0 0
tmpfs /tmp tmpfs rw 0 0
/dev/sdb1 /var/tmp xfs rw 0 0
";
        // /tmp is its own tmpfs mount; /var/tmp is a disk-backed xfs mount.
        assert_eq!(
            fstype_for_path(mounts, Path::new("/tmp/spill")),
            Some("tmpfs")
        );
        assert_eq!(
            fstype_for_path(mounts, Path::new("/var/tmp/spill")),
            Some("xfs")
        );
        // A path under no specific mount falls to root.
        assert_eq!(fstype_for_path(mounts, Path::new("/home/x")), Some("ext4"));
        assert_eq!(fstype_for_path("", Path::new("/x")), None);
    }
}
