#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! VMware VMDK disk image reader for the Issen forensic pipeline.
//!
//! Wraps the [`vmdk`] crate to provide a [`DataSource`] implementation for
//! monolithic sparse VMDK images (VMware Workstation / Fusion).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use issen_core::error::RtError;
use issen_core::plugin::traits::DataSource;

/// A backing stream a [`vmdk::VmdkReader`] can sit on: random-access and
/// thread-safe so [`VmdkDataSource`] stays `Send + Sync`.
///
/// Sealed (blanket impl only) — callers do not implement it directly; any
/// `Read + Seek + Send` type qualifies. This lets the reader sit on either a
/// loose `File` ([`VmdkDataSource::open`]) or a zip-entry-backed stream
/// ([`VmdkDataSource::open_zip`]) behind one boxed type.
pub trait ReadSeekSend: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeekSend for T {}

/// Errors specific to VMDK image operations.
#[derive(Debug, thiserror::Error)]
pub enum VmdkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("VMDK parse error: {0}")]
    Vmdk(String),
}

impl From<vmdk::VmdkError> for VmdkError {
    fn from(e: vmdk::VmdkError) -> Self {
        match e {
            vmdk::VmdkError::Io(io) => Self::Io(io),
            other => Self::Vmdk(other.to_string()),
        }
    }
}

impl From<VmdkError> for RtError {
    fn from(e: VmdkError) -> Self {
        match e {
            VmdkError::Io(io) => Self::Io(io),
            VmdkError::Vmdk(msg) => Self::Parse {
                offset: 0,
                message: format!("vmdk: {msg}"),
            },
        }
    }
}

/// A [`DataSource`] backed by a VMware VMDK disk image.
///
/// The backing is type-erased to [`ReadSeekSend`] so the same source serves a
/// loose `.vmdk` file ([`open`](Self::open)) and a `.vmdk` read directly out of
/// a `.zip` with no temp extraction ([`open_zip`](Self::open_zip)).
pub struct VmdkDataSource {
    reader: Mutex<vmdk::VmdkReader<Box<dyn ReadSeekSend>>>,
    size: u64,
}

impl std::fmt::Debug for VmdkDataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmdkDataSource")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl VmdkDataSource {
    /// Open a VMDK disk image (monolithic sparse / stream-optimised).
    pub fn open(path: &Path) -> Result<Self, VmdkError> {
        let file = File::open(path)?;
        let backing: Box<dyn ReadSeekSend> = Box::new(file);
        Self::from_backing(backing)
    }

    /// Open a single-extent `.vmdk` that lives INSIDE a `.zip` — directly,
    /// without extracting it to a temp directory first.
    ///
    /// A `Stored` entry is read **in place** as a positioned sub-range of the
    /// zip file (zero extraction, zero inflate, true random access). A
    /// `Deflated` entry is **inflated once into RAM** (deflate is
    /// sequential-only) and read back from a [`std::io::Cursor`]. Either backing
    /// feeds [`vmdk::VmdkReader`]'s lazy grain-table cache, so the in-memory
    /// index stays bounded regardless of virtual-disk size.
    ///
    /// Scope: the common single-extent monolithic-sparse / stream-optimised
    /// case (one `.vmdk` entry that is itself a complete binary VMDK). A
    /// multi-extent image (a text descriptor `.vmdk` plus separate `-s00N` /
    /// `-flat` extent files) is **out of scope** and rejected.
    ///
    /// # Errors
    /// [`VmdkError`] if the zip cannot be read, holds no `.vmdk` entry, or the
    /// entry is not a self-contained binary VMDK.
    pub fn open_zip(zip_path: &Path) -> Result<Self, VmdkError> {
        // One handle backs the in-place `Stored` sub-range read; a second drives
        // the zip's central-directory walk + on-demand inflation.
        let backing_file = Arc::new(File::open(zip_path)?);
        let mut archive = zip::ZipArchive::new(File::open(zip_path)?)
            .map_err(|e| VmdkError::Vmdk(format!("zip open: {e}")))?;

        // Find the first `.vmdk` entry (deterministic by name). Single-extent
        // only — the descriptor+extents multi-file shape is out of scope.
        let mut names: Vec<(usize, String)> = (0..archive.len())
            .map(|i| -> Result<(usize, String), VmdkError> {
                let e = archive
                    .by_index_raw(i)
                    .map_err(|e| VmdkError::Vmdk(format!("zip entry {i}: {e}")))?;
                Ok((i, e.name().to_string()))
            })
            .collect::<Result<_, _>>()?;
        names.sort_by(|a, b| a.1.cmp(&b.1));

        let Some((idx, name)) = names.into_iter().find(|(_, n)| is_vmdk_entry(n)) else {
            return Err(VmdkError::Vmdk(format!(
                "no .vmdk entry found in {}",
                zip_path.display()
            )));
        };

        let mut entry = archive
            .by_index(idx)
            .map_err(|e| VmdkError::Vmdk(format!("zip entry {name}: {e}")))?;
        let backing: Box<dyn ReadSeekSend> =
            if entry.compression() == zip::CompressionMethod::Stored {
                // Contiguous, uncompressed -> a positioned sub-range of the zip.
                Box::new(SubRangeReader::new(
                    Arc::clone(&backing_file),
                    entry.data_start(),
                    entry.size(),
                ))
            } else {
                // Compressed -> inflate the whole entry once, read from RAM.
                let mut buf = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
                entry
                    .read_to_end(&mut buf)
                    .map_err(|e| VmdkError::Vmdk(format!("inflate {name}: {e}")))?;
                Box::new(std::io::Cursor::new(buf))
            };
        Self::from_backing(backing)
    }

    /// Build a source from an already-erased backing (shared by `open`/`open_zip`).
    fn from_backing(backing: Box<dyn ReadSeekSend>) -> Result<Self, VmdkError> {
        let reader = vmdk::VmdkReader::open(backing)?;
        let size = reader.virtual_disk_size();
        Ok(Self {
            reader: Mutex::new(reader),
            size,
        })
    }
}

/// True when a zip entry names a `.vmdk` file (case-insensitive), excluding
/// directory entries.
fn is_vmdk_entry(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.len() > 5
        && base
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("vmdk"))
}

/// A positioned, read-only sub-range view over a shared file: `[base, base+len)`
/// presented as its own `0..len` address space. Lets a `Stored` zip entry serve
/// as a `Read + Seek` backing with zero extraction.
///
/// Reads under a `pread`-style positioned syscall where available
/// (`read_at`/`seek_read`), so concurrent clones do not contend on a shared
/// cursor; the internal `pos` is the only per-clone state.
struct SubRangeReader {
    file: Arc<File>,
    base: u64,
    len: u64,
    pos: u64,
}

impl SubRangeReader {
    fn new(file: Arc<File>, base: u64, len: u64) -> Self {
        Self {
            file,
            base,
            len,
            pos: 0,
        }
    }
}

impl Read for SubRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.len - self.pos;
        let to_read = (buf.len() as u64).min(remaining) as usize;
        let abs = self.base + self.pos;
        let n = positioned_read(&self.file, abs, &mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SubRangeReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of sub-range",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Positioned read at an absolute file offset without moving a shared cursor.
#[cfg(unix)]
fn positioned_read(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

/// Positioned read at an absolute file offset without moving a shared cursor.
#[cfg(windows)]
fn positioned_read(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

impl DataSource for VmdkDataSource {
    fn len(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, RtError> {
        let mut guard = self.reader.lock().expect("mutex poisoned");
        guard.seek(SeekFrom::Start(offset)).map_err(RtError::Io)?;
        let mut total = 0;
        while total < buf.len() {
            match guard.read(&mut buf[total..]).map_err(RtError::Io)? {
                0 => break,
                n => total += n,
            }
        }
        Ok(total)
    }
}

// ── CollectionProvider ────────────────────────────────────────────────

use issen_unpack::{CollectionManifest, CollectionProvider, Confidence};

/// Format-recognition and manifest provider for VMware VMDK disk images.
#[derive(Debug, Default)]
pub struct VmdkProvider;

impl CollectionProvider for VmdkProvider {
    #[allow(clippy::unnecessary_literal_bound)] // trait fixes the `-> &str` signature
    fn name(&self) -> &str {
        "VMDK"
    }

    fn probe(&self, path: &Path) -> Result<Confidence, RtError> {
        use std::io::Read;
        // VMDK sparse extent magic: 0x564D444B stored LE = bytes [0x4B, 0x44, 0x4D, 0x56]
        const VMDK_MAGIC: [u8; 4] = [0x4B, 0x44, 0x4D, 0x56];
        let mut f = std::fs::File::open(path).map_err(RtError::Io)?;
        let mut magic = [0u8; 4];
        match f.read_exact(&mut magic) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Confidence::None),
            Err(e) => return Err(RtError::Io(e)),
        }
        if magic == VMDK_MAGIC {
            Ok(Confidence::High)
        } else {
            Ok(Confidence::None)
        }
    }

    fn open(&self, path: &Path) -> Result<CollectionManifest, RtError> {
        // Decode the VMDK, then run the NTFS disk-triage pipeline: detect the
        // partition table, open each NTFS volume, and extract the standard
        // Windows triage artifacts into a manifest the ingest pipeline parses.
        let source = VmdkDataSource::open(path)?;
        Ok(issen_disk::triage_manifest(&source, self.name())?)
    }
}

inventory::submit!(issen_unpack::registry::ProviderRegistration {
    create: || Box::new(VmdkProvider),
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sparse_vmdk(sector_data: &[u8]) -> Vec<u8> {
        vmdk::testutil::test_sparse_vmdk(sector_data)
    }

    fn write_tmp(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f
    }

    #[test]
    fn open_nonexistent_returns_err() {
        assert!(VmdkDataSource::open(Path::new("/tmp/nope.vmdk")).is_err());
    }

    #[test]
    fn is_vmdk_entry_matches_vmdk_only() {
        assert!(is_vmdk_entry("disk.vmdk"));
        assert!(is_vmdk_entry("sub/dir/disk.VMDK"));
        assert!(is_vmdk_entry("DC01-flat-s001.vmdk"));
        assert!(!is_vmdk_entry("disk.vmdk/")); // directory entry
        assert!(!is_vmdk_entry("disk.E01"));
        assert!(!is_vmdk_entry("notes.txt"));
        assert!(!is_vmdk_entry(".vmdk")); // no stem
    }

    #[test]
    fn open_zip_no_vmdk_entry_returns_err() {
        let zip_path = std::env::temp_dir().join("issen_vmdk_no_entry.zip");
        {
            let f = std::fs::File::create(&zip_path).unwrap();
            let mut zw = zip::ZipWriter::new(f);
            zw.start_file("readme.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            zw.write_all(b"hello").unwrap();
            zw.finish().unwrap();
        }
        let err = VmdkDataSource::open_zip(&zip_path).unwrap_err();
        assert!(format!("{err}").contains("no .vmdk entry"));
        let _ = std::fs::remove_file(&zip_path);
    }

    /// Env-gated (fleet real-data pattern): point `ISSEN_VMDK_TEST` at a small
    /// single-extent `.vmdk` (e.g. `compressed_stream_opt.vmdk` or
    /// `tw_sparse-s001.vmdk`); the test zips it BOTH stored and deflated and
    /// asserts `open_zip` == `open(loose)` byte-identical over the whole virtual
    /// disk — proving the Stored (in-place sub-range) and Deflated (inflate)
    /// glue. Skips cleanly when unset.
    #[test]
    fn open_zip_matches_open_loose_stored_and_deflated() {
        let Ok(vmdk) = std::env::var("ISSEN_VMDK_TEST") else {
            eprintln!("skip open_zip test: set ISSEN_VMDK_TEST to a single-extent .vmdk path");
            return;
        };
        let vmdk = std::path::PathBuf::from(vmdk);
        let oracle = VmdkDataSource::open(&vmdk).expect("open loose vmdk");
        let total = oracle.len() as usize;
        let mut want = vec![0u8; total];
        oracle.read_at(0, &mut want).expect("read loose");
        let bytes = std::fs::read(&vmdk).expect("read vmdk bytes");

        for method in [
            zip::CompressionMethod::Stored,
            zip::CompressionMethod::Deflated,
        ] {
            let zip_path = std::env::temp_dir().join(format!("issen_vmdk_bridge_{method:?}.zip"));
            {
                let f = std::fs::File::create(&zip_path).unwrap();
                let mut zw = zip::ZipWriter::new(f);
                let opts = zip::write::SimpleFileOptions::default().compression_method(method);
                zw.start_file("image.vmdk", opts).unwrap();
                zw.write_all(&bytes).unwrap();
                zw.finish().unwrap();
            }
            let via_zip = VmdkDataSource::open_zip(&zip_path).expect("open_zip");
            assert_eq!(via_zip.len() as usize, total, "{method:?} total_size");
            let mut got = vec![0u8; total];
            via_zip.read_at(0, &mut got).expect("read via zip");
            assert_eq!(got, want, "{method:?}: bytes via zip differ from loose");
            let _ = std::fs::remove_file(&zip_path);
        }
    }

    #[test]
    fn len_matches_virtual_disk_size() {
        let vmdk = sparse_vmdk(&vec![0u8; 512]);
        let f = write_tmp(&vmdk);
        let src = VmdkDataSource::open(f.path()).expect("open");
        assert_eq!(src.len(), vmdk::testutil::GRAIN_SIZE_BYTES as u64);
    }

    #[test]
    fn read_at_returns_correct_bytes() {
        let mut data = vec![0u8; 512];
        data[10] = 0xCA;
        data[11] = 0xFE;
        let vmdk = sparse_vmdk(&data);
        let f = write_tmp(&vmdk);
        let src = VmdkDataSource::open(f.path()).expect("open");
        let mut buf = [0u8; 2];
        src.read_at(10, &mut buf).expect("read_at");
        assert_eq!(buf, [0xCA, 0xFE]);
    }

    #[test]
    fn vmdk_data_source_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VmdkDataSource>();
    }

    #[test]
    fn vmdk_error_converts_to_rt_error() {
        let e = VmdkError::Vmdk("bad magic".into());
        assert!(matches!(RtError::from(e), RtError::Parse { .. }));
    }

    // ── VmdkProvider tests ────────────────────────────────────────────

    #[test]
    fn vmdk_provider_name() {
        assert_eq!(VmdkProvider.name(), "VMDK");
    }

    #[test]
    fn vmdk_provider_probe_valid_magic_returns_high() {
        // VMDK sparse magic: 0x564D444B LE = bytes [0x4B, 0x44, 0x4D, 0x56]
        let magic_bytes = 0x564D_444Bu32.to_le_bytes();
        let vmdk_data = vmdk::testutil::test_sparse_vmdk(&[0u8; 512]);
        let f = write_tmp(&vmdk_data);
        assert_eq!(
            magic_bytes[..],
            vmdk_data[..4],
            "test VMDK must start with sparse magic"
        );
        // RED: stub returns None — FAILS
        assert_eq!(
            VmdkProvider.probe(f.path()).expect("probe"),
            Confidence::High
        );
    }

    #[test]
    fn vmdk_provider_probe_wrong_magic_returns_none() {
        let f = write_tmp(b"not-vmdk\x00\x00\x00\x00");
        assert_eq!(
            VmdkProvider.probe(f.path()).expect("probe"),
            Confidence::None
        );
    }

    #[test]
    fn vmdk_provider_probe_nonexistent_returns_err() {
        // RED: stub returns Ok(None) — FAILS
        assert!(VmdkProvider
            .probe(Path::new("/tmp/nonexistent_99999.vmdk"))
            .is_err());
    }

    #[test]
    fn vmdk_provider_open_invalid_returns_err() {
        let f = write_tmp(b"not a vmdk");
        assert!(VmdkProvider.open(f.path()).is_err());
    }

    #[test]
    fn vmdk_provider_open_nonexistent_returns_err() {
        assert!(VmdkProvider
            .open(Path::new("/tmp/nonexistent_99999.vmdk"))
            .is_err());
    }

    #[test]
    fn vmdk_provider_open_runs_disk_triage() {
        // A VMDK wrapping a disk with no partition table: open() now runs the
        // NTFS disk-triage pipeline (issen_disk::triage_manifest), which tags
        // the collection os_type = Windows. The old stub left it Unknown.
        // (Full artifact extraction is covered by issen-disk's own tests.)
        let disk = vec![0u8; 64 * 512];
        let vmdk_data = vmdk::testutil::test_sparse_vmdk(&disk);
        let f = write_tmp(&vmdk_data);
        let manifest = VmdkProvider.open(f.path()).expect("open runs triage");
        assert_eq!(manifest.format_name, "VMDK");
        assert!(matches!(
            manifest.metadata.os_type,
            issen_unpack::OsType::Windows
        ));
    }

    #[test]
    fn vmdk_provider_registered_in_inventory() {
        use issen_unpack::registry::ProviderRegistration;
        let names: Vec<String> = inventory::iter::<ProviderRegistration>
            .into_iter()
            .map(|r| (r.create)().name().to_string())
            .collect();
        assert!(
            names.contains(&"VMDK".to_string()),
            "VmdkProvider must be in inventory; got: {names:?}"
        );
    }
}
