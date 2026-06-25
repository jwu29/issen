# issen-mft-tree test fixtures

See the fleet catalog `issen/docs/corpus-catalog.md` for the full index; this file
is the co-located provenance detail.

#### dc01_mft_record_74419.bin

- **Source:** DFIR Madness "Stolen Szechuan Sauce" Case 001, host **CitadelDC01**
  (Server 2012 R2, NT 6.3.9600). By James Smith — <https://dfirmadness.com/the-stolen-szechuan-sauce/>.
- **Identity:** a single 1024-byte `$MFT` FILE record — entry **74419**, sequence 1.
  File: `C:\Windows\WinSxS\…\Classic_{37E2F32E-C821-4094-B429-2B4E8EA810AA}.settingcontent-ms`
  (a benign WinSxS component-store metadata record; no personal/sensitive data).
- **Extraction (verbatim):** from `DC01-E01.zip → E01-DC01/20200918_0347_CDrive.E01`
  (split E01+E02), C: partition at sector offset 718848:
  ```
  icat -o 718848 20200918_0347_CDrive.E01 0 \
    | dd bs=1024 skip=74419 count=1 of=dc01_mft_record_74419.bin
  ```
- **MD5:** `4c911975cff69016c3095553ed4540c6`
- **Ground truth (TSK `istat -o 718848 … 74419`, independent oracle):** `$SI`
  Modified = `2013-06-18 23:02:18.305856600 HKT` = `2013-06-18T15:02:18.305856600Z`.
  The trailing `600` is the non-zero 100 ns digit that a microsecond-truncating
  FILETIME converter silently drops.
- **Use case:** `from_mft_preserves_100ns_filetime_precision` in `src/parse.rs` —
  regression guard that `$SI`/`$FN` FILETIMEs keep full 100 ns precision (the
  `mft` crate's `winstructs` truncates 100 ns → µs).
- **Redistribution:** Case 001 is published free for DFIR education; a 1 KB
  non-sensitive WinSxS metadata record is committed under that allowance.
