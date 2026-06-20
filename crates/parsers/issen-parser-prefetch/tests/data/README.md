# issen-parser-prefetch test fixtures

#### COREUPDATER.EXE-157C54BB.pf
- **Source**: `prefetch-forensic` test corpus (SecurityRonin/`h4x0r`),
  `tests/data/COREUPDATER.EXE-157C54BB.pf`, itself from the **Stolen Szechuan
  Sauce** DFIR case (Case 001, Desktop host).
- **Writeup**: https://thedfirreport.com/2020/11/30/stolen-szechuan-sauce/
- **Dataset**: https://github.com/dlcowen/TheStolenSzechuanSauce
- **MD5**: `d3db6935c7ad9f93964b0893997af049`
- **Identity**: real `MAM\x04` (Xpress-Huffman) + SCCA v30 prefetch for the Case 001
  implant `coreupdater.exe` (Meterpreter). One run; volume serial `B0E0E8FF`;
  **51 loaded files** including paths ending in `NTDLL.DLL` and `COREUPDATER.EXE`.
- **Used by**: `tests/depth.rs` (the prefetch parser-depth regression — the
  wrapper must surface the loaded-file LIST, not just its count).

Cross-reference: [`issen/docs/corpus-catalog.md`](../../../../../docs/corpus-catalog.md).
