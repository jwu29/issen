# issen-parser-lnk test fixtures

#### removable_media.lnk
- **Source**: `lnk-forensic` test corpus (SecurityRonin/`h4x0r`), `tests/data/removable_media.lnk`.
- **Provenance**: spec-exact, hand-authored byte-for-byte per [MS-SHLLINK] (a macOS host
  cannot author a real Windows Shell Link); validated by `lnk-core`'s own tests.
- **MD5**: `ba3dbe2429bdfa93d8a0a9be80ca0fbe`
- **Contents**: a `.lnk` targeting `E:\payload.exe` on a REMOVABLE volume
  "KINGSTON USB" (drive serial `0xDEADBEEF`) — exercises the target-path + USB-origin
  fields the wrapper must surface.
- **Used by**: `tests/depth.rs` (the LNK parser-depth regression).

#### network_share.lnk
- **Source**: `lnk-forensic` test corpus (SecurityRonin/`h4x0r`), `tests/data/network_share.lnk`.
- **Provenance**: SYNTHETIC, spec-exact hand-authored per [MS-SHLLINK] (a macOS host
  cannot author a real Windows Shell Link); validated by `lnk-core`'s own tests.
- **MD5**: `547e0d2686e6652d8d144fb1b767bf9a`
- **Contents**: a `.lnk` whose `LinkInfo` carries a `CommonNetworkRelativeLink`
  (`NetName = \\SERVER\share`, `DeviceName = Z:`) — exercises the UNC network-share
  origin (lateral-movement join key) the wrapper must surface.
- **Used by**: `tests/depth.rs` (the LNK parser-depth regression).

#### command_args.lnk
- **Source**: hand-authored spec-exact per [MS-SHLLINK] (`StringData` section), generated
  by a dependency-free `rustc` program modeled on `lnk-forensic`'s `gen_lnk.rs` (the
  generator source is reproduced in this repo's commit message / corpus-catalog).
- **Provenance**: SYNTHETIC, spec-exact; validated by `lnk-core::parse_shell_link`.
- **MD5**: `93628f2fb784ca33ea2cd63e8ed87eff`
- **Contents**: a weaponized-shortcut shape — `StringData` carries name `System Update`,
  relative path `.\powershell.exe`, working dir `C:\Windows\System32`, and arguments
  `-nop -w hidden -enc SQBFAFgAKABuAGUAdwApAA==` (an encoded-PowerShell launcher).
  Exercises the command-line-arguments + working-dir depth the wrapper must surface.
- **Used by**: `tests/depth.rs` (the LNK parser-depth regression).

#### 9b9cdc69c1c24e2b.automaticDestinations-ms
- **Source**: REAL captured Windows JumpList from the DFIR Madness "Stolen Szechuan Sauce"
  scenario — `20200918_0347_CDrive.E01` (DC01), NTFS partition at byte offset `718848`.
- **In-image path**: `Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms`
  — **inode 86968** (extracted with `icat -o 718848 "$E01" 86968 > <file>`).
- **Provenance**: REAL-ext (real third-party corpus). Validated as a genuine OLE/CFB
  compound file by the published `cfb-forensic` crate (`live_entry_names` returns the live
  streams `Root Entry`, `DestList`, `1`–`5`); decoded through issen's path via
  `lnk-core::parse_automatic_destinations` / `parse_jumplist_bytes`.
- **MD5**: `18b8fe1fee7120db495c5a6aba947533`
- **Contents**: AppID `9b9cdc69c1c24e2b` (Notepad). Five DestList entries — recent files
  opened on host `citadel-dc01` under `C:\FileShare\Secret\`: `Beth_Secret.txt`,
  `Szechuan Sauce.txt`, `SECRET_beth.txt`, `PortalGunPlans.txt`, `NoJerry.txt`.
  Each embedded LNK carries a `TrackerDataBlock` (distributed-link-tracking droid
  GUIDs): origin machine (NetBIOS) `citadel-dc01`; the birth-droid object GUIDs are
  UUID-v1 with node (MAC) `00:0C:29:E1:84:E6` (VMware OUI `00:0C:29`, the virtualized
  lab host) — cross-machine origin evidence for the *target* file's creation.
- **License**: DFIR Madness corpus, educational / research use.
- **Used by**: `tests/jumplist_depth.rs` (incl. the birth-droid origin case),
  `tests/jumplist_cfb_validation.rs`, and the issen-cli depth gate
  `tests/parser_depth_gate.rs` (incl. the `birth_droid_*` cross-machine-origin case).

#### 28c8b86deab549a1.customDestinations-ms
- **Source**: REAL captured Windows JumpList from the DFIR Madness "Stolen Szechuan Sauce"
  scenario — `20200918_0347_CDrive.E01` (DC01), NTFS partition at byte offset `718848`.
- **In-image path**: `Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/28c8b86deab549a1.customDestinations-ms`
  — **inode 87092** (extracted with `icat -o 718848 "$E01" 87092 > <file>`).
- **Provenance**: REAL-ext. The CustomDestinations form is the flat, non-CFB layout — the
  published `cfb-forensic` crate confirms it is *not* an OLE compound file
  (`live_entry_names` returns `None`); decoded through issen's path via
  `lnk-core::parse_custom_destinations` / `parse_jumplist_bytes`.
- **MD5**: `a4af29faae0cdfd56fe2295611d54488`
- **Contents**: AppID `28c8b86deab549a1` (Internet Explorer 32-bit). Custom-destination
  entries targeting `C:\Program Files\Internet Explorer\iexplore.exe`.
- **License**: DFIR Madness corpus, educational / research use.
- **Used by**: `tests/jumplist_depth.rs` and the issen-cli depth gate
  `tests/parser_depth_gate.rs`.

Cross-reference: [`issen/docs/corpus-catalog.md`](../../../../../docs/corpus-catalog.md).
