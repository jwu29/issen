# RapidTriage

[![Stars](https://img.shields.io/github/stars/SecurityRonin/rapidtriage?style=for-the-badge)](https://github.com/SecurityRonin/rapidtriage/stargazers) [![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge)](LICENSE) [![Build](https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge)]() [![Rust](https://img.shields.io/badge/rust-1.80+-orange?style=for-the-badge&logo=rust)](https://www.rust-lang.org) [![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey?style=for-the-badge)]() [![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ff69b4?style=for-the-badge&logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**One command. One output. The full attack narrative.**

---

```
$ rt analyse collection.tar.gz

[CRITICAL] Rootkit concealed miner activity
  Rule    : correlation.miner.rootkit-concealment
  Evidence: ld_preload /lib/x86_64-linux-gnu/libymv.so.3
            PID 977 "top" [thread: libuv-worker] → XMRig
            127.0.0.1:59182 → 127.0.0.1:3333 [Stratum tunnel]
```

A rootkit hiding a crypto miner behind an SSH tunnel. Found automatically. Zero manual grep.

---

## How it works

- **Ingests** UAC live response collections, Volatility sockstat output, EVTX logs, and memory dumps — simultaneously.
- **Correlates** evidence across sources using the Pivot engine: a network connection isn't a finding on its own; combined with a hidden PID and a loaded rootkit library, it is.
- **Outputs** a structured Finding with severity, rule name, and the full evidence chain — ready for your report.

No Python env. No dependency hell. One static binary.

---

## Install

```bash
# Requires Rust 1.80+
cargo install --git https://github.com/SecurityRonin/rapidtriage rt-cli

# Verify
rt --version
```

## First command

```bash
rt analyse collection.tar.gz
```

That's it. Everything else is optional.

---

## Quick reference

```bash
# Parse artifacts into a DuckDB timeline and scan for IOCs
rt ingest evidence/ --output case.duckdb --scan

# Analyse a physical memory dump (LiME, AVML, crash dump)
rt memf dump.lime --command all

# Detect remote access tools (LOLRMM-based)
rt remote-access --artifacts evidence/

# Update threat intel feeds (Sigma, YARA, Suricata, Zeek)
rt feed update
```

---

## What it covers

| Category | Formats / Sources |
|---|---|
| **Collection formats** | UAC `.tar.gz`, Velociraptor, KAPE triage zip |
| **Memory formats** | LiME, AVML, WinPMEM, crash dump (DMP), Hibernation (hiberfil.sys) |
| **Detection types** | YARA rules, Sigma rules, STIX indicators, hash IOCs |
| **Artifact sources** | EVTX, registry hives, MFT, USN Journal, prefetch, $LogFile |
| **Network analysis** | Volatility sockstat, pcap, Zeek logs |
| **Output formats** | Terminal (colour-coded), JSON, HTML report, DuckDB timeline |
| **RAT detection** | LOLRMM rule set (400+ tools) |

---

## Architecture

<details>
<summary>Crate layout</summary>

```
rt-cli                  # The rt binary — commands and arg parsing
rt-correlation          # Pivot engine: Evidence → Findings via YAML rules
rt-parser-uac           # UAC collection parser
rt-parser-evtx          # Windows Event Log (EVTX) parser
rt-mem                  # Physical memory analysis (LiME, AVML, crash dump)
rt-signatures           # YARA / Sigma / STIX / hash IOC scanning
rt-fswalker             # Parallel filesystem walker (rayon)
rt-timeline             # DuckDB-backed timeline ingestion
rt-remote-access        # LOLRMM-based RAT detection
rt-report               # HTML report generation
```

Each crate is independently testable and versioned. The CLI wires them together; you can also use the crates as a library in your own tooling.

</details>

---

## Correlation Rules

Most tools find indicators. RapidTriage finds **attack patterns** by joining evidence across sources automatically.

A Correlation Rule looks like this:

```yaml
id: correlation.miner.rootkit-concealment
severity: critical
description: Rootkit concealing cryptominer activity via LD_PRELOAD
clauses:
  - source: uac.ld_preload
    field: library_path
    match: "lib*.so.*"
  - source: memory.process_threads
    field: thread_name
    match: "libuv-worker"
  - source: network.connections
    field: dest_port
    match: 3333            # Stratum mining protocol
logic: all
emit:
  finding: "Rootkit concealed miner activity"
  evidence: [library_path, pid, thread_name, src_addr, dest_addr]
```

Rules are YAML files in `~/.config/rapidtriage/rules/`. Ship your own. Share with your team.

<details>
<summary>Why YAML rules and not hard-coded detections?</summary>

Hard-coded detections age badly. Threat actors change port numbers, rename binaries, and swap libraries. YAML rules are versionable, shareable, and reviewable in a pull request. The correlation engine is stable; the rules are data.

The built-in rule set covers the most common patterns (miners, rootkits, SSH tunnels, LOLRMM RATs). Your custom rules compose with the built-ins — one `rt analyse` call evaluates all of them.

</details>

---

## Demo

```
$ rt analyse collection-WIN10-CORP-20260401.zip

╔══════════════════════════════════════════════════════════╗
║  RapidTriage — Collection Analysis                       ║
╚══════════════════════════════════════════════════════════╝

  Collection : collection-WIN10-CORP-20260401.zip
  Host       : WIN10-CORP
  OS         : Windows 10 Enterprise 22H2 (19045.4291)
  Collected  : 2026-04-01T14:32:07Z
  Artifacts  : MFT, EVTX, Registry, Prefetch, Amcache

  Parsed 1,247,831 MFT entries in 3.2s
  Parsed 48 EVTX logs (312,406 events) in 1.8s
  Parsed 4 registry hives in 0.4s

┌─ PERSISTENCE ───────────────────────────────────────────
│
│  [SERVICE] AnyDeskMaint
│    Binary  : C:\ProgramData\Temp\Support\anydesk.exe --service
│    Start   : Auto (SERVICE_AUTO_START)
│    Account : LocalSystem
│    Created : 2026-03-28T09:14:22Z
│
│  [REG RUN KEY] HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│    Name    : AnyDeskUpdate
│    Value   : "C:\ProgramData\Temp\Support\anydesk.exe" --start-with-win
│    Modified: 2026-03-28T09:14:38Z

┌─ REMOTE ACCESS ─────────────────────────────────────────
│
│  [LOLRMM] AnyDesk (relocated binary)
│    Path    : C:\ProgramData\Temp\Support\anydesk.exe
│    SHA256  : a1b2c3d4e5f60718293a4b5c6d7e8f90aabbccdd11223344556677889900eeff
│    Size    : 5,389,312 bytes
│    Signed  : philandro Software GmbH (valid, not revoked)
│    Config  : ad.router.custom_id = "corp-maint-04"
│
│  [C2 CONNECTION]
│    Dest IP : 194.36.28.117:7070
│    First   : 2026-03-28T09:17:03Z
│    Last    : 2026-04-01T13:58:41Z
│    Note    : IP not in AnyDesk relay network (AS 208323 / BL Networks, RU)

┌─ TIMELINE ──────────────────────────────────────────────
│
│  2026-03-28T09:12:55Z  [EVTX Security 4624]  Logon Type 3 — CORP\svc_backup
│                         from 10.20.5.44 (WIN-RUNBOOK)
│  2026-03-28T09:14:18Z  [MFT]  File created: C:\ProgramData\Temp\Support\anydesk.exe
│                         Parent created at same time — directory is new
│  2026-03-28T09:14:22Z  [EVTX System 7045]   Service installed: AnyDeskMaint
│                         ImagePath: C:\ProgramData\Temp\Support\anydesk.exe --service
│                         Account: LocalSystem | Type: user mode (0x10)
│  2026-03-28T09:17:03Z  [EVTX Security 5156] Outbound TCP — anydesk.exe (PID 6284)
│                         → 194.36.28.117:7070

┌─ CORRELATION FINDINGS ──────────────────────────────────
│
│  [CRITICAL] LOLRMM with non-vendor C2 infrastructure
│    Rule    : remote-access.lolrmm.custom-c2
│    Evidence: AnyDesk outside vendor path (C:\ProgramData\Temp\Support\)
│              Outbound → 194.36.28.117 (AS 208323, not AnyDesk relay ASN)
│              MFT entry + EVTX 7045 + EVTX 5156 + Registry Run key
│    MITRE   : T1219, T1543.003
│
│  [HIGH] Lateral movement via service account
│    Rule    : lateral-movement.service-account.file-drop
│    Evidence: Type 3 logon CORP\svc_backup from 10.20.5.44 (WIN-RUNBOOK)
│              File drop + service install within 120s of logon
│    MITRE   : T1021.002

  2 findings | 1 critical, 1 high | 4 artifact sources correlated
```

The correlation engine flagged AnyDesk installed under `C:\ProgramData\Temp\Support\` — not its standard `Program Files` path — with outbound connections to a Russian ASN outside AnyDesk's relay infrastructure. The timeline shows a service account logon from an internal host, followed by file drop, service install, and first C2 callback within a four-minute window: the attacker pivoted from `WIN-RUNBOOK` using `svc_backup` credentials to deploy the RAT on `WIN10-CORP`.

---

## Contributing

PRs welcome. The most valuable contributions right now:

- New Correlation Rules (add to `crates/rt-correlation/rules/`)
- Parser support for additional collection formats (Velociraptor, KAPE)
- Platform-specific memory analysis improvements

Please open an issue before large changes so we can align on approach.

```bash
git clone https://github.com/SecurityRonin/rapidtriage
cd rapidtriage
cargo test --workspace
```

All crates follow strict TDD — write failing tests first, then the implementation.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

**Found this useful?** [Sponsor development](https://github.com/sponsors/h4x0r) to keep the threat intel feeds updated and new parsers shipping.
