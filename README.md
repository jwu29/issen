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

## Pivot Rules — the unique mechanism

Most tools find indicators. RapidTriage finds **attack patterns** by joining evidence across sources automatically.

A Pivot Rule looks like this:

```yaml
id: correlation.miner.rootkit-concealment
severity: critical
description: Rootkit concealing cryptominer activity via LD_PRELOAD
pivots:
  - source: uac.ld_preload
    field: library_path
    match: "lib*.so.*"
  - source: memory.process_threads
    field: thread_name
    match: "libuv-worker"
  - source: network.connections
    field: dest_port
    match: 3333            # Stratum mining protocol
logic: all                  # all three must match
emit:
  finding: "Rootkit concealed miner activity"
  evidence: [library_path, pid, thread_name, src_addr, dest_addr]
```

Rules are YAML files in `~/.config/rapidtriage/pivot-rules/`. Ship your own. Share with your team.

<details>
<summary>Why YAML rules and not hard-coded detections?</summary>

Hard-coded detections age badly. Threat actors change port numbers, rename binaries, and swap libraries. YAML rules are versionable, shareable, and reviewable in a pull request. The correlation engine is stable; the rules are data.

The built-in rule set covers the most common patterns (miners, rootkits, SSH tunnels, LOLRMM RATs). Your custom rules compose with the built-ins — one `rt analyse` call evaluates all of them.

</details>

---

## Real example: CTF cryptominer case

A UAC collection from a compromised Linux host. Analyst time from first command to written finding: **30 seconds**.

**What was hiding:**

- `libymv.so.3` injected via `/etc/ld.so.preload` — hiding the miner process from `ps`, `top`, and `ls /proc`
- XMRig running as PID 977 with a disguised name (`top`), identifiable only by its `libuv-worker` thread
- Mining traffic tunnelled over SSH (port 3333 → localhost:3333) to evade network egress controls

**What the tool output:**

```
[CRITICAL] Rootkit concealed miner activity
  Rule    : correlation.miner.rootkit-concealment
  Evidence: ld_preload /lib/x86_64-linux-gnu/libymv.so.3
            PID 977 "top" [thread: libuv-worker] → XMRig
            127.0.0.1:59182 → 127.0.0.1:3333 [Stratum tunnel]

[HIGH] SSH Stratum tunnel detected
  Rule    : network.tunnel.stratum-over-ssh
  Evidence: sshd forwarding 127.0.0.1:3333 → external
            connection age: 14d 3h (persistent)

[HIGH] Hidden process detected
  Rule    : rootkit.pid-hiding
  Evidence: PID 977 absent from /proc but present in memory scan
            process name mismatch: "top" vs ELF export table
```

No grep. No manual timeline correlation. No Python environment to install first.

---

## Contributing

PRs welcome. The most valuable contributions right now:

- New Pivot Rules (add to `crates/rt-correlation/rules/`)
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
