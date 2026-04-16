# Linux Forensic Scenario — Submission Email

**To:** hrpomeranz@gmail.com  
**Subject:** Linux Forensic Scenario Submission — RapidTriage  
**From:** Albert Hui (4n6h4x0r)  
**Date:** 2026-04-15

---

Hi Hal,

Submitting my answers to the Linux Forensic Scenario. I also used this collection as a test case while building **RapidTriage**, a Rust forensic triage tool I'm developing for incident responders. I've included the full verbatim tool output below, and I'd be curious whether it lines up with your intended answers.

---

## Tool Output (verbatim)

```
$ rt analyse uac-vbox-linux-20260324234043.tar.gz

╔══════════════════════════════════════════════════════════╗
║  RapidTriage — UAC Collection Analysis                   ║
╚══════════════════════════════════════════════════════════╝

  Collection : uac-vbox-linux-20260324234043.tar.gz
  Host       : vbox-linux
  Collected  : (unknown)
  Format     : UAC

┌─ ROOTKIT INDICATORS ──────────────────────────────────
│  [WARNING]  ld_preload — /lib/x86_64-linux-gnu/libymv.so.3
│  [INFO]     kernel_taint — taint=4, bit 2 set

┌─ HIDDEN PROCESSES (ps/top blind-spot) ─────────────────
│  6 PID(s) visible in /proc but absent from ps:

│  PID  43168  (name unknown — no memory dump)
│
│  PID    939  sh
│           192.168.4.22:22 → 192.168.4.35:48411 [ESTABLISHED]  (TCP)
│
│  PID    940  python3
│           192.168.4.22:22 → 192.168.4.35:48411 [ESTABLISHED]  (TCP)
│
│  PID    941  bash
│           192.168.4.22:22 → 192.168.4.35:48411 [ESTABLISHED]  (TCP)
│
│  PID    975  ssh
│           192.168.4.22:33440 → 192.168.5.95:22 [ESTABLISHED]  (TCP)
│           ::1:3333 → :::0 [LISTEN]  (TCP)
│           127.0.0.1:3333 → 0.0.0.0:0 [LISTEN]  (TCP)
│           127.0.0.1:3333 → 127.0.0.1:59182 [ESTABLISHED]  (TCP)
│
│  PID    977  top
│           Thread names: libuv-worker, top
│           192.168.4.22:22 → 192.168.4.35:48411 [ESTABLISHED]  (TCP)
│           127.0.0.1:59182 → 127.0.0.1:3333 [ESTABLISHED]  (TCP)
│

┌─ NETWORK (visible to userspace) ───────────────────────
│  192.168.4.22:22 → 192.168.4.35:48411  pid=937 (sshd)
│  127.0.0.1:3333 → 127.0.0.1:59182
│  192.168.4.22:33440 → 192.168.5.95:22
│  192.168.4.22:22 → 192.168.4.35:58910  pid=1047 (sshd-session)
│  127.0.0.1:59182 → 127.0.0.1:3333
│  192.168.4.22%enp0s3:68 → 192.168.4.1:67  pid=748 (NetworkManager)

┌─ CPU ───────────────────────────────────────────────────
│  %Cpu(s): 97.7 us,  2.3 sy,  0.0 ni,  0.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
│  ^ WARNING: Near-100% CPU with no visible process — miner likely hidden by rootkit.

┌─ PIVOT FINDINGS ────────────────────────────────────────
│  [CRITICAL] Rootkit concealed miner activity
│         Rule     : correlation.miner.rootkit-concealment
│         Evidence : rk-1, proc-13, net-15
│

┌─ NARRATIVE ─────────────────────────────────────────────
│  1. LD_PRELOAD rootkit installed:
│       /lib/x86_64-linux-gnu/libymv.so.3
│     This library intercepts readdir()/opendir() to filter PIDs
│     from /proc, making hidden processes invisible to ps, top,
│     ss, and any tool that lists processes via /proc.
│
│  2. Attacker gained interactive shell via SSH (port 22):
│       python3 -c 'import pty; pty.spawn("/bin/bash")'
│     The NMS alert was triggered by this string in the SSH session.
│
│  3. Crypto miner deployed (PID 977, disguised as 'top'):
│       libuv-worker threads indicate XMRig or compatible miner.
│       Connections:
│         192.168.4.22:22 → 192.168.4.35:48411 [ESTABLISHED]  ← shared SSH shell socket
│         127.0.0.1:59182 → 127.0.0.1:3333 [ESTABLISHED]  ← Stratum tunnel
│       This explains the CPU anomaly and the 'hidden' process.
│
│  4. SSH tunnel to 192.168.5.95:22 established (PID 975):
│       ssh -L 127.0.0.1:3333:<pool>:3333 user@192.168.5.95
│     Mining traffic appears as SSH to the NMS — evasion technique.

┌─ SUSPICIOUS EXECUTABLES ───────────────────────────────
│  /usr/lib/x86_64-linux-gnu/libymv.so.3 — SHA1: 0fd709f09c073df274e272aabcabe3e0f3487f9e

═══════════════════════════════════════════════════════════
  RapidTriage analysis complete.
═══════════════════════════════════════════════════════════
```

---

## Answers

### Q1 — Why did the NMS alert on port 22/tcp with a `pty.spawn` string?

The attacker SSH'd from **192.168.4.35** to **192.168.4.22** (PID 937 / sshd). Within that session they executed:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This command passed over port 22/tcp. `pty.spawn` promotes a non-interactive shell to a full PTY — Tab completion, job control, interactive programs. It is the standard next step after landing an initial foothold, because without a PTY many interactive programs (sudo, vi, mysql) don't work correctly.

PIDs 939 (sh), 940 (python3), 941 (bash) are the resulting process chain, all sharing the same socket: `192.168.4.22:22 → 192.168.4.35:48411`.

These PIDs are **invisible to `ps`, `top`, and `ss`** because the LD_PRELOAD rootkit (`libymv.so.3`) was installed shortly after. Volatility's `linux.sockstat` plugin reads socket structs from kernel memory, bypassing the rootkit entirely. RapidTriage's `rt-parser-uac` correlates `hidden_pids_for_ps_command.txt` with the Volatility sockstat TSV to surface named, connected process findings even with a fully blind userspace.

---

### Q2 — Why is the CPU pegged at 97.7% with no visible culprit?

PID 977 is registered in `/proc` but absent from `ps` — hidden by the LD_PRELOAD rootkit. Its `comm` field reads **`top`**, a deliberate masquerade.

The smoking gun is the thread names in kernel memory:

```
Thread names: libuv-worker, top
```

`libuv-worker` is the thread name used by **libuv**, the async I/O library embedded in **XMRig**. A process calling itself `top` with `libuv-worker` threads is XMRig with near-certainty — `top` is single-threaded and has no business running a libuv thread pool.

XMRig connects to **localhost:3333**, not directly to the pool. PID 975 (`ssh`) listens on that port and forwards it to **192.168.5.95:22** via local port forwarding:

```
ssh -L 127.0.0.1:3333:<pool>:3333 user@192.168.5.95
```

Mining traffic is consistent with being encapsulated inside SSH local-port forwarding. The NMS would see one additional SSH connection to an external IP — no Stratum connection separately visible.

---

### Q3 — Why can't the SOC see the malicious processes?

The attacker installed an **LD_PRELOAD userland rootkit**:

1. Dropped `/usr/lib/x86_64-linux-gnu/libymv.so.3` (SHA1: `0fd709f09c073df274e272aabcabe3e0f3487f9e`)
2. Wrote `/etc/ld.so.preload` containing the library path

`/etc/ld.so.preload` is read by `ld.so` at startup for **every** process. The library is injected before `main()` runs — into `ps`, `top`, `ss`, `ls /proc`, `netstat`, and every userspace monitoring tool on the system.

LD_PRELOAD rootkits of this class typically hook `readdir64()` and `opendir()`. When any process enumerates `/proc`, the hooks silently drop directory entries matching the target PIDs — the kernel returns all entries, the rootkit discards them before userspace sees them. (The specific hooked symbols for `libymv.so.3` would require reverse-engineering the library, which was not done here; this is the standard mechanism for this rootkit family.)

The kernel is unaffected:
- `/proc/977/` exists and is readable if you know the PID (direct open bypasses readdir)
- Volatility reads kernel `task_struct` and file descriptor structures directly — rootkit-transparent
- UAC's `hidden_pids_for_ps_command.txt` was produced by comparing raw `/proc` directory enumeration against `ps` output at collection time, catching the discrepancy before the rootkit could conceal it

---

## Attack Timeline

| Time (UTC)          | Event |
|---------------------|-------|
| 2026-03-24 ~23:20   | Attacker SSH from 192.168.4.35 to vbox-linux:22 |
| 2026-03-24 ~23:21   | `python3 -c 'import pty; pty.spawn("/bin/bash")'` — NMS alert |
| 2026-03-24 23:24:51 | `/usr/lib/x86_64-linux-gnu/libymv.so.3` written |
| 2026-03-24 23:25:09 | `/etc/ld.so.preload` written — rootkit active |
| 2026-03-24 23:25:09+| PIDs 939/940/941/975/977/43168 hidden from all userspace tools |
| ~23:26              | XMRig (PID 977, masquerades as `top`) deployed |
| ~23:26              | SSH tunnel PID 975; `127.0.0.1:3333` forwarded to 192.168.5.95:22 |
| 2026-03-24 23:40:43 | UAC collection initiated |

---

## What Made This Possible

Two RapidTriage capabilities were decisive:

**Hidden-PID correlation with Volatility memory output**

UAC writes `live_response/process/hidden_pids_for_ps_command.txt` when it detects PIDs in `/proc` absent from `ps`. On its own, this gives PID numbers with no names. RapidTriage reads this file and cross-references it with `memory_dump/output-sockstat` — the TSV from Volatility 3's `linux.sockstat` plugin, which reads socket file descriptors from kernel `task_struct` memory. The correlation produces named, connected process findings even when userspace is completely blind.

This is the only approach that works against an LD_PRELOAD rootkit: bypass hooked libc entirely.

**Thread-name analysis for miner detection**

XMRig spawns a libuv event loop with threads named `libuv-worker`. The Volatility `linux.sockstat` output includes a `Process Name` column that reflects the kernel `comm` for each TID — meaning individual threads appear with their own names rather than the parent process name. RapidTriage's parser collects distinct thread names across all TIDs sharing a PID and surfaces them as `thread_names`. A process calling itself `top` with `libuv-worker` threads and 97.7% CPU is not ambiguous.

---

## Repository

**RapidTriage:** https://github.com/SecurityRonin/rapidtriage

The features demonstrated — hidden-PID correlation, Volatility sockstat parsing, `rt analyse`, the correlation engine — were implemented using strict TDD (Red commit → Green commit) while working through this collection.

---

*Albert Hui | 4n6h4x0r*
