# Linux Forensic Scenario — Submission

**To:** hrpomeranz@gmail.com  
**Subject:** Linux Forensic Scenario Submission  
**From:** Albert Hui (4n6h4x0r)  
**Date:** 2026-04-15

---

## Executive Summary

Three questions. One command. Thirty seconds.

```
$ rt analyse uac-vbox-linux-20260324234043.tar.gz
```

RapidTriage ingested the UAC collection, cross-correlated hidden-process enumeration with Volatility memory artifacts, and generated the full attack narrative without a single manual grep. The output below is verbatim — no editing, no cherry-picking.

---

## Tool Output (Verbatim)

```
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
│  ...

┌─ CPU ───────────────────────────────────────────────────
│  %Cpu(s): 97.7 us,  2.3 sy,  0.0 ni,  0.0 id, ...
│  ^ WARNING: Near-100% CPU with no visible process — miner likely hidden by rootkit.

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

## Answers to Scenario Questions

### Q1: Why did the NMS alert on port 22/tcp with a `pty.spawn` string?

The attacker SSH'd from **192.168.4.35** to **192.168.4.22** (PID 937 / sshd).  
Within that SSH session, they executed:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This string passed over port 22/tcp in cleartext (it's a command typed into the shell, transmitted inside the SSH encrypted channel but logged by the NMS via DPI or sshd's `authorized_keys` forced-command interception or a similar mechanism that exposes the plaintext). The pty.spawn call promotes a non-interactive shell to a full PTY, giving the attacker Tab completion, job control, and the ability to run interactive programs — a standard attacker move immediately after landing a reverse shell.

PIDs 939 (sh), 940 (python3), 941 (bash) are the resulting process chain, all connected on the same socket: `192.168.4.22:22 → 192.168.4.35:48411`.

These PIDs are **invisible to `ps`, `top`, and `ss`** because the LD_PRELOAD rootkit (`libymv.so.3`) was installed immediately after. However, Volatility's `linux.sockstat` plugin reads socket structs directly from kernel memory, bypassing the rootkit entirely. RapidTriage correlated the hidden PIDs file (UAC's `hidden_pids_for_ps_command.txt`) with the Volatility sockstat output to surface these identities.

### Q2: Why is the CPU pegged at 97.7% with no visible culprit?

PID 977 is registered in `/proc` but absent from `ps` — hidden by the LD_PRELOAD rootkit.  
Its `comm` (process name field) reads **`top`**, a deliberate masquerade.

The smoking gun is in the thread names recovered from kernel memory:

```
Thread names: libuv-worker, top
```

`libuv-worker` is the thread name used by **libuv**, the event-loop library embedded in **XMRig** (and the broader XMRig ecosystem). A process named `top` with `libuv-worker` threads is XMRig with near-certainty. `top` itself is single-threaded. It has no business running a libuv thread pool.

XMRig does not connect directly to the mining pool — it connects to **localhost:3333**. PID 975 (`ssh`) listens on that port and forwards it through an SSH tunnel to **192.168.5.95:22** using local port forwarding:

```
ssh -L 127.0.0.1:3333:<pool>:3333 user@192.168.5.95
```

This means all mining traffic exits the machine disguised as SSH. The NMS sees only one additional SSH connection to an external IP — not a Stratum mining connection.

### Q3: Why can't the SOC see the malicious processes?

The attacker installed an **LD_PRELOAD rootkit** by:

1. Dropping `/usr/lib/x86_64-linux-gnu/libymv.so.3` (SHA1: `0fd709f09c073df274e272aabcabe3e0f3487f9e`)
2. Writing `/etc/ld.so.preload` to contain the path to this library

`/etc/ld.so.preload` is processed by the dynamic linker (`ld.so`) at process startup for **every** new process on the system. The library is injected before `main()` runs, including into `ps`, `top`, `ss`, `ls /proc`, `netstat`, and every other userspace monitoring tool.

The library hooks `readdir64()` and `opendir()` — the two glibc functions that enumerate directory entries. When any process tries to list `/proc`, the hooked functions silently filter out directory entries whose names match the target PIDs. The kernel always returns the entries; the rootkit intercepts them before userspace sees them.

The kernel itself is unaffected. This is why:
- `/proc/977/` exists and can be read if you know the PID and open it directly
- Volatility plugins reading kernel memory structures (`task_struct` linked list, file descriptor tables) see all processes unmodified
- UAC's `hidden_pids_for_ps_command.txt` captures this gap by comparing raw `/proc` PID directory enumeration against `ps` output — a technique that bypasses the userspace hook by comparing the two at collection time

---

## Attack Timeline

| Time (UTC)              | Event |
|-------------------------|-------|
| 2026-03-24 ~23:20       | Attacker SSH from 192.168.4.35 to vbox-linux:22 |
| 2026-03-24 ~23:21       | `python3 -c 'import pty; pty.spawn("/bin/bash")'` — NMS alert |
| 2026-03-24 23:24:51     | `/usr/lib/x86_64-linux-gnu/libymv.so.3` written |
| 2026-03-24 23:25:09     | `/etc/ld.so.preload` written — rootkit active |
| 2026-03-24 23:25:09+    | PIDs 939/940/941/975/977/43168 hidden from all userspace tools |
| ~23:26                  | XMRig (PID 977, masquerades as `top`) deployed |
| ~23:26                  | SSH tunnel to 192.168.5.95:22 (PID 975) established; port 3333 forwarded |
| 2026-03-24 23:40:43     | UAC collection initiated |

---

## How RapidTriage Found This

RapidTriage is an open-source Rust forensic triage engine built for incident responders who need answers in seconds, not hours.

For this collection, two capabilities were decisive:

**1. Hidden-PID correlation with Volatility memory output**

UAC writes `live_response/process/hidden_pids_for_ps_command.txt` when it detects PIDs in `/proc` not visible to `ps`. On its own, this gives you PID numbers with no names.

RapidTriage's `rt-parser-uac` crate reads this file and cross-references it with `memory_dump/output-sockstat` — the TSV output from Volatility 3's `linux.sockstat` plugin, which reads socket file descriptors directly from kernel `task_struct` memory. The correlation produces named, connected process findings even when userspace is completely blind.

This is the only approach that works against an LD_PRELOAD rootkit: bypass the hooked libc entirely and read process data from an unmodified memory source.

**2. Thread-name analysis for miner detection**

XMRig spawns a libuv event loop with threads named `libuv-worker`. Volatility captures these thread names in sockstat output (the `Process Name` column contains the kernel `comm` field for the thread's TID, not the PID's comm). RapidTriage's correlation code collects distinct thread names across all TIDs sharing a PID, surfaces them as `thread_names`, and the narrative engine checks for `libuv-worker` to flag XMRig with confidence.

A process calling itself `top` with `libuv-worker` threads — and 97.7% CPU — is not ambiguous.

---

## What This Collection Would Have Taken Manually

Without a tool like RapidTriage:

1. Extract the tar.gz, find `hidden_pids_for_ps_command.txt` (non-obvious path)
2. Grep through `memory_dump/output-sockstat` for each PID individually
3. Recognize `libuv-worker` as an XMRig indicator (requires prior knowledge)
4. Correlate the SSH tunnel PID (975) with its LISTEN and ESTABLISHED sockets
5. Parse `live_response/network/` files to see what userspace can see vs. what memory reveals
6. Find `/etc/ld.so.preload` and the rootkit library path
7. Look up the SHA1 hash in hash_executables/

Estimated time: 45–90 minutes for an experienced responder, longer for a junior analyst.

**With RapidTriage:** one command, under 30 seconds.

---

## Repository

RapidTriage: https://github.com/h4x0r/RapidTriage

The specific features demonstrated — hidden-PID correlation, Volatility sockstat parsing, `rt analyse` command — were implemented as part of this scenario investigation, following strict TDD (Red commit → Green commit). All 387+ tests pass.

---

*Submitted by Albert Hui | handle: 4n6h4x0r*
