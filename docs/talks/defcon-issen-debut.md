# Stop Being the Integration Layer

## Issen — the open, scriptable triage layer you can *drive*: disk + memory, findings-first, one timeline, any OS

**DEF CON · 30-minute slot (≈26 min content + buffer)**

**Albert Hui** (4n6h4x0r) · github.com/SecurityRonin

> Rewritten around the one claim that survived a full competitive teardown: not any capability
> (every one has prior art) and not any capability-*combination* (AXIOM does disk+VSS+memory) — but
> the **form**: the whole first-pass triage as an open, free, single static binary, on any OS, that
> a script or a pipeline can drive end-to-end. That's the one thing a commercial Windows GUI suite
> structurally can't be. Backing research: `dfir-tool-landscape-findings.md`,
> `issen-competitive-landscape.md`. Demo-led: one Case-001 investigation carries Act 2.

---

### Speaker prep notes (not slides)

- **North star — pitch the FORM, never a capability.** Every capability and combination has a mature
  owner (Volatility=memory, Plaso=formats, X-Ways=VSS Event List, AXIOM=disk+VSS+memory triad). Do
  NOT claim any feature is unique. Claim only: open + scriptable + single free static binary + any OS
  + the triage combination + safe/structured output — i.e. *drivable*. Credit competitors generously;
  the generosity is what makes the room trust the one claim you do make.
- **Demo evidence:** DFIR Madness "Stolen Szechuan Sauce" Case-001 (real Win Server DC + Win10
  desktop, disk + memory, public answer key). Pre-stage in `/tmp/case001/`: `DC01.E01` (+ segments),
  `DESKTOP-SDN1RPT.E01`, `DC01.mem.zip`, `DESKTOP-SDN1RPT.mem.zip` (Case-001 memory ships zipped;
  Issen reads dumps straight from the archive — leave them `.zip` to showcase transparent archive
  reading, verified in `issen-mem/dump_source.rs`). VSS beat needs a 2nd image (Case-001 has no
  shadow copies) — **Magnet PC-MUS-001.E01** (the VSS Tier-1 oracle).
- **Demo discipline (2 live demos max — more overruns):**
  - **Live #1:** disk+memory ingest → flagged rows, then the warm resume.
  - **Live #2:** the investigation off a pre-run DB — `--flagged` → pivot → `issen memory … netstat`.
  - **Captures (not live, ~20–25s each):** the VSS beat on PC-MUS, `4n6mount`, the report render, and
    (optional) a **one-liner shell pipeline** running the whole triage end-to-end (Slide 9) if you build it.
  - Pre-run the full pipeline the night before into `/tmp/case001/prerun.duckdb` (fallback + query/report source).
  - Memory symbols **pre-cached locally** — verify `issen memory … netstat` works with the network OFF.
  - Never fake a live run. If it breaks: say so deadpan, switch to the pre-run DB on camera. This crowd
    forgives a crash; it never forgives a fake.
- **Shipped vs gated (confirm before the talk):**
  - SHIPPED: unified disk+memory default command (ADR 0012); NTFS/ext4/APFS/HFS+/ISO over MBR/GPT;
    VSS (`vsc-forensic`, **published**); resumable ingest; DuckDB store; jsonguard-safe exports.
  - GATED (one modest touch, Slide 8): the `fvfs:` open-recipe URI surfaced per finding — confirm the
    exact flag (`--show-source`/`source_uri`) or DROP that line. It's a small nicety, not load-bearing.
  - The **scriptability payoff (Slide 9)** is the crux of the talk's USP — it needs no capture (the
    live demo already proved it's all commands); optionally show a one-liner pipeline running the whole
    triage, or just deliver the line: "everything you saw was one scriptable surface — the glue is a command now."
  - **Verify the install channels are actually LIVE before publishing the deck** (0.x may not have all
    set up): brew tap (`securityronin/tap/issen`), the **Cloudsmith apt repo must be created first** or
    the `setup.deb.sh` 404s, the winget package (`SecurityRonin.issen`), and crates.io (`cargo install issen-cli`).
    Drop any channel that isn't live rather than ship an install line that fails when someone types it.
- Terminal: dark, 28pt+, `--color always` if the projector eats auto-detect. Kill notifications, VPN,
  everything but the demo box. Cut order + timing at the end.
- **Trademarks / competitor claims (published-deck hygiene):** every capability claim about a named
  product is factual and sourced (`dfir-tool-landscape-findings.md` is the defense file). No logos, no
  "versus," no price figures (the "six-figure" claim was removed — Magnet pricing is non-public and
  "a six-figure license" is likely false; say "paid commercial seat" instead). Include this footer on
  the published deck: *"AXIOM & Magnet (Magnet Forensics), X-Ways (X-Ways Software Technology AG), and
  Autopsy (Basis Technology / Sleuth Kit Labs); plus TZWorks, USB Detective, and the Sanderson
  Forensic Toolkit for SQLite — all are trademarks of their respective owners. Named for factual
  comparison (nominative fair use); no affiliation/endorsement implied."*
  This is a practitioner read, not legal advice — a short IP-counsel skim is cheap insurance if the
  stakes are high.

---

# ACT 1 — You are the integration layer

---

## [00:00–02:30] Cold open — you own everything, and you're still the glue

### Slide 1 — (no title)

**On screen:**

- Black slide, one line, white monospace:
- `2:47 a.m. — every tool in the lab, and you're the glue.`

**Script:**

> It's 2:47 in the morning. You're on an IR retainer. A domain controller is owned, the desktop it
> spread to is imaged, and legal wants a preliminary read by nine.
>
> And here's the thing — you're not under-tooled. Your lab has *everything*. The Zimmerman suite.
> TZWorks. Volatility. USB Detective. The Sanderson SQLite toolkit. A pricey AXIOM license somebody
> just renewed. You own the best tools in the field.
>
> And you're *still* at 2 a.m. with five of them open, being the thing that connects them — matching
> a process in memory to a file on disk by hand, reconciling two clocks, cleaning an export that
> broke because a filename had a comma in it.
>
> The forensics isn't the hard part tonight. Every one of those tools is excellent. The hard part is
> that *you* are the integration layer.
>
> Show of hands — who's been the integration layer this month?
>
> [pause — hands go up]
>
> Yeah. That's the job I want to talk about. Not the parsing. The *stitching between* the parsers.

---

### Slide 2 — The job vs the work

**On screen:**

- **The job:** what happened on these machines, and when
- **The work:** being the glue between good tools

**Script:**

> The question is simple: what happened, in what order, across both machines, disk and memory. The
> evidence is right there. What eats the night is the *integration* — converting formats, matching a
> memory connection to a disk artifact, reconciling clocks, fixing the export that Excel mangled.
>
> À-la-carte workflows quietly become analyst-managed integration. That's not a knock on the tools —
> they're superb. It's a gap *between* them. And it's a gap somebody should have filled with
> software, not a tired human and a spreadsheet.

---

## [02:30–03:45] The field is genuinely great

### Slide 3 — Credit where it's due

**On screen:** *(no tables, no logos, no "versus")*

- **Open specialists** — Hayabusa · Chainsaw (Sigma, fast) · **Volatility 3** (memory) · Plaso (formats)
- **Suites, each a real edge** — **X-Ways**: VSS in its Event List · **AXIOM**: disk + VSS + memory, one timeline
- these are good tools, built by good people — none is the enemy tonight

**Script:**

> Let me name the field, generously — because this room has already named it, silently.
>
> The open specialists are superb. Hayabusa and Chainsaw, Sigma on logs, single Rust binary, faster
> than I'll ever be at the event logs. Volatility 3 is where memory analysis becomes repeatable,
> scriptable work — the standard, and deservedly. Plaso parses more formats than anything alive.
>
> And the suites earn their money. X-Ways folds volume shadow copies — the historical states of the
> disk — into its Event List timeline, fast. And AXIOM — credit where it's due — actually does the
> whole thing: disk, shadow copies, *and* memory, correlated into one timeline in a single case.
> That's real, and it's good. None of these is the enemy tonight.

---

## [03:45–05:30] So why are you still the glue?

### Slide 4 — Own it all — and still stitching

**On screen:**

- Own the whole shelf → one host *still* = ~5 tools + (for many) a **Windows VM**
- Try to **script it end-to-end** — pipe one tool into the next? Not across **GUI state · Windows-only · lossy CSV**
- The gap isn't a capability. Every capability exists. **The gap is a surface you can *script*.**

**Script:**

> So if AXIOM does disk, shadow copies, and memory in one timeline — why are you still the glue at
> 2 a.m.? Two reasons, and then a third.
>
> One: it's a GUI, it's Windows, and it's a paid commercial seat — so it's the analyst clicking through it,
> on the box it runs on, in the license you have seats for. Two: the moment you step outside it — the
> fast Sigma tool, a Volatility run, the SQLite deep-dive — you're back to five apps and, for a lot
> of us, a Windows VM we boot grudgingly because half the good toolbox is Windows-first.
>
> And here's the third. You'd think, in the year of pipelines and automation, you could just *script*
> this — pipe one tool into the next and let it run. Mostly, no. And not for the reason you'd guess.
> The good CLI tools script fine: Volatility, Plaso, Eric's command-line tools. Where it breaks is the
> *mixed* workflow — the steps behind a GUI with no scriptable surface, the licensed Windows-only
> desktop app, and the bridge between every tool: CSV. And CSV is an unsafe, lossy boundary — quoting
> and encoding and newlines that shift your columns and garble your unicode the moment Excel touches
> them, and cells that start with an equals sign and *execute* when someone opens the file. The
> automation surface is uneven, and the seams are exactly where your script — or you, at 2 a.m. — gets
> stuck.
>
> So the gap isn't a missing capability. Every capability exists somewhere on that shelf. The gap is
> that none of it is a *surface you can drive* — with a script, in a pipeline, or by a tired human who
> just wants one clean pass. Here's that surface, as a command.

---

# ACT 2 — Meet Issen, and one investigation

> Demo-led. One Case-001 investigation carries the act, so the talk is about *solving an intrusion*
> — and proving the surface is drivable — not listing features.

---

## [05:30–07:30] Meet Issen

### Slide 5 — Issen

**On screen:**

- `issen`
- One free static binary · Rust · macOS / Linux / Windows
- No Python · no runtime deps · no license server · **scriptable · structured output**
- **The first-pass triage a script — or a pipeline, or you — can drive.**

```
brew install securityronin/tap/issen     # macOS

winget install SecurityRonin.issen       # Windows

# Linux (Debian/Ubuntu): add the repo, then install
curl -1sLf https://dl.cloudsmith.io/public/securityronin/issen/setup.deb.sh | sudo bash
sudo apt install issen

cargo install issen-cli                  # anywhere Rust runs
```

**Script:**

> This is Issen. It's new, it's open, and I'd rather show it to you than talk about it.
>
> The name means "one flash" — *issen*, the single stroke of the blade. Hold that thought; it'll make
> sense in about a minute.
>
> One static binary, Rust, the same tool on macOS, Linux, and Windows — so the Windows VM isn't
> mandatory. No Python environment, no runtime deps, nothing to license. And it's a CLI with a
> structured store and clean, safe output — so it drops straight into a pipeline, a CI job, or a
> fleet sweep.
>
> I'm not going to tell you Issen does more than AXIOM. It doesn't — no cloud, no mobile, less depth
> in every specialist's lane, and I'll show you exactly where the edges are. Here's what it *is*: the
> one open, free, scriptable, single binary that does the whole first-pass triage — disk and memory,
> findings-first, one timeline — on the laptop you already have. It's the piece that *was* the seam.
> The part you, or your automation, can finally drive instead of hand-stitch.
>
> Install is the whole slide: brew, apt, winget, cargo. Copy the one executable to an air-gapped box
> on a USB stick and it works. Let me show you the command.

---

## [07:30–12:30] DEMO 1 — the one command

### Slide 6 — Triage disk and memory, in one command

**On screen:**

```
issen DC01.E01 DESKTOP-SDN1RPT.E01 DC01.mem.zip DESKTOP-SDN1RPT.mem.zip -o case001.duckdb
```

- 2 disk images + 2 memory dumps → 1 flagged timeline
- reads the images directly · NTFS · ext4 · APFS · HFS+ · ISO over MBR/GPT · shadow copies fold in where present
- **dumps & images stay zipped** — read straight from the `.zip`, no unzip, no temp copy
- **fast:** DC01 (4.6 GB E01, from the zip) → full flagged timeline in **~64 s** *(measured — M4 Pro MacBook Pro)*
- *default ingest = triage set; deeper parsers are explicit commands (Slide 11)*

**Script:**

> The evidence is Case-001 from DFIR Madness — the "Stolen Szechuan Sauce" corpus. Public, real, a
> genuinely compromised DC and desktop, with a published answer key. Download it tonight and check
> every claim I make. Please do.
>
> Two disk images, two memory dumps. One command. No Python, no mounting step — it reads the images
> directly. And notice the dumps are still *zipped* — that's how they ship and how you store them to
> save space; Issen reads them straight out of the archive, no unzip, no temp copy. Where a disk
> carries shadow copies, it folds those historical states into the same timeline. One honesty note,
> up front, once: the default pass is the *triage* set — MFT, event logs,
> registry, prefetch, LNK, jump lists, shimcache, amcache. A few deeper parsers are their own
> commands; there's a slide on exactly where that line is.

**[DEMO — live #1]**

```bash
cd /tmp/case001
issen DC01.E01 DESKTOP-SDN1RPT.E01 DC01.mem.zip DESKTOP-SDN1RPT.mem.zip -o case001.duckdb
```

**Point at (briefly — don't narrate every internal):** the per-source, per-artifact parallelism
racing. *Then stop talking and let it run.* When it lands: *"flagged rows already — findings, not a
firehose."*

**Script (short, over the run):**

> Everything on one clock — UTC, nanosecond precision, timezone rendered explicitly. Not a directory
> of CSVs; one DuckDB file, columnar. When we measured columnar bulk-load against naive row inserts
> on this corpus it was about eleven times faster. And the whole thing is quick — on my laptop, an
> M4 Pro, the DC01 disk, four-plus gigs of E01 read straight from the zip, went to a full flagged
> timeline — parsed, correlated, scanned — in about a minute. Not because it cuts corners; because
> it's one Rust binary writing columnar batches, not a Python stack shuffling CSVs. That's the flash
> the name promises: the whole first pass, one stroke, about a minute. It's done, and it's already
> telling me what to look at.

### Slide 7 — Run it again → it resumes

**On screen:**

- `↻ same command → resumes` · warm re-run ~37× faster (Case-001, my box)

**Script:**

> New evidence on day three? Laptop died mid-ingest?

**[DEMO — live #1 continued]**

```bash
issen DC01.E01 DESKTOP-SDN1RPT.E01 DC01.mem.zip DESKTOP-SDN1RPT.mem.zip -o case001.duckdb   # again
```

> Same command, back in seconds. Resumable by default — it fingerprints each stage and only redoes
> what changed; on Case-001 the warm re-run was about thirty-seven times faster than the cold path,
> on my box. Ctrl-C stopped being a catastrophe. And notice — *the same command*. Nothing to
> remember, nothing to sequence. That matters in a minute.

---

## [12:30–17:00] DEMO 2 — the investigation

### Slide 8 — Start at the finding, pivot, corroborate in memory

**On screen:**

```
issen timeline case001.duckdb --flagged --min-severity high
issen timeline case001.duckdb --path '*coreupdater*'
issen timeline case001.duckdb --around <t> --window 5m
issen memory DC01.mem.zip --command netstat          # deep memory view
```

- finding → search → pivot both hosts → memory (already folded in)

**Script:**

> A million-row timeline you can't question is just a bigger CSV. So let's work the case.

**[DEMO — live #2, off the pre-run DB]**

```bash
# 1. Start where it matters: the serious findings, severity-graded.
issen timeline case001.duckdb --flagged --min-severity high

# 2. The malware, by name. Glob the timeline for it.
issen timeline case001.duckdb --path '*coreupdater*'

# 3. The real question: what else happened right then — across BOTH hosts?
issen timeline case001.duckdb --around 2020-09-19T03:21:00Z --window 5m

# 4. The memory C2 is already flagged (the one command folded memory in); here's the deep view.
issen memory DC01.mem.zip --command netstat
```

**Real captured output** *(Case-001 DC01, M4 Pro MacBook Pro — genuine runs; the `--flagged` list shows 2 representative rows of the 131 high findings, column spacing condensed for width, values verbatim):*

```
$ issen timeline case001.duckdb --flagged --min-severity high
Scan findings: 252452 total
  high: 131
  medium: 7056
  low: 97356
  info: 147909

SEVERITY  ENGINE  RULE              DESCRIPTION                              SUBJECT
high      Native  native-t1543.003  New Windows service installed (7045)     \SystemRoot\system32\drivers\HdAudio.sys
high      Native  native-t1543.003  New Windows service installed (7045)     C:\Windows\System32\coreupdater.exe

$ issen timeline case001.duckdb --path '*coreupdater*'
2020-09-19T03:24:06.4395405Z  FileCreate   UsnJournal  coreupdater[1].exe
2020-09-19T03:24:12.0932530Z  FileCreate   Mft         Windows/System32/coreupdater.exe
2020-09-19T03:56:37Z          ProcessExec  Registry    {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\coreupdater.exe

$ issen memory DC01.mem.zip --command netstat
Proto  Local              Remote               State        PID   Process
TCPv4  10.42.85.10:62613  203.78.103.109:443   ESTABLISHED  3644  coreupdater.exe   ← C2, matches answer key
```

**Point at:**

- `--flagged`: *"findings first, severity-graded — 252k findings, but only 131 high. Each names its
  SUBJECT. Scan the 7045 service installs: most are familiar drivers — HdAudio.sys. One is a service
  running C:\Windows\System32\coreupdater.exe. That's the thread — a lead to pull and confirm
  (signature, hash-to-VirusTotal, and the memory C2 in a second), not a verdict by itself. The finding
  hands you the name; you don't guess what to grep. (YARA and Sigma ran inside ingest, so these were
  born in the timeline.)"*
- `--path`: *"the actual Case-001 malware — dropped via UsnJournal, executed per the registry
  shimcache. From the public answer key, not planted."*
- `--around`: *"the cross-host pivot you used to do by alt-tabbing two Excel windows."*
- `netstat` → `coreupdater.exe → 203.78.103.109:443`: *"the memory C2, read straight from the dump
  zip — consistent with command-and-control, matching the answer key."*

**Script:**

> I started at a flagged disk artifact, pivoted across both hosts by time, and corroborated it in
> memory — without leaving the tool, standing up Python, or hunting a symbol path. The memory here is
> a *triage subset* folded into the investigation, not a replacement for Volatility. Every finding is
> worded as what it *is*: consistent with a technique. The tool flags; you conclude.

**[CAPTURE — the past, too · different image (this one has shadow copies)]**

> Thirty seconds on shadow copies. Case-001 had none — so here's a Magnet CTF disk that does.

```bash
issen PC-MUS-001.E01 -o pcmus.duckdb
issen timeline pcmus.duckdb --path '*<deleted-file>*'
```

**Point at:** a file **deleted in the live volume**, recovered **from a shadow copy**, folded into
the *same* timeline. *(Presenter: pick the concrete deleted-file + snapshot date from the PC-MUS
answer key; pre-record.)*

> Deleted on the live volume; a snapshot from before the cleanup still has it, in the same timeline.
> Reading shadow copies isn't new — X-Ways and Plaso do it too. Folding them into one *scriptable*
> triage pass, next to the memory, is the point.

### Slide 9 — Output a reviewer — *and a pipeline* — can trust

**On screen:**

- Safe **both ends of the pipe**: hostile evidence can't crash it *in* · exports can't attack a reviewer *out*
- In: parsers **fuzzed + panic-free** — a malformed image is an error, not an exploit *(trust slide)*
- Out: RFC-4180 · formula-injection guarded · JSON sanitized (`jsonguard`); `=cmd…` arrives as **text**, not execution
- Everything you just saw = **commands + a structured store** → *the glue is now a script, not a human*

**Script:**

> Now the payoff — and it cuts both ways, because evidence is attacker-controlled data at *both* ends
> of the pipe. Coming *in*: a malformed or booby-trapped image can't crash Issen or run code through
> it — the parsers are fuzzed and panic-free by construction, so a bad image is an error, not an
> exploit (more on that in a moment). Going *out*: the exports don't attack your reviewer either —
> Issen consistently quotes RFC-4180, guards against formula injection, sanitizes the JSON, because
> attackers put `=cmd` in filenames on purpose so the evidence executes when someone opens the export
> in Excel. Attacker data in, attacker data out; handled at both ends. That takes most of the export-
> cleanup plumbing off your plate — it doesn't replace you reading the file, it removes the part that
> fought you.
>
> But look at what everything I just did actually *was*. Commands. Into a structured store. With clean,
> safe output. Which means it isn't just something you *click* — it's something you *script*.
>
> Remember the question from the start — why couldn't you just automate the triage across your tools?
> Because they were GUIs, and Windows-only, and glued with lossy CSV — the seams broke the pipe. This
> doesn't. It's one scriptable surface, on any OS, with output clean enough to pipe into the next
> step. **This is the first-pass triage you can drive end to end — with a script, in a CI job, across
> a fleet, or by hand at 2 a.m.** The integration layer stops being *you* and becomes a *command*.
> That's the whole point of Issen. Not that it does more than the suites — that it's the one shape
> they can't be: drivable.

---

## [17:00–18:30] Triage, then deep-dive

### Slide 10 — Then hand off to the tools you trust

**On screen:** *(pre-recorded capture — not live)*

- Triage *starts* the investigation — then you **validate**: LECmd · pf · usnjrnl_rewind.py · your scripts
- `4n6mount image.E01 /mnt/evidence` — mounts the image so **any** deep-dive tool works against it
- mac / linux / win · read-only + copy-on-write

**Script:**

> And Issen knows its lane. It's a *triage* tool — it gets you to the needle fast, but triage is
> where the investigation starts, not where it ends. Once it points you at the artifact, you go deep
> with the specialist you already trust: LECmd on that LNK, pf on that prefetch, usnjrnl_rewind.py on
> the USN journal.
>
> Issen is *built* to hand off. `4n6mount` — the same reader as a FUSE mount — presents the image as
> a normal read-only directory on Mac, Linux, or Windows, copy-on-write so the evidence stays
> pristine. Every à-la-carte tool you love works straight against it. Fast unified triage from Issen,
> then deep-dive with whatever you trust. Nobody's asking you to give up the tools you love.

---

# ACT 3 — Honest, and how to trust it

---

## [18:30–24:15] Where it stops, the family, and trust

### Slide 11 — The honest scope: what's wired, what's coming

**On screen:**

- **Triage — wiring into default ingest, release by release** (explicit commands today):
  - deep registry (run keys / UserAssist / amcache) · full browser history
  - SRUM → `issen srum SRUDB.dat` · Biome → `issen biome <stream>`
- **0.x** — early, honest, moving fast
- Deep-dive (deleted-record carving, …) is a *different job* → next slide

**Script:**

> This is the slide most talks don't have, and it's the one I care about most. Take a picture and
> hold me to it on GitHub.
>
> There are triage parsers in the binary not yet wired into the one-command pass — deep registry,
> full browser history, SRUM. They run as explicit commands today; `issen srum` parses a SRUDB.dat
> right now. Wiring them into the default pass is exactly what the next releases are.
>
> It's 0.x, and I'll frame that without apology: it already does the boring part that eats your week —
> the parsing, the stitching, the clock discipline, the safe exports — end to end, on real evidence,
> today. The rest is scoped and public.

### Slide 12 — Meet the family: one sharp tool per job

**On screen:**

- Issen = the **triage front door**
- Deep-dive on one artifact class → an open specialist: `sqlite-forensic` *(differential-tested vs 4 carvers)* · `ntfs-forensic` · `browser-forensic` · `winevt-forensic` · `memory-forensic`
- the front door before you decide which specialist deserves the rest of your night

**Script:**

> And some jobs aren't triage at all. SQLite deleted-record carving — WAL replay, free-page
> reconstruction — is deep forensics; that's `sqlite-forensic`, differentially cross-checked against
> four independent carvers — undark, fqlite, bring2lite, and DC3's SQLite Dissect. NTFS,
> browser, event-log, memory — each has its own sharp, open tool. Issen is the triage front door to
> that family: one tool per job, all open — not one monolith stretched thin.

### Slide 13 — The whole family *(the comprehensiveness map)*

**On screen:** *(dense by design — a wall of open repos, grouped by cluster; each mostly a
`<x>-core` reader + `<x>-forensic` analyzer pair, oracle-validated)*

- **Everything DFIR — one Rust crate at a time.** *(banner line over the wall)*

- **Knowledge & codecs** — forensicnomicon · forensic-vfs · state-history-forensic · forensic-hashdb · jsonguard · blazehash · xpress-huffman · lzvn · cfb-forensic · shellitem
- **Containers** — ewf · vmdk · vhd · vhdx · qcow2 · aff4 · dmg · ad1 · iso9660 · udf · zip · dar
- **Volume systems** — mbr · gpt · apm *(-partition-forensic)*
- **Filesystems** — ntfs · ext4fs · apfs · hfsplus · fat · **4n6mount** *(FUSE bridge)*
- **Crypto layers** — bitlocker · filevault · dpapi
- **Memory** — memory-forensic *(memf: hardware · windows · linux · format)*
- **Logs & events** — winevt · journald
- **Windows artifacts** — winreg · prefetch · lnk · usnjrnl · exec-pe · srum
- **App & user activity** — browser · sqlite · snss · segb · useract · shellhist · trash · peripheral
- **History & provenance** — vsc *(VSS)* · snapshot · git
- **Orchestration** — issen *(cli · correlation · forensic-pivot · parsers)* · disk-forensic

*50+ open repos · maturity varies (published → in-progress) · what's wired into the one-command pass is on Slide 11*

**Script:** *(~40s — do NOT read the list; let the wall speak)*

> Don't read this — screenshot it. This is the whole family, by cluster: containers, volume systems,
> filesystems, crypto, memory, logs, every Windows and app artifact, history. Fifty-odd open repos,
> each a sharp reader-plus-analyzer pair, each validated against an oracle. That's the point of the
> wall — Issen isn't a monolith; it's the open front door to *this*. One binary for triage, and the
> whole ecosystem underneath when you go deep. That's the whole project in six words: everything
> DFIR, one Rust crate at a time. Maturity varies, and what's wired into the one command
> is on the honest-scope slide — but it's all open, and it's all yours.

### Slide 14 — Why you can trust the rows

**On screen:**

- **Fuzzed** — targets on the high-risk binary structures, in CI
- **Cross-checked** — vs The Sleuth Kit (disk), Volatility (memory), and four independent SQLite carvers, on public corpora
- **Case-001** — the public corpus you saw, answer key and all
- Findings say "consistent with" — never "proves"

**Script:**

> Three reasons to trust output from a 0.x tool, all checkable in the repo. One: the high-risk
> parsers have fuzz targets chewing on them in CI — a malformed image gets you an error, not a crash.
> Two: correctness isn't self-graded — we cross-check against independent oracles, The Sleuth Kit for
> disk, Volatility for memory, and four independent carvers for SQLite — undark, fqlite, bring2lite,
> and DC3's SQLite Dissect — on real public evidence. Three: everything tonight
> was the public Case-001 corpus, so you can reproduce all of it. Early doesn't have to mean sloppy.

---

## [24:15–26:00] Close

### Slide 15 — Tonight

**On screen:**

```
brew install securityronin/tap/issen
```

- Corpus: DFIR Madness "Stolen Szechuan Sauce" (public, real, answer key)
- github.com/SecurityRonin — issues, rules, PRs welcome
- **Stop being the integration layer.**

**Script:**

> The close is short, because the ask is simple and it's free. It's Apache-licensed, it's one binary —
> install it tonight, the hotel wifi can handle a brew install. Download Case-001, the same corpus I
> ran on, and check my work; it has an answer key, so you don't have to take my word for anything.
> File the issue when you find what I got wrong — you will, it's 0.x, and every one makes it better
> for the next person up at 2:47.
>
> Write detection rules? They're YAML — come write some. Write Rust? The parsers are open — come break
> some. Automating triage across a fleet? This is the surface to script.
>
> Here's the whole talk in one line. The field is great — keep your tools, they're good. But the
> integration layer between them shouldn't be *you*, at 2 a.m., with a spreadsheet. Now it's a binary
> you can drive — with a script, in a pipeline, or just by running it yourself.
>
> Stop being the integration layer. Thanks, DEF CON — I'll be at the village table after; bring your
> weirdest image formats.

### Slide 16 — Cheat sheet *(leave-up / applause slide)*

**On screen:**

```
# install (pick one)
brew install securityronin/tap/issen     # macOS

winget install SecurityRonin.issen       # Windows

# Linux: add repo, then install
curl -1sLf https://dl.cloudsmith.io/public/securityronin/issen/setup.deb.sh | sudo bash
sudo apt install issen

cargo install issen-cli                  # anywhere Rust runs

# triage a case — disk + memory → one timeline (re-run to resume)
issen DC01.E01 DESKTOP.E01 DC01.mem.zip DESKTOP.mem.zip -o case.duckdb

# work the timeline
issen timeline case.duckdb --flagged --min-severity medium
issen timeline case.duckdb --path '*coreupdater*'
issen timeline case.duckdb --around <t> --window 5m
issen memory DC01.mem.zip --command netstat

# hand off to your tools
4n6mount case.E01 /mnt/evidence

# practice: DFIR Madness "Stolen Szechuan Sauce" (public, answer key)
# full surface: issen --help  ·  github.com/SecurityRonin
```

**Script:**

> And this stays up while you file out — photograph it. Install line, the one triage command, the
> handful of verbs to work the timeline, the mount for your own tools, and the public corpus to try
> it all on tonight. That's the whole tool on one screen. Go get your night back.

*(Delivery: flip to this immediately after the closing line and leave it up through applause /
Q&A-in-the-hall. It's the reference people screenshot — do not talk over it beyond the one line.)*

---

## Timing summary

| Section | Slides | Time | Running total |
|---|---|---|---|
| Cold open — you own everything, still the glue | 1–2 | 2:30 | 2:30 |
| The field is great (credit + unique wins, incl. AXIOM triad) | 3 | 1:15 | 3:45 |
| So why are you still the glue? (the gap — can't script it end-to-end) | 4 | 1:45 | 5:30 |
| Meet Issen + install | 5 | 2:00 | 7:30 |
| **DEMO 1** — one command + resume | 6–7 | 5:00 | 12:30 |
| **DEMO 2** — investigation + VSS capture | 8 | 4:30 | 17:00 |
| Output humans + pipelines can trust (the USP payoff) | 9 | 1:30 | 18:30 |
| Triage → deep-dive handoff | 10 | 1:30 | 20:00 |
| Honest scope + the family | 11–12 | 2:00 | 22:00 |
| The whole family (fleet map — don't read it) | 13 | 0:45 | 22:45 |
| Trust | 14 | 1:30 | 24:15 |
| Close | 15 | 1:30 | **25:45** |
| Cheat sheet *(leave-up through applause; ~15s spoken)* | 16 | 0:15 | 26:00 |
| Buffer (demo overrun / laughs / applause) | — | 4:00 | 30:00 |

**Cut order if running long:** the family beat (Slide 12) → the `--path` step in Demo 2 → the VSS
capture (Slide 8) → Slide 10 (handoff) narration to one sentence over the capture → the resume demo
(describe, don't run). **Never cut Slide 11** (honesty) or the scriptability payoff on **Slide 9** —
those two carry the talk's credibility and its USP.

**Callback discipline:**
- The **scriptability question** is a bookend: *posed* on Slide 4 ("you'd think you could just script
  this end-to-end — you can't, across GUI/Windows/lossy-CSV") → *answered* on Slide 9 ("this, you can —
  the glue becomes a command") → *offered* on Slide 15 ("automating triage across a fleet? script it").
  This is the spine; land all three, don't add more.
- **"Stop being the integration layer"** bookends: Slide 1 (implicit, the pain) → Slide 15 (explicit,
  the resolution). It's the title and the last idea.
- Do not over-repeat either; a callback lands three times, then curdles.

---

# Delivery & stagecraft direction

> Art-direction and performance notes (Gemini 3.1 Pro High). The read on the room: "If you look
> polished, they tune you out. If you look competent, honest, and slightly tired, they follow you
> anywhere." Calm, lethal competence — John Wick reloading, not a hype-man. **Especially:** keep the
> scriptability payoff concrete and un-hyped — no buzzwords, no hand-waving. You earn it by showing
> clean commands first, then *naming* what they unlock (a script, a pipeline). Show, then claim.

## Cold open — the first 90 seconds
- **Lighting:** kill the stage wash. Walk out in near-dark, lit by projector bleed. No walk-on music,
  no "hi, my name is."
- **Slide:** true black `#000000`, one line of small centered monospace.
- **Delivery:** look at your monitor for ~3 seconds of dead air before a word. Low, weary tone —
  recalling a bad night, not pitching. Hit "you own the best tools in the field… and you're still the
  glue" as the turn.
- **The turn:** on "show of hands," step out from behind the podium into the light, raise your own
  hand, stop talking. The silence pulls the hands up.

## Visual art direction
- Brutalist, high-contrast, terminal-native. True-black backgrounds so slide edges vanish.
- Palette: Nord or Catppuccin Macchiato. Type: JetBrains Mono / Iosevka for code; Inter (Heavy) for
  the rare header. Ban Arial/Helvetica/Calibri.
- Left-aligned, huge negative space; leave the **bottom third empty** (back rows can't see it).
- Recurring device: end a narrative slide's last thought with a blinking block cursor `█`.

## Live-demo choreography
- 28pt minimum, clean prompt (Starship). Drive commands with **`doitlive`** — one keypress plays a
  pre-written command at smooth speed: no typos, real kinetics.
- **The strike:** hit Enter on the ingest, take your hands off the keyboard, half-step back, and let
  the parallel progress bars race. *Don't talk over them.*
- **Silence as a weapon:** after `--flagged` shows the coreupdater finding, and again when `netstat`
  prints the same process holding the C2, pause ~3 seconds. Let the room connect disk to memory before
  you speak.
- **Failure survival:** if it dies — no giggle, no apology. Deadpan: *"And that's why it's 0.x.
  Switching to the warm cache."* Snap to the pre-run DB (tmux window).

## The USP beat (Slide 9) — stage it as the peak
- This is the emotional crest. Slow down. After "look at what everything I just did actually *was* —
  commands," pause. Let them realize it themselves before you land "the glue becomes a command."
- Deliver the line and let the earlier demos be the proof — the room just watched it be all commands,
  one clean structured store, safe output. Do not oversell; the payoff is that it's *obviously*
  scriptable, not that you claimed it. Concrete, not hype.

## Three engineered "phone-out" moments
1. **The install (Slide 5):** four lines up, say "this is the whole slide," then take a slow drink of
   water. ~10s of dead air makes them read it, clock there's no catch, and photograph it.
2. **The disk→memory connection (Slide 8):** the moment `netstat` shows the same `coreupdater.exe`
   holding the C2 the disk timeline flagged. Let it sit.
3. **The honesty slide (Slide 11):** *"Take a picture of this one and hold me to it on GitHub."* A
   speaker listing what their tool can't do yet is anomalous enough to trigger cameras — and banks
   credibility for the rest of the con.

## Delivery mechanics
- **Energy:** tired, cynical room — don't be a hype-man. Calm, lethal competence.
- **Pacing:** fast through the pain (they live it); slow hard on the disk→memory reveal and the Slide 9
  scriptability payoff.
- **Posture/wardrobe:** feet shoulder-width, don't pace. Plain black tee / unbranded dark hoodie —
  zero logos, not even your employer's. Practitioner, not vendor.
- **No-Q&A room:** on the final line, point clearly to exactly where you'll be standing.

## AV cues
- Hard cuts only, zero fades — clicking should feel like hitting Enter.
- At mic check, ask AV to boost the low-end EQ slightly for broadcast resonance.

---

# Revision log — the arc that produced this deck

Drafted by **fable**, art-directed by **Gemini 3.1 Pro High**, adversarially reviewed and fact-checked
by **Codex (GPT-5)** + web verification, over a multi-pass competitive teardown. The deck was rebuilt
each time a claim failed prior-art scrutiny; this is the version that survived.

**What we learned (the ledger behind the positioning — full detail in `dfir-tool-landscape-findings.md`):**
- Every **capability** has a mature owner (Volatility=memory, Plaso=formats, X-Ways=VSS Event List,
  Hayabusa/Chainsaw=Sigma). Not USPs.
- Every **capability-combination** has one too — **AXIOM 3.0 does disk + VSS + memory in one timeline**
  (web-verified). "Read-in-place," the `fvfs:` open-recipe, VSS-super-timeline, disk+memory, and the
  disk+vss+memory triad were each floated as the headline and each killed by prior art.
- **The only thing that survives is the FORM:** open + scriptable + single free static binary + any OS
  + the triage combination + safe/structured output = *drivable*. The one shape a commercial Windows
  GUI suite structurally cannot be. Sharpest expression: **"the integration layer becomes a command,
  not a human — a triage you can script,"** because it's the single claim a skeptic can't immediately
  name a tool against. *(The earlier "AI agent" framing was cut — we ship no agent integration, and
  the AI-agent angle is cliché to this crowd; the honest core is scriptability, which needs no AI.)*

**Honesty rules baked in (do not re-break):**
- Credit competitors by real strengths; concede AXIOM's triad; never claim a capability or combination
  as unique.
- Memory is a wedge vs the *free* tier only; the suites (and AXIOM) do memory.
- "Not scriptable" for suites → "GUI-first; scriptable-with-composable-output isn't the default surface"
  (Magnet Automate / X-Ways X-Tensions exist as separate layers).
- CSV → "unsafe, lossy integration boundary," never "every tool emits broken CSV" (Codex; OWASP-backed
  injection angle is fine).
- Autopsy is cross-platform + has CLI ingest — don't call it GUI-only; Sanderson SQLite-GUI left
  unverified (do not name as CLI-free without the manual).
- The scriptability payoff is *earned* (show clean commands, then name it), never a buzzword opener.
  **No "AI agent" framing anywhere** — we ship no agent integration and the crowd is allergic to AI hype.
- forensic-vfs is an **enabler** ("why it's a clean single Rust binary, no Python"), not a headline;
  dfVFS/Plaso have read-in-place + path-spec prior art.
- Findings "consistent with," never "proves"; no self-grading matrix; only sanctioned numbers —
  ~11× appender, ~37× warm resume, and **~64 s cold DC01 ingest (measured 2026-07: 4.6 GB E01 read
  from the zip → full ingest+correlate+scan, M4 Pro MacBook Pro, ~6.5 GB peak RAM)**. Label speed
  measured/this-machine; **no "Nx faster than AXIOM"** (no measured cross-tool comparison). All deck
  output blocks are **real captured runs** (coreupdater `--path`, `--flagged high`, netstat C2). The
  namesake tie-in (*issen* = "one flash") is fine as ONE dry plant + payoff. 0.x framed with pride.
- APFS + VSS are **shipped coverage** (VSS published), never headlined.
- Verify before staking a demo: the unified disk+memory command (ADR 0012 — shipped), the `fvfs:`
  `--show-source` surface (gated — drop if absent), and (optional) a one-liner shell pipeline for the
  Slide 9 scriptability beat.
