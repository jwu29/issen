# Issen DEF CON deck — Gamma import script (self-contained / published version)

**This version is written to stand alone.** A reader who never heard the talk gets the full argument
from the cards themselves — because a published deck has no speaker. For a *sparse live-projection*
variant (minimal on-screen text, meat in the spoken narrative), use `defcon-issen-debut.md` instead,
or hide each card's body text in Gamma when presenting live.

**How to import (verified against Gamma's Generate API + Import docs):**

- **Paste-in-UI:** Gamma → *New with AI* → *Import* → *Paste in text*. Paste **only** the block
  between the `▼ COPY` / `▲ STOP` markers. Choose **"Preserve" text** and **one card per divider**
  (Gamma splits on the `---` lines).
- **Generate API:** send that block as `inputText` with
  `{ "cardSplit": "inputTextBreaks", "textMode": "preserve", "format": "presentation" }`.
  Cards are separated by `\n---\n`. **Use `preserve`** — `generate` rewrites the cards and loses the
  voice and the precise claims.
- **Theme:** dark, monospace (near-`#000000`, JetBrains Mono / Iosevka, a Nord/Catppuccin green
  accent). Let Gamma set images/layout; keep code blocks as-is.
- **Presenting it live?** A short "delivery cues" section is at the very bottom (silences, phone-out
  beats, failure survival) — the only things that can't live on a self-contained card.
- 17 cards. On-screen content is self-contained prose + the real `issen` commands.

---

▼▼▼ COPY FROM HERE INTO GAMMA ▼▼▼

# Stop Being the Integration Layer

### Issen — the open, scriptable triage layer you can *drive*

One free static binary. Disk **and** memory into one findings-first timeline. macOS · Linux · Windows.

A talk about why a *fully-stocked* DFIR lab still hand-stitches five tools at 2 a.m. — and the one
shape of tool that fixes it. Not a new capability. A new *form*: open-source, scriptable, single-binary,
and drivable by a script, a pipeline, or a tired analyst.

**Albert Hui** (4n6h4x0r) · github.com/SecurityRonin

---

# 2:47 a.m. — and you're the glue

You are not under-tooled. Your lab owns the best tools in the field — the Zimmerman suite, TZWorks,
Volatility, USB Detective, the Sanderson SQLite toolkit, a pricey AXIOM license someone just renewed.

And you are *still* at 2 a.m. with five of them open, being the thing that connects them: matching a
process in memory to a file on disk by hand, reconciling two clocks, cleaning an export that broke
because a filename had a comma in it.

**The forensics isn't the hard part tonight. The stitching between the parsers is. You are the
integration layer.**

---

# The job is analysis. The work is plumbing.

- **The job** — what happened on these machines, in what order, across disk and memory
- **The work** — converting formats, reconciling clocks, fixing the export Excel mangled

The evidence is right there; the question is simple. What eats the night is the *integration*.
À-la-carte workflows quietly become analyst-managed integration — and that's not a knock on the
tools. It's the gap *between* them, and it should have been filled by software, not by a tired human
with a spreadsheet.

---

# The field is genuinely great

The tools you already use are excellent. This is not a pitch against them.

- **Open specialists** — Hayabusa & Chainsaw (fast Sigma on logs, single Rust binary), **Volatility 3**
  (the memory-forensics standard, and deservedly), Plaso (more formats than anything alive)
- **Commercial suites** — X-Ways folds Volume Shadow Copies into its **Event List** timeline; and
  **AXIOM does the whole thing — disk, shadow copies, *and* memory, correlated into one timeline in a
  single case.**

Credit where it's due. None of these is the enemy.

---

# So why are you still the glue?

Even with AXIOM correlating disk + VSS + memory in one timeline, three things keep you stitching:

- It's a **GUI**, it's **Windows**, it's a **paid commercial seat** — the analyst clicks through it, on the box
  it runs on, in the seats you licensed.
- Step outside it — the fast Sigma tool, a Volatility run, a SQLite deep-dive — and you're back to
  ~5 apps and, for many, a **Windows VM** booted grudgingly because half the good toolbox is Windows-first.
- **Try to script it end-to-end** — pipe one tool into the next and let it run? Not across the mixed
  workflow. The good CLI tools (Volatility, Plaso, the EZ command-line tools) script fine — but the
  steps behind **GUI state · Windows-only apps · lossy, unsafe CSV** bridges break the pipe.

**The gap isn't a missing capability — every capability already exists. The gap is that none of it is
a surface you can *script*.**

---

# issen — the drivable triage layer

*Issen* (一閃) means **"one flash"** — the single stroke of the blade. The whole first pass, in one.

One **free static binary**. Rust. macOS / Linux / Windows. No Python, no runtime deps, no license
server. A CLI with a structured store and clean, safe output — so it drops into a pipeline, a CI job,
or a fleet sweep.

It does **not** do more than AXIOM — no cloud, no mobile, less depth in every specialist's lane.
What it **is**: the one open, free, scriptable single binary that runs the whole first-pass triage —
disk + memory, findings-first, one timeline — on the laptop you already have.

```
brew install securityronin/tap/issen     # macOS

winget install SecurityRonin.issen       # Windows

# Linux (Debian/Ubuntu): add the repo, then install
curl -1sLf https://dl.cloudsmith.io/public/securityronin/issen/setup.deb.sh | sudo bash
sudo apt install issen

cargo install issen-cli                  # anywhere Rust runs
```

---

# One command: disk + memory → one timeline

```
issen DC01.E01 DESKTOP-SDN1RPT.E01 DC01.mem.zip DESKTOP-SDN1RPT.mem.zip -o case001.duckdb
```

Point it at the evidence, name the output, done. No mounting step — it reads the images directly, and
the memory dumps **straight out of their `.zip`** (no unzip, no temp copy — the way they actually
ship). Where a disk carries shadow copies, those historical states fold into the same timeline.

- **2 disk images + 2 memory dumps → 1 flagged timeline**, one clock (UTC, nanosecond)
- Stored in **DuckDB** (columnar; ≈11× faster to load than naive row inserts), not a directory of CSVs
- **Fast — the "one flash":** DC01 (4.6 GB E01, read from the zip) → full flagged timeline, parsed + correlated + scanned, in **~64 s** *(measured, M4 Pro MacBook Pro)*
- Default pass = the triage set: MFT · event logs · registry · prefetch · LNK · jump lists · shimcache · amcache

*Evidence: the public **DFIR Madness "Stolen Szechuan Sauce" Case-001** corpus — a real intrusion, with
a published answer key, so you can verify every claim.*

---

# Resumable by default

```
issen DC01.E01 DESKTOP-SDN1RPT.E01 DC01.mem.zip DESKTOP-SDN1RPT.mem.zip -o case001.duckdb   # again
```

Re-run the *same command* — it fingerprints each stage and only redoes what changed. On Case-001 the
warm re-run was **≈37× faster** than the cold path. Got new evidence on day three? Same command plus
one filename; it parses the new image and leaves the rest alone. Ctrl-C stopped being a catastrophe.

---

# Work the case: finding → pivot → memory

```
issen timeline case001.duckdb --flagged --min-severity high
issen timeline case001.duckdb --path '*coreupdater*'
issen timeline case001.duckdb --around 2020-09-19T03:21:00Z --window 5m
issen memory DC01.mem.zip --command netstat
```

Real output — genuine runs on Case-001 DC01 (M4 Pro MacBook Pro; the `--flagged` list shows 2
representative rows of the 131 high findings, spacing condensed for width, values verbatim):

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
TCPv4  10.42.85.10:62613  203.78.103.109:443  ESTABLISHED  3644  coreupdater.exe   ← C2, matches answer key
```

- **`--flagged`** — severity-graded, MITRE-tagged findings. 252k total, 131 high — and each names its
  **subject**. Among the 7045 service installs, most subjects are familiar drivers (HdAudio.sys); one
  is `C:\Windows\System32\coreupdater.exe`. The subject is the *lead* — the artifact to pull and
  **confirm** (code signature, hash → VirusTotal, and here the memory C2 below) — not a verdict on its
  own. YARA + Sigma ran *inside* ingest, so detections are born in the timeline.
- **`--path`** — the malware by name: dropped via the USN journal, executed per the registry shimcache.
- **`--around`** — what else happened right then, across *both* hosts — the cross-host pivot you used
  to do by alt-tabbing two Excel windows.
- **`issen memory … netstat`** — the C2 `coreupdater.exe → 203.78.103.109:443`, read straight from the
  dump `.zip`; **matches the Case-001 answer key**.

Memory here is a *triage subset* folded into the timeline, not a Volatility replacement. Every finding
is worded as what it is — *consistent with* a technique. The tool flags; you conclude.

*On a disk that has shadow copies, a file deleted on the live volume is recovered from a snapshot into
the same timeline — triage the past, not just the present.*

---

# Output a reviewer — and a pipeline — can trust

Evidence is attacker-controlled data at **both ends of the pipe**, and Issen treats it that way both
times. **Coming in:** a malformed or booby-trapped image can't crash it or run code through it — the
parsers are **fuzzed and panic-free by construction**, so a bad image is an *error, not an exploit*
(see the trust card). **Going out:** exports are safe by default — strict **RFC-4180 CSV**,
**formula-injection guarded**, **JSON sanitized** (via `jsonguard`); `=cmd|' /C calc'!A0` arrives as
**text, not execution** (attackers put `=cmd` in filenames so the evidence executes when a reviewer
opens the export in Excel). That takes most of the export-cleanup plumbing off your plate.

Now look at what the whole investigation actually *was*: **commands, into a structured store, with
clean output.**

That is the answer to the question from the start. You couldn't script your old workflow end-to-end
because it was GUIs, Windows-only apps, and lossy CSV — the seams broke the pipe. **This is none of
those. This is the first-pass triage you can drive end to end — with a script, in a CI job, across a
fleet, or by hand at 2 a.m.** The integration layer stops being *you* and becomes a *command*. Not
that it does more than the suites — that it's the one shape they can't be: *drivable.*

---

# Triage, then deep-dive — keep your tools

Issen knows its lane. Triage *starts* the investigation; it doesn't end it. Once Issen points you at
the artifact, you go deep with the specialist you already trust — **LECmd** on that LNK, **pf** on
that prefetch, **usnjrnl_rewind.py** on the USN journal.

```
4n6mount image.E01 /mnt/evidence
```

`4n6mount` — the same reader, as a FUSE mount — presents the image as a normal read-only directory
(copy-on-write, so the evidence stays pristine) on Mac, Linux, or Windows. Every à-la-carte tool you
own works straight against it. **Fast unified triage from Issen, then deep-dive with whatever you
trust.** Nobody is asking you to give up the tools you love.

---

# The honest scope (0.x, and proud of it)

Some parsers ship in the binary but aren't yet wired into the one-command pass. They run as explicit
commands today:

- **deep registry** (run keys / UserAssist / amcache), **full browser history**
- SRUM → `issen srum SRUDB.dat` · Biome → `issen biome <stream>`

Wiring them into the default pass is exactly what the next releases are. It's **0.x** — and it already
does the boring 80% that eats your week (parsing, stitching, clock discipline, safe exports) end to
end, on real evidence, today. The rest is scoped and public. *Take a picture of this one and hold me
to it on GitHub.*

---

# One sharp tool per job

Some jobs aren't triage at all. SQLite deleted-record carving — WAL replay, free-page reconstruction
— is deep forensics; that's **`sqlite-forensic`**, differentially cross-checked against four
independent carvers (undark · fqlite · bring2lite · DC3 SQLite Dissect). NTFS, browser,
event-log, and memory each have their own open specialist.

Issen is the **triage front door** to that family: one sharp tool per artifact class, all open — not
one monolith stretched thin. Triage gets you to the interesting artifact; the specialist takes it
apart.

---

# The whole family — one open crate per artifact

### Everything DFIR — one Rust crate at a time.

Every name below is its own open repo, most as a **`-core` reader + `-forensic` analyzer** pair, each
validated against an independent oracle. Issen wires them for triage; each stands alone for deep-dive.

**Knowledge & codecs** — forensicnomicon · forensic-vfs · state-history-forensic · forensic-hashdb · jsonguard · blazehash · xpress-huffman · lzvn · cfb-forensic · shellitem

**Containers** *(image formats)* — ewf · vmdk · vhd · vhdx · qcow2 · aff4 · dmg · ad1 · iso9660 · udf · zip · dar

**Volume systems** — mbr · gpt · apm *(`-partition-forensic`)*

**Filesystems** — ntfs · ext4fs · apfs · hfsplus · fat · **4n6mount** *(FUSE bridge)*

**Crypto layers** — bitlocker · filevault · dpapi

**Memory** — memory-forensic *(memf: hardware · windows · linux · format)*

**Logs & events** — winevt · journald

**Windows artifacts** — winreg · prefetch · lnk · usnjrnl · exec-pe · srum

**App & user activity** — browser · sqlite · snss · segb · useract · shellhist · trash · peripheral

**History & provenance** — vsc *(VSS)* · snapshot · git

**Orchestration** — issen *(cli · correlation · forensic-pivot · parsers)* · disk-forensic

*50+ open repos. Maturity varies — published through in-progress; **what's wired into the
one-command pass is on the honesty slide**. This is the ecosystem, not a claim that all of it is in
the default pipeline.*

---

# Why you can trust a 0.x tool

- **Fuzzed** — the high-risk parsers have fuzz targets running in CI; a malformed image gets you an
  error, not a crash.
- **Cross-checked** — against independent oracles: **The Sleuth Kit** (disk), **Volatility** (memory),
  and **four SQLite carvers** (undark · fqlite · bring2lite · DC3 SQLite Dissect) — on
  real public evidence, with the write-ups in the docs.
- **Reproducible** — everything here ran on public **Case-001**, answer key and all. Check the work.

Early doesn't have to mean sloppy.

---

# Stop being the integration layer

```
brew install securityronin/tap/issen
```

- Free, **Apache-2.0**, one binary — install it tonight.
- Try it on DFIR Madness **"Stolen Szechuan Sauce"** (public, real, answer key) and verify every claim.
- Contribute — detection rules are **YAML**, the parsers are open Rust: **github.com/SecurityRonin**
- **Automating triage across a fleet? This is the surface to script.**

The field is great — keep your tools; they're good. But the integration layer between them shouldn't
be *you*, at 2 a.m., with a spreadsheet. Now it's a binary you can drive — with a script, in a
pipeline, or just by running it yourself.

*AXIOM & Magnet (Magnet Forensics), X-Ways (X-Ways Software Technology AG), and Autopsy (Basis
Technology / Sleuth Kit Labs); plus TZWorks, USB Detective, and the Sanderson Forensic Toolkit for
SQLite — all are trademarks of their respective owners. Named for factual comparison (nominative fair
use); no affiliation or endorsement is implied.*

---

# Cheat sheet — screenshot this

**Install** *(pick one)*

```
brew install securityronin/tap/issen     # macOS

winget install SecurityRonin.issen       # Windows

# Linux (Debian/Ubuntu): add the repo, then install
curl -1sLf https://dl.cloudsmith.io/public/securityronin/issen/setup.deb.sh | sudo bash
sudo apt install issen

cargo install issen-cli                  # anywhere Rust runs
```

**Triage a case — disk + memory → one timeline** *(re-run the same line to resume)*

```
issen DC01.E01 DESKTOP.E01 DC01.mem.zip DESKTOP.mem.zip -o case.duckdb
```

**Work the timeline**

```
issen timeline case.duckdb --flagged --min-severity medium      # start at findings
issen timeline case.duckdb --path '*coreupdater*'               # search by name/path
issen timeline case.duckdb --around 2020-09-19T03:21:00Z --window 5m   # pivot, all hosts
issen memory DC01.mem.zip --command netstat                         # deep memory view
```

**Hand off to your deep-dive tools**

```
4n6mount case.E01 /mnt/evidence          # read-only mount → point LECmd/pf/your tools at it
```

**Practice on real evidence** — DFIR Madness *"Stolen Szechuan Sauce"* (public, answer key):
`dfirmadness.com` · full surface: `issen --help` · `issen timeline --help` · **github.com/SecurityRonin**

▲▲▲ STOP COPYING — everything below is for a live presenter, do NOT import ▲▲▲

---

# Delivery cues (only for presenting it live)

The cards above are self-contained for readers. These are the things that can't live on a slide — the
choreography — for anyone giving the talk. Full verbatim script: `defcon-issen-debut.md`.

- **Cold open (Card "2:47 a.m."):** near-dark stage, no walk-on music. 3 seconds of silence before the
  first word. Low, weary tone. On "you own the best tools… and you're still the glue," step into the
  light; on the implicit "show of hands," raise your own hand and go silent — the room's hands follow.
- **Install card:** say "this is the whole slide," then take a slow drink of water. ~10 s of dead air
  makes the room read it, clock there's no catch, and photograph it. (Phone-out #1.)
- **One-command demo:** hit Enter, take your hands off the keyboard, half-step back, and let the
  parallel progress bars race. Do **not** talk over them.
- **Finding → memory:** pause ~3 s when `netstat` prints the same `coreupdater.exe` holding the C2 the
  disk timeline already flagged. That disk↔memory click is the most filmable beat. (Phone-out #2.)
- **"Output a pipeline can trust" card (the peak):** slow down. After "look at what everything I just
  did *was* — commands," pause before you land "the glue becomes a command." Optionally show a
  one-liner shell pipeline running the whole triage, then stop talking. This card carries the USP; don't rush it.
- **Honest-scope card:** introduce with "take a picture of this one and hold me to it on GitHub." A
  speaker listing what their tool can't do yet triggers cameras and banks credibility. (Phone-out #3.)
- **Failure survival:** if a live demo dies — no giggle, no apology. Deadpan: "And that's why it's
  0.x. Switching to the warm cache," then snap to a pre-run DB. This crowd forgives a crash; it never
  forgives a fake.
- **Wardrobe/energy:** plain black tee or unbranded dark hoodie, zero logos. Calm, lethal competence —
  not a hype-man. Keep the scriptability payoff concrete — no buzzwords, no AI hype: show the clean
  commands first, *then* name what they unlock (a script, a pipeline).
