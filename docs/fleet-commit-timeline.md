# SecurityRonin Fleet — Commit-History Timeline

A curated, Aeon-Timeline-styled view of the SecurityRonin forensic fleet's git
history. Each architectural layer is its own colored track; events are the
high-signal milestone commits (births, first-GREEN features, crates.io
publishes, registry migrations), not every commit.

**Scope:** 45 git repositories of the forensic fleet + orchestration tooling.
**Date range:** 2026-03-02 (usnjrnl-forensic, the eldest fleet repo) through
2026-06-15. **Total commits tallied across the 45 repos:** 4,871.

The numbers below are derived from `git log` / `git tag` in each repo (repo
birth = first commit date, last = most recent commit date, count =
`git rev-list --count HEAD`). Two complementary diagrams follow: a **`timeline`**
for the chronological narrative, and a themed **`gantt`** for the per-repo
lifespans laid out as Aeon-style horizontal tracks colored by layer.

---

## Narrative timeline (milestones by period)

Sections are time periods; under each period the `repo : milestone` events are
grouped. Colors are applied per layer via the theme below.

```mermaid
%%{init: {'theme':'base','themeVariables':{'primaryColor':'#1f2a44','primaryTextColor':'#e8ecf4','primaryBorderColor':'#3a4a6b','lineColor':'#7a88a8','cScale0':'#5b8def','cScale1':'#46b39d','cScale2':'#e0a458','cScale3':'#c9596b','cScale4':'#9b6bd6','cScale5':'#3aa0c9','cScale6':'#d77fa1'}}}%%
timeline
    title SecurityRonin Forensic Fleet — Curated Commit Timeline (2026)
    section Mar 2026 — Foundations
        Disk and orchestration seeds : usnjrnl-forensic born (USN + TriForce)
            : issen born (RapidTriage triage toolkit)
            : winreg-forensic workspace scaffold (8 crates)
            : memory-forensic workspace scaffold (memf-format)
            : ext4fs-forensic design spec
            : ewf pure-Rust E01 reader (Read plus Seek)
    section Apr 2026 — Knowledge and Mount
        KNOWLEDGE leaf extracted : forensicnomicon extracted from memory-forensic
            : forensicnomicon v0.1.0 tagged
            : 4n6mount universal FUSE framework
            : winevt-forensic workspace scaffold
    section May 2026 — Container and Parser wave
        Containers multiply : ewf-forensic analyzer crate (cargo new)
            : vhdx-forensic init
            : vmdk-forensic RED tests
            : qcow2-forensic RED tests
            : aff4 reader RED stubs
            : iso9660 IsoReader (sessions plus boot)
            : dmg DmgReader (koly plus mish plus zlib)
            : dar DarReader (catalog plus CRC32)
        Parsers and history : browser-forensic GREEN (Chrome plus Firefox)
            : srum-forensic ese-core RED tests
            : journald-forensic scaffold
            : exec-pe-forensic RED PE analysis
            : state-history-forensic API-shape RED tests
            : git-forensic integration RED stubs
            : jsonguard crate scaffold
    section Jun 2026 — Partitions, FS, publish sweep
        Partition and FS family : mbr-partition-forensic v0.1.0
            : gpt-partition-forensic CRC32 RED vectors
            : apm-partition-forensic extracted
            : disk-forensic analyse_disk dispatch RED
            : ntfs-forensic VBR parse RED then v0.6.1
            : hfsplus-forensic extracted standalone
            : udf-forensic extracted standalone
        Codecs and small parsers : xpress-huffman 0.1.0 (MS-XCA)
            : lzo LZO1X v0.1.1
            : sqlite-forensic native header RED
            : prefetch-forensic MAM decompress RED
            : lnk-forensic MS-SHLLINK RED
            : cfb-forensic MS-CFB carving RED
            : shellitem ITEMIDLIST framing RED
            : shellhist-forensic bash zsh fish PSReadLine
            : peripheral-forensic scaffold
            : segb-forensic SEGB v1 v2 RED
            : snss-forensic extracted standalone
            : useract-forensic UserActivity RED
        Publish and registry sweep : forensicnomicon 0.5 across the fleet
            : usnjrnl consumes published ntfs-core 0.7
            : memf consumes published jsonguard 0.2.3
            : issen registry-izes winreg plus srum deps
            : issen wires Biome useract capability
```

---

## Per-repo lifespans (Aeon-style tracks by layer)

Each bar runs from the repo's first commit to its last; sections are the
fleet's architectural layers (the Aeon "tracks"), and `gantt` colors them via
the `active`/`done`/`crit`/`milestone` tag classes themed below. Bar length
reflects calendar lifespan, not commit volume.

```mermaid
%%{init: {'theme':'base','themeVariables':{'taskTextColor':'#0b1020','taskTextOutsideColor':'#e8ecf4','sectionBkgColor':'#161d2e','altSectionBkgColor':'#1b2336','gridColor':'#3a4a6b','todayLineColor':'#c9596b','doneTaskBkgColor':'#5b8def','doneTaskBorderColor':'#3a6bc4','activeTaskBkgColor':'#46b39d','activeTaskBorderColor':'#2f8473','critBkgColor':'#e0a458','critBorderColor':'#b87f33'}}}%%
gantt
    title Fleet repo lifespans by architectural layer (first commit to last)
    dateFormat YYYY-MM-DD
    axisFormat %m/%d

    section KNOWLEDGE
    forensicnomicon        :done,    2026-04-14, 2026-06-15
    state-history-forensic :active,  2026-05-14, 2026-06-15
    jsonguard              :active,  2026-05-21, 2026-06-14
    xpress-huffman         :crit,    2026-06-12, 2026-06-12
    lzo                    :crit,    2026-06-07, 2026-06-07

    section CONTAINER
    ewf                    :done,    2026-03-05, 2026-06-14
    ewf-forensic           :done,    2026-05-12, 2026-06-09
    vhdx-forensic          :done,    2026-05-11, 2026-06-15
    vhd                    :active,  2026-05-22, 2026-06-14
    vmdk-forensic          :done,    2026-05-22, 2026-06-15
    qcow2-forensic         :active,  2026-05-22, 2026-06-15
    iso9660-forensic       :done,    2026-05-25, 2026-06-15
    dd                     :active,  2026-05-21, 2026-06-14
    dmg                    :crit,    2026-05-25, 2026-06-14
    aff4                   :active,  2026-05-22, 2026-06-14
    dar-forensic           :done,    2026-05-25, 2026-06-15
    segb-forensic          :crit,    2026-06-14, 2026-06-15

    section FILESYSTEM
    ntfs-forensic          :done,    2026-06-04, 2026-06-15
    ext4fs-forensic        :done,    2026-03-31, 2026-06-15
    hfsplus-forensic       :active,  2026-06-04, 2026-06-15
    udf-forensic           :crit,    2026-06-04, 2026-06-15
    4n6mount               :active,  2026-04-03, 2026-06-07

    section LOG
    winevt-forensic        :done,    2026-04-25, 2026-06-15
    srum-forensic          :done,    2026-05-04, 2026-06-15
    journald-forensic      :active,  2026-05-05, 2026-06-15

    section MEMORY
    memory-forensic        :done,    2026-03-31, 2026-06-15

    section PARSER
    browser-forensic       :done,    2026-05-03, 2026-06-15
    sqlite-forensic        :done,    2026-06-10, 2026-06-15
    prefetch-forensic      :crit,    2026-06-12, 2026-06-14
    winreg-forensic        :done,    2026-03-27, 2026-06-15
    lnk-forensic           :crit,    2026-06-13, 2026-06-13
    cfb-forensic           :crit,    2026-06-13, 2026-06-13
    snss-forensic          :crit,    2026-06-15, 2026-06-15
    shellitem              :crit,    2026-06-13, 2026-06-13
    shellhist-forensic     :crit,    2026-06-13, 2026-06-13
    peripheral-forensic    :crit,    2026-06-13, 2026-06-13
    exec-pe-forensic       :active,  2026-05-29, 2026-06-15
    git-forensic           :active,  2026-05-26, 2026-06-13
    useract-forensic       :active,  2026-06-13, 2026-06-15

    section PARTITION
    usnjrnl-forensic       :done,    2026-03-02, 2026-06-15
    mbr-partition-forensic :done,    2026-06-03, 2026-06-15
    gpt-partition-forensic :done,    2026-06-04, 2026-06-15
    apm-partition-forensic :active,  2026-06-04, 2026-06-15
    disk-forensic          :done,    2026-06-05, 2026-06-15

    section ORCHESTRATION
    issen                  :done,    2026-03-23, 2026-06-15
```

---

## Rendered image

A pre-rendered SVG of the per-repo lifespan gantt is committed alongside this
file (GitHub also renders the Mermaid blocks above natively):

![Fleet commit timeline](img/fleet-commit-timeline.svg)

---

### Top repos by commit count (context for the timeline)

| Repo | Layer | Commits | Born | Last |
|---|---|---:|---|---|
| memory-forensic | MEMORY | 808 | 2026-03-31 | 2026-06-15 |
| forensicnomicon | KNOWLEDGE | 772 | 2026-04-14 | 2026-06-15 |
| issen | ORCHESTRATION | 630 | 2026-03-23 | 2026-06-15 |
| iso9660-forensic | CONTAINER | 295 | 2026-05-25 | 2026-06-15 |
| srum-forensic | LOG | 272 | 2026-05-04 | 2026-06-15 |
| winevt-forensic | LOG | 250 | 2026-04-25 | 2026-06-15 |
| vmdk-forensic | CONTAINER | 195 | 2026-05-22 | 2026-06-15 |
| browser-forensic | PARSER | 196 | 2026-05-03 | 2026-06-15 |
| dar-forensic | CONTAINER | 122 | 2026-05-25 | 2026-06-15 |
| ewf-forensic | CONTAINER | 120 | 2026-05-12 | 2026-06-09 |
| ntfs-forensic | FILESYSTEM | 115 | 2026-06-04 | 2026-06-15 |
| sqlite-forensic | PARSER | 110 | 2026-06-10 | 2026-06-15 |
| usnjrnl-forensic | PARTITION/FS | 107 | 2026-03-02 | 2026-06-15 |
