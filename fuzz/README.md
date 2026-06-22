# issen fuzz harness

A standalone [`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
workspace targeting **issen's own untrusted-byte parsing** — the wrapper
functions that take attacker-controllable `&[u8]` and parse/interpret them with
issen-side logic. The invariant for every target is **"must not panic."**

The underlying `*-core` readers (ntfs-core, winreg-core, lnk-core, segb-core,
prefetch-core, …) are already fleet-fuzzed in their own repos, so pure
delegators (registry / biome / prefetch / lnk wrappers that merely hand bytes to
a fuzzed core and map the result onto the timeline) are **deliberately not
re-fuzzed here**.

## Targets

| Target | Entry point | What it parses |
|---|---|---|
| `usnjrnl` | `UsnRecordV2::parse` | `$UsnJrnl:$J` records — manual little-endian offset reads + bounds checks |
| `pe` | `parse_pe` | PE section slicing, Shannon entropy, ASCII/UTF-16 string extraction (over goblin) |
| `logfile` | `parse_logfile_bytes` | `$LogFile` clearing-integrity pass + LFS transaction-replay reconstruction loop |
| `mft_logfile` | `validate_logfile_from_bytes` | `$LogFile` restart-page parsing |
| `mft_mirror` | `validate_mirror_from_bytes` | `$MFT` / `$MFTMirr` first-four-entry comparison (two buffers) |
| `fish_history` | `parse_fish_history` | fish-shell history (YAML-like) — pure issen decode, no core delegation |
| `magic_table` | `identify_format` | magic-byte offset matching against the static table |
| `fuzz_pipeline` | all of the above | broadest entry: one buffer fanned across every parser |

## Running

Linux (and CI) needs **no workaround** — every target links cleanly under the
cargo-fuzz AddressSanitizer build:

```sh
cargo +nightly fuzz build
cargo +nightly fuzz run logfile -- -max_total_time=60
```

## macOS dev workaround (`-ld_classic`)

On `aarch64-apple-darwin` the four targets that link an
`inventory`-registered parser crate — `logfile`, `usnjrnl`, `pe`, and
`fuzz_pipeline` — **fail to link** under the default ASan build:

```
ld: initializer pointer has no target in '…libissen_parser_logfile-….rlib(…)'
clang: error: linker command failed with exit code 1
```

### Root cause

issen registers its parsers at compile time with `inventory::submit!` (28
registrations across the `issen-parser-*` crates; collected via
`inventory::collect!(ParserRegistration)`). `inventory` implements this by
emitting an init-pointer into the Mach-O `__mod_init_func` section. Apple's new
default linker (**ld-prime**) strictly validates those init-pointers and rejects
the ones cargo-fuzz's `-Wl,-dead_strip` + ASan/sancov instrumentation leaves
without a live target — hence *"initializer pointer has no target."* The
**classic** linker does not perform this validation and accepts them.

The `*-core` reader libraries (ntfs-core, etc.) **do not hit this** — they carry
no `inventory::submit!` registrations, so their own fuzz harnesses link fine on
macOS. This workaround is needed only because *issen* is the orchestration layer
that owns the parser registry.

### Two things to know on macOS

**1. To make the ASan build *link*, fall back to the classic linker:**

```sh
RUSTFLAGS="-Clink-arg=-Wl,-ld_classic" cargo +nightly fuzz build
```

cargo-fuzz **appends** its sancov/ASan flags to a pre-set `RUSTFLAGS` env, so the
linker flag survives. A `.cargo/config.toml [target.…] rustflags` does **not**
work here: cargo-fuzz sets the `RUSTFLAGS` *environment variable*, which takes
precedence over (and fully replaces) any config-file `rustflags`. The config is
silently ignored, so it is intentionally not shipped.

> `-ld_classic` is **deprecated by Apple** (it warns now and may be removed in a
> future toolchain). Local dev convenience only.

**2. To actually *run* on macOS, drop ASan — use `--sanitizer none`:**

```sh
cargo +nightly fuzz run logfile --sanitizer none -- -max_total_time=60
```

The `-ld_classic` ASan binary *links* but then **SEGVs at startup** (`-runs=0`,
before any input) inside libFuzzer's own banner print —
`fuzzer::Printf → vfprintf → flockfile` — with no issen code on the stack. The
cause is a second, unrelated toolchain mismatch: the classic linker links the
`libfuzzer-sys` objects (built for macOS 26.2) against min-version 11.0, and the
ASan-intercepted stdio then faults. It is **not** an issen panic. `--sanitizer
none` sidesteps both problems — it still keeps sancov coverage-guided fuzzing
(only ASan's memory-error checks are dropped, which these `forbid(unsafe)` /
panic-free crates do not need to prove the "must not panic" invariant), and it
links with the default linker (no `-ld_classic` needed).

The inventory-free targets (`mft_logfile`, `mft_mirror`, `fish_history`,
`magic_table`) build and run under full ASan on macOS with no flag at all.

> The authoritative, fully-instrumented (ASan + sancov) fuzzing path is
> **Linux / CI**, which hits none of these macOS linker problems.

## CI

`.github/workflows/fuzz.yml` builds and 45s-smoke-runs every target per matrix on
`ubuntu-latest` — no `-ld_classic`, since the Apple linker is not involved.
