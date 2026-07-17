# cargo-vet Fleet Rollout — Copy-Paste Template

`cargo vet` is the third layer of the supply-chain triad (`renovate` = fresh,
`cargo deny` = known-bad, `cargo vet` = unreviewed code / injection — the xz-utils
layer). It is fleet law: see `~/.claude/CLAUDE.core.md` "three-layer supply-chain
triad" and `~/.claude/skills/pre-publish-gate.md` §2 "cargo vet".

This doc is the near-zero-maintenance recipe. Rolling cargo-vet to a new fleet repo
is copy-paste of the four pieces below plus one command. Reference implementation:
**blazehash** (verified green on both the local dev graph and the CI graph).

## The one-line "green it" procedure

```bash
cd <repo>
cargo vet init                       # only if supply-chain/ is absent
# 1. paste the [imports.*] block into supply-chain/config.toml (below)
# 2. paste the [policy.*] first-party block for THIS repo's own crates (below)
cargo vet regenerate imports         # fetch aggregate audit sets -> imports.lock
cargo vet regenerate exemptions      # minimize exemptions to exactly what imports miss
cargo vet fmt                        # canonicalize config.toml
cargo vet --locked                   # MUST print "Vetting Succeeded" and exit 0
```

If `cargo vet --locked` still fails, read the error — it names the exact crate and
the exact fix (usually a missing first-party policy entry). Do NOT blanket-exempt to
silence a genuine un-reviewed finding; refresh imports or add a *noted* exemption.

## 1. `[imports.*]` — the aggregate audit sets (copy verbatim)

Paste this into `supply-chain/config.toml` right after the `[cargo-vet]` table. These
four maintainer aggregates do the heavy lifting so common crates need no manual review.
All four URLs verified live (HTTP 200, real audit content) 2026-07-17.

```toml
[imports.google]
url = "https://raw.githubusercontent.com/google/rust-crate-audits/main/audits.toml"

[imports.mozilla]
url = "https://raw.githubusercontent.com/mozilla/supply-chain/main/audits.toml"

[imports.bytecode-alliance]
url = "https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/supply-chain/audits.toml"

[imports.embark]
url = "https://raw.githubusercontent.com/EmbarkStudios/rust-ecosystem/main/audits.toml"
```

Note the **mozilla** URL is `mozilla/supply-chain/main/audits.toml` — NOT
`mozilla/cargo-vet/...` (that is the cargo-vet *tool* repo's tiny self-audit, a common
mis-copy that leaves you effectively unimported).

## 2. First-party crates — `audit-as-crates-io = false`

Our own workspace members and fleet path/git deps are first-party. When their local
version matches a published crates.io version, vet demands a policy entry or fails with:

```
× Some non-crates.io-fetched packages match published crates.io versions
    <crate>:<version>
  help: Add a `policy.*.audit-as-crates-io` entry for them
```

Declare every such crate first-party (do NOT audit it as a crates.io package):

```toml
[policy.<your-app-or-lib>]
audit-as-crates-io = false

[policy.<your-core-crate>]
audit-as-crates-io = false
```

Example (blazehash):

```toml
[policy.blazehash]
audit-as-crates-io = false

[policy.blazehash-core]
audit-as-crates-io = false

[policy.ewf]           # SecurityRonin fleet crate, dev-patched to a local checkout
audit-as-crates-io = false
```

`false` = "this is our first-party code, don't audit as crates.io." `true` = "this is
primarily *derived third-party* code, audit it as the crates.io package" — use `true`
only for a genuine locally-modified fork of someone else's crate, which is rare in the
fleet.

## 2b. The fleet gotcha — a gitignored `[patch.crates-io]` for a sibling fleet crate

Many fleet repos carry a gitignored `.cargo/config.toml` that patches a sibling fleet
crate to a local checkout for dev, e.g.:

```toml
# .cargo/config.toml (gitignored)
[patch.crates-io]
ewf = { path = "../ewf/ewf" }
```

This creates two different dependency graphs, and the committed config must green in
**both**:

- **Local (patch on):** the fleet crate resolves as a *path* source → first-party.
  Covered by `[policy.<crate>] audit-as-crates-io = false`.
- **CI (patch absent — the file is gitignored):** the fleet crate resolves from
  *crates.io* → an auditable dependency. Covered by an `[[exemptions.<crate>]]` entry
  (our own published crate; `cargo vet regenerate exemptions` adds it automatically when
  run with the patch disabled).

Keep **both** the `[policy]` entry and the exemption — each is inert in the other graph,
neither errors as "unused."

**Committed `Cargo.lock` must be CI-consistent.** If the lock was last regenerated with
the patch active, the fleet crate's lock entry has *no `source` line* (path-sourced) and
CI's `cargo vet --locked` fails (`cargo metadata` can't satisfy the missing path). Fix
it with a surgical 2-line delta — disable the patch, run `cargo metadata` (no `--locked`)
so cargo adds only the crates.io `source` + `checksum` to that one entry, then re-enable
the patch WITHOUT running the resolver again:

```bash
sed -i '' 's|^<crate> = { path|# <crate> = { path|' .cargo/config.toml   # disable patch
cargo metadata --format-version=1 >/dev/null                            # +2 lines: source+checksum
git diff --numstat Cargo.lock                                          # verify blast radius == 2
# re-enable the patch in .cargo/config.toml; do NOT run cargo again before committing
```

## 3. CI `vet` job (copy into `ci.yml` as a separate job)

```yaml
  vet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-sha> # vX.Y.Z
      - uses: dtolnay/rust-toolchain@<full-sha> # stable
      - name: Install cargo-vet
        uses: taiki-e/install-action@<full-sha>
        with:
          tool: cargo-vet
      - name: Fetch dependencies
        run: cargo fetch
      - name: Check supply chain
        run: cargo vet --locked
```

- Use `cargo vet --locked` (fails on a stale lock/config rather than silently
  re-resolving). `cargo install cargo-vet` is the alternative to the `taiki-e/install-action`
  step if a repo prefers a plain install.
- **No `continue-on-error: true`.** cargo-vet is a real gate. A vet that is allowed to
  fail is CI noise, and a mis-maintained (perpetually-red) vet is worse than none —
  either keep the imports current or remove the job, never leave it half-configured.
- Third-party actions pinned to full commit SHAs per the CI standard.

## 4. What "low-maintenance" means here

- Imports carry the common ecosystem; exemptions cover only the remainder. On blazehash
  the imports fully audit ~172 crates and the exemption list is the minimized residue.
- When a dep bump makes vet red from a *stale import set*, run
  `cargo vet regenerate imports` (refresh) then `cargo vet regenerate exemptions`
  (re-minimize) — never hand-hack the exemption list, never blanket-exempt a genuine
  un-reviewed version.
- Renovate keeps deps fresh; a fresh dep whose new version isn't yet in any aggregate
  lands as a fresh exemption on the next `regenerate` — expected, low-touch churn.

## Rollout status

- [x] **blazehash** — reference implementation (imports + first-party policy for
  blazehash/blazehash-core/ewf + CI-consistent lock + `cargo vet --locked` job).
- [ ] Remaining ~40 fleet repos — copy §1 + §2 (+ §2b where a sibling patch exists),
  run the §"green it" procedure, adopt the §3 job.
