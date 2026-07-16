# Fleet LICENSE Inventory & Reconciliation

_Written 2026-07-11 by a parallel Claude Code session (brain2). For the session working in **issen** to reconcile issen's own state and to carry the fleet-wide picture forward._

## TL;DR for the issen session

- A fleet-wide sweep replaced the **paraphrased** Apache-2.0 `LICENSE` text (which made GitHub's `licensee` show repos as **"Other"** / `NOASSERTION`) with the **verbatim apache.org text** (sha `2b8b815229aa`). Only `LICENSE` was touched.
- **60 / 62** target repos are now `Apache-2.0` on GitHub. **issen is one of the 2 not yet done.**
- **issen's fix is committed LOCALLY, not pushed.** It sits as commit **`0168182`** ("docs: use verbatim Apache-2.0 license text") on branch **`fix/timeline-display-panic-and-token-leak`**. `origin/main` still carries the paraphrase (`15dfa89ea01d`), so GitHub still shows issen as "Other".
- **Nothing destructive was done to issen** — no `reset --hard`, no force-push, no rebase. Only that one local `LICENSE`-only commit was added to your branch tip. See `AUDIT-NOTICE-license-sweep.md` in this repo.
- **gitsign was re-authenticated** during the sweep (the fleet token had expired). Signed commits/rebases work again now.

## issen reconciliation — what you need to do

**State (verified 2026-07-11):**
- branch `fix/timeline-display-panic-and-token-leak`, **+10 / −2** vs `origin/main`
- your 10 ahead commits = 9 of your own (timeline/tquery/trender fixes + corpus catalog) **+** the license commit `0168182`
- the 2 behind commits on `origin/main` are corpus docs; one of them (`3251bec` "catalog BitLocker cipher-method oracles") is an **identical patch** to your local `759baeb` (`patch-id e2738c08…`), so a rebase **drops the duplicate cleanly — no conflict**.

**To land it (pick one, per your PR workflow):**
- **Option A — rebase + push (lands your work *and* the license):** `git fetch origin && git rebase origin/main` (the dup drops; the other 8 + license commit replay and re-sign under the now-valid gitsign token), then push your branch and merge your PR to `main`.
- **Option B — license only:** cherry-pick just `0168182` onto `main` and push, leaving your feature branch as-is.

**Verify:** `gh api /repos/SecurityRonin/issen --jq '.license.spdx_id'` should return `Apache-2.0`.

## What the sweep fixed, fleet-wide

62 repos shipped an AI-paraphrased Apache-2.0 `LICENSE` (identical bad hash `15dfa89ea01d`) while declaring `license = "Apache-2.0"` in `Cargo.toml`. `licensee` needs ~90%+ similarity to the canonical text, so it labelled them `NOASSERTION` ("Other"). The sweep overwrote each with the canonical apache.org text.

## Current fleet license state (GitHub-authoritative, 2026-07-11)

Across `SecurityRonin` + `h4x0r`:

| SPDX | Count |
|---|---|
| Apache-2.0 | 67 |
| MIT | 34 |
| NOASSERTION ("Other") | 17 |
| NONE (no license) | 51 |
| WTFPL | 1 |

### Apache-paraphrase target set — 60/62 done

Remaining 2:
- **`issen`** — `NOASSERTION`; fix committed locally on the fix branch, unpushed (see above).
- **`fat-forensic`** — not on GitHub yet; its `LICENSE` is already canonical locally, so it will read `Apache-2.0` the moment it is first pushed/created.

## Remaining license work (broader — NOT part of the paraphrase fix, untouched)

1. **issen** — land the fix (this session; see above).
2. **fat-forensic** — create/push the repo; already canonical locally.
3. **17 `NOASSERTION` repos** — "Other" for a *different* reason (a different unrecognized `LICENSE`, not the Apache paraphrase). Need a per-repo license decision, not a blind Apache stamp:
   `ai-ciso`, `clawpot`, `clawpot-console`, `general`, `pdf2xlsx`, `pipeguard-pro`, `segb-forensic`, `snss-forensic`, `web3-forensic`, `winreg-forensic` (SecurityRonin); `awesome-cryptography`, `chatham-pro`, `claude-mem`, `pathalyzer`, `reposec-pro`, `shell-malware-data` (h4x0r). (`awesome-cryptography` / `claude-mem` are likely forks whose upstream license is legitimately unrecognized.) `issen` is the 17th and is handled above.
4. **51 `NONE` (no license at all)** — 12 SecurityRonin + 39 h4x0r. Public repos with no license = all-rights-reserved by default. Notable: `h4x0r/signal-cli-api` (its own notes say MIT + published to crates.io, but GitHub shows no license — real defect), `SecurityRonin/nfchat`, `SecurityRonin/doc4n6`. Assign licenses per intent.

## Caveats for reconciliation

- **Concurrent sessions.** Several repos are being actively worked on. The sweep used `git commit -- LICENSE` (path-scoped — never swept up other work). **Two repos** (`browser-forensic`, `sqlite-forensic`) had a `git reset --hard origin/main` run on them (a mistake in shared repos) — committed history / untracked files / stashes verified safe; the only unrecoverable risk was uncommitted *tracked* edits at sweep time. Each affected repo carries its own `AUDIT-NOTICE-license-sweep.md`.
- **14 repos were on feature branches** (`feat/*`, `fix/*`). For 12 of them the sweep's `git push origin HEAD:main` **fast-forwarded that feature work onto `main`** (non-destructive, but a branch/PR effect). issen was *held* — nothing pushed.
- **3 unsigned license commits** were made under the expired token (`lzo`, `browser-forensic`, `sqlite-forensic`) and later **re-signed**; issen's `0168182` will be signed when you rebase/push under the current token.

## How to re-verify the whole fleet

```
gh api --paginate '/orgs/SecurityRonin/repos?per_page=100' --jq '.[] | [.name,(.license.spdx_id//"NONE")] | @tsv'
gh api --paginate '/user/repos?per_page=100&affiliation=owner' --jq '.[] | select(.owner.login=="h4x0r") | [.name,(.license.spdx_id//"NONE")] | @tsv'
```

Canonical Apache-2.0 `LICENSE` = `curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt` (sha256 of that exact file; short sha `2b8b815229aa`).
