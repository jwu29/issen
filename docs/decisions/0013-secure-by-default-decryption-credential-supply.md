# 0013. Secure-by-default credential supply for encrypted volumes (BitLocker / FileVault / LUKS)

- Status: Proposed
- Date: 2026-07
- Deciders: SecurityRonin

## Context

The fleet is growing a CRYPTO layer — a transform between CONTAINER and
FILESYSTEM that turns an encrypted sector stream plus a credential into a
plaintext sector stream, so the filesystem parsers can navigate inside encrypted
evidence. The first decryptors are standalone Pattern-A crates: `bitlocker-core`
(BitLocker/FVE), `filevault-core` (macOS CoreStorage FileVault 2), and LUKS
(reusing `luks-rs`). Each is validated byte-for-byte against its reference tool
(libbde / libfvde / cryptsetup).

To *use* any of them, `issen` must accept a decryption credential and hand it to
the volume. That raises a design question the moment it touches the CLI, and the
naive answer is dangerous.

Three forces shape the decision:

1. **Secrets on a command line leak.** An inline `--password hunter2` (or a
   48-digit recovery key as an argument) is visible in `ps`, the shell history
   file, and `/proc/<pid>/cmdline` to every local user. For a tool whose whole job
   is handling other people's evidence keys, that is disqualifying — a
   secure-by-design failure, not a documentation footnote.

2. **Credential shapes are heterogeneous, but the UX must not be.** BitLocker
   accepts a recovery password (eight groups of six digits), a user password, or a
   `.BEK` startup key; FileVault accepts a password or a personal recovery key;
   LUKS accepts a passphrase or a keyfile. A separate flag per format per
   credential type would be a thicket. The format is detectable from the volume,
   so the surface can stay uniform.

3. **Real cases have many encrypted volumes, and the evidence chain matters.** An
   examiner rarely has one disk; they have several, each with its own recovery key
   pulled from AD/MBAM. And the report must record *how* a volume was unlocked —
   which protector, whose key — without ever recording the secret itself.

## Decision

**One credential model in the crypto layer; several safe supply mechanisms in
issen; no inline secrets, ever.**

At the `forensic-vfs` `CryptoDecoder` boundary, a single `secrecy`-wrapped,
zeroize-on-drop credential type:

```rust
enum Credential {
    Password(SecretString),
    RecoveryKey(SecretString),
    KeyFile(PathBuf),
    StartupKey(PathBuf),   // BitLocker .BEK
}
```

`issen-cli` populates it — the value is **never** an inline argument:

| Mechanism | Intended use | Surface |
|---|---|---|
| Interactive no-echo prompt (**default**) | a human at a terminal; an encrypted volume is found → prompt | zero-config |
| Key file | scriptable; a native LUKS keyfile, or a file holding the passphrase/recovery key | `--key-file <path>` |
| **Key manifest** | the real case — several encrypted volumes, each with its own key | `--keys <manifest.toml>` |
| Environment variable | CI / automation | `--key-env <VAR>` |
| Inventory-only (**default when no key, non-interactive**) | record the volume + protectors, do not unlock | — |

The manifest is the load-bearing mechanism for real work: it maps a volume
identifier to a credential source, so one ingest of N encrypted disks needs no
interactive babysitting.

```toml
[[volume]]
match = "bitlocker:<fve-guid>"   # or a partition path / byte offset
recovery = "111111-222222-…"     # or password = "…" / key_file = "…"

[[volume]]
match = "luks:sdb2"
key_file = "/case/keys/sdb2.key"
```

Two behaviours are part of the decision, not add-ons:

- **Unlocking is opt-in enrichment, never a gate.** An encrypted volume with no
  supplied credential does not abort ingest. The `-forensic` analyzers already
  inventory protector types, cipher method, and clear-key-present as findings, so
  the zero-key path yields *"BitLocker volume present; protectors: recovery + TPM;
  AES-XTS"* — degrade-to-inventory, in the spirit of ADR-0008 (fail loud on a
  broken *bootstrap*, degrade gracefully on a per-artifact miss). A supplied key
  that fails to unlock is a loud error naming the volume; a volume simply left
  locked is a normal finding.

- **Provenance is recorded; the secret is not.** The report captures which
  protector unlocked the volume and the credential *source* (e.g.
  "examiner-supplied manifest"), never the key material. Secrets live only in
  `SecretString` and are zeroized on drop.

## Consequences

- The zero-knowledge path is safe: a user who supplies nothing gets an inventory,
  and a user who is prompted never puts a secret on the command line. Insecure use
  would require deliberate effort, and there is no inline-secret flag to reach for.
- One uniform credential surface covers all three formats and every credential
  type; adding a fourth format later reuses it.
- The manifest scales to real multi-disk cases and keeps automation off the
  interactive path.
- Costs: a manifest schema and a no-echo tty prompt to implement and test; the
  `CryptoDecoder` seam in `forensic-vfs` (the same integration point that carries
  the VSS `Snapshot` wiring) must exist before this surface has anything to supply
  a key *to*. This ADR is therefore **Proposed** — the design is locked; it is
  realised when the crypto layer is wired into the VFS.
- Rejected alternatives: an inline `--password <value>` flag (leaks via
  `ps`/history/`/proc` — rejected on security grounds); a separate unlock
  subcommand or per-format flags (fragments the UX the tool exists to unify —
  rejected in favour of the uniform credential model).
