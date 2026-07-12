# `issen-disk` test fixtures

Per-file provenance for committed test data used by `issen-disk` integration
tests. The fleet-wide machine index is
[`issen/docs/corpus-catalog.md`](../../../../docs/corpus-catalog.md); this README
is the co-located human detail — cross-reference, never duplicate.

The repo-root `.gitignore` ignores `tests/data/`, so small, clearly-licensed
fixtures here are committed with `git add -f`. Large evidence archives are never
committed (they stay gitignored and are documented, not stored).

#### ext4-minimal.img

- **Source / Identity:** copied verbatim from the `ext4fs-forensic` repo's
  `tests/data/minimal.img` (its own reference fixture). A self-minted 4 MiB bare
  **ext4** filesystem (`extents`, `metadata_csum`, `64bit`, `extra_isize`;
  4096-byte blocks; label `test-ext4`). It is a bare filesystem image — no
  partition table (no MBR signature at 510; ext magic `0x53 0xEF` at byte 1080).
  Contains `/hello.txt` ("Hello, ext4!", inode 12) and `/subdir/nested.txt`
  ("Nested file"). No journal.
- **MD5:** `966b3e52d95cb84679a973f43fd3702e`
- **Size:** 4194304 bytes (4 MiB)
- **Generator (verbatim, in the upstream repo):**
  `ext4fs-forensic/tests/create-minimal-image.sh` — requires Linux + root:

  ```sh
  dd if=/dev/zero of=minimal.img bs=1M count=4
  mkfs.ext4 -F -b 4096 -O extents,metadata_csum,64bit,extra_isize -L "test-ext4" minimal.img
  # mount -o loop, write hello.txt + subdir/nested.txt, umount
  ```

- **Used by:** `tests/nonntfs_triage.rs` — drives `collect_ext4` end-to-end
  (open the bare ext4 volume, read `/hello.txt` + `/subdir/nested.txt`),
  proving non-NTFS triage collection works against a real e2fsprogs image.
- **License / redistribution:** self-minted by the Apache-2.0 `ext4fs-forensic`
  build; repo-internal, no third-party rights. **Self-minted `mkfs.ext4` image
  — NOT a real-world forensic image** (format-level parsing is grounded in real
  e2fsprogs output; there is no independent recovery ground truth).
