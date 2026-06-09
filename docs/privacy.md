# Privacy Policy

*Last updated: 2026-04-19*

## Summary

Issen is a local command-line tool. It does not collect, transmit, or store any personal data on remote servers.

## Google Drive Integration

When you ingest from a `gdrive://` source, Issen resolves Google credentials from a token cached **locally** at `~/.config/issen/gdrive_token.json` on your machine. That token grants the `drive.readonly` scope — read-only access to files you explicitly identify by URL or file ID.

No token or credential is ever sent to Security Ronin Ltd or any third party other than Google.

## Data Access

- Issen requests only the `drive.readonly` scope.
- It reads only the specific file(s) you supply on the command line.
- It does not index, list, or enumerate your Google Drive.
- File contents are processed in memory and written to your local manifest — nothing is uploaded.

## Telemetry

Issen has **no telemetry**. It makes no network requests except those you initiate:
- OAuth token exchange with `oauth2.googleapis.com` when refreshing Google Drive credentials
- File content download from `googleapis.com` when ingesting a `gdrive://` source
- Threat-intel feed downloads when you run `issen feed update` or `issen pivot sync`
- Remote evidence fetches from the URI you pass to `issen ingest --source` (S3, GCS, SFTP, …)

## Open Source

Issen is open source (Apache-2.0). You can audit every network call at [github.com/SecurityRonin/issen](https://github.com/SecurityRonin/issen).

## Contact

Privacy questions: [security@securityronin.com](mailto:security@securityronin.com)

---

[Terms of Service](terms.md) · [Home](index.md) · © 2026 Security Ronin Ltd
