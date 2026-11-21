# Project rules

- All processing is local. No telemetry or cloud backend. Ask the owner before any step that sends data off this machine. During development, obtain approval before live provider calls, downloads or uploads, and any external transmission. In the app, obtain explicit approval for the specific outbound action and disclose the destination and data involved.
- Show a consent screen before any scan. Scan only accounts the owner confirms are theirs, and apply the same rule to imported account data.
- Store persistent tokens and the SQLCipher database key in Windows Credential Manager under the current Windows user, using Windows-protected credential storage (DPAPI). Encrypt the local database with SQLCipher and fail closed if encryption is unavailable. Never log passwords, tokens, or email bodies, and never persist passwords or email bodies. Keep outbound letter text and any transient email content in memory only. Discard imported passwords immediately.
- Include a confirmed **Wipe all app data** button that removes app-managed data, credentials, and database sidecars. Wiping is local. Any action involving a remote provider needs its own approval.
- Do not automate CAPTCHAs or identity checks.

## Milestone workflow

1. Write this file first, document the architecture and proposed file tree, run local checks, summarize, and stop for the owner's review.
2. Build the encrypted schema, domain normalization and deduplication, and confidence scoring with unit tests.
3. Add discovery sources, importers, consent, and resumable scanning with synthetic fixtures.
4. Add privacy contacts, jurisdiction templates, preview and approval, delivery, and separately confirmed deletion.
5. Add request tracking, deadlines, reply detection, follow-ups, and Windows toasts.
6. Add the dashboard, filterable table, bulk actions, details and timeline, dark mode, and CSV and PDF reporting.
7. Build a single Windows installer and document setup, security, and legal limitations.

After each milestone, run its checks and the existing test suite, fix failures, and summarize the result before moving on. Keep normal tests offline and use synthetic fixtures. Use Python 3.12 and PySide6 for the Windows app.
