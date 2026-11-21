# Local account discovery and privacy requests

## Scope

A single-user Windows 11 desktop app will use Python 3.12 and PySide6 to find evidence of services the owner signed up for, help the owner review those findings, and prepare and track personal data requests. It will scan the owner’s selected mailboxes and explicit local CSV exports. The scan summary will show the sources and dates covered, skipped items, and partial scans. Accounts outside those sources or without recognizable evidence can remain undiscovered.

Read [AGENTS.md](../../../AGENTS.md) for the rules governing development and app behavior. See the [implementation plan](../plans/2026-11-20-account-discovery.md) for milestone exits and the proposed file tree.

## Architecture choices

- **Proposed desktop architecture.** A PySide6 Widgets process owns the UI and delegates scanning, importing, and delivery to cancellable workers. A single storage service serializes database writes. Plain Python modules handle normalization, scoring, templates, and tracking, so their tests can run without a Qt display.
- **Mail discovery tradeoff.** Broad provider search can reduce API calls, but search features differ between providers and can require wider access. The proposed path uses header-only reads, processing provider pages locally. IMAP can optionally narrow candidates with server-side subject search when the owner has approved that scan. There is no browser scraping or direct access to browser or vault databases.
- **Installer choice.** Proposed target is Windows 11 x64, with a PyInstaller directory build bundled into one Inno Setup installer. This ships the Python runtime, Qt plugins, and the SQLCipher native library together and avoids extracting the runtime on every launch. Milestone 2 checks the Python 3.12 SQLCipher binding on Windows before the schema depends on it.

## Local data and consent

Use an app-specific folder under the current user’s `%LOCALAPPDATA%` for the SQLCipher database and any app-managed files. Generate a random database key and store it with provider OAuth tokens in Windows Credential Manager, using Windows-protected storage under the current user. Store tokens only there when persisted, with reusable tokens kept out of provider debug logging, settings, and database rows. IMAP and SMTP passwords, when needed, are entered for the session and held in memory. OAuth uses the system browser, a public desktop client, loopback callback, and PKCE. Validate OAuth state, pin standard provider endpoints, and require TLS for mail connections. Verify the account identity after authorization and stop on a mismatch.

Initialize SQLCipher before touching the schema, require a working cipher, use in-memory SQL temporary storage, and let no packaged build fall back to plaintext SQLite. Persist account addresses, sanitized service URLs and usernames, service and confidence data, opaque message or thread identifiers when needed, and minimal workflow state. Never persist raw headers, mail subjects or bodies, imported passwords, generated letters, tokens outside Credential Manager, or full provider error bodies. Operational feedback uses redacted error codes and counts. Use fake secrets in tests to check persistence, temporary files, and diagnostics.

Every initial or resumed scan starts with a consent screen listing the selected sources, account identity, scan range, and the outbound connections involved. Local imports also require consent and an explicit file choice. A remote scan approval covers the displayed provider calls and refreshes for that scan session. OAuth connection, each approved send or send batch, reply checks, and portal launch have their own approvals. Closing or cancelling ends session permission. Updates are user-initiated local file imports. The app has no telemetry, remote fonts, tracking pixels, or cloud backend. Provider and portal access is the direct network activity the owner authorizes.

The confirmed **Wipe all app data** action cancels jobs, closes open files and database connections, deletes app-owned data and database sidecars, and removes all matching Credential Manager entries. Report any partial failure and allow a retry. Wipe does not reach user-owned input files, exports saved outside the app data directory, or copies held by mail providers. Use generic toast text. For portal handoff, use Windows clipboard formats that exclude app-provided text from clipboard history and cloud sync, and clear it after a timeout if it is still the app’s clipboard item.

## Data model and discovery

| Data | Purpose |
| --- | --- |
| `accounts` | Local account ID, verified address, provider, and credential reference |
| `services`, `service_accounts` | Canonical domain and per-account username, normalized URL, and review state |
| `evidence` | Service-account record, source and evidence category, relevant timestamp, and stable item ID for deduplication |
| `scan_runs`, `scan_checkpoints` | Account, scan parameters, progress, and provider-specific cursor |
| `requests`, `request_events` | Request kind, jurisdiction, template version, destination, send state, message or thread correlation, dates, and timeline events |

Normalize URLs and sender domains using IDNA and a bundled Public Suffix List including private suffixes. Store a normalized origin for imported URLs so paths, userinfo, queries, and fragments cannot persist embedded secrets. Reject malformed hosts and non-web URLs. Use the registrable domain for deduplication and a local alias map for documented brand relationships. Preserve separate accounts within a shared service and prevent multi-tenant hosts and shared delivery domains from merging unrelated services. Treat ambiguous sender and unsubscribe domains as review candidates rather than assuming service ownership.

Confidence scores are deterministic and explainable. Start with import evidence at 80 points, explicit welcome or verification at 70, password reset at 45, receipt at 35, and unsubscribe-only at 15. Use the strongest category plus 10 per additional distinct category, capped at 100. Repeated messages in one category add zero. Use high (80–100), medium (45–79), and low (0–44) bands, with ambiguous attribution capped at 44 pending review. Keep the user’s review decision across rescans. A score never authorizes a send.

| Source | Read and resume strategy |
| --- | --- |
| Gmail OAuth | Use the Gmail metadata scope, page message IDs and fetch selected headers. The metadata scope does not support Gmail’s `q` parameter, so classify subjects locally. Use a committed history watermark for incremental scans, scoped to mailbox and scan selection. Recover expired page tokens or history by starting a deduplicated rescan. |
| Outlook / Microsoft Graph OAuth | Start with delegated `Mail.ReadBasic` and select message IDs, conversation IDs, dates, sender, subject, and available internet headers. Page with validated provider continuation URLs. Verify header availability and the minimum usable scope in a separately approved live check. Explain any required permission increase before requesting it. |
| Generic IMAP | Use read-only folder selection, bounded UID windows and non-seen-changing header fetches. Bind checkpoints to folder and UIDVALIDITY and capture an upper UID for the scan. A UIDVALIDITY change triggers reconciliation and rescan of the affected folder. |
| CSV | Stream rows from owner-selected exports of Chrome, Edge, Firefox, Brave, Bitwarden, 1Password, and KeePass. Use format-specific header mappings and immediately drop all fields except sanitized URL and username. Require an owner-confirmed account association where it cannot be inferred safely. Identify resumable imports by file fingerprint and committed row number. Restart with deduplication if the file changes. |

Classify welcome, verification, password reset, receipt, and List-Unsubscribe signals using only the selected headers. Treat those headers as untrusted, and never follow URLs found in mail. Process bounded batches, atomically commit evidence and the matching cursor, and keep multiple account scans independent. Retry transient reads with bounded backoff and provider retry guidance. Cancelling or replaying a page preserves committed evidence and keeps the scan resumable. Show totals when known and progress counts otherwise.

## Requests and tracking

Bundle a versioned JSON privacy contact catalog with provenance and reviewed dates, destination kind, and explicitly mapped service aliases. Updatable local JSON is validated before it replaces the active catalog. Validate recipient syntax and permit only HTTPS destinations for portals. Allow a user-verified contact when the catalog lacks coverage. A mail-derived address or URL never automatically becomes the request destination.

Provide separate access templates for GDPR Article 15, UK GDPR, and California CCPA, prefilled with the owner’s name and the selected account email. Show the exact sender, recipient, subject, and body for approval. Keep edits ephemeral and invalidate approval whenever the preview changes. If the owner selects multiple services, show all recipients and their individual previews before sending one request per service and account. Use the selected account’s Gmail send scope, Graph `Mail.Send`, or configured SMTP. Separate read and send permission where providers support it. Use a persisted per-account limit and a pending-send record. If the provider might have accepted a send, mark it uncertain and reconcile with Sent before any retry. Never automatically resend an uncertain submission.

For portal-only services, copy approved text and open the verified site in the default browser after explicit owner action. The owner completes sign-in, CAPTCHA, identity checks, and submission. Record portal submission only when the owner confirms it. Deletion uses a different template and a separate, explicit confirmation. Follow-ups go through the same preview and approval flow.

Record sent date and show the requested 30-day countdown alongside the estimated jurisdiction-specific deadline. Calculate GDPR and UK GDPR estimates using one calendar month and California access estimates using 45 days by default. Label deadlines as estimates and support an explicitly recorded adjusted deadline. Verify the rules against current regulator guidance before release. Detect replies on approved mailbox checks using provider thread or conversation IDs and `In-Reply-To` or `References` message IDs. Correlate thread and participants, exclude self-sent copies, and flag ambiguous matches for review. Track receipt of a reply and let the owner mark a request fulfilled. Native Windows toasts run locally while the app is running and surface overdue items on the next launch.

## Desktop workflow

The dashboard shows coverage, discovered services, requests, and approaching deadlines. The table filters by source, account, confidence, review state, or request status, with bulk review and request preparation. Service details show evidence categories, associated accounts, destination, and request timeline. Support a system theme or explicit light or dark selection. CSV and PDF exports contain the selected inventory and tracking fields, are saved to a user-selected path, and exclude credentials and mail content. Protect CSV text fields from execution as formulas in spreadsheet software. Reports saved outside the app data directory remain with the owner.

## Verification boundaries

Use synthetic fixtures and fake protocol transports for ordinary tests. Generate 100,000-plus metadata rows on demand for pagination and memory checks. On Windows, verify genuine SQLCipher, wrong-key rejection, Credential Manager, wipe, native toasts, and the packaged app on a clean x64 machine. The final offline acceptance test launches the installed app, runs the consented mock scan, compares the resulting inventory with the fixture manifest, and generates and previews an access request. Live mailbox checks, external downloads and sending real requests require specific approval.
