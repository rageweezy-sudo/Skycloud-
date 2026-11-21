# Account Discovery and Privacy Requests Implementation Plan

**Goal** — Deliver a local Windows desktop app that discovers services from the owner’s mail and CSV exports and helps draft, send, and track approved personal data requests.

**Architecture** — PySide6 owns the desktop interface. Cancellable workers handle bounded mailbox and file reads, while pure Python rules derive service evidence and render requests. SQLCipher stores local application state and Windows Credential Manager stores credentials.

**Tech stack** — Python 3.12, PySide6 Widgets, SQLCipher, Windows Credential Manager, pytest, PyInstaller, and Inno Setup.

**Spec** — [Architecture and design](../specs/2026-11-20-account-discovery-design.md)

## Global constraints

Follow [AGENTS.md](../../../AGENTS.md). Obtain approval before any development step that sends data off the machine. Keep development fixtures synthetic. Use test doubles for network operations and prevent network access during ordinary test runs. Run milestone-specific checks and the full suite, resolve failures, and summarize before moving on. Milestone 1 ends at the review stop requested by the owner.

## Review focus

| Failure mode | Required check |
| --- | --- |
| Cipher missing or database key wrong | Milestone 2 verifies the database fails closed and leaves no plaintext database. |
| Shared sender or private-suffix host | Milestone 2 verifies separate tenants stay separate and ambiguous attribution remains low confidence. |
| A page replays after a crash or cursor expiry | Milestone 3 verifies full, interrupted, and restarted scans produce the same evidence and inventory. |
| Provider accepts a send but the response gets lost | Milestone 4 verifies the attempt stays uncertain and is never resent automatically. |
| A reply shares a conversation with an unrelated request | Milestone 5 verifies matching uses request identifiers and participants, and routes ambiguity to owner review. |

## Proposed file tree

Milestone 1 created the rules and the two planning documents. The tree maps the implemented package and tests.

```text
AGENTS.md
docs/
  superpowers/
    specs/2026-11-20-account-discovery-design.md
    plans/2026-11-20-account-discovery.md
pyproject.toml
README.md
src/
  account_privacy/
    __init__.py
    __main__.py                    Windows app entry point and composition
    core/
      models.py                    Account, service, evidence, and request records
      local_files.py               Local path validation
      wipe.py                      App data removal
      domains.py                   URL normalization and service attribution
      scoring.py                   Evidence scores and review bands
      storage.py                   SQLCipher repository and atomic checkpoints
      migrations/                 Versioned SQL schema
      credentials.py               Windows Credential Manager integration
    discovery/
      scan.py                      Consent, cancellation, paging, and progress
      evidence.py                  Mail header classification
      oauth.py                     Desktop OAuth and account verification
      http.py                      Approved HTTPS transport and read retries
      demo.py                      Built-in synthetic mailbox
      gmail.py                     Gmail metadata adapter
      graph.py                     Microsoft Graph metadata adapter
      imap.py                      Generic IMAP metadata adapter
      csv_import.py                CSV mappings and streaming parser
    requests/
      contacts.py                  Catalog validation and destination lookup
      templates.py                 Access, follow-up, and deletion rendering
      delivery.py                  Approval, limits, send state, and portal handoff
      transports.py               Gmail, Graph, and SMTP mail submission
      tracking.py                 Deadlines and reply correlation
    ui/
      main_window.py               Dashboard, inventory table, and bulk selection
      service_detail.py            Evidence and timeline
      dialogs.py                   Consent, preview, account setup, and wipe
      export.py                    Local CSV and PDF reports
      windows.py                   Native clipboard safeguards and local toasts
    resources/
      public_suffix_list.dat       Bundled Public Suffix List
      privacy_contacts.json        Catalog and documented domain aliases
      mock_headers.json            Built-in synthetic mailbox data
      templates/                  Jurisdiction-specific letter text
tests/
  fixtures/                        Mock headers, sample CSVs, expected inventory
  test_domains.py
  test_scoring.py
  test_storage.py
  test_discovery.py
  test_csv_import.py
  test_requests.py
  test_tracking.py
  test_ui.py
  test_end_to_end.py
  test_oauth.py
  test_providers.py
  test_wipe.py
packaging/
  account_privacy.spec             PyInstaller entry point and runtime data
  installer.iss                    Inno Setup installer and launcher identity
  build.ps1                        Reproducible Windows build command
```

## Milestone 1 — Rules and architecture

- [x] Write `AGENTS.md` before creating any other project file.
- [x] Write the design covering consent, local storage, provider and export boundaries, usage flows, and verification.
- [x] Write the proposed file tree and staged implementation plan.
- [x] Run local documentation checks for milestone coverage, policy requirements, relative links, and the proposed file tree. Six offline checks passed. Stop for review.

## Milestone 2 — Encrypted core

- [ ] Establish the package and test harness. Verify the selected SQLCipher binding can encrypt, reopen, and reject a wrong key under Windows x64 Python 3.12. Verify a cipherless build fails closed. Any dependency acquisition requires prior approval.
- [ ] Define `Account`, `Service`, `ServiceAccount`, and `Evidence` records in `core/models.py`. Implement vault and repository interfaces plus initial schema migrations with uniqueness scoped to service, account, and stable evidence ID. Test repeated imports, transaction rollback, migrations, and vault failures.
- [ ] Implement `normalize_origin(url)` and `registrable_domain(host)` in `core/domains.py`. Test scheme validation, IDNA, private suffixes, stripping sensitive URL components, tenant separation, and documented aliases.
- [ ] Implement `score_evidence(categories, ambiguous)` in `core/scoring.py`. Test score boundaries, order independence, repeated-category suppression, ambiguous attribution, and retained user review decisions.
- [ ] Run `python -m pytest -q` and record the Windows encryption results.

## Milestone 3 — Discovery and imports

- [ ] Implement the consent screen and operation-scoped authorization. Test denial, cancellation, owner-account verification, and separation between account authorizations without live network.
- [ ] Implement paged `HeaderSource` adapters for Gmail, Microsoft Graph, and generic IMAP. Each adapter emits `HeaderPage` records with bounded metadata items and an opaque continuation. Test OAuth PKCE and state with test doubles, approved refresh, TLS requirements, and provider-specific invalid checkpoints.
- [ ] Implement header classification for welcome, verify, reset, receipt, and List-Unsubscribe. Commit evidence and checkpoint in one transaction. Use synthetic fixtures for multiple emails, at least 100,001 items, interrupted scans, replay, and cursor recovery. Verify results against a fixture inventory and assert request and header buffers remain bounded.
- [ ] Implement URL and username imports for Chrome, Edge, Firefox, Brave, Bitwarden, 1Password, and KeePass CSV formats. Test each with synthetic passwords, format variants, malformed and quoted rows, cancellation, and changed-file recovery. Assert passwords and sensitive URL components never reach repositories or diagnostics.
- [ ] Run `python -m pytest -q`. Run separately approved provider checks for permission and header behavior when available, with the live results recorded separately from the mock suite.

## Milestone 4 — Requests and delivery

- [ ] Add a bundled versioned privacy contact JSON catalog and local update path. Test provenance fields, invalid updates, alias lookup, address validation, and HTTPS-only portals.
- [ ] Render jurisdiction-specific access and deletion templates with the owner’s name and account email. Test exact preview contents, approval invalidation on edit, separate deletion confirmation, and one approved destination per service-account request.
- [ ] Implement Gmail, Graph, and SMTP submission behind the approved preview. Test consent before all outbound calls, rate limits across restarts, safe failure handling, and an accepted send with a lost response. Mark the latter uncertain and require Sent reconciliation or owner review before any retry.
- [ ] Test portal previews, approved default-browser launch, and Windows clipboard handling. Verify app-provided text is marked to exclude clipboard history and cloud sync and that submission requires owner confirmation. Implement the confirmed local wipe and test cleanup of the database, sidecars, and credentials, including partial failures.
- [ ] Run `python -m pytest -q` using mock delivery only unless a specific live test is approved.

## Milestone 5 — Tracking and reminders

- [ ] Implement sent date and estimated deadlines, 30-day countdown, and recorded deadline adjustments. Test month ends, leap years, local date boundaries, California timing, and alternate deadline display.
- [ ] Implement approved mailbox reply checks. Test Gmail threads, Graph conversations, and RFC message-ID matching, including self copies, duplicates, participant mismatches, and unrelated messages in the same conversation. Keep only minimal tracking metadata.
- [ ] Add follow-up templates, timeline states, and local Windows toast reminders while the app is open. Verify overdue items surface at next launch and toast text does not contain personal data.
- [ ] Run `python -m pytest -q` and check a native toast on Windows.

## Milestone 6 — Desktop UI and reports

- [ ] Add dashboard, filterable service table, bulk actions, detail page, request timeline, and light, dark, and system theme modes. Test account separation, filter combinations, selection, and that bulk actions still invoke the applicable consent or approval dialog.
- [ ] Add explicit local CSV and PDF exports. Test report fields, spreadsheet formula protection, paginated PDF output, and omission of mail and credentials. Treat remote file paths as outbound destinations requiring separate approval.
- [ ] Exercise the UI with PySide6 and synthetic data. Run `python -m pytest -q`, including an offline mock discovery-to-preview smoke test.

## Milestone 7 — Installer and acceptance

- [ ] Build a single per-user Windows x64 installer with the bundled Python runtime, Qt plugins, resources, and SQLCipher native library. Keep uninstall and the in-app wipe separate so the owner can choose when to delete data.
- [ ] Write the README with Google and Microsoft OAuth desktop-client setup, local-only security design, consent and wipe behavior, supported exports, and the “not legal advice” disclaimer. Verify jurisdiction estimates and catalog source provenance with approval for any external lookup.
- [ ] Run `python -m pytest -q`. On a clean Windows x64 machine, install the app from the single installer, launch it, run a consented scan of synthetic fixtures, compare the exact service list with the expected fixture manifest, and generate and preview a filled-in access request. Verify encrypted persistence, restart, native reminders, and wipe in the installed build. Record actual results and any live-provider checks pending approval.


## Implementation and verification status

| Milestone | Verified in this workspace | Pending |
| --- | --- | --- |
| 2 | Schema migrations and transactions, evidence deduplication, scoring, PSL and IDNA handling, and fail-closed behavior for an absent cipher | Windows SQLCipher round-trip and Credential Manager |
| 3 | Consent binding, a resumable 100,001-item scan, all seven CSV formats, and fake OAuth, Gmail, Graph, and IMAP transports | Native consent dialog and separately approved live-provider checks |
| 4 | Access and deletion previews, separate approvals, portal and delivery test doubles, rate limits, uncertain submissions, and local wipe tests | Windows clipboard and Credential Manager wipe, plus any separately approved live send |
| 5 | Calendar estimates, the 30-day countdown, request timeline and reply matching tests | Native Windows toast |
| 6 | GUI wiring and source syntax, CSV export and the headless fixture-to-preview workflow | PySide6 window and PDF runtime checks |
| 7 | Offline Python wheel and bundled resources, Windows build recipe, and setup guide | Build the installer and complete the clean Windows acceptance run |

The final offline run executed 43 cases using the Python 3.12 standard-library test runner with socket connections blocked. Forty passed. Three were skipped because SQLCipher, Windows Credential Manager, and PySide6 were unavailable. The mock fixture inventory matched all four services and their confidence scores.
