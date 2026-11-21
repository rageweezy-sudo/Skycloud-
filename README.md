# Skycloud-
Privacy simplified

# Account Privacy

Account Privacy is a Windows 11 x64 desktop app for discovering services from your own mail and local CSV exports. It prepares access requests under GDPR Article 15, UK GDPR, or the California CCPA. You approve each send or portal handoff. Requests for deletion have a separate confirmation.

## Test the workflow locally

1. Open Account Privacy and select **Scan mock fixtures**. Approve the synthetic scan.
2. The Services table should show four entries. Search for `example.org`, select it, and choose **Prepare access request**.
3. Choose **GDPR**. The preview should include the demo name, `demo@example.test`, a synthetic contact, and Article 15. Demo previews cannot send.
4. Clear the filter to see the full fixture inventory.

| Service | Confidence |
| --- | ---: |
| `alice.github.io` | 70 |
| `example.com` | 15 |
| `example.net` | 45 |
| `example.org` | 80 |

## Connect your own mail

Add the email address you own and select the correct provider. Use **Connect email** to configure and authorize Gmail or Microsoft. Read and send permissions are connected separately. On the provider sign-in page, select the same email address you entered in the app. If the identities differ, the app stops the connection. Tokens remain in Windows Credential Manager.

### Google

1. In Google Cloud Console, choose a project, enable Gmail API, and configure the OAuth consent screen. If the application has testing access, add your own Google account as a test user.
2. Create an OAuth client with application type **Desktop app**. In Account Privacy enter its client ID and desktop client secret.
3. Connect **Read mail metadata** for discovery and reply checks. Connect **Send approved requests** only when you want to send. Gmail uses the `gmail.metadata` and `gmail.send` scopes, respectively. The send connection also verifies your Google email identity using OpenID Connect.
4. Google may restrict access or token lifetime for testing and restricted scopes. Reconnect if the provider expires a grant. Follow Google’s verification process if your project requires public distribution.

### Microsoft

1. In Microsoft Entra, register an application for the account types you will use. Include personal Microsoft accounts if your address is an Outlook.com or other personal Microsoft account.
2. Add a **Mobile and desktop applications** redirect URI of `http://localhost/oauth/callback`. The desktop app uses a loopback port assigned by Windows. Use the application client ID. A client secret is unnecessary.
3. Configure delegated Microsoft Graph permissions `User.Read`, `Mail.ReadBasic`, and optionally `Mail.Send`. Microsoft or an organization’s administrator may require consent.
4. Connect separate read and send permissions in the app. The provider’s live header behavior and permissions still need to be verified on the intended account type before release.

### IMAP and SMTP

For generic IMAP, enter your provider’s TLS server, port, folder, and session password when starting an approved scan. Use your provider’s app password if required. Sending uses your configured SMTP endpoint with implicit TLS or STARTTLS on port 587. The app holds the password only for that operation.

## Import files and use the inventory

Export a CSV from Chrome, Edge, Firefox, Brave, Bitwarden, 1Password, or KeePass. Enter its local path and choose the export format. Approve the import and confirm that all entries are yours. The app retains only the normalized web origin and username from each entry. The original export may contain passwords. Store or remove that file using your normal password-export handling.

Scan coverage shows which selected sources were processed. Missing mail, unsupported exports, unrecognized subjects, and accounts with no visible sign-up evidence can leave gaps. Review low-confidence entries and confirm the service and destination before sending.

The bundled catalog is a small starter list. For other services, enter a privacy mailbox or HTTPS portal you verified. **Import contact catalog** accepts a newer local JSON file in the bundled format. Each entry contains its canonical `domain`, `kind` (`email` or `portal`), `destination`, and `source`. The catalog can also supply explicit domain aliases.

## Local data and outbound approval

- Your Windows user owns the SQLCipher database under `%LOCALAPPDATA%\AccountPrivacy`. Windows Credential Manager protects the encryption key and persistent OAuth tokens. The app fails closed when SQLCipher or the credential vault is unavailable.
- The app never logs or stores passwords or email bodies. It reads selected header metadata, does not follow mail links, and keeps request text in memory. It has no telemetry or cloud backend.
- OAuth, mailbox scans and reply checks, outgoing requests, and portal launches each require explicit approval. Approved email and portal operations communicate directly with the named providers or service. Portal sign-in, submission, CAPTCHA, and identity checks are manual.
- **Wipe all app data** removes app-managed files and saved credentials after confirmation. Manually remove any copies you exported outside the app data directory. The wipe cannot remove mailbox or portal copies.
- The deadline estimate depends on the selected jurisdiction and the sent date. Use the separate 30-day countdown for tracking, and adjust the estimated deadline if the applicable date changes.

This software and its letter templates are not legal advice. Applicability, response deadlines, and verification requirements can vary.

## Build a single Windows installer

Use an x64 Windows 11 machine with Python 3.12 and Inno Setup 6 installed. Install the project and development dependencies from your approved package source or a local wheelhouse. Use a Python 3.12 x64 `sqlcipher3` build linked against SQLCipher. A local installation can use `pip --no-index --find-links` with a wheelhouse that contains the project and its dependencies.

From a PowerShell prompt with the build environment already prepared, run:

```powershell
.\packaging\build.ps1 -Python python
```

The script verifies the SQLCipher binding, runs the app tests, stages the bundled Python and Qt runtime, and produces `dist\AccountPrivacy-Setup-x64.exe`. Pass `-InnoCompiler` if your compiler is in a different location. The script does not download dependencies.

Before distributing the installer, install it on clean Windows 11 x64 and run the fixture workflow. Also verify a restart preserves the inventory, a wrong key cannot open the database, the native toast appears, and a confirmed wipe removes the app's files and Credential Manager entries. Use synthetic data for this acceptance check. Obtain separate approval before any live mailbox or delivery checks.

## Development tests

With pytest installed, run `python -m pytest -q`. The ordinary suite uses synthetic data and test doubles. The encryption, Credential Manager, and Qt tests run when their respective runtime capabilities are present. In a workspace without pytest, run the same unittest-based cases with `PYTHONPATH=src python -B -m unittest discover -s tests -v` from a POSIX shell.
