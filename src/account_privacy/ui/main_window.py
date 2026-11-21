import json
import webbrowser
from datetime import UTC, date, datetime, time
from pathlib import Path
from uuid import uuid4

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
)

from account_privacy.core.credentials import CredentialError
from account_privacy.core.local_files import local_path
from account_privacy.core.models import Account, Provider, ReviewState
from account_privacy.core.storage import StorageError
from account_privacy.core.wipe import WipeError, wipe_app_data
from account_privacy.discovery.csv_import import CSVDiscovery, ExportFormat
from account_privacy.discovery.demo import ACCOUNT as DEMO_ACCOUNT, SELECTION as DEMO_SELECTION, DemoHeaders
from account_privacy.discovery.gmail import GmailHeaders
from account_privacy.discovery.graph import GraphHeaders
from account_privacy.discovery.imap import IMAPHeaders, IMAPSettings
from account_privacy.discovery.oauth import CLIENTS, ClientSettings, OAuthSession, connect_destinations
from account_privacy.discovery.scan import ApprovalError, DiscoveryError, HeaderDiscovery, run_scan
from account_privacy.requests.contacts import Catalog, Contact, ContactError, ContactKind, mail_address
from account_privacy.requests.delivery import Delivery, DeliveryError
from account_privacy.requests.templates import Jurisdiction, RequestKind, make_draft
from account_privacy.requests.tracking import check_replies, deadline, notify_due
from account_privacy.requests.transports import OAuthMail, SMTPMail, SMTPSettings

from .dialogs import confirm_operation, form_values, preview_request
from .export import COLUMNS, export_csv, export_pdf, report_rows
from .service_detail import show_service, show_text
from .windows import clear_private_text, copy_private_text, show_reminder


class Worker(QThread):
    progress = Signal(str)

    def __init__(self, action, parent):
        super().__init__(parent)
        self.action = action
        self.result = None
        self.error = None

    def run(self):
        try:
            self.result = self.action(self.progress.emit)
        except (ApprovalError, DiscoveryError, StorageError, DeliveryError, CredentialError) as error:
            self.error = str(error)
        except Exception:
            self.error = "The operation could not be completed."


def button(text, action):
    item = QPushButton(text)
    item.clicked.connect(action)
    return item


def table(headers):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
    widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    widget.setAlternatingRowColors(True)
    widget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    widget.verticalHeader().setVisible(False)
    return widget


def fill_table(widget, rows):
    widget.setRowCount(len(rows))
    for row_index, row in enumerate(rows):
        for column, value in enumerate(row):
            widget.setItem(row_index, column, QTableWidgetItem(str(value)))


class MainWindow(QMainWindow):
    def __init__(self, storage, vault, data_directory):
        super().__init__()
        self.storage = storage
        self.vault = vault
        self.data_directory = data_directory
        self.delivery = Delivery(storage)
        self.catalog = Catalog.from_json(storage.preference("contact_catalog")) if storage.preference("contact_catalog") else Catalog.bundled()
        self._job = None
        self._approval = None
        self._after_job = None
        self._closing = False
        self._storage_closed = False
        self._clipboard_sequence = None
        self._original_palette = self.palette()
        self._shown = []
        self._requests = []
        self._accounts = []
        self.setWindowTitle("Account Privacy")
        self.resize(1200, 760)
        content = QWidget()
        self.setCentralWidget(content)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(12)
        title = QLabel("Account Privacy")
        title.setStyleSheet("font-size: 27px; font-weight: 600;")
        layout.addWidget(title)
        self.dashboard = QLabel()
        self.dashboard.setTextFormat(Qt.TextFormat.PlainText)
        self.dashboard.setWordWrap(True)
        layout.addWidget(self.dashboard)

        account_bar = QHBoxLayout()
        account_bar.addWidget(QLabel("Account"))
        self.account = QComboBox()
        account_bar.addWidget(self.account, 1)
        account_bar.addWidget(button("Add account", self.add_account))
        account_bar.addWidget(button("Connect email", self.connect_email))
        account_bar.addWidget(button("Scan mailbox", self.scan_mail))
        account_bar.addWidget(button("Import CSV", self.import_csv))
        account_bar.addWidget(button("Scan mock fixtures", self.scan_demo))
        account_bar.addWidget(button("Scan coverage", self.scan_coverage))
        layout.addLayout(account_bar)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        inventory = QWidget()
        self.tabs.addTab(inventory, "Services")
        inventory_layout = QVBoxLayout(inventory)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by service, account or username")
        self.search.textChanged.connect(self.apply_filters)
        filters.addWidget(self.search, 2)
        self.confidence = QComboBox()
        self.confidence.addItems(("All confidence levels", "high", "medium", "low"))
        self.confidence.currentIndexChanged.connect(self.apply_filters)
        filters.addWidget(self.confidence)
        self.review_filter = QComboBox()
        self.review_filter.addItems(("All review states", *(state.value for state in ReviewState)))
        self.review_filter.currentIndexChanged.connect(self.apply_filters)
        filters.addWidget(self.review_filter)
        self.status_filter = QComboBox()
        self.status_filter.addItems(("All request states", "No request", "sent", "reply", "fulfilled", "portal_pending", "uncertain", "failed", "pending"))
        self.status_filter.currentIndexChanged.connect(self.apply_filters)
        filters.addWidget(self.status_filter)
        self.account_filter = QComboBox()
        self.account_filter.currentIndexChanged.connect(self.apply_filters)
        filters.addWidget(self.account_filter)
        self.source_filter = QComboBox()
        self.source_filter.currentIndexChanged.connect(self.apply_filters)
        filters.addWidget(self.source_filter)
        inventory_layout.addLayout(filters)
        self.services = table(COLUMNS)
        self.services.doubleClicked.connect(self.service_details)
        inventory_layout.addWidget(self.services, 1)
        actions = QHBoxLayout()
        actions.addWidget(button("Service detail", self.service_details))
        actions.addWidget(button("Confirm selected", lambda: self.review_selected(ReviewState.CONFIRMED)))
        actions.addWidget(button("Dismiss selected", lambda: self.review_selected(ReviewState.DISMISSED)))
        actions.addWidget(button("Prepare access request", lambda: self.prepare_selected(RequestKind.ACCESS)))
        actions.addWidget(button("Request deletion…", lambda: self.prepare_selected(RequestKind.DELETE)))
        actions.addStretch()
        actions.addWidget(button("Export CSV", lambda: self.export_report(False)))
        actions.addWidget(button("Export PDF", lambda: self.export_report(True)))
        inventory_layout.addLayout(actions)

        requests = QWidget()
        self.tabs.addTab(requests, "Requests")
        requests_layout = QVBoxLayout(requests)
        self.requests = table(("Service", "Request", "Jurisdiction", "Status", "Sent", "30-day countdown", "Estimated deadline"))
        self.requests.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.requests.doubleClicked.connect(self.request_timeline)
        requests_layout.addWidget(self.requests, 1)
        request_tools = QHBoxLayout()
        request_tools.addWidget(button("Check mailbox replies", self.check_mail))
        request_tools.addWidget(button("Timeline", self.request_timeline))
        request_tools.addWidget(button("Follow up", self.follow_up))
        request_tools.addWidget(button("Record sent", self.mark_sent))
        request_tools.addWidget(button("Record not sent", self.mark_not_sent))
        request_tools.addWidget(button("Record fulfilled", self.mark_fulfilled))
        request_tools.addWidget(button("Adjust deadline", self.adjust_deadline))
        request_tools.addStretch()
        requests_layout.addLayout(request_tools)

        footer = QHBoxLayout()
        self.theme = QComboBox()
        self.theme.addItems(("System theme", "Light", "Dark"))
        theme_name = self.storage.preference("theme", "System theme")
        self.theme.setCurrentText(theme_name)
        self.theme.currentTextChanged.connect(self.set_theme)
        footer.addWidget(self.theme)
        footer.addWidget(button("Import contact catalog", self.import_contacts))
        self.wipe_button = button("Wipe all app data", self.wipe)
        footer.addWidget(self.wipe_button)
        footer.addStretch()
        self.cancel = button("Cancel current operation", self.cancel_job)
        self.cancel.setEnabled(False)
        self.statusBar().addPermanentWidget(self.cancel)
        layout.addLayout(footer)
        self.set_theme(theme_name)
        self.refresh()
        self.reminders = QTimer(self)
        self.reminders.timeout.connect(self.remind)
        self.reminders.start(15 * 60_000)
        QTimer.singleShot(1000, self.remind)

    def set_theme(self, theme):
        self.storage.set_preference("theme", theme)
        if theme == "System theme":
            self.setPalette(self._original_palette)
            return
        dark = theme == "Dark"
        palette = QPalette()
        colors = {
            QPalette.ColorRole.Window: ("#f3f5f8", "#161b23"),
            QPalette.ColorRole.Base: ("#ffffff", "#202836"),
            QPalette.ColorRole.AlternateBase: ("#eef3f8", "#252f3e"),
            QPalette.ColorRole.WindowText: ("#152132", "#f0f4fa"),
            QPalette.ColorRole.Text: ("#152132", "#f0f4fa"),
            QPalette.ColorRole.Button: ("#e5edf4", "#293647"),
            QPalette.ColorRole.ButtonText: ("#152132", "#f0f4fa"),
            QPalette.ColorRole.Highlight: ("#135cb2", "#467dc8"),
            QPalette.ColorRole.HighlightedText: ("#ffffff", "#ffffff"),
        }
        for role, pair in colors.items():
            palette.setColor(role, QColor(pair[dark]))
        self.setPalette(palette)

    def refresh(self):
        current = self.account.currentData()
        filtered = self.account_filter.currentData()
        self._accounts = self.storage.list_accounts()
        self._inventory = self.storage.inventory()
        self._requests = self.storage.list_requests()
        for combo in (self.account, self.account_filter):
            combo.blockSignals(True)
            combo.clear()
            if combo == self.account_filter:
                combo.addItem("All accounts", None)
            for account in self._accounts:
                label = "Mock fixtures" if account.id == DEMO_ACCOUNT.id else f"{account.email} · {account.provider}"
                combo.addItem(label, account.id)
            index = combo.findData(current if combo == self.account else filtered)
            if index >= 0:
                combo.setCurrentIndex(index)
            combo.blockSignals(False)
        source = self.source_filter.currentData()
        self.source_filter.blockSignals(True)
        self.source_filter.clear()
        self.source_filter.addItem("All sources", None)
        for name in sorted({source for entry in self._inventory for source in entry.sources}):
            self.source_filter.addItem(name, name)
        index = self.source_filter.findData(source)
        if index >= 0:
            self.source_filter.setCurrentIndex(index)
        self.source_filter.blockSignals(False)
        ready = sum(entry.service_account.review == ReviewState.CONFIRMED for entry in self._inventory)
        active = [record for record in self._requests if record.state in ("sent", "reply") and record.kind != "follow_up"]
        near = sum(deadline(record, date.today()).estimated_days_remaining <= 3 for record in active if record.sent_at)
        coverage = self.storage.preference("scan_summary", "No completed scans")
        self.dashboard.setText(f"{len(self._inventory)} service accounts  ·  {ready} confirmed  ·  {len(active)} active requests  ·  {near} due soon or overdue\n{coverage}")
        self.apply_filters()
        rows = []
        for request in self._requests:
            estimate = deadline(request, date.today())
            rows.append((
                request.service_account.service.domain, request.kind.replace("_", " "), request.jurisdiction,
                request.state, request.sent_at.astimezone().date() if request.sent_at else "",
                f"{estimate.thirty_days_remaining} days" if estimate else "", estimate.estimated_due if estimate else "",
            ))
        fill_table(self.requests, rows)

    def apply_filters(self, *_):
        if not hasattr(self, "_inventory"):
            return
        accounts = {account.id: account.email for account in self._accounts}
        query = self.search.text().casefold()
        selected_account = self.account_filter.currentData()
        source = self.source_filter.currentData()
        confidence = self.confidence.currentText() if self.confidence.currentIndex() else None
        review = self.review_filter.currentText() if self.review_filter.currentIndex() else None
        state = self.status_filter.currentText() if self.status_filter.currentIndex() else None
        entries = [
            entry for entry in self._inventory
            if (not selected_account or entry.service_account.account_id == selected_account)
            and (not source or source in entry.sources)
            and (not confidence or entry.confidence.band == confidence)
            and (not review or entry.service_account.review == review)
        ]
        rows = report_rows(entries, accounts, self._requests)
        selected = [
            (entry, row) for entry, row in zip(entries, rows)
            if (not state or state == (row[5] or "No request"))
            and (not query or query in " ".join(row[:3]).casefold())
        ]
        self._shown = [entry for entry, _ in selected]
        fill_table(self.services, [row for _, row in selected])

    def alert(self, message):
        box = QMessageBox(self)
        box.setWindowTitle("Account Privacy")
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(message)
        box.exec()
        box.deleteLater()

    def ask(self, title, text):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(text)
        box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(QMessageBox.StandardButton.Cancel)
        accepted = box.exec() == QMessageBox.StandardButton.Yes
        box.deleteLater()
        return accepted

    def selected_account(self):
        account_id = self.account.currentData()
        for account in self._accounts:
            if account.id == account_id:
                return account
        self.alert("Add and select an account first.")
        return None

    def add_account(self):
        provider, ok = QInputDialog.getItem(self, "Add account", "Source", list(Provider), 0, False)
        if not ok:
            return
        value = form_values(self, "Add your account", [("Email address", "", False)])
        if value is None:
            return
        try:
            email = mail_address(value[0].strip())
        except ContactError as error:
            self.alert(str(error))
            return
        if not self.ask("Confirm ownership", f"Confirm that {email} is your own account."):
            return
        provider = Provider(provider)
        existing = next((account for account in self._accounts if account.provider == provider and account.email.casefold() == email.casefold()), None)
        account = existing or Account(uuid4().hex, email, provider)
        if existing is None:
            self.storage.save_account(account)
        self.refresh()
        self.account.setCurrentIndex(self.account.findData(account.id))

    def oauth_session(self, account, scope, *, setup=False):
        name = f"client/{account.provider}/id"
        key = f"client/{account.provider}/secret"
        client_id = self.storage.preference(name)
        secret = self.vault.read(key)
        if setup and not client_id:
            fields = [("Desktop OAuth client ID", "", False)]
            if account.provider == Provider.GMAIL:
                fields.append(("Google desktop client secret", "", True))
            values = form_values(self, "Desktop OAuth setup", fields)
            if values is None:
                return None
            client_id = values[0].strip()
            if not client_id or not client_id.isascii() or any(char.isspace() for char in client_id):
                self.alert("Enter the desktop OAuth client ID.")
                return None
            if len(values) > 1 and values[1].strip():
                secret = values[1].strip().encode()
                self.vault.write(key, secret)
            self.storage.set_preference(name, client_id)
        if not client_id:
            self.alert("Select Connect email to configure OAuth first.")
            return None
        return OAuthSession(account, ClientSettings(client_id, secret.decode() if secret else None), self.vault, scope)

    def connect_email(self):
        account = self.selected_account()
        if not account:
            return
        if account.provider not in CLIENTS:
            self.alert("IMAP and SMTP ask for credentials when you start an approved operation.")
            return
        role, ok = QInputDialog.getItem(self, "Email permission", "Choose permission", ["Read mail metadata", "Send approved requests"], 0, False)
        if not ok:
            return
        spec = CLIENTS[account.provider]
        scope = spec.read_scope if role == "Read mail metadata" else spec.send_scope
        try:
            session = self.oauth_session(account, scope, setup=True)
        except CredentialError as error:
            self.alert(str(error))
            return
        if session is None:
            return
        approval = confirm_operation(
            self, title="Connect your email", summary=f"Open the provider’s sign-in page for {account.email}. "
            f"The app will send your email as a sign-in hint, exchange the authorization code, and verify the signed-in address.\n\nPermission: {role}",
            action="Open sign-in", operation="connect", account_id=account.id, source=account.provider, selection=scope,
            destinations=connect_destinations(account.provider, scope), confirm_owner=True,
        )
        if approval:
            self.begin_job(approval, "Waiting for email authorization…", lambda _: session.connect(approval), lambda _: self.statusBar().showMessage("Email permission connected."))

    def header_source(self, account, *, replies=False):
        if account.provider in CLIENTS:
            spec = CLIENTS[account.provider]
            session = self.oauth_session(account, spec.read_scope)
            if session is None:
                return None
            selection = "all-mail"
            watermark = None
            if account.provider == Provider.GMAIL and not replies:
                previous = self.storage.latest_scan(account.id, account.provider, selection, complete=True)
                if previous and previous.cursor:
                    kind, watermark = json.loads(previous.cursor)
                    if kind != "watermark":
                        watermark = None
            source = GmailHeaders(session, watermark) if account.provider == Provider.GMAIL else GraphHeaders(session, check_sent=replies)
            return source, selection, spec.scan_destinations
        if account.provider == Provider.IMAP:
            values = form_values(self, "IMAP mailbox", [
                ("Server", self.storage.preference(f"imap/{account.id}/host"), False),
                ("TLS port", "993", False), ("Folder", "INBOX", False), ("Session password", "", True),
            ])
            if values is None:
                return None
            host, port, folder, password = values
            settings = IMAPSettings(host.strip(), int(port), folder.strip())
            if not password:
                raise ValueError("Enter the session password.")
            self.storage.set_preference(f"imap/{account.id}/host", settings.host)
            return IMAPHeaders(account.email, settings, password), settings.selection, (settings.destination,)
        self.alert("Choose an email provider to scan a mailbox.")
        return None

    def scan_mail(self):
        self.perform_mail_operation(False)

    def check_mail(self):
        self.perform_mail_operation(True)

    def perform_mail_operation(self, replies):
        account = self.selected_account()
        if not account:
            return
        try:
            configured = self.header_source(account, replies=replies)
        except (ValueError, CredentialError):
            self.alert("Check the provider settings and credential access.")
            return
        if configured is None:
            return
        source, selection, destinations = configured
        operation = "replies" if replies else "scan"
        title = "Check mailbox replies" if replies else "Consent to mailbox scan"
        summary = f"Read header metadata from your {account.provider} account {account.email} and process it on this device. The app may use the listed endpoints to authenticate and read pages. No message bodies are fetched."
        if account.provider == Provider.IMAP:
            summary += f"\nFolder: {source.settings.folder}"
        else:
            summary += "\nScope: all available mail, with incremental Gmail scans after the first run."
        approval = confirm_operation(
            self, title=title, summary=summary, action="Check replies" if replies else "Start scan",
            operation=operation, account_id=account.id, source=account.provider, selection=selection,
            destinations=destinations, confirm_owner=True,
        )
        if not approval:
            return
        if replies:
            self.begin_job(approval, "Checking replies…", lambda _: check_replies(self.storage, account, source, approval, selection),
                           lambda count: self.statusBar().showMessage(f"Recorded {count} new replies."))
        else:
            self.start_scan(HeaderDiscovery(account, account.provider, selection, source, self.catalog.aliases), approval)

    def import_csv(self):
        account = self.selected_account()
        if not account:
            return
        if account.id == DEMO_ACCOUNT.id:
            self.alert("Select your own account to import a real CSV.")
            return
        kind, ok = QInputDialog.getItem(self, "Import CSV", "Export format", list(ExportFormat), 0, False)
        if not ok:
            return
        file, ok = QInputDialog.getText(self, "Local CSV", "Path to the CSV file on this device")
        if not ok or not file.strip():
            return
        path = Path(file.strip().strip('"'))
        source = CSVDiscovery(account, path, ExportFormat(kind), aliases=self.catalog.aliases)
        approval = confirm_operation(
            self, title="Consent to local import",
            summary=f"Scan {path.name} from {kind} and associate its URL and username rows with {account.email}. "
            "Confirm that every entry in the selected export is from your own account data.",
            action="Import CSV", operation="scan", account_id=account.id, source=source.name,
            selection=source.selection, confirm_owner=True,
        )
        if approval:
            self.start_scan(source, approval)

    def scan_demo(self):
        approval = confirm_operation(
            self, title="Scan mock fixtures", summary="Run the built-in synthetic mailbox on this device. It contains seven invented messages and does not contact an email provider.",
            action="Scan fixtures", operation="scan", account_id=DEMO_ACCOUNT.id, source="demo", selection=DEMO_SELECTION,
        )
        if not approval:
            return
        self.storage.save_account(DEMO_ACCOUNT)
        self.start_scan(HeaderDiscovery(DEMO_ACCOUNT, "demo", DEMO_SELECTION, DemoHeaders()), approval)

    def start_scan(self, source, approval):
        previous = self.storage.latest_scan(source.account.id, source.name, source.selection, complete=False)
        def run(progress):
            return run_scan(
                self.storage, source, approval, previous.id if previous else None,
                progress=lambda run: progress(f"{source.name} · {run.processed:,} items checked"),
            )
        def finished(run):
            status = "Complete" if run.complete else "Paused"
            label = f"{status} · {source.name} · {source.account.email} · {run.processed:,} items checked"
            self.storage.set_preference("scan_summary", label)
            self.statusBar().showMessage(label)
        self.begin_job(approval, "Scanning…", run, finished)

    def scan_coverage(self):
        addresses = {account.id: account.email for account in self._accounts}
        labels = [
            f"{addresses.get(run.account_id, 'Unknown')} · {run.source} · "
            f"{run.processed:,} items checked · {'Complete' if run.complete else 'Partial'}"
            for run in self.storage.scan_history()
        ]
        show_text(self, "Scan coverage", "\n".join(labels) if labels else "No scans have been run.")

    def begin_job(self, approval, description, action, after):
        if self._job is not None:
            approval.close()
            return
        self._approval = approval
        self._after_job = after
        self._job = Worker(action, self)
        self._job.progress.connect(self.statusBar().showMessage)
        self._job.finished.connect(self.finish_job)
        self.centralWidget().setEnabled(False)
        self.cancel.setEnabled(True)
        self.statusBar().showMessage(description)
        self._job.start()

    def cancel_job(self):
        if self._approval:
            self._approval.close()
            self.cancel.setEnabled(False)
            self.statusBar().showMessage("Cancelling after the current provider operation…")

    def finish_job(self):
        worker = self._job
        self._job = None
        self._approval.close()
        self._approval = None
        self.cancel.setEnabled(False)
        self.centralWidget().setEnabled(True)
        if worker.error and not self._closing:
            self.alert(worker.error)
        elif not worker.error:
            self._after_job(worker.result)
        self._after_job = None
        worker.deleteLater()
        self.refresh()
        if self._closing:
            self.close()

    def selected_services(self):
        return [self._shown[index.row()] for index in self.services.selectionModel().selectedRows()]

    def service_details(self, *_):
        entries = self.selected_services()
        if entries:
            show_service(self, self.storage, entries[0])

    def review_selected(self, review):
        for entry in self.selected_services():
            self.storage.set_review(entry.service_account, review)
        self.refresh()

    def prepare_selected(self, kind):
        selected = self.selected_services()
        if not selected:
            self.alert("Select at least one service.")
            return
        if kind == RequestKind.DELETE and len(selected) != 1:
            self.alert("Select one service for a deletion request.")
            return
        mode = len(selected) > 1
        for entry in selected:
            account = next(account for account in self._accounts if account.id == entry.service_account.account_id)
            self.prepare(account, entry.service_account, kind, preview_only=mode)

    def prepare(self, account, service, kind, *, parent=None, preview_only=False):
        demo = account.id == DEMO_ACCOUNT.id
        contact = None
        if parent:
            contact = Contact(service.service.domain, ContactKind(parent.destination_kind), parent.destination, "Original request")
        elif demo:
            contact = Contact(service.service.domain, ContactKind.EMAIL, "privacy@example.org", "Synthetic fixture")
        else:
            contact = self.catalog.contacts.get(service.service.domain)
        if contact is None:
            inputs = form_values(self, "Add a verified privacy contact", [
                ("Email address or HTTPS portal", "", False),
                ("Where you verified this contact", "", False),
            ])
            if inputs is None:
                return
            target, source = (value.strip() for value in inputs)
            try:
                contact = Contact(service.service.domain, ContactKind.PORTAL if target.startswith("https://") else ContactKind.EMAIL, target, source)
            except ContactError as error:
                self.alert(str(error))
                return
        jurisdiction = parent.jurisdiction if parent else None
        if jurisdiction is None:
            jurisdiction, ok = QInputDialog.getItem(self, "Request jurisdiction", "Applicable law", list(Jurisdiction), 0, False)
            if not ok:
                return
        starting_name = "Demo Owner" if demo else self.storage.preference("owner_name")
        provided = form_values(self, "Request details", [("Your name", starting_name, False)])
        if provided is None:
            return
        try:
            draft = make_draft(
                account, service, contact, provided[0], Jurisdiction(jurisdiction), kind,
                sent_date=parent.sent_at.astimezone().date() if parent else None,
                parent_id=parent.id if parent else None, reply_message_id=parent.message_id if parent else None,
                follow_up_deletion=bool(parent and parent.kind == "delete"),
            )
        except ValueError as error:
            self.alert(str(error))
            return
        if not demo:
            self.storage.set_preference("owner_name", provided[0].strip())
        approved_draft = preview_request(self, draft, demo=demo or preview_only)
        if approved_draft:
            self.deliver(approved_draft)

    def deliver(self, draft):
        is_portal = draft.contact.kind == ContactKind.PORTAL
        account = draft.account
        if is_portal:
            operation = "portal"
            targets = (draft.contact.origin,)
            description = "Copy your approved request to the clipboard and open the privacy portal. You submit it yourself."
            transport = None
        else:
            operation = "send"
            description = f"Send this exact request from {account.email} to {draft.contact.destination}. Your mail provider will receive the sender, recipient, subject and request text."
            try:
                if account.provider in CLIENTS:
                    provider = CLIENTS[account.provider]
                    session = self.oauth_session(account, provider.send_scope)
                    if session is None:
                        return
                    transport, targets = OAuthMail(session), provider.scan_destinations
                else:
                    values = form_values(self, "SMTP delivery", [
                        ("Server", self.storage.preference(f"smtp/{account.id}/host"), False),
                        ("TLS port (465 or 587)", "465", False), ("Session password", "", True),
                    ])
                    if values is None:
                        return
                    host, port, password = values
                    settings = SMTPSettings(host.strip(), int(port), starttls=int(port) == 587)
                    if not password:
                        raise ValueError
                    transport, targets = SMTPMail(settings, password), (settings.destination,)
                    self.storage.set_preference(f"smtp/{account.id}/host", settings.host)
            except (ValueError, CredentialError):
                self.alert("Check the mail settings and credential access.")
                return
        approval = confirm_operation(
            self, title="Approve portal handoff" if is_portal else "Approve sending",
            summary=description, action="Open portal" if is_portal else "Send request",
            operation=operation, account_id=account.id, source=account.provider, selection=draft.digest, destinations=targets,
        )
        if not approval:
            return
        deletion = None
        if draft.kind == RequestKind.DELETE:
            deletion = confirm_operation(
                self, title="Confirm deletion request",
                summary=f"This asks {draft.service_account.service.domain} to delete eligible personal data. You may lose access to the service or account history.",
                action="Confirm deletion request", operation="delete", account_id=account.id, source=account.provider, selection=draft.digest,
            )
            if not deletion:
                approval.close()
                return
        if is_portal:
            try:
                self.delivery.portal(draft, approval, webbrowser.open, self.copy_request, deletion=deletion)
                self.statusBar().showMessage("Portal opened. Use Record sent after submitting your request.")
                self.refresh()
            except (ValueError, DeliveryError, ApprovalError) as error:
                self.clear_clipboard()
                self.alert(str(error))
        else:
            self.begin_job(
                approval, "Sending approved request…",
                lambda _: self.delivery.send(draft, approval, transport, deletion=deletion),
                lambda record: self.statusBar().showMessage(f"Submission status: {record.state}"),
            )

    def copy_request(self, text):
        self._clipboard_sequence = copy_private_text(text, int(self.winId()))
        sequence = self._clipboard_sequence
        QTimer.singleShot(120_000, lambda: self.clear_clipboard() if sequence == self._clipboard_sequence else None)

    def clear_clipboard(self):
        if self._clipboard_sequence is not None:
            clear_private_text(self._clipboard_sequence, int(self.winId()))
            self._clipboard_sequence = None

    def selected_request(self):
        selected = self.requests.selectionModel().selectedRows()
        if selected:
            return self._requests[selected[0].row()]
        self.alert("Select a request first.")
        return None

    def request_timeline(self, *_):
        request = self.selected_request()
        if not request:
            return
        events = sorted(self.storage.request_events(request.id), key=lambda event: event.timestamp)
        lines = [f"{event.timestamp.astimezone():%Y-%m-%d %H:%M}  {event.kind.replace('_', ' ')}" for event in events]
        show_text(self, f"{request.service_account.service.domain} request timeline", "\n".join(lines))

    def mark_sent(self):
        request = self.selected_request()
        if request is None:
            return
        if request.state not in ("portal_pending", "uncertain", "pending"):
            self.alert("This request already has a submission result.")
            return
        today = date.today()
        value, ok = QInputDialog.getText(
            self, "Record verified submission",
            "Enter the date you submitted this request or verified its sent copy (YYYY-MM-DD)",
            text=today.isoformat(),
        )
        if not ok:
            return
        try:
            sent_day = date.fromisoformat(value.strip())
            if sent_day > today:
                raise ValueError
        except ValueError:
            self.alert("Enter a submission date of today or earlier.")
            return
        sent_at = datetime.combine(sent_day, time(12)).astimezone(UTC)
        if request.state == "portal_pending":
            self.delivery.confirm_portal_submission(request.id, sent_at)
        else:
            self.storage.finish_request(request.id, request.state, "sent", sent_at)
        self.refresh()

    def mark_fulfilled(self):
        request = self.selected_request()
        if request is None:
            return
        if request.state not in ("sent", "reply"):
            self.alert("Select a sent request or one that has a reply.")
            return
        self.storage.finish_request(request.id, request.state, "fulfilled", datetime.now(UTC))
        self.refresh()

    def mark_not_sent(self):
        request = self.selected_request()
        if request is None:
            return
        if request.state not in ("portal_pending", "uncertain", "pending"):
            self.alert("Select an unresolved submission.")
            return
        if not self.ask("Resolve submission", "Confirm that you checked your Sent folder or portal and verified the request was never submitted."):
            return
        self.storage.finish_request(request.id, request.state, "failed", datetime.now(UTC))
        self.refresh()

    def adjust_deadline(self):
        request = self.selected_request()
        if request is None:
            return
        if request.sent_at is None:
            self.alert("Select a sent request.")
            return
        value, ok = QInputDialog.getText(self, "Adjust estimated deadline", "New deadline (YYYY-MM-DD)")
        if not ok:
            return
        try:
            due = date.fromisoformat(value.strip())
            self.storage.adjust_request_deadline(request.id, due, datetime.now(UTC))
            self.refresh()
        except ValueError:
            self.alert("Enter a date in YYYY-MM-DD format.")

    def follow_up(self):
        request = self.selected_request()
        if request is None:
            return
        if request.state not in ("sent", "reply") or request.kind == "follow_up":
            self.alert("Select an active original request.")
            return
        account = next(account for account in self._accounts if account.id == request.service_account.account_id)
        self.prepare(account, request.service_account, RequestKind.FOLLOW_UP, parent=request)

    def export_report(self, pdf):
        extension = "pdf" if pdf else "csv"
        filename, ok = QInputDialog.getText(self, f"Export {extension.upper()}", "New file path on this device")
        if not ok or not filename.strip():
            return
        try:
            raw = Path(filename.strip().strip('"'))
            path = local_path(raw if raw.suffix.casefold() == "." + extension else raw.with_suffix("." + extension))
            if path.exists() and not self.ask("Replace report", "Replace the existing file at this path?"):
                return
            entries = self.selected_services() or self._shown
            rows = report_rows(entries, {account.id: account.email for account in self._accounts}, self._requests)
            (export_pdf if pdf else export_csv)(path, rows)
            self.statusBar().showMessage(f"Exported {len(rows)} rows.")
        except (OSError, ValueError):
            self.alert("Choose a writable path on a local drive.")

    def import_contacts(self):
        filename, ok = QInputDialog.getText(self, "Update contact catalog", "Path to a local privacy contacts JSON file")
        if not ok or not filename.strip():
            return
        try:
            path = local_path(Path(filename.strip().strip('"')))
            with path.open("rb") as input_file:
                raw = input_file.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ContactError("The catalog is too large")
            content = raw.decode("utf-8-sig")
            catalog = Catalog.from_json(content)
            if catalog.version <= self.catalog.version:
                raise ContactError("Use a newer catalog version")
        except (OSError, ValueError):
            self.alert("Choose a valid, newer contacts catalog on a local drive.")
            return
        if self.ask("Replace contact catalog", f"Replace the active catalog with version {catalog.version} ({len(catalog.contacts)} contacts)?"):
            self.storage.set_preference("contact_catalog", content)
            self.catalog = catalog
            self.statusBar().showMessage("Contact catalog updated.")

    def remind(self):
        if not self._storage_closed:
            notify_due(self.storage, show_reminder)

    def wipe(self):
        if not self.ask("Wipe all app data", "Permanently remove the app’s local inventory, requests, settings and saved credentials from this Windows user account?"):
            return
        self.clear_clipboard()
        self.storage.close()
        self._storage_closed = True
        try:
            wipe_app_data(self.data_directory, self.vault)
        except (WipeError, ValueError) as error:
            self.alert(str(error))
            for widget in self.centralWidget().findChildren(QWidget):
                if isinstance(widget, (QPushButton, QComboBox, QLineEdit, QTabWidget)):
                    widget.setEnabled(widget is self.wipe_button)
            return
        self.close()

    def closeEvent(self, event):
        if self._job is not None:
            self._closing = True
            self.cancel_job()
            event.ignore()
            return
        self.clear_clipboard()
        self.storage.close()
        self._storage_closed = True
        super().closeEvent(event)
