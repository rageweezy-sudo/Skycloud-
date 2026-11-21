from datetime import date

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout

from account_privacy.requests.tracking import deadline


def show_service(parent, storage, entry):
    service = entry.service_account
    summary = [
        f"Service  {service.service.domain}",
        f"Username  {service.username or 'Unknown'}",
        f"Website  {service.origin or 'Unknown'}",
        f"Confidence  {entry.confidence.points} ({entry.confidence.band})",
        f"Evidence  {entry.evidence_count} • " + ", ".join(entry.confidence.categories),
        f"Review  {service.review}",
        "",
        "Request timeline",
    ]
    for record in storage.list_requests():
        if record.service_account != service:
            continue
        summary.append(f"{record.kind.replace('_', ' ').title()} • {record.jurisdiction} • {record.state}")
        if record.sent_at:
            estimate = deadline(record, date.today())
            summary.append(f"Sent {record.sent_at.astimezone().date()} • estimated due {estimate.estimated_due} • {estimate.thirty_days_remaining} days on the 30-day countdown")
        events = sorted(storage.request_events(record.id), key=lambda event: event.timestamp)
        summary.extend(f"  {event.timestamp.astimezone():%Y-%m-%d %H:%M}  {event.kind.replace('_', ' ')}" for event in events)
    show_text(parent, service.service.domain, "\n".join(summary))


def show_text(parent, title, text):
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.resize(650, 450)
    layout = QVBoxLayout(dialog)
    editor = QPlainTextEdit(text)
    editor.setReadOnly(True)
    layout.addWidget(editor)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.exec()
    dialog.deleteLater()
