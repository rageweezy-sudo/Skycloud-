from PySide6.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QLabel, QVBoxLayout

from account_privacy.discovery.scan import Approval


def confirm_operation(
    parent, *, title: str, summary: str, action: str,
    operation: str, account_id: str, source: str, selection: str,
    destinations: tuple[str, ...] = (), confirm_owner: bool = False,
) -> Approval | None:
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setMinimumWidth(480)
    layout = QVBoxLayout(dialog)
    text = QLabel(summary)
    from PySide6.QtCore import Qt

    text.setTextFormat(Qt.TextFormat.PlainText)
    text.setWordWrap(True)
    layout.addWidget(text)
    if destinations:
        targets = QLabel("Destinations\n" + "\n".join(destinations))
        targets.setTextFormat(Qt.TextFormat.PlainText)
        targets.setWordWrap(True)
        layout.addWidget(targets)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
    accept = buttons.addButton(action, QDialogButtonBox.ButtonRole.AcceptRole)
    accept.setAutoDefault(False)
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setDefault(True)
    if confirm_owner:
        ownership = QCheckBox("I confirm that this is my own account and data.")
        accept.setEnabled(False)
        ownership.toggled.connect(accept.setEnabled)
        layout.addWidget(ownership)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    return Approval(operation, account_id, source, selection, destinations)


def form_values(parent, title, fields):
    """Return local form values. A field specifies its label, default, and whether to mask."""
    from PySide6.QtWidgets import QFormLayout, QLineEdit

    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setMinimumWidth(460)
    layout = QFormLayout(dialog)
    inputs = []
    for name, default, masked in fields:
        editor = QLineEdit(default)
        if masked:
            editor.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow(name, editor)
        inputs.append(editor)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addRow(buttons)
    values = tuple(item.text() for item in inputs) if dialog.exec() == QDialog.DialogCode.Accepted else None
    for item, (_, _, masked) in zip(inputs, fields):
        if masked:
            item.clear()
    dialog.deleteLater()
    return values


def preview_request(parent, draft, *, demo: bool = False):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QFormLayout, QLineEdit, QMessageBox, QPlainTextEdit

    dialog = QDialog(parent)
    dialog.setWindowTitle("Request preview")
    dialog.resize(700, 550)
    layout = QVBoxLayout(dialog)
    form = QFormLayout()
    for key, value in (
        ("Service", draft.service_account.service.domain), ("From", draft.account.email),
        ("Destination", draft.contact.destination), ("Contact source", draft.contact.source),
    ):
        label = QLabel(value)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(key, label)
    subject = QLineEdit(draft.subject)
    form.addRow("Subject", subject)
    layout.addLayout(form)
    body = QPlainTextEdit(draft.body)
    layout.addWidget(body, 1)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    outcome = []
    if not demo:
        next_button = buttons.addButton("Continue to approval", QDialogButtonBox.ButtonRole.ActionRole)
        next_button.setAutoDefault(False)

        def accept():
            try:
                outcome.append(draft.edited(subject.text(), body.toPlainText()))
            except ValueError as error:
                QMessageBox.warning(dialog, "Check the request", str(error))
                return
            dialog.accept()

        next_button.clicked.connect(accept)
    layout.addWidget(buttons)
    dialog.exec()
    subject.clear()
    body.clear()
    dialog.deleteLater()
    return outcome[0] if outcome else None
