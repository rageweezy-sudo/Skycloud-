import csv
import os
import tempfile
from collections.abc import Iterable
from datetime import date
from html import escape
from pathlib import Path

from account_privacy.core.local_files import local_path
from account_privacy.core.models import RequestRecord
from account_privacy.core.storage import InventoryEntry
from account_privacy.requests.tracking import deadline

COLUMNS = ("Service", "Account", "Username", "Confidence", "Review", "Request status", "Sent date", "Estimated deadline")


def report_rows(
    inventory: Iterable[InventoryEntry], account_addresses: dict[str, str], requests: Iterable[RequestRecord]
) -> list[tuple[str, ...]]:
    latest = {}
    for request in requests:
        if request.kind == "follow_up":
            continue
        service = request.service_account
        latest.setdefault((service.service.domain, service.account_id, service.username), request)
    result = []
    for entry in inventory:
        service = entry.service_account
        request = latest.get((service.service.domain, service.account_id, service.username))
        estimate = deadline(request, date.today()) if request else None
        result.append((
            service.service.domain, account_addresses.get(service.account_id, ""),
            service.username, str(entry.confidence.points), service.review,
            request.state if request else "", request.sent_at.astimezone().date().isoformat() if request and request.sent_at else "",
            estimate.estimated_due.isoformat() if estimate else "",
        ))
    return result


def safe_csv_text(value: str) -> str:
    if value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export_csv(path: Path, rows: Iterable[tuple[str, ...]]) -> None:
    target = local_path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8-sig", newline="", dir=target.parent, suffix=".tmp", delete=False,
        ) as output:
            temporary = Path(output.name)
            writer = csv.writer(output)
            writer.writerow(COLUMNS)
            writer.writerows(tuple(safe_csv_text(value) for value in row) for row in rows)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def export_pdf(path: Path, rows: list[tuple[str, ...]]) -> None:
    from PySide6.QtGui import QPageLayout, QPageSize, QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    target = local_path(path)
    with tempfile.NamedTemporaryFile(dir=target.parent, suffix=".pdf", delete=False) as output:
        temporary = Path(output.name)
    try:
        document = QTextDocument()
        headers = "".join(f"<th>{escape(label)}</th>" for label in COLUMNS)
        cells = "".join("<tr>" + "".join(f"<td>{escape(value)}</td>" for value in row) + "</tr>" for row in rows)
        document.setHtml(
            "<h1>Account Privacy</h1><table border='1' cellspacing='0' cellpadding='4' width='100%'>"
            f"<thead><tr>{headers}</tr></thead><tbody>{cells}</tbody></table>"
        )
        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setPageSize(QPageSize(QPageSize.PageSize.A4))
        printer.setPageOrientation(QPageLayout.Orientation.Landscape)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(str(temporary))
        document.print_(printer)
        if not temporary.stat().st_size:
            raise OSError("Could not generate the PDF")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
