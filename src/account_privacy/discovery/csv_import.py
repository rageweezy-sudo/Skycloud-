import csv
import hashlib
import io
import json
import os
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from account_privacy.core.domains import normalize_origin, service_domain
from account_privacy.core.local_files import local_path
from account_privacy.core.models import Account, Evidence, EvidenceCategory, Service, ServiceAccount

from .scan import Approval, ApprovalError, DiscoveryError, DiscoveryPage, InvalidCheckpoint


class ExportFormat(StrEnum):
    CHROME = "chrome"
    EDGE = "edge"
    FIREFOX = "firefox"
    BRAVE = "brave"
    BITWARDEN = "bitwarden"
    ONEPASSWORD = "1password"
    KEEPASS = "keepass"


_BROWSER = (("url",), ("username",))
_COLUMNS = {
    ExportFormat.CHROME: _BROWSER,
    ExportFormat.EDGE: _BROWSER,
    ExportFormat.FIREFOX: _BROWSER,
    ExportFormat.BRAVE: _BROWSER,
    ExportFormat.BITWARDEN: (("login_uri",), ("login_username",)),
    ExportFormat.ONEPASSWORD: (("website", "url"), ("username",)),
    ExportFormat.KEEPASS: (("web site", "url", "website"), ("login name", "username", "user name")),
}


class CSVDiscovery:
    def __init__(
        self, account: Account, path: Path, kind: ExportFormat, *, page_size: int = 250, aliases=None
    ) -> None:
        if not 1 <= page_size <= 1000:
            raise ValueError("CSV page size must be between 1 and 1,000")
        self.account = account
        self._path = Path(os.path.abspath(path))
        self.name = "csv:" + kind
        self.selection = hashlib.sha256(os.fsencode(self._path)).hexdigest()
        self._kind = kind
        self._page_size = page_size
        self._aliases = aliases
        self._stream = None
        self._reader = None
        self._fingerprint = None
        self._stat = None
        self._row = 0

    def _open(self) -> None:
        raw = local_path(self._path).open("rb")
        self._stream = io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")
        self._stat = self._file_state()
        # The resume marker uses file metadata without hashing password fields.
        self._fingerprint = hashlib.sha256(repr(self._stat).encode("ascii")).hexdigest()
        header_line = self._stream.readline(65_536)
        dialect = csv.Sniffer().sniff(header_line, delimiters=",;\t")
        self._stream.seek(0)
        self._reader = csv.reader(self._stream, dialect, strict=True)
        header = [column.strip().casefold() for column in next(self._reader, ())]
        options = _COLUMNS[self._kind]
        self._url, self._username = (
            next((header.index(name) for name in names if name in header), None) for names in options
        )
        if self._url is None or self._username is None:
            raise DiscoveryError("The export is missing its URL or username column")
        self._row = 0

    def _file_state(self) -> tuple[int, int, int, int]:
        current = os.fstat(self._stream.fileno())
        return current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def _evidence(self, row: list[str]) -> Evidence | None:
        if len(row) <= max(self._url, self._username):
            return None
        try:
            origin = normalize_origin(row[self._url])
            domain = service_domain(urlsplit(origin).hostname or "", self._aliases)
        except ValueError:
            return None
        username = row[self._username].strip()
        record = ServiceAccount(Service(domain), self.account.id, username, origin)
        stable_id = hashlib.sha256(json.dumps([origin, username], ensure_ascii=False).encode("utf-8")).hexdigest()
        return Evidence(record, self.name, stable_id, EvidenceCategory.IMPORT)

    def page(self, cursor: str | None, approval: Approval) -> DiscoveryPage:
        approval.require("scan", self.account.id, self.name, self.selection)
        try:
            return self._page(cursor, approval)
        except (OSError, UnicodeError, csv.Error):
            self.close()
            raise DiscoveryError("Could not read the selected CSV export") from None

    def _page(self, cursor: str | None, approval: Approval) -> DiscoveryPage:
        offset = 0
        fingerprint = None
        if cursor is not None:
            try:
                fingerprint, offset = json.loads(cursor)
                if type(offset) is not int or offset < 0:
                    raise ValueError
            except (ValueError, TypeError):
                raise InvalidCheckpoint("Invalid CSV scan checkpoint") from None
        if self._stream is None or self._row != offset:
            self.close()
            self._open()
        if fingerprint is not None and fingerprint != self._fingerprint:
            raise InvalidCheckpoint("The export changed since the scan checkpoint")
        for _ in range(self._row, offset):
            if approval.closed:
                raise ApprovalError("The import was cancelled")
            if next(self._reader, None) is None:
                raise InvalidCheckpoint("The export no longer contains the checkpoint")
        self._row = offset
        entries = []
        limit = offset + self._page_size
        complete = False
        while self._row < limit and not approval.closed:
            row = next(self._reader, None)
            if row is None:
                complete = True
                break
            entry = self._evidence(row)
            del row
            if entry is not None:
                entries.append(entry)
            self._row += 1
        if self._file_state() != self._stat:
            self.close()
            raise InvalidCheckpoint("The export changed while it was being read")
        next_cursor = None if complete else json.dumps([self._fingerprint, self._row])
        return DiscoveryPage(tuple(entries), next_cursor, self._row - offset, complete)
