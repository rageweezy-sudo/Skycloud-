import imaplib
import json
import re
import ssl
from dataclasses import dataclass, field
from datetime import UTC
from email import policy
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime

import idna

from .evidence import SELECTED_HEADERS, MailHeader
from .scan import Approval, DiscoveryError, HeaderPage, InvalidCheckpoint

_UID = re.compile(rb"\bUID ([0-9]+)\b")
_FETCH = "(UID BODY.PEEK[HEADER.FIELDS (" + " ".join(SELECTED_HEADERS) + ")])"
_UID_WINDOW = 250


@dataclass(frozen=True, slots=True)
class IMAPSettings:
    host: str
    port: int = 993
    folder: str = "INBOX"

    def __post_init__(self):
        try:
            host = idna.encode(self.host, uts46=True, std3_rules=True).decode("ascii").removesuffix(".")
        except (idna.IDNAError, UnicodeError):
            raise ValueError("Invalid IMAP server name") from None
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid IMAP port")
        if not self.folder or not self.folder.isascii() or any(ord(char) < 32 for char in self.folder):
            raise ValueError("Enter an ASCII IMAP folder name")
        object.__setattr__(self, "host", host)

    @property
    def destination(self) -> str:
        return f"imaps://{self.host}:{self.port}"

    @property
    def selection(self) -> str:
        return json.dumps([self.host, self.port, self.folder])


@dataclass(slots=True, repr=False)
class IMAPHeaders:
    account_email: str
    settings: IMAPSettings
    password: str = field(repr=False)
    _connection: imaplib.IMAP4_SSL | None = field(default=None, init=False)
    _validity: int | None = field(default=None, init=False)
    _upper: int | None = field(default=None, init=False)

    def _open(self, approval: Approval) -> None:
        approval.require_destination(self.settings.destination)
        self._connection = imaplib.IMAP4_SSL(
            self.settings.host, self.settings.port, ssl_context=ssl.create_default_context(), timeout=20,
        )
        connection = self._connection
        approval.require_destination(self.settings.destination)
        connection.login(self.account_email, self.password)
        approval.require_destination(self.settings.destination)
        folder = self.settings.folder.replace("\\", "\\\\").replace('"', '\\"')
        status, _ = connection.select(f'"{folder}"', readonly=True)
        if status != "OK":
            raise DiscoveryError("Could not select the IMAP folder")
        validity = connection.response("UIDVALIDITY")[1][0]
        next_uid = connection.response("UIDNEXT")[1][0]
        if validity is None or next_uid is None:
            raise DiscoveryError("The IMAP server did not supply UID information")
        self._validity, self._upper = int(validity), int(next_uid) - 1

    def close(self) -> None:
        if self._connection is not None:
            self._connection.shutdown()
            self._connection = None

    def page(self, cursor: str | None, approval: Approval) -> HeaderPage:
        try:
            return self._page(cursor, approval)
        except (OSError, imaplib.IMAP4.error, UnicodeError):
            raise DiscoveryError("Could not read the IMAP mailbox") from None

    def _page(self, cursor: str | None, approval: Approval) -> HeaderPage:
        if self._connection is None:
            self._open(approval)
        validity, start, upper = self._validity, 1, self._upper
        if cursor is not None:
            try:
                validity, start, upper = json.loads(cursor)
                if any(type(value) is not int for value in (validity, start, upper)) or start < 1 or upper > self._upper:
                    raise ValueError
            except (ValueError, TypeError):
                raise InvalidCheckpoint("Invalid IMAP checkpoint") from None
            if validity != self._validity:
                raise InvalidCheckpoint("The IMAP folder UIDVALIDITY changed")
        if start > upper:
            return HeaderPage((), None, complete=True)
        end = min(upper, start + _UID_WINDOW - 1)
        approval.require_destination(self.settings.destination)
        status, records = self._connection.uid("FETCH", f"{start}:{end}", _FETCH)
        if status != "OK":
            raise DiscoveryError("Could not read the IMAP header window")
        messages = []
        for record in records:
            if not isinstance(record, tuple):
                continue
            uid = _UID.search(record[0])
            if uid is None or not start <= int(uid[1]) <= end:
                continue
            content = BytesHeaderParser(policy=policy.default).parsebytes(record[1])
            try:
                date = parsedate_to_datetime(str(content.get("Date", "")))
                date = date.replace(tzinfo=UTC) if date.utcoffset() is None else date
            except (ValueError, TypeError, OverflowError):
                date = None
            messages.append(MailHeader(
                item_id=f"{self.settings.folder}/{validity}/{uid[1].decode()}",
                sender=str(content.get("From", "")), subject=str(content.get("Subject", "")),
                unsubscribe=", ".join(str(value) for value in content.get_all("List-Unsubscribe", [])),
                observed_at=date, message_id=str(content["Message-ID"]) if content["Message-ID"] else None,
                in_reply_to=str(content.get("In-Reply-To", "")), references=str(content.get("References", "")),
                recipients=str(content.get("To", "")),
            ))
        following = None if end == upper else json.dumps([validity, end + 1, upper])
        return HeaderPage(tuple(messages), following, complete=following is None)
