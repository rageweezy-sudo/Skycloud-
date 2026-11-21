from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from threading import Event
from typing import Protocol
from urllib.parse import urlsplit

from account_privacy.core.models import Account, Evidence
from account_privacy.core.storage import ScanRun, Storage

from .evidence import MailHeader, classify_header


class ApprovalError(RuntimeError):
    pass


class DiscoveryError(RuntimeError):
    pass


class InvalidCheckpoint(DiscoveryError):
    pass


@dataclass(frozen=True, slots=True)
class Approval:
    operation: str
    account_id: str
    source: str
    selection: str
    destinations: tuple[str, ...]
    _closed: Event = field(default_factory=Event, init=False, repr=False, compare=False)

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def close(self) -> None:
        self._closed.set()

    def require(self, operation: str, account_id: str, source: str, selection: str) -> None:
        if self.closed or (self.operation, self.account_id, self.source, self.selection) != (operation, account_id, source, selection):
            raise ApprovalError("This operation needs your approval")

    def require_destination(self, url: str) -> None:
        try:
            parsed = urlsplit(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
        except ValueError:
            raise ApprovalError("Destination is invalid") from None
        if self.closed or origin not in self.destinations or parsed.username is not None:
            raise ApprovalError("This destination needs your approval")

    def wait(self, seconds: float) -> None:
        if self._closed.wait(seconds):
            raise ApprovalError("The operation was cancelled")


@dataclass(frozen=True, slots=True)
class HeaderPage:
    headers: tuple[MailHeader, ...]
    cursor: str | None
    total: int | None = None
    complete: bool = False


class HeaderSource(Protocol):
    def page(self, cursor: str | None, approval: Approval) -> HeaderPage: ...


@dataclass(frozen=True, slots=True)
class DiscoveryPage:
    evidence: tuple[Evidence, ...]
    cursor: str | None
    processed: int
    complete: bool
    total: int | None = None


class DiscoverySource(Protocol):
    account: Account
    name: str
    selection: str

    def page(self, cursor: str | None, approval: Approval) -> DiscoveryPage: ...


@dataclass(slots=True)
class HeaderDiscovery:
    account: Account
    name: str
    selection: str
    source: HeaderSource
    aliases: Mapping[str, str] | None = None
    since: datetime | None = None

    def page(self, cursor: str | None, approval: Approval) -> DiscoveryPage:
        approval.require("scan", self.account.id, self.name, self.selection)
        page = self.source.page(cursor, approval)
        evidence = tuple(
            entry
            for header in page.headers
            if self.since is None or (header.observed_at is not None and header.observed_at >= self.since)
            for entry in classify_header(header, self.account, self.name, self.aliases)
        )
        return DiscoveryPage(evidence, page.cursor, len(page.headers), page.complete, page.total)

    def close(self) -> None:
        close = getattr(self.source, "close", None)
        if close is not None:
            close()


def run_scan(
    storage: Storage,
    source: DiscoverySource,
    approval: Approval,
    run_id: str | None = None,
    progress: Callable[[ScanRun], None] | None = None,
) -> ScanRun:
    binding = (source.account.id, source.name, source.selection)
    approval.require("scan", *binding)
    if source.account not in storage.list_accounts():
        raise ApprovalError("Confirm the account before scanning")
    run = storage.get_scan(run_id) if run_id else storage.create_scan(*binding)
    if (run.account_id, run.source, run.selection) != binding:
        raise ApprovalError("This scan belongs to another source or account")

    restarted = False
    try:
        while not run.complete and not approval.closed:
            try:
                page = source.page(run.cursor, approval)
            except InvalidCheckpoint:
                if restarted or run.cursor is None:
                    raise
                run = storage.restart_scan(run.id, run.revision)
                restarted = True
                continue
            except ApprovalError:
                if approval.closed:
                    break
                raise
            if approval.closed:
                break
            if not page.complete and (page.cursor is None or page.cursor == run.cursor):
                raise DiscoveryError("The source did not advance its scan cursor")
            run = storage.commit_page(
                run.id, run.revision, page.evidence, page.cursor, page.processed, complete=page.complete
            )
            if progress is not None:
                progress(run)
        return run
    finally:
        close = getattr(source, "close", None)
        if close is not None:
            close()
