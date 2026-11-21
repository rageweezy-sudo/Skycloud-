import calendar
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, tzinfo
from typing import Iterable

from account_privacy.core.models import Account, RequestRecord
from account_privacy.core.storage import Storage
from account_privacy.discovery.evidence import MailHeader, addresses
from account_privacy.discovery.scan import Approval, HeaderSource, InvalidCheckpoint

from .contacts import ContactKind
from .templates import Jurisdiction
from .transports import message_id

_MESSAGE_ID = re.compile(r"<[^<>\s]+>")


@dataclass(frozen=True, slots=True)
class Deadline:
    estimated_due: date
    thirty_day_due: date
    estimated_days_remaining: int
    thirty_days_remaining: int


def deadline(record: RequestRecord, today: date, zone: tzinfo | None = None) -> Deadline | None:
    if record.sent_at is None:
        return None
    sent = record.sent_at.astimezone(zone).date()
    thirty = sent + timedelta(days=30)
    if record.adjusted_due:
        estimated = date.fromisoformat(record.adjusted_due)
    elif record.jurisdiction == Jurisdiction.CCPA:
        estimated = sent + timedelta(days=45)
    else:
        year, month = sent.year + (sent.month == 12), sent.month % 12 + 1
        estimated = date(year, month, min(sent.day, calendar.monthrange(year, month)[1]))
    return Deadline(estimated, thirty, (estimated - today).days, (thirty - today).days)


@dataclass(frozen=True, slots=True)
class ReplyMatch:
    request_id: str | None = None
    ambiguous: tuple[str, ...] = ()


def match_reply(message: MailHeader, account: Account, requests: Iterable[RequestRecord]) -> ReplyMatch:
    owner = account.email.casefold()
    senders = {address.casefold() for address in addresses(message.sender)}
    recipients = {address.casefold() for address in addresses(message.recipients)}
    if len(senders) != 1 or owner in senders or owner not in recipients:
        return ReplyMatch()
    direct = set(_MESSAGE_ID.findall(message.in_reply_to))
    references = set(_MESSAGE_ID.findall(message.references))
    matches: dict[int, list[str]] = {}
    for record in requests:
        if (
            record.service_account.account_id != account.id or record.destination_kind != ContactKind.EMAIL
            or record.sent_at is None or record.state not in ("sent", "reply", "fulfilled")
            or (message.observed_at is not None and message.observed_at < record.sent_at - timedelta(minutes=5))
            or record.destination.casefold() not in senders
        ):
            continue
        if record.message_id in direct:
            matches.setdefault(3, []).append(record.id)
        elif record.message_id in references:
            matches.setdefault(2, []).append(record.id)
        elif record.thread_id and message.thread_id == record.thread_id:
            matches.setdefault(1, []).append(record.id)
    strongest = matches[max(matches)] if matches else []
    if len(strongest) == 1:
        return ReplyMatch(strongest[0])
    return ReplyMatch(ambiguous=tuple(strongest))


def link_sent(
    storage: Storage, account: Account, header: MailHeader, requests: Iterable[RequestRecord], *, verified_sent: bool,
) -> None:
    if not verified_sent or not header.request_marker:
        return
    senders = {address.casefold() for address in addresses(header.sender)}
    recipients = {address.casefold() for address in addresses(header.recipients)}
    for record in requests:
        if (
            record.id == header.request_marker and record.service_account.account_id == account.id
            and record.destination_kind == ContactKind.EMAIL and account.email.casefold() in senders
            and record.destination.casefold() in recipients
        ):
            storage.reconcile_sent(
                record.id, header.observed_at or datetime.now(UTC), header.message_id or message_id(record.id), header.thread_id,
            )
            break


def record_replies(storage: Storage, account: Account, headers: Iterable[MailHeader]) -> int:
    headers = tuple(headers)
    records = storage.list_requests()
    changed = 0
    for header in headers:
        if header.in_sent:
            link_sent(storage, account, header, records, verified_sent=True)
    records = storage.list_requests()
    for header in headers:
        match = match_reply(header, account, records)
        item_id = hashlib.sha256(header.item_id.encode("utf-8")).hexdigest()
        occurred = header.observed_at or datetime.now(UTC)
        if match.request_id:
            changed += storage.record_reply(match.request_id, item_id, occurred)
        for request_id in match.ambiguous:
            storage.record_reply(request_id, item_id, occurred, ambiguous=True)
    return changed


def check_replies(
    storage: Storage, account: Account, source: HeaderSource, approval: Approval, selection: str,
) -> int:
    approval.require("replies", account.id, account.provider, selection)
    if account not in storage.list_accounts():
        raise ValueError("Confirm this account before checking replies")
    cursor = None
    changed = 0
    restarted = False
    try:
        while not approval.closed:
            try:
                page = source.page(cursor, approval)
            except InvalidCheckpoint:
                if not cursor or restarted:
                    raise
                cursor, restarted = None, True
                continue
            changed += record_replies(storage, account, page.headers)
            if page.complete:
                break
            if not page.cursor or page.cursor == cursor:
                raise InvalidCheckpoint("The reply checkpoint did not advance")
            cursor = page.cursor
    finally:
        approval.close()
        close = getattr(source, "close", None)
        if close is not None:
            close()
    return changed


def notify_due(storage: Storage, show, now: datetime | None = None) -> int:
    current = now or datetime.now(UTC)
    today = current.astimezone().date()
    count = 0
    for record in storage.list_requests():
        if record.state not in ("sent", "reply") or record.kind == "follow_up":
            continue
        estimate = deadline(record, today)
        if estimate is None or estimate.estimated_days_remaining > 3:
            continue
        key = estimate.estimated_due.isoformat() + ("/overdue" if estimate.estimated_days_remaining < 0 else "/soon")
        if storage.remember_notification(record.id, key, current):
            count += 1
    if count:
        show()
    return count
