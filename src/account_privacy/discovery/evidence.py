import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from email.utils import getaddresses
from urllib.parse import urlsplit

from account_privacy.core.domains import normalize_origin, service_domain
from account_privacy.core.models import Account, Evidence, EvidenceCategory, Service, ServiceAccount


@dataclass(frozen=True, slots=True, repr=False)
class MailHeader:
    item_id: str
    sender: str = ""
    subject: str = ""
    unsubscribe: str = ""
    observed_at: datetime | None = None
    thread_id: str | None = None
    message_id: str | None = None
    in_reply_to: str = ""
    references: str = ""
    recipients: str = ""
    request_marker: str = ""
    in_sent: bool = False


SELECTED_HEADERS = ("From", "Subject", "List-Unsubscribe", "Date", "Message-ID", "In-Reply-To", "References", "To", "X-Account-Privacy-Request-Id")
_SHARED_DOMAINS = frozenset({
    "amazonaws.com", "amazonses.com", "sendgrid.net", "mailgun.org", "mandrillapp.com",
    "mailchimp.com", "list-manage.com", "sparkpostmail.com", "postmarkapp.com",
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
})
_SIGNALS = (
    (EvidenceCategory.RESET, re.compile(r"\b(?:password reset|reset (?:your |the )?password|forgot(?:ten)? password)\b", re.I)),
    (EvidenceCategory.SIGNUP, re.compile(
        r"\b(?:welcome to|verify (?:your )?(?:email|account)|confirm (?:your )?(?:email|account|registration)|"
        r"activate (?:your )?account|thanks for (?:joining|signing up)|account (?:created|verification))\b", re.I)),
    (EvidenceCategory.RECEIPT, re.compile(
        r"\b(?:receipt|invoice|order confirmation|payment confirmation|payment received|thanks for your order)\b", re.I)),
)


def addresses(value: str) -> list[str]:
    return [address for _, address in getaddresses([value]) if address.count("@") == 1]


def _domain(host: str, aliases: Mapping[str, str] | None) -> str | None:
    try:
        candidate = service_domain(host, aliases)
    except ValueError:
        return None
    # A documented alias may map a specific delivery host to a distinct service.
    return candidate if candidate not in _SHARED_DOMAINS else None


def classify_header(
    header: MailHeader, account: Account, source: str, aliases: Mapping[str, str] | None = None
) -> tuple[Evidence, ...]:
    if header.in_sent:
        return ()
    senders = addresses(header.sender)
    if len(senders) != 1 or senders[0].casefold() == account.email.casefold():
        return ()
    domain = _domain(senders[0].rpartition("@")[2], aliases)
    categories = [category for category, pattern in _SIGNALS if pattern.search(header.subject)]
    if header.unsubscribe:
        categories.append(EvidenceCategory.UNSUBSCRIBE)
    if not categories:
        return ()

    ambiguous = domain is None or categories == [EvidenceCategory.UNSUBSCRIBE]
    if domain is None:
        candidates = set()
        for target in re.findall(r"<([^<>]+)>", header.unsubscribe)[:16]:
            try:
                if target.lower().startswith("mailto:"):
                    host = target.partition("?")[0].rpartition("@")[2]
                else:
                    host = urlsplit(normalize_origin(target)).hostname or ""
                alternate = _domain(host, aliases)
                if alternate:
                    candidates.add(alternate)
            except ValueError:
                continue
        if len(candidates) != 1:
            return ()
        domain = candidates.pop()

    record = ServiceAccount(Service(domain), account.id, account.email)
    fingerprint = hashlib.sha256(header.item_id.encode("utf-8")).hexdigest()
    return tuple(Evidence(record, source, fingerprint, category, header.observed_at, ambiguous) for category in categories)
