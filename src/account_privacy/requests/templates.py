import hashlib
import json
from dataclasses import dataclass, replace
from datetime import date
from enum import StrEnum
from importlib.resources import files

from account_privacy.core.models import Account, ServiceAccount

from .contacts import Contact, mail_address


class Jurisdiction(StrEnum):
    GDPR = "GDPR"
    UK_GDPR = "UK GDPR"
    CCPA = "CCPA"


class RequestKind(StrEnum):
    ACCESS = "access"
    DELETE = "delete"
    FOLLOW_UP = "follow_up"


_ACCESS = {
    Jurisdiction.GDPR: "Article 15 of the GDPR",
    Jurisdiction.UK_GDPR: "Article 15 of the UK GDPR",
    Jurisdiction.CCPA: "the California Consumer Privacy Act (CCPA)",
}
_DELETE = {
    Jurisdiction.GDPR: "Article 17 of the GDPR",
    Jurisdiction.UK_GDPR: "Article 17 of the UK GDPR",
    Jurisdiction.CCPA: "the California Consumer Privacy Act (California Civil Code § 1798.105)",
}
_SUBJECTS = {
    RequestKind.ACCESS: "Personal data access request",
    RequestKind.DELETE: "Personal data deletion request",
    RequestKind.FOLLOW_UP: "Follow-up on personal data request",
}
TEMPLATE_VERSION = 1


@dataclass(frozen=True, slots=True, repr=False)
class Draft:
    account: Account
    service_account: ServiceAccount
    contact: Contact
    jurisdiction: Jurisdiction
    kind: RequestKind
    subject: str
    body: str
    parent_id: str | None = None
    reply_message_id: str | None = None

    @property
    def digest(self) -> str:
        fields = (
            self.account.id, self.account.email, self.service_account.service.domain,
            self.service_account.username, self.contact.kind, self.contact.destination,
            self.jurisdiction, self.kind, self.subject, self.body, self.parent_id, self.reply_message_id,
        )
        return hashlib.sha256(json.dumps(fields, ensure_ascii=False).encode("utf-8")).hexdigest()

    def edited(self, subject: str, body: str) -> "Draft":
        if not subject.strip() or len(subject) > 250 or any(ord(char) < 32 for char in subject):
            raise ValueError("Use a single subject line of at most 250 characters")
        if not body.strip() or len(body) > 30_000 or "\x00" in body:
            raise ValueError("Enter between 1 and 30,000 characters of request text")
        return replace(self, subject=subject.strip(), body=body)


def make_draft(
    account: Account, service: ServiceAccount, contact: Contact, name: str, jurisdiction: Jurisdiction,
    kind: RequestKind = RequestKind.ACCESS, *, sent_date: date | None = None, parent_id: str | None = None,
    reply_message_id: str | None = None, follow_up_deletion: bool = False,
) -> Draft:
    if service.account_id != account.id or service.service.domain != contact.domain:
        raise ValueError("The source account and destination must match the service")
    mail_address(account.email)
    name = name.strip()
    if not name or len(name) > 200 or any(ord(char) < 32 for char in name):
        raise ValueError("Enter a single-line name of up to 200 characters")
    if kind == RequestKind.FOLLOW_UP and (sent_date is None or parent_id is None):
        raise ValueError("Select a sent request to follow up")
    law = (_DELETE if kind == RequestKind.DELETE or follow_up_deletion else _ACCESS)[jurisdiction]
    account_email = account.email
    if "@" in service.username:
        try:
            account_email = mail_address(service.username)
        except ValueError:
            pass
    template = files("account_privacy").joinpath("resources", "templates", f"{kind}.txt").read_text(encoding="utf-8")
    body = template.format(law=law, name=name, email=account_email, sent_date=sent_date)
    return Draft(account, service, contact, jurisdiction, kind, _SUBJECTS[kind], body, parent_id, reply_message_id)
