from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Provider(StrEnum):
    GMAIL = "gmail"
    GRAPH = "graph"
    IMAP = "imap"
    LOCAL = "local"


class EvidenceCategory(StrEnum):
    IMPORT = "import"
    SIGNUP = "signup"
    RESET = "reset"
    RECEIPT = "receipt"
    UNSUBSCRIBE = "unsubscribe"


class ReviewState(StrEnum):
    UNREVIEWED = "unreviewed"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


@dataclass(frozen=True, slots=True)
class Account:
    id: str
    email: str
    provider: Provider
    credential_ref: str | None = None


@dataclass(frozen=True, slots=True)
class Service:
    domain: str


@dataclass(frozen=True, slots=True)
class ServiceAccount:
    service: Service
    account_id: str
    username: str = ""
    origin: str | None = None
    review: ReviewState = ReviewState.UNREVIEWED


@dataclass(frozen=True, slots=True)
class Evidence:
    service_account: ServiceAccount
    source: str
    item_id: str
    category: EvidenceCategory
    observed_at: datetime | None = None
    ambiguous: bool = False


@dataclass(frozen=True, slots=True)
class RequestRecord:
    id: str
    service_account: ServiceAccount
    kind: str
    jurisdiction: str
    destination_kind: str
    destination: str
    state: str
    created_at: datetime
    sent_at: datetime | None = None
    message_id: str | None = None
    thread_id: str | None = None
    adjusted_due: str | None = None
    parent_id: str | None = None


@dataclass(frozen=True, slots=True)
class RequestEvent:
    kind: str
    timestamp: datetime
