from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from account_privacy.core.models import RequestRecord
from account_privacy.core.storage import Storage, StorageError
from account_privacy.discovery.scan import Approval, ApprovalError

from .contacts import ContactKind
from .templates import Draft, RequestKind, TEMPLATE_VERSION


class DeliveryError(RuntimeError):
    pass


class RejectedDelivery(DeliveryError):
    pass


@dataclass(frozen=True, slots=True)
class Receipt:
    message_id: str | None
    thread_id: str | None


class MailTransport(Protocol):
    def submit(self, draft: Draft, request_id: str, approval: Approval) -> Receipt: ...


class Delivery:
    def __init__(self, storage: Storage, now: Callable[[], datetime] | None = None) -> None:
        self.storage = storage
        self.now = now or (lambda: datetime.now(UTC))

    def _authorize(self, draft: Draft, approval: Approval, operation: str, deletion: Approval | None) -> None:
        binding = (draft.account.id, draft.account.provider, draft.digest)
        approval.require(operation, *binding)
        if draft.account not in self.storage.list_accounts():
            raise ApprovalError("The preview's email account no longer matches")
        if draft.kind == RequestKind.DELETE:
            if deletion is None:
                raise ApprovalError("Confirm that you want to request deletion")
            deletion.require("delete", *binding)

    def _reserve(self, draft: Draft) -> RequestRecord:
        try:
            return self.storage.reserve_request(
                draft.service_account, draft.kind, draft.jurisdiction, TEMPLATE_VERSION,
                draft.contact.kind, draft.contact.destination, self.now(), draft.parent_id,
            )
        except StorageError as error:
            raise DeliveryError(str(error)) from None

    def send(
        self, draft: Draft, approval: Approval, transport: MailTransport, *, deletion: Approval | None = None,
    ) -> RequestRecord:
        if draft.contact.kind != ContactKind.EMAIL:
            raise DeliveryError("This request uses a portal")
        self._authorize(draft, approval, "send", deletion)
        request = self._reserve(draft)
        try:
            receipt = transport.submit(draft, request.id, approval)
        except (ApprovalError, RejectedDelivery):
            return self.storage.finish_request(request.id, "pending", "failed", self.now())
        except Exception:
            return self.storage.finish_request(request.id, "pending", "uncertain", self.now())
        else:
            return self.storage.finish_request(
                request.id, "pending", "sent", self.now(), receipt.message_id, receipt.thread_id,
            )
        finally:
            approval.close()
            if deletion is not None:
                deletion.close()

    def portal(
        self, draft: Draft, approval: Approval, open_browser: Callable[[str], bool], clipboard: Callable[[str], None],
        *, deletion: Approval | None = None,
    ) -> RequestRecord:
        if draft.contact.kind != ContactKind.PORTAL:
            raise DeliveryError("This request uses email")
        self._authorize(draft, approval, "portal", deletion)
        approval.require_destination(draft.contact.origin)
        record = self._reserve(draft)
        try:
            clipboard(draft.body)
            if not open_browser(draft.contact.destination):
                raise DeliveryError("Could not open the privacy portal")
        except Exception:
            self.storage.finish_request(record.id, "portal_pending", "failed", self.now())
            raise DeliveryError("Could not prepare the privacy portal") from None
        finally:
            approval.close()
            if deletion is not None:
                deletion.close()
        return record

    def confirm_portal_submission(self, request_id: str, sent_at: datetime | None = None) -> RequestRecord:
        return self.storage.finish_request(request_id, "portal_pending", "sent", sent_at or self.now())
