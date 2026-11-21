import base64
import json
import smtplib
import ssl
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.utils import formatdate

import idna

from account_privacy.core.models import Provider
from account_privacy.discovery.http import HTTPFailure
from account_privacy.discovery.oauth import CLIENTS, OAuthSession
from account_privacy.discovery.scan import Approval, DiscoveryError

from .delivery import Receipt, RejectedDelivery
from .templates import Draft

_GMAIL_SEND = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
_GRAPH_SEND = "https://graph.microsoft.com/v1.0/me/sendMail"
REQUEST_HEADER = "X-Account-Privacy-Request-Id"


def message_id(request_id: str) -> str:
    return f"<{request_id}@accountprivacy.invalid>"


def _mime(draft: Draft, request_id: str) -> EmailMessage:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = draft.account.email
    message["To"] = draft.contact.destination
    message["Subject"] = draft.subject
    message["Date"] = formatdate()
    message["Message-ID"] = message_id(request_id)
    message[REQUEST_HEADER] = request_id
    if draft.reply_message_id:
        message["In-Reply-To"] = draft.reply_message_id
        message["References"] = draft.reply_message_id
    message.set_content(draft.body)
    return message


@dataclass(slots=True, repr=False)
class OAuthMail:
    session: OAuthSession

    def submit(self, draft: Draft, request_id: str, approval: Approval) -> Receipt:
        provider = draft.account.provider
        if self.session.account != draft.account or self.session.scope != CLIENTS[provider].send_scope:
            raise RejectedDelivery("Connect the approved account for sending first")
        try:
            token = self.session.access_token(approval)
        except DiscoveryError:
            raise RejectedDelivery("The mail permission needs to be connected before sending") from None
        if provider == Provider.GMAIL:
            raw = base64.urlsafe_b64encode(_mime(draft, request_id).as_bytes()).decode("ascii")
            url, payload, content_type = _GMAIL_SEND, json.dumps({"raw": raw}).encode(), "application/json"
        elif provider == Provider.GRAPH:
            # MIME carries the same exact preview, reply headers, and unique correlation ID.
            encoded = base64.b64encode(_mime(draft, request_id).as_bytes())
            url, payload, content_type = _GRAPH_SEND, encoded, "text/plain"
        else:
            raise RejectedDelivery("Unsupported mail transport")
        try:
            result = self.session.http.request(
                url, approval, token=token, method="POST", data=payload, content_type=content_type,
            )
        except HTTPFailure as error:
            if error.status in (400, 401, 403, 404, 422, 429):
                raise RejectedDelivery("The provider rejected the request") from None
            raise
        # Graph can rewrite Message-ID. Its Sent copy can be reconciled by the custom header.
        return Receipt(message_id(request_id) if provider == Provider.GMAIL else None, result.get("threadId"))


@dataclass(frozen=True, slots=True)
class SMTPSettings:
    host: str
    port: int = 465
    starttls: bool = False

    def __post_init__(self):
        try:
            host = idna.encode(self.host, uts46=True, std3_rules=True).decode("ascii").removesuffix(".")
        except (idna.IDNAError, UnicodeError):
            raise ValueError("Invalid SMTP server name") from None
        if not 1 <= self.port <= 65535:
            raise ValueError("Invalid SMTP port")
        object.__setattr__(self, "host", host)

    @property
    def destination(self) -> str:
        return f"{'smtp' if self.starttls else 'smtps'}://{self.host}:{self.port}"


@dataclass(slots=True, repr=False)
class SMTPMail:
    settings: SMTPSettings
    password: str = field(repr=False)

    def submit(self, draft: Draft, request_id: str, approval: Approval) -> Receipt:
        settings = self.settings
        approval.require_destination(settings.destination)
        context = ssl.create_default_context()
        client = None
        submitted = False
        try:
            if settings.starttls:
                client = smtplib.SMTP(settings.host, settings.port, timeout=20)
                client.starttls(context=context)
            else:
                client = smtplib.SMTP_SSL(settings.host, settings.port, timeout=20, context=context)
            approval.require_destination(settings.destination)
            client.login(draft.account.email, self.password)
            approval.require_destination(settings.destination)
            message = _mime(draft, request_id)
            submitted = True
            outcome = client.send_message(message, draft.account.email, [draft.contact.destination])
            if outcome:
                raise RejectedDelivery("The mail server rejected the recipient")
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError, smtplib.SMTPAuthenticationError):
            raise RejectedDelivery("The mail server rejected the request") from None
        except (OSError, smtplib.SMTPException):
            if not submitted:
                raise RejectedDelivery("Could not connect to the mail server") from None
            raise
        finally:
            if client is not None:
                client.close()
        return Receipt(message_id(request_id), None)
