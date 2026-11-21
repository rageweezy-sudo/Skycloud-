from datetime import datetime
from urllib.parse import urlencode, urlsplit

from .evidence import MailHeader
from .http import HTTPFailure
from .oauth import OAuthSession
from .scan import Approval, HeaderPage, InvalidCheckpoint

BASE = "https://graph.microsoft.com/v1.0/me/messages"
FIELDS = "id,conversationId,internetMessageId,receivedDateTime,sender,from,subject,internetMessageHeaders,toRecipients,parentFolderId"


class GraphHeaders:
    def __init__(self, session: OAuthSession, *, check_sent: bool = False) -> None:
        self._session = session
        self._check_sent = check_sent
        self._sent_folder = None

    @staticmethod
    def _validate(url: str) -> None:
        try:
            parts = urlsplit(url)
        except ValueError:
            raise InvalidCheckpoint("Invalid Microsoft Graph continuation") from None
        if (parts.scheme, parts.netloc, parts.path, parts.fragment) != (
            "https", "graph.microsoft.com", "/v1.0/me/messages", "",
        ):
            raise InvalidCheckpoint("Invalid Microsoft Graph continuation")

    def _message(self, item: dict) -> MailHeader:
        headers = {}
        for header in item.get("internetMessageHeaders") or []:
            name = header.get("name", "").casefold()
            value = header.get("value", "")
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
        try:
            date = datetime.fromisoformat(item.get("receivedDateTime") or "")
            observed = date if date.utcoffset() is not None else None
        except ValueError:
            observed = None
        sender = (item.get("from") or item.get("sender") or {}).get("emailAddress", {}).get("address", "")
        recipients = ", ".join(record.get("emailAddress", {}).get("address", "") for record in item.get("toRecipients", ()))
        return MailHeader(
            item["id"], sender, item.get("subject") or "", headers.get("list-unsubscribe", ""),
            observed, item.get("conversationId"), item.get("internetMessageId"), headers.get("in-reply-to", ""),
            headers.get("references", ""), recipients,
            headers.get("x-account-privacy-request-id", ""),
            self._sent_folder is not None and item.get("parentFolderId") == self._sent_folder,
        )

    def page(self, cursor: str | None, approval: Approval) -> HeaderPage:
        url = cursor or BASE + "?" + urlencode({"$top": 100, "$select": FIELDS})
        self._validate(url)
        if self._check_sent and self._sent_folder is None:
            folder = self._session.http.request(
                "https://graph.microsoft.com/v1.0/me/mailFolders/sentitems?$select=id", approval,
                token=self._session.access_token(approval), headers={"Prefer": 'IdType="ImmutableId"'},
            )
            self._sent_folder = folder.get("id")
        try:
            data = self._session.http.request(
                url, approval, token=self._session.access_token(approval), headers={"Prefer": 'IdType="ImmutableId"'},
            )
        except HTTPFailure as error:
            if cursor and error.status in (400, 404, 410):
                raise InvalidCheckpoint("Microsoft Graph no longer accepts this checkpoint") from None
            raise
        following = data.get("@odata.nextLink")
        if following:
            self._validate(following)
        return HeaderPage(tuple(self._message(item) for item in data.get("value", ())), following, complete=not following)
