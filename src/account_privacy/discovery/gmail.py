import json
from datetime import UTC, datetime
from urllib.parse import quote, urlencode

from .evidence import SELECTED_HEADERS, MailHeader
from .http import HTTPFailure
from .oauth import OAuthSession
from .scan import Approval, HeaderPage, InvalidCheckpoint

BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


class GmailHeaders:
    def __init__(self, session: OAuthSession, history_start: str | None = None) -> None:
        self._session = session
        self._history_start = history_start

    def _get(self, path, query, approval):
        token = self._session.access_token(approval)
        return self._session.http.request(BASE + path + ("?" + urlencode(query, doseq=True) if query else ""), approval, token=token)

    def _message(self, item_id, approval):
        try:
            item = self._get("/messages/" + quote(item_id, safe=""), {
                "format": "metadata", "metadataHeaders": SELECTED_HEADERS,
                "fields": "id,threadId,internalDate,labelIds,payload(headers)",
            }, approval)
        except HTTPFailure as error:
            if error.status == 404:
                return None
            raise
        headers = {}
        for header in item.get("payload", {}).get("headers", []):
            name = header.get("name", "").casefold()
            value = header.get("value", "")
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
        try:
            observed = datetime.fromtimestamp(int(item["internalDate"]) / 1000, UTC)
        except (KeyError, ValueError, OverflowError, OSError, TypeError):
            observed = None
        return MailHeader(
            item_id, headers.get("from", ""), headers.get("subject", ""), headers.get("list-unsubscribe", ""),
            observed, item.get("threadId"), headers.get("message-id"), headers.get("in-reply-to", ""),
            headers.get("references", ""), headers.get("to", ""),
            headers.get("x-account-privacy-request-id", ""), "SENT" in item.get("labelIds", ()),
        )

    def page(self, cursor: str | None, approval: Approval) -> HeaderPage:
        mode, watermark, token = "history" if self._history_start else "all", self._history_start, None
        if cursor is not None:
            try:
                mode, watermark, token = json.loads(cursor)
                if mode not in ("all", "history") or not isinstance(token, str):
                    raise ValueError
            except (ValueError, TypeError):
                raise InvalidCheckpoint("Invalid Gmail scan checkpoint") from None
        elif mode == "all":
            watermark = self._get("/profile", {}, approval).get("historyId")
        query = {"maxResults": 100}
        if token:
            query["pageToken"] = token
        try:
            if mode == "history":
                query.update(startHistoryId=watermark, historyTypes="messageAdded")
                data = self._get("/history", query, approval)
                ids = [record["message"]["id"] for change in data.get("history", []) for record in change.get("messagesAdded", [])]
            else:
                query["fields"] = "nextPageToken,resultSizeEstimate,messages(id)"
                data = self._get("/messages", query, approval)
                ids = [record["id"] for record in data.get("messages", [])]
        except HTTPFailure as error:
            if error.status in (400, 404) and (cursor or mode == "history"):
                self._history_start = None
                if cursor:
                    raise InvalidCheckpoint("Gmail no longer accepts this checkpoint") from None
                return self.page(None, approval)
            raise
        headers = tuple(header for item in dict.fromkeys(ids) if (header := self._message(item, approval)) is not None)
        following = data.get("nextPageToken")
        # A completed checkpoint retains the history watermark for the next scan.
        next_cursor = (
            json.dumps([mode, watermark, following]) if following
            else json.dumps(["watermark", data.get("historyId", watermark)])
        )
        estimate = data.get("resultSizeEstimate")
        return HeaderPage(headers, next_cursor, estimate if type(estimate) is int else None, not following)
