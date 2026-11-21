import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from account_privacy.discovery.gmail import BASE as GMAIL_BASE, GmailHeaders
from account_privacy.discovery.graph import BASE as GRAPH_BASE, GraphHeaders
from account_privacy.discovery.imap import IMAPHeaders, IMAPSettings
from account_privacy.discovery.scan import Approval, InvalidCheckpoint


class FakeSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.http = self
        self.urls = []

    def access_token(self, approval):
        return "synthetic"

    def request(self, url, approval, **kwargs):
        approval.require_destination(url)
        self.urls.append(url)
        return next(self.responses)


class ProviderTests(unittest.TestCase):
    def test_gmail_uses_metadata_and_paginates_with_watermark(self):
        session = FakeSession([
            {"historyId": "300"},
            {"messages": [{"id": "first"}], "nextPageToken": "following"},
            {"payload": {"headers": [{"name": "Subject", "value": "Welcome to Example"}]}},
            {"messages": [{"id": "second"}]},
            {"threadId": "thread", "payload": {"headers": [{"name": "From", "value": "sender@example.org"}]}},
        ])
        source = GmailHeaders(session)
        approval = Approval("scan", "a", "gmail", "{}", ("https://gmail.googleapis.com",))
        first = source.page(None, approval)
        self.assertFalse(first.complete)
        self.assertEqual(first.headers[0].subject, "Welcome to Example")
        last = source.page(first.cursor, approval)
        self.assertTrue(last.complete)
        self.assertEqual(last.headers[0].thread_id, "thread")
        self.assertEqual(json.loads(last.cursor), ["watermark", "300"])
        self.assertEqual(urlsplit(session.urls[0]).path, urlsplit(GMAIL_BASE + "/profile").path)
        self.assertEqual(parse_qs(urlsplit(session.urls[2]).query)["format"], ["metadata"])
        self.assertEqual(parse_qs(urlsplit(session.urls[3]).query)["pageToken"], ["following"])
        self.assertNotIn("q=", session.urls[1])

    def test_graph_checks_continuation_before_sending_credentials(self):
        session = FakeSession([{"@odata.nextLink": "https://example.test/steal"}])
        source = GraphHeaders(session)
        approval = Approval("scan", "a", "graph", "{}", ("https://graph.microsoft.com",))
        with self.assertRaises(InvalidCheckpoint):
            source.page(None, approval)
        with self.assertRaises(InvalidCheckpoint):
            source.page("https://graph.microsoft.com/v1.0/me/sendMail", approval)
        self.assertEqual(len(session.urls), 1)
        fields = parse_qs(urlsplit(session.urls[0]).query)["$select"][0].split(",")
        self.assertNotIn("body", fields)

    def test_graph_reads_bounded_page_of_selected_fields(self):
        session = FakeSession([
            {"value": [{
                "id": "a", "subject": "Verify your email",
                "from": {"emailAddress": {"address": "me@example.org"}},
                "internetMessageHeaders": [{"name": "List-Unsubscribe", "value": "<mailto:a@example.org>"}],
            }], "@odata.nextLink": GRAPH_BASE + "?$skiptoken=second"},
            {"value": []},
        ])
        source = GraphHeaders(session)
        approval = Approval("scan", "a", "graph", "{}", ("https://graph.microsoft.com",))
        first = source.page(None, approval)
        self.assertEqual(first.headers[0].unsubscribe, "<mailto:a@example.org>")
        self.assertTrue(source.page(first.cursor, approval).complete)

    def test_imap_uses_read_only_peek_and_checks_uidvalidity(self):
        settings = IMAPSettings("imap.example.org")
        approval = Approval("scan", "a", "imap", settings.selection, (settings.destination,))
        response = MagicMock()
        response.select.return_value = ("OK", [b"1"])
        response.response.side_effect = [("UIDVALIDITY", [b"12"]), ("UIDNEXT", [b"302"])]
        response.uid.return_value = ("OK", [
            (b"1 (UID 5 BODY[HEADER.FIELDS] {57}", b"From: test@example.org\r\nSubject: Welcome to Example\r\n\r\n"),
            b")",
        ])
        source = IMAPHeaders("owner@example.test", settings, "synthetic")
        with patch("account_privacy.discovery.imap.imaplib.IMAP4_SSL", return_value=response):
            first = source.page(None, approval)
            response.select.assert_called_once_with('"INBOX"', readonly=True)
            self.assertEqual(response.uid.call_args.args[:2], ("FETCH", "1:250"))
            self.assertIn("BODY.PEEK[HEADER.FIELDS", response.uid.call_args.args[2])
            self.assertEqual(first.headers[0].subject, "Welcome to Example")
            with self.assertRaises(InvalidCheckpoint):
                source.page("[31, 251, 301]", approval)
        source.close()
