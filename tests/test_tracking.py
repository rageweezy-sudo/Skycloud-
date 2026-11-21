import sqlite3
import unittest
from datetime import UTC, date, datetime

from account_privacy.core.models import Account, Evidence, EvidenceCategory, Provider, Service, ServiceAccount
from account_privacy.core.storage import Storage
from account_privacy.discovery.evidence import MailHeader
from account_privacy.requests.tracking import deadline, match_reply, record_replies


class TrackingTests(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(sqlite3.connect(":memory:", isolation_level=None))
        self.addCleanup(self.storage.close)
        self.account = Account("a", "me@example.test", Provider.GRAPH)
        self.storage.save_account(self.account)
        self.service = ServiceAccount(Service("example.org"), "a", self.account.email)
        self.storage.add_evidence([Evidence(self.service, "test", "1", EvidenceCategory.SIGNUP)])
        self.sent = datetime(2024, 1, 31, 15, tzinfo=UTC)

    def request(self, kind, message, sent=None):
        sent = sent or self.sent
        record = self.storage.reserve_request(
            self.service, kind, "GDPR", 1, "email", "privacy@example.org", sent, None,
        )
        return self.storage.finish_request(record.id, "pending", "sent", sent, message, "shared-thread")

    def test_leap_month_and_thirty_day_countdown(self):
        record = self.request("access", "<one@example.org>")
        dates = deadline(record, date(2024, 2, 1), zone=UTC)
        self.assertEqual(dates.estimated_due, date(2024, 2, 29))
        self.assertEqual(dates.thirty_day_due, date(2024, 3, 1))
        self.assertEqual(dates.thirty_days_remaining, 29)
        adjusted = self.storage.adjust_request_deadline(record.id, date(2024, 4, 1), self.sent)
        self.assertEqual(deadline(adjusted, date(2024, 2, 1), zone=UTC).estimated_due, date(2024, 4, 1))

    def test_shared_thread_needs_unambiguous_request(self):
        first = self.request("access", "<one@example.org>")
        second = self.request("delete", "<two@example.org>", self.sent.replace(hour=16))
        reply = MailHeader(
            "r", sender="privacy@example.org", thread_id="shared-thread",
            recipients=self.account.email, in_reply_to="<two@example.org>",
        )
        self.assertEqual(match_reply(reply, self.account, [first, second]).request_id, second.id)
        vague = MailHeader("r", sender="privacy@example.org", thread_id="shared-thread", recipients=self.account.email)
        self.assertEqual(set(match_reply(vague, self.account, [first, second]).ambiguous), {first.id, second.id})
        self.assertIsNone(match_reply(MailHeader("r", sender="a@other.net", thread_id="shared-thread", recipients=self.account.email), self.account, [first]).request_id)
        self.assertIsNone(match_reply(MailHeader("r", sender=self.account.email, thread_id="shared-thread", recipients=self.account.email), self.account, [first]).request_id)
        record_replies(self.storage, self.account, [reply, reply])
        self.assertEqual(self.storage.get_request(second.id).state, "reply")
        self.assertEqual([event.kind for event in self.storage.request_events(second.id)], ["pending", "sent", "reply"])
