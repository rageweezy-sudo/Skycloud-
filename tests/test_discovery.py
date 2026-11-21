import sqlite3
import unittest
from datetime import UTC, datetime

from account_privacy.core.models import Account, Provider
from account_privacy.core.storage import Storage
from account_privacy.discovery.evidence import MailHeader, classify_header
from account_privacy.discovery.scan import (
    Approval, ApprovalError, HeaderDiscovery, HeaderPage, InvalidCheckpoint, run_scan,
)


class FakeHeaders:
    destination = "https://example.test"

    def __init__(self, total, break_at=None):
        self.total = total
        self.break_at = break_at
        self.calls = []
        self.largest = 0

    def page(self, cursor, approval):
        approval.require_destination(self.destination)
        first = int(cursor or 0)
        self.calls.append(first)
        if first == self.break_at:
            self.break_at = None
            raise InvalidCheckpoint()
        end = min(first + 200, self.total)
        headers = tuple(
            MailHeader(str(i), "Example <noreply@example.com>", "Verify your account" if i == 0 else "News")
            for i in range(first, end)
        )
        self.largest = max(self.largest, len(headers))
        return HeaderPage(headers, str(end) if end < self.total else None, self.total, end == self.total)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.repository = Storage(sqlite3.connect(":memory:", isolation_level=None))
        self.addCleanup(self.repository.close)
        self.account = Account("a", "me@example.test", Provider.GMAIL)
        self.other = Account("b", "other@example.test", Provider.GMAIL)
        for account in (self.account, self.other):
            self.repository.save_account(account)

    def test_without_matching_consent_does_not_call_source(self):
        headers = FakeHeaders(1)
        source = HeaderDiscovery(self.account, "gmail", "{}", headers)
        approval = Approval("scan", "b", "gmail", "{}", (headers.destination,))
        with self.assertRaises(ApprovalError):
            run_scan(self.repository, source, approval)
        self.assertEqual(headers.calls, [])

    def test_large_paginated_scan_resumes_and_recovers_expired_cursor(self):
        headers = FakeHeaders(100_001, break_at=400)
        source = HeaderDiscovery(self.account, "gmail", "{}", headers)
        def grant():
            return Approval("scan", "a", "gmail", "{}", (headers.destination,))
        approval = grant()
        run = run_scan(self.repository, source, approval, progress=lambda run: approval.close())
        self.assertEqual(run.processed, 200)
        resumed = run_scan(self.repository, source, grant(), run.id)
        self.assertTrue(resumed.complete)
        self.assertEqual(resumed.processed, 100_001)
        self.assertEqual(headers.calls[:4], [0, 200, 400, 0])
        self.assertLessEqual(headers.largest, 200)
        result = self.repository.inventory()
        self.assertEqual([(row.service_account.service.domain, row.evidence_count) for row in result], [("example.com", 1)])

    def test_shared_sender_without_attribution_is_not_a_service(self):
        message = MailHeader("1", "someone@sendgrid.net", "Confirm your email")
        self.assertEqual(classify_header(message, self.account, "gmail"), ())
        linked = MailHeader(
            "2", "someone@sendgrid.net", "Confirm your email",
            "<https://unsubscribe.example.com/some-token>", datetime(2025, 4, 1, tzinfo=UTC),
        )
        evidence = classify_header(linked, self.account, "gmail")
        self.assertEqual({row.service_account.service.domain for row in evidence}, {"example.com"})
        self.assertTrue(all(row.ambiguous for row in evidence))

    def test_self_sent_and_plain_promotions_are_excluded(self):
        for message in (
            MailHeader("1", self.account.email, "Verify your account"),
            MailHeader("2", "ads@example.com", "A newsletter about us"),
        ):
            self.assertEqual(classify_header(message, self.account, "gmail"), ())
