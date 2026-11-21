import sqlite3
import unittest
from datetime import UTC, datetime
from unittest.mock import Mock

from account_privacy.core.models import Account, Evidence, EvidenceCategory, Provider, Service, ServiceAccount
from account_privacy.core.storage import Storage
from account_privacy.discovery.scan import Approval, ApprovalError
from account_privacy.requests.contacts import Contact, ContactKind, Catalog, ContactError, mail_address
from account_privacy.requests.delivery import Delivery, DeliveryError, Receipt
from account_privacy.requests.templates import Draft, Jurisdiction, RequestKind, make_draft


class RequestsTests(unittest.TestCase):
    def setUp(self):
        self.storage = Storage(sqlite3.connect(":memory:", isolation_level=None))
        self.addCleanup(self.storage.close)
        self.account = Account("a", "owner@example.test", Provider.GMAIL)
        self.record = ServiceAccount(Service("example.org"), "a", self.account.email)
        self.storage.save_account(self.account)
        self.storage.add_evidence([Evidence(self.record, "mock", "1", EvidenceCategory.SIGNUP)])
        self.contact = Contact("example.org", ContactKind.EMAIL, "privacy@example.org", "Local fixture")
        self.draft = make_draft(self.account, self.record, self.contact, "Taylor Example", Jurisdiction.GDPR)
        self.delivery = Delivery(self.storage, now=lambda: datetime(2025, 2, 3, tzinfo=UTC))

    def assert_preview(self, draft: Draft):
        self.assertIn("Taylor Example", draft.body)
        self.assertIn(self.account.email, draft.body)
        self.assertIn("Article 15", draft.body)
        self.assertNotIn(draft.body, repr(draft))

    @staticmethod
    def approve(draft, operation="send"):
        return Approval(operation, draft.account.id, draft.account.provider, draft.digest, ("https://gmail.googleapis.com",))

    def test_preview_approval_binds_exact_content_and_records_sent(self):
        self.assert_preview(self.draft)
        transport = Mock()
        transport.submit.return_value = Receipt("<reply@example.org>", "123")
        edited = self.draft.edited(self.draft.subject, self.draft.body + "\nExtra")
        with self.assertRaises(ApprovalError):
            self.delivery.send(edited, self.approve(self.draft), transport)
        transport.submit.assert_not_called()
        receipt = self.delivery.send(self.draft, self.approve(self.draft), transport)
        self.assertEqual((receipt.state, receipt.thread_id), ("sent", "123"))
        self.assertEqual([event.kind for event in self.storage.request_events(receipt.id)], ["pending", "sent"])

    def test_uncertain_provider_result_is_not_retried(self):
        transport = Mock()
        transport.submit.side_effect = OSError("synthetic connection lost")
        request = self.delivery.send(self.draft, self.approve(self.draft), transport)
        self.assertEqual(request.state, "uncertain")
        with self.assertRaises(DeliveryError):
            self.delivery.send(self.draft, self.approve(self.draft), transport)
        self.assertEqual(transport.submit.call_count, 1)

    def test_rate_limit_survives_new_delivery_instance(self):
        transport = Mock()
        transport.submit.return_value = Receipt(None, None)
        self.delivery.send(self.draft, self.approve(self.draft), transport)
        next_delivery = Delivery(self.storage, now=self.delivery.now)
        with self.assertRaises(DeliveryError):
            next_delivery.send(self.draft.edited("Second request", "Changed"), self.approve(self.draft.edited("Second request", "Changed")), transport)
        self.assertEqual(transport.submit.call_count, 1)

    def test_deletion_needs_an_additional_confirmation(self):
        draft = make_draft(self.account, self.record, self.contact, "Taylor Example", Jurisdiction.CCPA, RequestKind.DELETE)
        transport = Mock()
        transport.submit.return_value = Receipt(None, None)
        with self.assertRaises(ApprovalError):
            self.delivery.send(draft, self.approve(draft), transport)
        transport.submit.assert_not_called()
        self.delivery.send(draft, self.approve(draft), transport, deletion=self.approve(draft, "delete"))
        transport.submit.assert_called_once()

    def test_portal_opens_and_copies_without_recording_submission(self):
        contact = Contact("example.org", ContactKind.PORTAL, "https://example.org/privacy", "Local fixture")
        draft = make_draft(self.account, self.record, contact, "Taylor Example", Jurisdiction.UK_GDPR)
        approval = Approval("portal", "a", Provider.GMAIL, draft.digest, ("https://example.org",))
        open_browser, clipboard = Mock(return_value=True), Mock()
        request = self.delivery.portal(draft, approval, open_browser, clipboard)
        self.assertEqual(request.state, "portal_pending")
        open_browser.assert_called_once_with(contact.destination)
        clipboard.assert_called_once_with(draft.body)
        self.assertEqual(self.delivery.confirm_portal_submission(request.id).state, "sent")

    def test_catalog_rejects_unsafe_updates(self):
        for destination in ("http://example.org/privacy", "https://owner:secret@example.org/privacy", "file:///C:/a"):
            data = '{"version": 1, "contacts": [{"domain": "example.org", "kind": "portal", "source": "test", "destination": "' + destination + '"}]}'
            with self.subTest(destination=destination), self.assertRaises(ContactError):
                Catalog.from_json(data)

    def test_malformed_email_shows_a_validation_error(self):
        for address in ("@example.org", "a@@example.org", "a@", "owner@example.org\nBcc: other@example.org"):
            with self.subTest(address=address), self.assertRaises(ContactError):
                mail_address(address)
