import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from account_privacy.core.storage import Storage
from account_privacy.discovery.demo import ACCOUNT, SELECTION, DemoHeaders
from account_privacy.discovery.scan import Approval, HeaderDiscovery, run_scan
from account_privacy.requests.contacts import Contact, ContactKind
from account_privacy.requests.templates import Jurisdiction, make_draft
from account_privacy.ui.export import export_csv, safe_csv_text


class EndToEndTests(unittest.TestCase):
    def test_mock_inventory_to_filled_preview(self):
        repository = Storage(sqlite3.connect(":memory:", isolation_level=None))
        self.addCleanup(repository.close)
        repository.save_account(ACCOUNT)
        approval = Approval("scan", ACCOUNT.id, "demo", SELECTION, ())
        result = run_scan(repository, HeaderDiscovery(ACCOUNT, "demo", SELECTION, DemoHeaders()), approval)
        self.assertTrue(result.complete)
        self.assertEqual(result.processed, 7)
        rows = repository.inventory()
        expected = json.loads((Path(__file__).parent / "fixtures" / "demo_inventory.json").read_text())
        self.assertEqual({row.service_account.service.domain: row.confidence.points for row in rows}, expected)
        record = next(row.service_account for row in rows if row.service_account.service.domain == "example.org")
        contact = Contact("example.org", ContactKind.EMAIL, "privacy@example.org", "Synthetic contact")
        draft = make_draft(ACCOUNT, record, contact, "Demo Owner", Jurisdiction.GDPR)
        self.assertEqual(draft.contact.destination, "privacy@example.org")
        self.assertIn("Demo Owner", draft.body)
        self.assertIn("demo@example.test", draft.body)
        self.assertIn("Article 15", draft.body)
        self.assertEqual(repository.list_requests(), [])

    def test_export_neutralizes_spreadsheet_expressions(self):
        self.assertEqual(safe_csv_text("   =SUM(A1:A2)"), "'   =SUM(A1:A2)")
        self.assertEqual(safe_csv_text("@SUM(A1:A2)"), "'@SUM(A1:A2)")
        self.assertEqual(safe_csv_text("me@example.test"), "me@example.test")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            export_csv(path, [("example.org", "me@example.test", "=1+2", "70", "confirmed", "", "", "")])
            self.assertIn(",'=1+2,", path.read_text(encoding="utf-8-sig"))
