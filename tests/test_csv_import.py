import tempfile
import unittest
from pathlib import Path

from account_privacy.core.models import Account, Provider
from account_privacy.discovery.csv_import import CSVDiscovery, ExportFormat
from account_privacy.discovery.scan import Approval, InvalidCheckpoint


class CSVImportTests(unittest.TestCase):
    def test_each_format_emits_only_origin_and_username(self):
        fixtures = {
            ExportFormat.CHROME: "name,url,username,password,note",
            ExportFormat.EDGE: "name,url,username,password,note",
            ExportFormat.FIREFOX: "name,url,username,password,note",
            ExportFormat.BRAVE: "name,url,username,password,note",
            ExportFormat.BITWARDEN: "name,login_uri,login_username,login_password,notes",
            ExportFormat.ONEPASSWORD: "Title,Website,Username,Password,Notes",
            ExportFormat.KEEPASS: "Account,Web Site,Login Name,Password,Comments",
        }
        for kind, header in fixtures.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "export.csv"
                path.write_text(header + '\nTest,https://example.org/path/password,me@example.test,unique-password,sensitive-note\n', encoding="utf-8")
                source = CSVDiscovery(Account("a", "me@example.test", Provider.LOCAL), path, kind)
                approval = Approval("scan", "a", source.name, source.selection, ())
                page = source.page(None, approval)
                source.close()
                self.assertTrue(page.complete)
                self.assertEqual(len(page.evidence), 1)
                record = page.evidence[0].service_account
                self.assertEqual((record.origin, record.username), ("https://example.org", "me@example.test"))
                self.assertNotIn("unique-password", repr(page))
                self.assertNotIn("sensitive-note", repr(page))

    def test_changed_file_resume_restarts_and_row_replay_has_stable_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.csv"
            path.write_text("url,username,password\nhttps://example.org,a,secret\n", encoding="utf-8")
            account = Account("a", "me@example.test", Provider.LOCAL)
            source = CSVDiscovery(account, path, ExportFormat.CHROME, page_size=1)
            approval = Approval("scan", "a", source.name, source.selection, ())
            page = source.page(None, approval)
            self.assertFalse(page.complete)
            source.close()
            path.write_text("url,username,password\nhttps://example.org,a,changed\n", encoding="utf-8")
            resumed = CSVDiscovery(account, path, ExportFormat.CHROME)
            with self.assertRaises(InvalidCheckpoint):
                resumed.page(page.cursor, approval)
            restarted = resumed.page(None, approval)
            self.assertEqual(page.evidence[0].item_id, restarted.evidence[0].item_id)
            resumed.close()
