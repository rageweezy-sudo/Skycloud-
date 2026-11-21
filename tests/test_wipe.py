import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from account_privacy.core.credentials import CredentialError
from account_privacy.core.wipe import WipeError, wipe_app_data


class WipeTests(unittest.TestCase):
    def test_only_app_directory_and_vault_are_wiped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "AccountPrivacy"
            app.mkdir()
            for name in ("inventory.db", "inventory.db-journal", "inventory.db-wal", "inventory.db-shm"):
                (app / name).write_bytes(b"synthetic")
            export = root / "my-report.csv"
            export.touch()
            vault = Mock()
            wipe_app_data(app, vault)
            self.assertFalse(app.exists())
            self.assertTrue(export.exists())
            vault.delete_all.assert_called_once_with()

    def test_partial_failure_can_be_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / "AccountPrivacy"
            app.mkdir()
            vault = Mock()
            vault.delete_all.side_effect = [CredentialError("synthetic"), None]
            with self.assertRaises(WipeError):
                wipe_app_data(app, vault)
            self.assertFalse(app.exists())
            wipe_app_data(app, vault)
