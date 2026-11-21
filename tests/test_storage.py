import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from account_privacy.core.credentials import CredentialError, WindowsCredentialVault
from account_privacy.core.models import Account, Evidence, EvidenceCategory, Provider, ReviewState, Service, ServiceAccount
from account_privacy.core.storage import ScanConflict, Storage, StorageError, open_storage


class MemoryVault:
    def __init__(self):
        self.items = {}

    def read(self, name):
        return self.items.get(name)

    def write(self, name, value):
        self.items[name] = value

    def delete(self, name):
        self.items.pop(name, None)


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        # Exercise SQL and transactions without touching a plaintext file.
        self.repository = Storage(sqlite3.connect(":memory:", isolation_level=None))
        self.addCleanup(self.repository.close)
        self.repository.save_account(Account("one", "one@example.test", Provider.LOCAL))
        self.repository.save_account(Account("two", "two@example.test", Provider.LOCAL))

    def test_replay_collapses_evidence_and_preserves_user_review(self):
        record = ServiceAccount(Service("example.com"), "one", "one@example.test", "https://example.com")
        evidence = Evidence(record, "csv", "row", EvidenceCategory.IMPORT)
        self.repository.add_evidence([evidence, evidence])
        self.repository.set_review(record, ReviewState.DISMISSED)
        self.repository.add_evidence([evidence])
        found = self.repository.inventory()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].service_account.review, ReviewState.DISMISSED)
        self.assertEqual(found[0].evidence_count, 1)
        self.assertEqual(found[0].confidence.points, 80)

    def test_accounts_and_usernames_remain_distinct(self):
        service = Service("example.com")
        records = [ServiceAccount(service, "one", "a"), ServiceAccount(service, "one", "b"), ServiceAccount(service, "two", "a")]
        self.repository.add_evidence([Evidence(record, "csv", "row", EvidenceCategory.IMPORT) for record in records])
        self.assertCountEqual([entry.service_account for entry in self.repository.inventory()], records)

    def test_ambiguous_signals_do_not_raise_attributed_score(self):
        record = ServiceAccount(Service("example.com"), "one")
        self.repository.add_evidence([Evidence(record, "mail", "1", EvidenceCategory.SIGNUP, ambiguous=True)])
        self.assertEqual(self.repository.inventory()[0].confidence.points, 44)
        self.repository.add_evidence([Evidence(record, "mail", "2", EvidenceCategory.RECEIPT)])
        self.assertEqual(self.repository.inventory()[0].confidence.points, 35)

    def test_checkpoint_failure_rolls_back_evidence_and_stale_writer_is_rejected(self):
        record = ServiceAccount(Service("example.com"), "one")
        run = self.repository.create_scan("one", "csv", "{}")
        good = Evidence(record, "csv", "1", EvidenceCategory.IMPORT)
        wrong = Evidence(ServiceAccount(Service("other.com"), "two"), "csv", "2", EvidenceCategory.IMPORT)
        with self.assertRaises(StorageError):
            self.repository.commit_page(run.id, 0, [good, wrong], "next", 2)
        self.assertEqual(self.repository.inventory(), [])
        self.assertEqual(self.repository.get_scan(run.id), run)
        updated = self.repository.commit_page(run.id, 0, [good], "next", 1)
        self.assertEqual((updated.cursor, updated.revision, updated.processed), ("next", 1, 1))
        with self.assertRaises(ScanConflict):
            self.repository.commit_page(run.id, 0, [], "stale", 1)
        self.assertEqual(self.repository.inventory()[0].evidence_count, 1)

    def test_storage_sanitizes_origins_even_if_a_caller_forgets(self):
        record = ServiceAccount(Service("example.com"), "one", origin="https://u:secret@example.com/private")
        self.repository.add_evidence([Evidence(record, "csv", "1", EvidenceCategory.IMPORT)])
        self.assertEqual(self.repository.inventory()[0].service_account.origin, "https://example.com")

    def test_migration_runs_once_and_rejects_a_newer_schema(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        Storage(connection)
        before = connection.execute("PRAGMA user_version").fetchone()[0]
        self.assertGreater(before, 0)
        Storage(connection)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], before)
        connection.execute("PRAGMA user_version = 100")
        with self.assertRaises(StorageError):
            Storage(connection)


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "inventory.db"
        self.vault = MemoryVault()

    def test_missing_cipher_leaves_no_files_or_credentials(self):
        with patch("account_privacy.core.storage._load_driver", side_effect=ImportError):
            with self.assertRaises(StorageError):
                open_storage(self.path, self.vault)
        self.assertEqual(list(self.path.parent.iterdir()), [])
        self.assertEqual(self.vault.items, {})

    def test_sqlite_cannot_silently_replace_sqlcipher(self):
        with patch("account_privacy.core.storage._load_driver", return_value=sqlite3):
            with self.assertRaises(StorageError):
                open_storage(self.path, self.vault)
        self.assertEqual(list(self.path.parent.iterdir()), [])
        self.assertEqual(self.vault.items, {})

    def test_unavailable_vault_leaves_no_database(self):
        class FailingVault(MemoryVault):
            def read(self, name):
                raise CredentialError("Test vault unavailable")

        class CipherProbe:
            def execute(self, query):
                return self

            def fetchone(self):
                return ("4.0",)

            def close(self):
                pass

        with (
            patch("account_privacy.core.storage._load_driver", return_value=sqlite3),
            patch.object(sqlite3, "connect", return_value=CipherProbe()) as connect,
        ):
            with self.assertRaises(StorageError):
                open_storage(self.path, FailingVault())
        connect.assert_called_once_with(":memory:")
        self.assertFalse(self.path.exists())

    def test_sqlcipher_ciphertext_reopens_and_rejects_wrong_key(self):
        try:
            import sqlcipher3  # noqa: F401
        except ImportError:
            self.skipTest("The SQLCipher binding is unavailable")
        repository = open_storage(self.path, self.vault)
        self.addCleanup(repository.close)
        repository.save_account(Account("one", "sensitive@example.test", Provider.LOCAL))
        repository.close()
        content = self.path.read_bytes()
        self.assertFalse(content.startswith(b"SQLite format 3"))
        self.assertNotIn(b"sensitive@example.test", content)
        reopened = open_storage(self.path, self.vault)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.list_accounts()[0].email, "sensitive@example.test")
        reopened.close()
        reference, key = next(iter(self.vault.items.items()))
        self.vault.write(reference, bytes(value ^ 255 for value in key))
        with self.assertRaises(StorageError):
            open_storage(self.path, self.vault)

    @unittest.skipUnless(sys.platform == "win32", "Requires Windows Credential Manager")
    def test_windows_credential_vault_round_trip(self):
        vault = WindowsCredentialVault()
        name = "test/" + uuid4().hex
        self.addCleanup(vault.delete, name)
        self.assertIsNone(vault.read(name))
        vault.write(name, b"synthetic-token")
        self.assertEqual(vault.read(name), b"synthetic-token")
        vault.delete(name)
        self.assertIsNone(vault.read(name))
