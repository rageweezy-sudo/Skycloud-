import importlib.util
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from account_privacy.core.storage import Storage
from account_privacy.discovery.scan import Approval


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is unavailable")
class UITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def test_mock_scan_and_service_filter_through_window(self):
        from account_privacy.ui.main_window import MainWindow

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        storage = Storage(sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False))
        window = MainWindow(storage, Mock(), Path(directory.name) / "AccountPrivacy")
        self.addCleanup(window.close)

        def consent(parent, **fields):
            return Approval(fields["operation"], fields["account_id"], fields["source"], fields["selection"], ())

        with patch("account_privacy.ui.main_window.confirm_operation", side_effect=consent) as prompt:
            window.scan_demo()
            stop = time.monotonic() + 10
            while window._job is not None and time.monotonic() < stop:
                self.app.processEvents()
            self.assertIsNone(window._job)
            prompt.assert_called_once()
        self.assertEqual(window.services.rowCount(), 4)
        window.search.setText("example.org")
        self.assertEqual(window.services.rowCount(), 1)

        def sample_item(parent, title, label, options, *args):
            return options[0], True

        with (
            patch("account_privacy.ui.main_window.QInputDialog.getItem", side_effect=sample_item),
            patch("account_privacy.ui.main_window.form_values", return_value=("Demo Owner",)),
            patch("account_privacy.ui.main_window.preview_request", return_value=None) as preview,
        ):
            window.services.selectRow(0)
            from account_privacy.requests.templates import RequestKind

            window.prepare_selected(RequestKind.ACCESS)
            draft = preview.call_args.args[1]
            self.assertIn("Demo Owner", draft.body)
            self.assertEqual(draft.contact.destination, "privacy@example.org")
            self.assertTrue(preview.call_args.kwargs["demo"])
        self.assertEqual(storage.list_requests(), [])
