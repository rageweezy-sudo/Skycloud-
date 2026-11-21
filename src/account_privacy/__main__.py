import os
import sys
from pathlib import Path

from account_privacy.core.credentials import CredentialError, WindowsCredentialVault
from account_privacy.core.local_files import local_path
from account_privacy.core.storage import StorageError, open_storage


def main() -> int:
    if sys.platform != "win32":
        print("Account Privacy requires Windows 11.", file=sys.stderr)
        return 1

    from PySide6.QtCore import QLockFile
    from PySide6.QtWidgets import QApplication, QMessageBox

    from account_privacy.ui.main_window import MainWindow
    from account_privacy.ui.windows import APP_ID

    import ctypes

    shell = ctypes.WinDLL("shell32")
    shell.SetCurrentProcessExplicitAppUserModelID.argtypes = (ctypes.c_wchar_p,)
    shell.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    app = QApplication(sys.argv)
    app.setApplicationName("Account Privacy")
    app.setOrganizationName("Account Privacy")
    storage = None
    lock = None
    try:
        root = os.environ.get("LOCALAPPDATA")
        if not root:
            raise StorageError("Windows did not provide a local app data folder")
        data_path = local_path(Path(root) / "AccountPrivacy")
        lock = QLockFile(str(data_path.parent / "AccountPrivacy.instance.lock"))
        if not lock.tryLock(0):
            QMessageBox.warning(None, "Account Privacy", "Another copy is already running or the local lock is unavailable.")
            return 1
        vault = WindowsCredentialVault()
        storage = open_storage(data_path / "inventory.db", vault)
        window = MainWindow(storage, vault, data_path)
        window.show()
        return app.exec()
    except (StorageError, CredentialError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, (StorageError, CredentialError)) else "Could not open the local app data."
        QMessageBox.critical(None, "Account Privacy", message)
        return 1
    finally:
        if storage is not None:
            storage.close()
        if lock is not None and lock.isLocked():
            lock.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
