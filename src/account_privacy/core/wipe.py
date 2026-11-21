import shutil
from pathlib import Path

from .credentials import CredentialError
from .local_files import local_path


class WipeError(RuntimeError):
    pass


def wipe_app_data(data_directory: Path, vault) -> None:
    """Call only after user confirmation and shutdown of all app jobs and database handles."""
    path = local_path(data_directory)
    if path.name != "AccountPrivacy" or path.parent == path:
        raise WipeError("Could not verify the app data location")
    failed = []
    try:
        if path.exists():
            shutil.rmtree(path)
    except OSError:
        failed.append("local files")
    try:
        vault.delete_all()
    except CredentialError:
        failed.append("saved credentials")
    if failed:
        raise WipeError("Could not remove " + " and ".join(failed))
