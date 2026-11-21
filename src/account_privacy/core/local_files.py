"""Path checks shared by local imports, exports, and app storage."""
import os
import stat
import sys
from pathlib import Path


def local_path(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if sys.platform != "win32":
        return path
    import ctypes

    if not path.drive or path.drive.startswith(("\\", "//")):
        raise ValueError("Choose a file on a local drive")
    if ctypes.windll.kernel32.GetDriveTypeW(path.anchor) not in (2, 3, 5, 6):
        raise ValueError("Choose a file on a local drive")
    for ancestor in (*reversed(path.parents), path):
        try:
            attributes = ancestor.lstat().st_file_attributes
        except FileNotFoundError:
            continue
        if attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Choose a direct path on a local drive")
    return path
