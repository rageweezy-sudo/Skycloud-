from pathlib import Path

from PyInstaller.utils.hooks import collect_dynamic_libs

root = Path(SPECPATH).resolve().parent
source = root / "src"
package = source / "account_privacy"
analysis = Analysis(
    [str(package / "__main__.py")],
    pathex=[str(source)],
    binaries=collect_dynamic_libs("sqlcipher3"),
    datas=[
        (str(package / "resources"), "account_privacy/resources"),
        (str(package / "core" / "migrations"), "account_privacy/core/migrations"),
    ],
    hiddenimports=["sqlcipher3.dbapi2", "PySide6.QtPrintSupport"],
    excludes=["tkinter", "pytest"],
    noarchive=False,
)
archive = PYZ(analysis.pure)
executable = EXE(
    archive,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="AccountPrivacy",
    console=False,
    upx=False,
)
bundle = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    upx=False,
    name="AccountPrivacy",
)
