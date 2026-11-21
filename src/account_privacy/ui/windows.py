import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

APP_ID = "AccountPrivacy.Desktop"
_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 2


def copy_private_text(text: str, window_handle: int) -> int:
    """Set clipboard data with Windows history and sync disabled for this item."""
    if sys.platform != "win32":
        raise RuntimeError("Private clipboard handling requires Windows")
    user = ctypes.WinDLL("user32", use_last_error=True)
    memory = ctypes.WinDLL("kernel32", use_last_error=True)
    user.OpenClipboard.argtypes = (wintypes.HWND,)
    user.OpenClipboard.restype = wintypes.BOOL
    user.SetClipboardData.argtypes = (wintypes.UINT, wintypes.HANDLE)
    user.SetClipboardData.restype = wintypes.HANDLE
    user.RegisterClipboardFormatW.argtypes = (wintypes.LPCWSTR,)
    user.RegisterClipboardFormatW.restype = wintypes.UINT
    user.GetClipboardSequenceNumber.restype = wintypes.DWORD
    memory.GlobalAlloc.argtypes = (wintypes.UINT, ctypes.c_size_t)
    memory.GlobalAlloc.restype = wintypes.HGLOBAL
    memory.GlobalLock.argtypes = (wintypes.HGLOBAL,)
    memory.GlobalLock.restype = ctypes.c_void_p
    memory.GlobalUnlock.argtypes = (wintypes.HGLOBAL,)
    memory.GlobalFree.argtypes = (wintypes.HGLOBAL,)

    def set_data(format_id: int, payload: bytes) -> None:
        handle = memory.GlobalAlloc(_GMEM_MOVEABLE, len(payload))
        if not handle:
            raise RuntimeError("Could not allocate clipboard data")
        try:
            address = memory.GlobalLock(handle)
            if not address:
                raise RuntimeError("Could not access clipboard data")
            ctypes.memmove(address, payload, len(payload))
            memory.GlobalUnlock(handle)
            if not user.SetClipboardData(format_id, handle):
                raise RuntimeError("Could not set clipboard data")
        except BaseException:
            memory.GlobalFree(handle)
            raise

    if not user.OpenClipboard(window_handle):
        raise RuntimeError("Could not open Windows clipboard")
    try:
        if not user.EmptyClipboard():
            raise RuntimeError("Could not clear Windows clipboard")
        for name in ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
            format_id = user.RegisterClipboardFormatW(name)
            if not format_id:
                raise RuntimeError("Could not disable clipboard synchronization")
            set_data(format_id, bytes(4))
        set_data(_CF_UNICODETEXT, text.encode("utf-16-le") + b"\0\0")
    except BaseException:
        user.EmptyClipboard()
        raise
    finally:
        user.CloseClipboard()
    return user.GetClipboardSequenceNumber()


def clear_private_text(sequence: int, window_handle: int) -> None:
    if sys.platform != "win32":
        return
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.OpenClipboard.argtypes = (wintypes.HWND,)
    user.OpenClipboard.restype = wintypes.BOOL
    user.GetClipboardSequenceNumber.restype = wintypes.DWORD
    if user.GetClipboardSequenceNumber() != sequence or not user.OpenClipboard(window_handle):
        return
    try:
        if user.GetClipboardSequenceNumber() == sequence:
            user.EmptyClipboard()
    finally:
        user.CloseClipboard()


def show_reminder() -> bool:
    if sys.platform != "win32":
        return False
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = root / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = r"""
[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
[Windows.UI.Notifications.ToastNotification,Windows.UI.Notifications,ContentType=WindowsRuntime] | Out-Null
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
    [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$text = $xml.GetElementsByTagName('text')
$text.Item(0).AppendChild($xml.CreateTextNode('Account Privacy')) | Out-Null
$text.Item(1).AppendChild($xml.CreateTextNode('A request deadline is approaching or overdue.')) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('AccountPrivacy.Desktop').Show($toast)
"""
    try:
        subprocess.Popen(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except OSError:
        return False
    return True
