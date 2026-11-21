import ctypes
import sys
from ctypes import wintypes
from typing import Protocol


class CredentialError(RuntimeError):
    pass


class CredentialVault(Protocol):
    def read(self, name: str) -> bytes | None: ...
    def write(self, name: str, value: bytes) -> None: ...
    def delete(self, name: str) -> None: ...


class _Credential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


_PCredential = ctypes.POINTER(_Credential)


class WindowsCredentialVault:
    PREFIX = "AccountPrivacy/"
    _GENERIC = 1
    _LOCAL_MACHINE = 2
    _NOT_FOUND = 1168
    _MAX_BLOB = 2560

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise CredentialError("Windows Credential Manager is unavailable")
        api = ctypes.WinDLL("Advapi32", use_last_error=True)
        api.CredReadW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_PCredential))
        api.CredReadW.restype = wintypes.BOOL
        api.CredWriteW.argtypes = (_PCredential, wintypes.DWORD)
        api.CredWriteW.restype = wintypes.BOOL
        api.CredDeleteW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD)
        api.CredDeleteW.restype = wintypes.BOOL
        api.CredEnumerateW.argtypes = (
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.POINTER(_PCredential)),
        )
        api.CredEnumerateW.restype = wintypes.BOOL
        api.CredFree.argtypes = (ctypes.c_void_p,)
        api.CredFree.restype = None
        self._api = api

    def read(self, name: str) -> bytes | None:
        result = _PCredential()
        if not self._api.CredReadW(self.PREFIX + name, self._GENERIC, 0, ctypes.byref(result)):
            if ctypes.get_last_error() == self._NOT_FOUND:
                return None
            raise CredentialError("Could not read from Windows Credential Manager")
        try:
            credential = result.contents
            return ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        finally:
            self._api.CredFree(result)

    def write(self, name: str, value: bytes) -> None:
        if not 0 < len(value) <= self._MAX_BLOB:
            raise CredentialError("Credential size is unsupported")
        blob = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        try:
            credential = _Credential(
                Type=self._GENERIC,
                TargetName=self.PREFIX + name,
                CredentialBlobSize=len(blob),
                CredentialBlob=ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte)),
                Persist=self._LOCAL_MACHINE,
                UserName="AccountPrivacy",
            )
            if not self._api.CredWriteW(ctypes.byref(credential), 0):
                raise CredentialError("Could not write to Windows Credential Manager")
        finally:
            ctypes.memset(blob, 0, len(blob))

    def delete(self, name: str) -> None:
        deleted = self._api.CredDeleteW(self.PREFIX + name, self._GENERIC, 0)
        if not deleted and ctypes.get_last_error() != self._NOT_FOUND:
            raise CredentialError("Could not remove from Windows Credential Manager")

    def delete_all(self) -> None:
        count = wintypes.DWORD()
        credentials = ctypes.POINTER(_PCredential)()
        if not self._api.CredEnumerateW(self.PREFIX + "*", 0, ctypes.byref(count), ctypes.byref(credentials)):
            if ctypes.get_last_error() == self._NOT_FOUND:
                return
            raise CredentialError("Could not enumerate app credentials")
        try:
            names = [
                credentials[index].contents.TargetName.removeprefix(self.PREFIX)
                for index in range(count.value)
                if credentials[index].contents.TargetName.startswith(self.PREFIX)
                and credentials[index].contents.Type == self._GENERIC
            ]
        finally:
            self._api.CredFree(credentials)
        failed = False
        for name in names:
            try:
                self.delete(name)
            except CredentialError:
                failed = True
        if failed:
            raise CredentialError("Some app credentials could not be removed")
