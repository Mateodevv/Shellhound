"""Windows filesystem paths for I/O, without changing stored artifact identities."""
import os

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    class _FileBasicInfo(ctypes.Structure):
        _fields_ = [(name, ctypes.c_longlong) for name in
                    ("creation", "access", "write", "change")] + [("attributes", wintypes.DWORD)]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _open_file = _kernel32.CreateFileW
    _open_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                           wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _open_file.restype = wintypes.HANDLE
    _file_info = _kernel32.GetFileInformationByHandleEx
    _file_info.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _file_info.restype = wintypes.BOOL
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = [wintypes.HANDLE]
    _close_handle.restype = wintypes.BOOL


def windows_change_time(path):
    """Metadata change time for cache validation, or None when unavailable."""
    if os.name != "nt":
        return None
    # Read attributes only, while allowing concurrent reads, writes and deletion.
    handle = _open_file(io_path(path), 0x80, 0x7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        return None
    try:
        info = _FileBasicInfo()
        if not _file_info(handle, 0, ctypes.byref(info), ctypes.sizeof(info)):
            return None
        return info.change or None
    finally:
        _close_handle(handle)


def display_path(path):
    value = os.fspath(path)
    if os.name == "nt":
        if value.upper().startswith("\\\\?\\UNC\\"):
            return "\\\\" + value[8:]
        if value.startswith("\\\\?\\"):
            return value[4:]
    return value


def io_path(path):
    """Use extended paths for local drives and UNC shares, including children.

    Normalize before adding the prefix: Windows stops interpreting `..` in
    extended paths. Callers must still resolve symlinks and enforce scope.
    """
    value = os.fspath(path)
    if os.name != "nt":
        return value
    value = os.path.abspath(display_path(value))
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value
