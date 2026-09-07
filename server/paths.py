"""Windows filesystem paths for I/O, without changing stored artifact identities."""
import os


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
