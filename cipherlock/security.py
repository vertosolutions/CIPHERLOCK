import os
from typing import Optional



def secure_wipe(data: object) -> None:
    """Best-effort secure memory wipe for byte-like objects."""
    if isinstance(data, bytes):
        data = bytearray(data)
    if isinstance(data, bytearray):
        for index in range(len(data)):
            data[index] = 0


class SecureByteArray(bytearray):
    """Bytearray that wipes itself when garbage collected."""

    def __del__(self) -> None:
        secure_wipe(self)



def secure_delete_file(path: str) -> None:
    """Overwrite and remove a file from disk."""
    size = os.path.getsize(path)
    with open(path, "r+b") as handle:
        handle.write(os.urandom(size))
        handle.flush()
        os.fsync(handle.fileno())
    os.remove(path)



def maybe_wipe(*values: Optional[object]) -> None:
    for value in values:
        if value is not None:
            secure_wipe(value)
