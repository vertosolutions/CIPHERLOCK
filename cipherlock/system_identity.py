import hashlib
import os
import platform
import uuid
from pathlib import Path


SYSTEM_ID_FILE = Path.home() / ".cipherlock_system_id"



def hide_file(filepath: Path) -> None:
    if platform.system() == "Windows":
        os.system(f'attrib +h "{filepath}"')



def get_or_create_system_id() -> str:
    if SYSTEM_ID_FILE.exists():
        return SYSTEM_ID_FILE.read_text(encoding="utf-8").strip()

    seed = f"{uuid.getnode()}:{platform.node()}:{platform.system()}"
    fingerprint = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    SYSTEM_ID_FILE.write_text(fingerprint, encoding="utf-8")
    hide_file(SYSTEM_ID_FILE)
    return fingerprint
