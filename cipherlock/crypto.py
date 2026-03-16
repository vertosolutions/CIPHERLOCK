from __future__ import annotations

import hashlib
import json
import os
import secrets
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .network_client import NetworkKeyClient, NetworkKeyError, derive_network_component
from .security import SecureByteArray, maybe_wipe, secure_delete_file
from .system_identity import get_or_create_system_id


@dataclass
class EncryptionOptions:
    max_attempts: int = -1
    random_filename: bool = False
    delete_original: bool = False
    require_lan_key: bool = False
    user_id: str = "default-user"


@dataclass
class DecryptionOptions:
    user_id: str = "default-user"



def _derive_key(password: SecureByteArray, salt: bytes, context: bytes = b"") -> SecureByteArray:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return SecureByteArray(kdf.derive(password + context))



def _encrypt_metadata(metadata: dict, key: bytes) -> bytes:
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    raw = json.dumps(metadata).encode("utf-8")
    return nonce + (encryptor.update(raw) + encryptor.finalize()) + encryptor.tag



def _decrypt_metadata(payload: bytes, key: bytes) -> dict:
    nonce, ciphertext, tag = payload[:12], payload[12:-16], payload[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    raw = decryptor.update(ciphertext) + decryptor.finalize()
    return json.loads(raw.decode("utf-8"))



def _pack_info(public_header: dict, encrypted_metadata: bytes) -> bytes:
    header_bytes = json.dumps(public_header).encode("utf-8")
    return len(header_bytes).to_bytes(4, "big") + header_bytes + encrypted_metadata



def _unpack_info(payload: bytes) -> tuple[dict, bytes]:
    header_len = int.from_bytes(payload[:4], "big")
    header = json.loads(payload[4 : 4 + header_len].decode("utf-8"))
    encrypted_metadata = payload[4 + header_len :]
    return header, encrypted_metadata



def _random_name(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class CipherEngine:
    def __init__(self, network_client: Optional[NetworkKeyClient] = None):
        self.network_client = network_client

    def encrypt_file(self, file_path: str, password: str, options: EncryptionOptions) -> str:
        plaintext = key = password_bytes = None
        part1 = part2 = None

        try:
            salt = os.urandom(16)
            nonce = os.urandom(12)
            password_bytes = SecureByteArray(password.encode("utf-8"))
            random_str = secrets.token_urlsafe(48)
            part1 = SecureByteArray(random_str[:32].encode("utf-8"))
            part2 = SecureByteArray(random_str[32:64].encode("utf-8"))

            network_nonce = os.urandom(16)
            network_required = options.require_lan_key
            network_component = b""
            system_id = get_or_create_system_id()
            if network_required:
                if not self.network_client:
                    raise NetworkKeyError("LAN policy enabled but no network client configured")
                key_share = self.network_client.fetch_key_share(options.user_id, system_id, network_nonce)
                network_component = derive_network_component(key_share, network_nonce)

            context = system_id.encode("utf-8") + network_component
            key = _derive_key(password_bytes, salt, context)

            plaintext = SecureByteArray(Path(file_path).read_bytes())
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            base_name = _random_name() if options.random_filename else Path(file_path).name
            enc_path = Path(file_path).with_name(f"{base_name}.enc")
            info_path = enc_path.with_suffix(".info")

            metadata = {
                "original_name": Path(file_path).name,
                "part2": bytes(part2).decode("utf-8"),
                "checksum": hashlib.sha256(bytes(part1) + bytes(part2)).hexdigest(),
            }
            public_header = {
                "network_required": network_required,
                "network_nonce": network_nonce.hex(),
            }
            info_path.write_bytes(_pack_info(public_header, _encrypt_metadata(metadata, key)))

            with enc_path.open("wb") as handle:
                handle.write(salt)
                handle.write(nonce)
                handle.write(options.max_attempts.to_bytes(4, "big", signed=True))
                handle.write(part1)
                handle.write(ciphertext)
                handle.write(encryptor.tag)

            if options.delete_original:
                secure_delete_file(file_path)

            return str(enc_path)
        finally:
            maybe_wipe(plaintext, key, password_bytes, part1, part2)

    def decrypt_file(self, encrypted_path: str, password: str, options: DecryptionOptions) -> str:
        plaintext = key = password_bytes = part1 = part2 = None
        info_path = Path(encrypted_path).with_suffix(".info")

        try:
            with open(encrypted_path, "r+b") as handle:
                salt = handle.read(16)
                nonce = handle.read(12)
                attempts = int.from_bytes(handle.read(4), "big", signed=True)
                part1 = SecureByteArray(handle.read(32))
                remaining = handle.read()

            if attempts == 0:
                raise PermissionError("Maximum attempts reached for this file")

            ciphertext, tag = remaining[:-16], remaining[-16:]
            public_header, encrypted_meta = _unpack_info(info_path.read_bytes())
            password_bytes = SecureByteArray(password.encode("utf-8"))

            try:
                key = self._resolve_key(password_bytes, salt, public_header, options)
                metadata = _decrypt_metadata(encrypted_meta, key)
            except Exception:
                self._decrement_attempts(encrypted_path, attempts)
                raise

            part2 = SecureByteArray(metadata["part2"].encode("utf-8"))
            checksum = hashlib.sha256(bytes(part1) + bytes(part2)).hexdigest()
            if checksum != metadata["checksum"]:
                self._decrement_attempts(encrypted_path, attempts)
                raise ValueError("Integrity verification failed")

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = SecureByteArray(decryptor.update(ciphertext) + decryptor.finalize())

            output_path = Path(encrypted_path).with_name(metadata["original_name"])
            output_path.write_bytes(plaintext)
            os.remove(encrypted_path)
            os.remove(info_path)
            return str(output_path)
        except InvalidTag as exc:
            raise ValueError("Wrong password or unauthorized network") from exc
        finally:
            maybe_wipe(plaintext, key, password_bytes, part1, part2)

    def _resolve_key(self, password: SecureByteArray, salt: bytes, header: dict, options: DecryptionOptions) -> SecureByteArray:
        system_id = get_or_create_system_id()
        network_component = b""

        if header.get("network_required"):
            if not self.network_client:
                raise NetworkKeyError("LAN file requires access to key-share service")
            network_nonce = bytes.fromhex(header["network_nonce"])
            key_share = self.network_client.fetch_key_share(options.user_id, system_id, network_nonce)
            network_component = derive_network_component(key_share, network_nonce)

        context = system_id.encode("utf-8") + network_component
        return _derive_key(password, salt, context)

    def _decrement_attempts(self, encrypted_path: str, attempts: int) -> None:
        if attempts < 0:
            return
        updated = attempts - 1
        with open(encrypted_path, "r+b") as handle:
            handle.seek(28)
            handle.write(updated.to_bytes(4, "big", signed=True))
        if updated <= 0:
            os.remove(encrypted_path)
            info_path = Path(encrypted_path).with_suffix(".info")
            if info_path.exists():
                os.remove(info_path)
