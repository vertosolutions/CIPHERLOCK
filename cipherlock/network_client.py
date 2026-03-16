from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class NetworkPolicy:
    server_url: str
    tenant: str
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    ca_cert: Optional[str] = None
    timeout_seconds: int = 5


class NetworkKeyError(RuntimeError):
    pass


class NetworkKeyClient:
    """Client for LAN key-share service.

    The service returns a key share only for authorized clients connected to
    the corporate network and presenting a valid mTLS certificate.
    """

    def __init__(self, policy: NetworkPolicy):
        self.policy = policy

    def fetch_key_share(self, user_id: str, system_id: str, file_nonce: bytes) -> bytes:
        url = f"{self.policy.server_url.rstrip('/')}/v1/keyshare"
        payload = {
            "tenant": self.policy.tenant,
            "user_id": user_id,
            "system_id": system_id,
            "file_nonce": file_nonce.hex(),
        }

        cert = None
        if self.policy.client_cert and self.policy.client_key:
            cert = (self.policy.client_cert, self.policy.client_key)

        verify = self.policy.ca_cert if self.policy.ca_cert else True

        try:
            response = requests.post(
                url,
                json=payload,
                cert=cert,
                verify=verify,
                timeout=self.policy.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise NetworkKeyError(f"Unable to reach LAN key server: {exc}") from exc

        if response.status_code != 200:
            raise NetworkKeyError(f"Key server rejected request: {response.status_code}")

        data = response.json()
        key_share_hex = data.get("key_share")
        if not key_share_hex:
            raise NetworkKeyError("Malformed key-share response")

        return bytes.fromhex(key_share_hex)



def derive_network_component(key_share: bytes, nonce: bytes) -> bytes:
    return hashlib.sha256(key_share + nonce).digest()
