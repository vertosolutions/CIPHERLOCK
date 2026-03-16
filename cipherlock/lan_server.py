"""LAN key-share service for Cipherlocks.

Run on an internal interface only, behind firewall rules.
For production, terminate TLS with mTLS enabled and provide client cert validation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from ipaddress import ip_address, ip_network
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel


ALLOWED_NETS = [ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"), ip_network("192.168.0.0/16")]
SERVER_MASTER_KEY = os.environ.get("CIPHERLOCK_SERVER_MASTER_KEY", "dev-only-change-me").encode("utf-8")

app = FastAPI(title="Cipherlocks LAN Key Server", version="1.0")


class KeyShareRequest(BaseModel):
    tenant: str
    user_id: str
    system_id: str
    file_nonce: str


class KeyShareResponse(BaseModel):
    key_share: str



def _request_in_allowed_lan(request: Request) -> bool:
    host: Optional[str] = request.client.host if request.client else None
    if not host:
        return False
    remote = ip_address(host)
    return any(remote in net for net in ALLOWED_NETS)



def _derive_key_share(payload: KeyShareRequest) -> bytes:
    message = f"{payload.tenant}|{payload.user_id}|{payload.system_id}|{payload.file_nonce}".encode("utf-8")
    return hmac.new(SERVER_MASTER_KEY, message, hashlib.sha256).digest()


@app.post("/v1/keyshare", response_model=KeyShareResponse)
async def keyshare(payload: KeyShareRequest, request: Request) -> KeyShareResponse:
    if not _request_in_allowed_lan(request):
        raise HTTPException(status_code=403, detail="Request must originate from corporate LAN")

    # mTLS enforcement should happen at reverse proxy / ingress. This service assumes
    # already-authenticated traffic and derives only a single share of the final key.
    key_share = _derive_key_share(payload)
    return KeyShareResponse(key_share=key_share.hex())
