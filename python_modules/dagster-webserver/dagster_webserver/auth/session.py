import base64
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from typing import Any


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class SignedCookieCodec:
    """Encodes a JSON payload into a tamper-proof, expiring cookie value.

    The value is `<base64 payload>.<base64 HMAC-SHA256>`. The payload is signed, not encrypted, so it
    must not hold secrets. The salt separates cookies with different purposes so a value minted for
    one can never be replayed as the other.
    """

    def __init__(self, secret: str, salt: str):
        self._key = hashlib.sha256(f"{salt}:{secret}".encode()).digest()

    def _sign(self, body: str) -> str:
        return _b64encode(hmac.new(self._key, body.encode("ascii"), hashlib.sha256).digest())

    def encode(self, payload: Mapping[str, Any], max_age_seconds: int) -> str:
        body = _b64encode(
            json.dumps(
                {**payload, "exp": int(time.time()) + max_age_seconds}, separators=(",", ":")
            ).encode()
        )
        return f"{body}.{self._sign(body)}"

    def decode(self, value: str | None) -> Mapping[str, Any] | None:
        """Returns the payload, or None if the value is missing, tampered with, or expired."""
        if not value or value.count(".") != 1:
            return None
        body, signature = value.split(".")
        if not hmac.compare_digest(signature, self._sign(body)):
            return None
        try:
            payload = json.loads(_b64decode(body))
        except ValueError:
            return None
        if not isinstance(payload, dict) or payload.get("exp", 0) < time.time():
            return None
        return payload
