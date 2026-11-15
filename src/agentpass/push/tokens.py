"""Single-use action tokens for notification Approve/Deny taps.

A token binds (approval_id, device_id) and an expiry under a per-process
HMAC key. Layout (b64url, no padding)::

    nonce(16) | expires(8, big-endian int seconds) | device_len(1)
    | device_id(utf-8) | mac(32)

``mac = HMAC-SHA256(key, f"{approval_id}|{device_id}|" + nonce + expires)``.
The key is in memory only, so tokens do not survive a restart.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import time
from collections.abc import Callable

NONCE_LEN = 16
EXPIRES_LEN = 8
MAC_LEN = 32
MAX_DEVICE_ID_BYTES = 255


class TokenRejected(Exception):
    """Raised for a refused token; ``reason`` is one of "malformed",
    "bad signature", "expired", "used"."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ActionTokens:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._key = os.urandom(32)
        self._used: dict[str, set[bytes]] = {}

    def _mac(self, approval_id: str, device_id: str, nonce: bytes, expires: bytes) -> bytes:
        message = f"{approval_id}|{device_id}|".encode() + nonce + expires
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def issue(self, approval_id: str, device_id: str, expires_at: float) -> str:
        device = device_id.encode()
        if len(device) > MAX_DEVICE_ID_BYTES:
            raise ValueError("device id longer than 255 bytes")
        nonce = os.urandom(NONCE_LEN)
        expires = int(expires_at).to_bytes(EXPIRES_LEN, "big")
        mac = self._mac(approval_id, device_id, nonce, expires)
        raw = nonce + expires + bytes([len(device)]) + device + mac
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def _check(self, token: str, approval_id: str) -> tuple[str, bytes]:
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            raise TokenRejected("malformed") from None
        head = NONCE_LEN + EXPIRES_LEN
        if len(raw) < head + 1 + MAC_LEN:
            raise TokenRejected("malformed")
        device_len = raw[head]
        if len(raw) != head + 1 + device_len + MAC_LEN:
            raise TokenRejected("malformed")
        nonce = raw[:NONCE_LEN]
        expires = raw[NONCE_LEN:head]
        try:
            device_id = raw[head + 1 : head + 1 + device_len].decode()
        except UnicodeDecodeError:
            raise TokenRejected("malformed") from None
        mac = raw[head + 1 + device_len :]
        if not hmac.compare_digest(mac, self._mac(approval_id, device_id, nonce, expires)):
            raise TokenRejected("bad signature")
        if self._clock() >= int.from_bytes(expires, "big"):
            raise TokenRejected("expired")
        if nonce in self._used.get(approval_id, ()):
            raise TokenRejected("used")
        return device_id, nonce

    def peek(self, token: str, approval_id: str) -> str:
        """Run every check without consuming; return the device id."""
        return self._check(token, approval_id)[0]

    def redeem(self, token: str, approval_id: str) -> str:
        """Run every check, then mark the token used; return the device id."""
        device_id, nonce = self._check(token, approval_id)
        self._used.setdefault(approval_id, set()).add(nonce)
        return device_id

    def forget(self, approval_id: str) -> None:
        """Drop the used-nonce bookkeeping for a resolved approval.

        Afterwards old tokens for it are no longer refused as "used"; callers
        must check the approval's state themselves.
        """
        self._used.pop(approval_id, None)
