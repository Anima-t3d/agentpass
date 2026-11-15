"""Test helpers for Web Push: a browser-side subscriber that decrypts what it receives."""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _public_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth_secret: bytes) -> bytes:
    """Undo RFC 8291 aes128gcm as the user agent would (single record)."""
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
    as_public = body[21 : 21 + idlen]
    ciphertext = body[21 + idlen :]
    assert rs == 4096
    ua_public = _public_bytes(ua_private)
    ecdh = ua_private.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public)
    )
    ikm = HKDF(
        hashes.SHA256(), 32, auth_secret, b"WebPush: info\x00" + ua_public + as_public
    ).derive(ecdh)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    record = AESGCM(cek).decrypt(nonce, ciphertext, None)
    assert record.endswith(b"\x02")
    return record[:-1]


class Subscriber:
    """One browser push subscription: its keys and endpoint."""

    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth_secret = os.urandom(16)
        self.p256dh = b64e(_public_bytes(self.key))
        self.auth = b64e(self.auth_secret)

    def open(self, body: bytes) -> dict:
        return json.loads(decrypt(body, self.key, self.auth_secret))
