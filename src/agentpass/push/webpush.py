"""Web Push cryptography: RFC 8291 (aes128gcm payloads) and RFC 8292 (VAPID).

Pure functions on top of ``cryptography``; no network access.
"""

from __future__ import annotations

import base64
import json
import os
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RECORD_SIZE = 4096
VAPID_LIFETIME_SECONDS = 12 * 3600


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _point(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def _hkdf(length: int, salt: bytes, ikm: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def encrypt(
    payload: bytes,
    p256dh: str,
    auth: str,
    *,
    salt: bytes | None = None,
    server_private_key: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """Encrypt ``payload`` for a push subscription as an RFC 8291 ``aes128gcm`` body.

    ``p256dh`` and ``auth`` are base64url without padding, as browsers provide them.
    ``salt`` and ``server_private_key`` are injectable for test vectors only.
    """
    # One record holds payload + 1 delimiter byte + 16 byte GCM tag.
    if len(payload) > RECORD_SIZE - 17:
        raise ValueError("payload too large for a single push record")
    ua_public = _b64d(p256dh)
    auth_secret = _b64d(auth)
    salt = salt if salt is not None else os.urandom(16)
    server_key = server_private_key or ec.generate_private_key(ec.SECP256R1())
    as_public = _point(server_key)

    ecdh = server_key.exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    )
    ikm = _hkdf(32, auth_secret, ecdh, b"WebPush: info\x00" + ua_public + as_public)
    cek = _hkdf(16, salt, ikm, b"Content-Encoding: aes128gcm\x00")
    nonce = _hkdf(12, salt, ikm, b"Content-Encoding: nonce\x00")

    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    header = salt + RECORD_SIZE.to_bytes(4, "big") + bytes([len(as_public)]) + as_public
    return header + ciphertext


def generate_vapid_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_key_b64(key: ec.EllipticCurvePrivateKey) -> str:
    """Uncompressed P-256 point, base64url without padding."""
    return _b64e(_point(key))


def vapid_headers(
    endpoint: str, private_key: ec.EllipticCurvePrivateKey, subject: str, now: int
) -> dict[str, str]:
    """RFC 8292 ``Authorization`` header for a push to ``endpoint``."""
    parts = urlsplit(endpoint)
    claims = {
        "aud": f"{parts.scheme}://{parts.netloc}",
        "exp": now + VAPID_LIFETIME_SECONDS,
        "sub": subject,
    }
    signing_input = (
        _b64e(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        + "."
        + _b64e(json.dumps(claims, separators=(",", ":")).encode())
    )
    r, s = decode_dss_signature(private_key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    token = f"{signing_input}.{_b64e(signature)}"
    return {"Authorization": f"vapid t={token}, k={public_key_b64(private_key)}"}


def load_vapid_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"{path} is not an EC private key")
    return key


def save_vapid_key(key: ec.EllipticCurvePrivateKey, path: str) -> None:
    """Write ``key`` as PEM with mode 0600; raises FileExistsError if ``path`` exists."""
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
