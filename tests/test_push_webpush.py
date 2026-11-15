"""Web Push crypto: RFC 8291 payload encryption and RFC 8292 VAPID."""

import base64
import json
import os
import stat

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from agentpass.push.webpush import (
    encrypt,
    generate_vapid_key,
    load_vapid_key,
    public_key_b64,
    save_vapid_key,
    vapid_headers,
)


def b64d(s: str) -> bytes:
    s = "".join(s.split())
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _private_from_scalar(scalar: bytes) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1())


def _public_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def test_encrypt_matches_rfc8291_appendix_a():
    # Inputs and expected body copied verbatim from RFC 8291 section 5 / Appendix A.
    plaintext = b64d("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24")
    ua_public = (
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
    )
    as_private = _private_from_scalar(b64d("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
    auth_secret = "BTBZMqHH6r4Tts7J_aSIgg"
    salt = b64d("DGv6ra1nlYgDCS1FRnbzlw")
    expected = b64d(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
        "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
        "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    )

    body = encrypt(plaintext, ua_public, auth_secret, salt=salt, server_private_key=as_private)

    assert body == expected


def _decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth_secret: bytes) -> bytes:
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


def test_encrypt_round_trips_with_fresh_keys():
    ua = ec.generate_private_key(ec.SECP256R1())
    auth = os.urandom(16)
    payload = json.dumps({"type": "approval", "approval_id": "a1"}).encode()

    body = encrypt(payload, b64e(_public_bytes(ua)), b64e(auth))
    other = encrypt(payload, b64e(_public_bytes(ua)), b64e(auth))

    assert _decrypt(body, ua, auth) == payload
    assert body != other  # fresh salt and server key per message


def test_vapid_jwt_verifies_and_has_audience():
    key = generate_vapid_key()
    headers = vapid_headers(
        "https://fcm.googleapis.com/fcm/send/abc",
        key,
        "mailto:ops@example.invalid",
        now=1_700_000_000,
    )

    scheme, _, rest = headers["Authorization"].partition(" ")
    assert scheme == "vapid"
    fields = dict(part.strip().split("=", 1) for part in rest.split(","))
    assert fields["k"] == public_key_b64(key)
    header_b64, claims_b64, sig_b64 = fields["t"].split(".")
    assert json.loads(b64d(header_b64)) == {"typ": "JWT", "alg": "ES256"}
    claims = json.loads(b64d(claims_b64))
    assert claims["aud"] == "https://fcm.googleapis.com"
    assert claims["exp"] == 1_700_000_000 + 43200
    assert claims["sub"] == "mailto:ops@example.invalid"
    sig = b64d(sig_b64)
    assert len(sig) == 64
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    key.public_key().verify(der, f"{header_b64}.{claims_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        key.public_key().verify(der, b"tampered", ec.ECDSA(hashes.SHA256()))


def test_public_key_b64_is_uncompressed_point():
    raw = b64d(public_key_b64(generate_vapid_key()))
    assert len(raw) == 65 and raw[0] == 4


def test_save_vapid_key_is_0600_and_refuses_overwrite(tmp_path):
    path = str(tmp_path / "vapid.pem")
    key = generate_vapid_key()

    save_vapid_key(key, path)

    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert public_key_b64(load_vapid_key(path)) == public_key_b64(key)
    with pytest.raises(FileExistsError):
        save_vapid_key(generate_vapid_key(), path)
    assert public_key_b64(load_vapid_key(path)) == public_key_b64(key)
