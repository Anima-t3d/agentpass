"""Challenge construction and WebAuthn verification for the approval page.

The challenge binds an assertion to one approval: the page issues it and the verifier
recomputes it from the pending request, both through `approval_challenge`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from webauthn import (
    base64url_to_bytes,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse

from agentpass.passkey.store import Credential, PasskeyStore, utc_now_iso


class AssertionRejected(Exception):
    """An assertion or registration failed verification. `reason` is safe to show."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_json(args: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only, no NaN.

    The single definition used to build the challenge on every path.
    """
    return json.dumps(
        args, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def expires_iso(expires_at: float | int | str) -> str:
    """Normalise an expiry (epoch seconds or ISO 8601) to `YYYY-MM-DDTHH:MM:SSZ`."""
    return _iso(parse_expiry(expires_at))


def parse_expiry(expires_at: float | int | str) -> float:
    if isinstance(expires_at, int | float):
        return float(expires_at)
    return datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(int(epoch), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def approval_challenge(
    approval_id: str, agent_id: str, tool: str, args: Any, expires_at: float | int | str
) -> bytes:
    """SHA-256(approval_id || agent_id || tool || canonical_json(args) || expires_at).

    Each field is length-prefixed so the boundaries are unambiguous ("a"+"bc" differs
    from "ab"+"c").
    """
    h = hashlib.sha256()
    for part in (approval_id, agent_id, tool, canonical_json(args), expires_iso(expires_at)):
        data = part.encode()
        h.update(len(data).to_bytes(4, "big"))
        h.update(data)
    return h.digest()


@dataclass
class VerifiedAssertion:
    credential_id: str
    new_sign_count: int
    challenge: bytes


def verify_approval_assertion(
    store: PasskeyStore,
    credential: Any,
    *,
    challenge: bytes,
    rp_id: str,
    origin: str,
) -> VerifiedAssertion:
    """Verify one assertion against an enrolled public key and the expected challenge.

    Checks signature, challenge, rp_id hash, origin, user presence and verification,
    and that the sign count increases (counters that are 0 on both sides are exempt, as
    the WebAuthn spec allows for authenticators without a counter). Stores the new count.
    """
    if not isinstance(credential, dict) or not isinstance(credential.get("id"), str):
        raise AssertionRejected("missing assertion")
    enrolled = store.get(credential["id"])
    if enrolled is None:
        raise AssertionRejected("unknown credential")
    try:
        result = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(enrolled.public_key),
            credential_current_sign_count=enrolled.sign_count,
            require_user_verification=True,
        )
    except InvalidAuthenticationResponse as e:
        raise AssertionRejected(f"invalid assertion: {e}") from e
    except Exception as e:  # malformed JSON/base64 from the client
        raise AssertionRejected("malformed assertion") from e
    store.advance_sign_count(enrolled.id, result.new_sign_count)
    return VerifiedAssertion(enrolled.id, result.new_sign_count, challenge)


def verify_registration(
    credential: Any, *, challenge: bytes, rp_id: str, origin: str, label: str = ""
) -> Credential:
    """Verify a registration (attestation `none`) and return the public-key record."""
    try:
        result = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as e:
        raise AssertionRejected(f"invalid registration: {e}") from e
    except Exception as e:
        raise AssertionRejected("malformed registration") from e
    transports: list[str] = []
    if isinstance(credential, dict):
        raw = (credential.get("response") or {}).get("transports") or []
        transports = [t for t in raw if isinstance(t, str)]
    return Credential(
        id=bytes_to_base64url(result.credential_id),
        public_key=bytes_to_base64url(result.credential_public_key),
        sign_count=result.sign_count,
        transports=transports,
        created_at=utc_now_iso(),
        label=label[:64],
    )
