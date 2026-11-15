"""Push device routes of the approval page (docs: PWA design, section C).

All of them need a page session, and the page's CSRF check applies to every write.

Turning one-tap approve on lets a notification tap approve ``any_trusted`` requests, so
it needs a fresh passkey assertion over a challenge this module issued for that device
and that purpose, once and recently. A sign-in or approval challenge, a spent one, or
one issued for another device is refused. Turning it off needs no assertion.
"""

from __future__ import annotations

import binascii
import logging
import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from aiohttp import web
from webauthn import base64url_to_bytes, generate_authentication_options, options_to_json
from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

from agentpass.passkey.page import ApprovalPage, client_challenge
from agentpass.passkey.session import CHALLENGE_TTL
from agentpass.passkey.verify import AssertionRejected, verify_approval_assertion
from agentpass.preview.sanitize import clip_escaped
from agentpass.push.models import PushDevice

logger = logging.getLogger("agentpass.push")

SUBSCRIBE_PATH = "/api/push/subscribe"
DEVICES_PATH = "/api/push/devices"
ENABLE_ONE_TAP = "enable-one-tap"
LABEL_LIMIT = 60
ENDPOINT_LIMIT = 2048
P256DH_LEN = 65  # uncompressed P-256 point
AUTH_LEN = 16
MAX_CHALLENGES = 64

_BROWSERS = (  # first match wins: Edge and Samsung carry "Chrome", Chrome carries "Safari"
    (("Edg/", "EdgA/", "EdgiOS/"), "Edge"),
    (("Firefox/", "FxiOS/"), "Firefox"),
    (("SamsungBrowser/",), "Samsung Internet"),
    (("Chrome/", "CriOS/"), "Chrome"),
    (("Safari/",), "Safari"),
)
_SYSTEMS = (  # Android before Linux, iOS before macOS ("like Mac OS X")
    (("Android",), "Android"),
    (("iPhone", "iPad"), "iOS"),
    (("Windows",), "Windows"),
    (("CrOS",), "ChromeOS"),
    (("Macintosh", "Mac OS X"), "macOS"),
    (("Linux",), "Linux"),
)


def default_label(user_agent: str) -> str:
    """ "Chrome on Android" style from a User-Agent; "Browser" if nothing is recognised."""

    def first(table: tuple[tuple[tuple[str, ...], str], ...]) -> str | None:
        return next((name for marks, name in table if any(m in user_agent for m in marks)), None)

    browser, system = first(_BROWSERS), first(_SYSTEMS)
    if browser is None:
        return "Browser"
    return f"{browser} on {system}" if system else browser


def _clean_label(value: str) -> str:
    """Clip to the limit, escape control and bidi characters, and keep the result within it."""
    return clip_escaped(value.strip()[:LABEL_LIMIT], LABEL_LIMIT).strip()


def _key_bytes(value: Any, length: int) -> bool:
    if not isinstance(value, str) or not value or len(value) > 128:
        return False
    try:
        return len(base64url_to_bytes(value)) == length
    except (binascii.Error, ValueError):
        return False


def _valid_endpoint(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > ENDPOINT_LIMIT:
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname)


def _bad(reason: str) -> web.HTTPException:
    return web.HTTPBadRequest(text=reason, content_type="text/plain")


def _not_found() -> web.HTTPException:
    return web.HTTPNotFound(text="no such device", content_type="text/plain")


def _view(d: PushDevice) -> dict[str, Any]:
    """What the page may see of a device: never the endpoint path or its keys."""
    return {
        "device_id": d.device_id,
        "label": d.label,
        "one_tap_approve": bool(d.one_tap_approve),
        "created_at": d.created_at,
        "last_seen": d.last_seen,
        "push_host": urlsplit(d.endpoint).hostname or "",
    }


async def _body(request: web.Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        raise _bad("invalid JSON") from None
    if not isinstance(body, dict):
        raise _bad("invalid JSON")
    return body


@dataclass
class _Binding:
    device_id: str
    purpose: str
    issued: float


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class DeviceRoutes:
    def __init__(
        self, page: ApprovalPage, db: Any, *, clock: Callable[[], float] = time.time
    ) -> None:
        self.page = page
        self.db = db
        self._clock = clock
        self._challenges: OrderedDict[bytes, _Binding] = OrderedDict()

    def mount(self, app: web.Application) -> None:
        app.router.add_post(SUBSCRIBE_PATH, self._subscribe)
        app.router.add_get(DEVICES_PATH, self._list)
        app.router.add_post(DEVICES_PATH + "/{id}/one-tap/options", self._one_tap_options)
        app.router.add_post(DEVICES_PATH + "/{id}/one-tap", self._one_tap)
        app.router.add_patch(DEVICES_PATH + "/{id}", self._rename)
        app.router.add_delete(DEVICES_PATH + "/{id}", self._delete)

    # --- subscribe and list ---

    async def _subscribe(self, request: web.Request) -> web.Response:
        session = self.page.require_session(request)
        body = await _body(request)
        subscription = body.get("subscription")
        if not isinstance(subscription, dict):
            raise _bad("missing subscription")
        endpoint = subscription.get("endpoint")
        keys = subscription.get("keys")
        if not _valid_endpoint(endpoint):
            raise _bad("endpoint must be an https URL")
        if not isinstance(keys, dict):
            raise _bad("missing subscription keys")
        p256dh, auth = keys.get("p256dh"), keys.get("auth")
        if not _key_bytes(p256dh, P256DH_LEN) or not _key_bytes(auth, AUTH_LEN):
            raise _bad("invalid subscription keys")
        label = body.get("label")
        if label is not None and not isinstance(label, str):
            raise _bad("label must be a string")
        label = _clean_label(label or "") or default_label(request.headers.get("User-Agent", ""))
        now = _now_iso()
        stored = await self.db.upsert_push_device(
            PushDevice(
                device_id=secrets.token_urlsafe(16),
                label=label,
                endpoint=endpoint,
                p256dh=p256dh,
                auth=auth,
                one_tap_approve=False,
                credential_id=session.credential_id,
                created_at=now,
                last_seen=now,
            )
        )
        logger.info("Push device %s subscribed (%s)", stored.device_id, _view(stored)["push_host"])
        return web.json_response({"device_id": stored.device_id})

    async def _list(self, request: web.Request) -> web.Response:
        self.page.require_session(request)
        devices = await self.db.list_push_devices()
        return web.json_response({"devices": [_view(d) for d in devices]})

    async def _device(self, request: web.Request) -> PushDevice:
        device = await self.db.get_push_device(request.match_info["id"])
        if device is None:
            raise _not_found()
        return device

    # --- rename and delete ---

    async def _rename(self, request: web.Request) -> web.Response:
        self.page.require_session(request)
        body = await _body(request)
        label = body.get("label")
        label = _clean_label(label) if isinstance(label, str) else ""
        if not label:
            raise _bad("label must be a non-empty string")
        device = await self._device(request)
        if not await self.db.set_push_device(device.device_id, label=label):
            raise _not_found()
        return web.json_response({"ok": True, "label": label})

    async def _delete(self, request: web.Request) -> web.Response:
        self.page.require_session(request)
        device_id = request.match_info["id"]
        if not await self.db.delete_push_device(device_id):
            raise _not_found()
        for challenge, binding in list(self._challenges.items()):
            if binding.device_id == device_id:
                del self._challenges[challenge]
        logger.info("Push device %s removed", device_id)
        return web.json_response({"ok": True})

    # --- one-tap ---

    def _check_throttle(self, request: web.Request) -> None:
        if self.page.throttled(self.page.source(request)):
            raise web.HTTPTooManyRequests(
                text="too many failed attempts", content_type="text/plain"
            )

    def _new_challenge(self, device_id: str) -> bytes:
        now = self._clock()
        for c, b in list(self._challenges.items()):
            if now - b.issued >= CHALLENGE_TTL:
                del self._challenges[c]
        while len(self._challenges) >= MAX_CHALLENGES:
            self._challenges.popitem(last=False)
        challenge = secrets.token_bytes(32)
        self._challenges[challenge] = _Binding(device_id, ENABLE_ONE_TAP, now)
        return challenge

    def _consume_challenge(self, challenge: bytes, device_id: str) -> bool:
        """True once for a live challenge issued to enable one-tap on ``device_id``."""
        binding = self._challenges.pop(challenge, None)
        return (
            binding is not None
            and binding.device_id == device_id
            and binding.purpose == ENABLE_ONE_TAP
            and self._clock() - binding.issued < CHALLENGE_TTL
        )

    async def _one_tap_options(self, request: web.Request) -> web.Response:
        self.page.require_session(request)
        self._check_throttle(request)
        device = await self._device(request)
        creds = self.page.store.list()
        if not creds:
            raise web.HTTPConflict(text="no passkey enrolled", content_type="text/plain")
        options = generate_authentication_options(
            rp_id=self.page.config.rp_id,
            challenge=self._new_challenge(device.device_id),
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.id)) for c in creds
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return web.Response(text=options_to_json(options), content_type="application/json")

    async def _one_tap(self, request: web.Request) -> web.Response:
        self.page.require_session(request)
        body = await _body(request)
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            raise _bad("enabled must be true or false")
        device = await self._device(request)
        if not enabled:  # turning it off is always safe
            await self.db.set_push_device(device.device_id, one_tap_approve=False)
            logger.info("One-tap approve off for push device %s", device.device_id)
            return web.json_response({"enabled": False})
        self._check_throttle(request)
        where = f"one-tap:{device.device_id}"
        credential = body.get("credential")
        challenge = client_challenge(credential)
        if challenge is None or not self._consume_challenge(challenge, device.device_id):
            raise await self.page.reject(request, where, "unknown or expired one-tap challenge")
        try:
            verified = verify_approval_assertion(
                self.page.store,
                credential,
                challenge=challenge,
                rp_id=self.page.config.rp_id,
                origin=self.page.config.origin,
            )
        except AssertionRejected as e:
            raise await self.page.reject(request, where, e.reason) from e
        if not await self.db.set_push_device(device.device_id, one_tap_approve=True):
            raise _not_found()
        logger.info(
            "One-tap approve on for push device %s (passkey %s)",
            device.device_id,
            verified.credential_id,
        )
        return web.json_response({"enabled": True})
