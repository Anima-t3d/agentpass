"""Web Push approval channel (docs: PWA design, section C).

``send`` pushes an encrypted notification with a single-use action token to every
subscribed device; ``finalize`` pushes "resolved" so the notification closes everywhere.
The service worker posts a tap to ``POST /api/push/action``.

What a tap may do is decided here, from server-side state only: Deny always; Approve
only when the device's stored one-tap setting is on and the rule is ``any_trusted``.
Otherwise the tap gets a link to the page, where a passkey assertion is needed. The
coordinator's ``satisfies`` refuses ``push_action`` for ``require: passkey`` and
``require: telegram`` in any case.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from aiohttp import ClientSession, ClientTimeout, web

from agentpass.approval.channel import (
    Answer,
    AnswerStatus,
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalRequest,
    ApprovalSink,
    ChannelHandle,
    ChannelUnavailable,
)
from agentpass.passkey.page import ApprovalPage
from agentpass.passkey.verify import parse_expiry
from agentpass.preview.model import Preview
from agentpass.preview.sanitize import clip_escaped
from agentpass.push.config import PushConfig
from agentpass.push.models import PushDevice
from agentpass.push.routes import DeviceRoutes
from agentpass.push.tokens import ActionTokens, TokenRejected
from agentpass.push.webpush import encrypt, load_vapid_key, public_key_b64, vapid_headers

logger = logging.getLogger("agentpass.push")

ACTION_PATH = "/api/push/action"
VAPID_PATH = "/api/push/vapid"
TEXT_LIMIT = 120
STOP_GRACE = 2.0  # seconds stop() waits for outstanding pushes before cancelling them
RESOLVED_TTL = 3600  # a "resolved" push may still close a stale notification later

Transport = Callable[[str, dict[str, str], bytes, float], Awaitable[int]]


def _clip(text: str) -> str:
    return clip_escaped(text, TEXT_LIMIT, "…")


def _error(status: int, body: dict[str, Any]) -> web.Response:
    return web.json_response(body, status=status)


class PushChannel(ApprovalChannel):
    name = "push"
    trust = "trusted"
    proof_kinds: ClassVar[set[str]] = {"push_action"}

    def __init__(
        self,
        config: PushConfig,
        page: ApprovalPage,
        db: Any,
        transport: Transport | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.page = page
        self.db = db
        self._transport = transport
        self._clock = clock
        self._http: ClientSession | None = None
        self._key: Any = None  # VAPID private key, loaded in start()
        self._sink: ApprovalSink | None = None
        self._pending: dict[str, ApprovalRequest] = {}
        self._tokens = ActionTokens(clock=clock)
        self._tasks: set[asyncio.Task[None]] = set()
        self.devices = DeviceRoutes(page, db, clock=clock)
        page.add_routes(self._mount)
        page.csrf_exempt.add(ACTION_PATH)

    def _mount(self, app: web.Application) -> None:
        app.router.add_post(ACTION_PATH, self._action)
        app.router.add_get(VAPID_PATH, self._vapid)
        self.devices.mount(app)

    # --- lifecycle ---

    async def start(self, sink: ApprovalSink) -> None:
        self._sink = sink
        try:
            self._key = load_vapid_key(self.config.vapid_key_path)
        except (OSError, ValueError) as e:
            self._key = None
            logger.error(
                "Push channel disabled: cannot load the VAPID key at %s (%s); "
                "create it with `agentpass push init-keys`",
                self.config.vapid_key_path,
                type(e).__name__,
            )
        if self._transport is None:
            self._http = ClientSession()

    async def stop(self) -> None:
        tasks = list(self._tasks)
        if tasks:  # let in-flight pushes (a just-finalized "resolved") go out first
            _, rest = await asyncio.wait(tasks, timeout=STOP_GRACE)
            for task in rest:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        if self._http is not None:
            await self._http.close()
            self._http = None
        self._pending.clear()

    async def health_check(self) -> bool:
        return self._key is not None

    # --- sending ---

    async def send(self, req: ApprovalRequest) -> ChannelHandle:
        if self._key is None:
            raise ChannelUnavailable("push channel has no VAPID key")
        devices = await self.db.list_push_devices()
        if not devices:
            raise ChannelUnavailable("no push devices")
        expires_at = parse_expiry(req.expires_at)
        self._pending[req.approval_id] = req
        title = _clip(f"{req.agent_name or req.agent_id} → {req.tool}")
        body = _clip(req.preview.title if isinstance(req.preview, Preview) else req.signature)
        ttl = max(0, int(expires_at - self._clock()))
        for device in devices:
            try:
                token = self._tokens.issue(req.approval_id, device.device_id, expires_at)
            except ValueError:
                logger.warning("Push device %s has an unusable id; skipped", device.device_id)
                continue
            payload = {
                "type": "approval",
                "approval_id": req.approval_id,
                "title": title,
                "body": body,
                "require": req.require,
                "one_tap": bool(device.one_tap_approve) and req.require == "any_trusted",
                "token": token,
                "expires_at": int(expires_at),
            }
            self._schedule(device, payload, ttl)
        return ChannelHandle(channel=self.name, ref={"approval_id": req.approval_id})

    async def finalize(self, handle: ChannelHandle, outcome: ApprovalOutcome) -> None:
        approval_id = handle.ref.get("approval_id")
        if not approval_id:
            return
        self._pending.pop(approval_id, None)  # first: a tap from now on is "already resolved"
        self._tokens.forget(approval_id)
        if self._key is None:
            return
        payload = {
            "type": "resolved",
            "approval_id": approval_id,
            "approved": bool(outcome.approved),
            "reason": str(outcome.reason),
        }
        for device in await self.db.list_push_devices():
            self._schedule(device, payload, RESOLVED_TTL)

    def _schedule(self, device: PushDevice, payload: dict[str, Any], ttl: int) -> None:
        task = asyncio.create_task(self._deliver(device, payload, ttl))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _deliver(self, device: PushDevice, payload: dict[str, Any], ttl: int) -> None:
        """One push to one device. Never raises; logs carry no payload, keys or endpoint."""
        kind = payload["type"]
        try:
            if urlsplit(device.endpoint).scheme != "https":
                logger.warning("Push device %s has a non-https endpoint; skipped", device.device_id)
                return
            data = json.dumps(payload, separators=(",", ":")).encode()
            body = encrypt(data, device.p256dh, device.auth)
            headers = vapid_headers(
                device.endpoint, self._key, self.config.subject, int(self._clock())
            )
            headers.update(
                {
                    "TTL": str(ttl),
                    "Urgency": "high",
                    "Content-Encoding": "aes128gcm",
                    "Content-Type": "application/octet-stream",
                }
            )
            status = await asyncio.wait_for(
                self._post(device.endpoint, headers, body, self.config.timeout),
                self.config.timeout,
            )
            if status in (404, 410):
                await self.db.delete_push_device_by_endpoint(device.endpoint)
                logger.info(
                    "Push device %s unsubscribed (HTTP %d); removed", device.device_id, status
                )
            elif 200 <= status < 300:
                await self.db.touch_push_device(device.device_id)
            else:
                logger.warning("Push %s to device %s: HTTP %d", kind, device.device_id, status)
        except TimeoutError:
            logger.warning("Push %s to device %s timed out", kind, device.device_id)
        except Exception as e:
            logger.warning(
                "Push %s to device %s failed: %s", kind, device.device_id, type(e).__name__
            )

    async def _post(
        self, endpoint: str, headers: dict[str, str], body: bytes, timeout: float
    ) -> int:
        if self._transport is not None:
            return await self._transport(endpoint, headers, body, timeout)
        if self._http is None:
            raise RuntimeError("push channel not started")
        async with self._http.post(
            endpoint, data=body, headers=headers, timeout=ClientTimeout(total=timeout)
        ) as response:
            return response.status

    # --- routes ---

    async def _vapid(self, request: web.Request) -> web.Response:
        self.page.require_session(request)
        if self._key is None:
            return _error(503, {"error": "push not configured"})
        return web.json_response({"public_key": public_key_b64(self._key)})

    async def _action(self, request: web.Request) -> web.Response:
        """A notification tap. No session: the token is the authority, bound to the
        approval and device. Rule and expiry come from the stored request, never the body."""
        try:
            body = await request.json()
        except Exception:
            body = None
        if not isinstance(body, dict):
            return _error(400, {"error": "bad request"})
        approval_id, action, token = body.get("approval_id"), body.get("action"), body.get("token")
        if not all(isinstance(v, str) for v in (approval_id, action, token)) or action not in (
            "approve",
            "deny",
        ):
            return _error(400, {"error": "bad request"})
        req = self._pending.get(approval_id)
        if req is None or self._sink is None:
            return _error(410, {"error": "already resolved"})
        try:
            device_id = self._tokens.peek(token, approval_id)
        except TokenRejected as e:
            logger.info("Push action refused for %s: %s", approval_id, e.reason)
            return _error(401, {"error": "invalid token"})
        device = await self.db.get_push_device(device_id)
        if device is None:
            logger.info("Push action refused for %s: device removed", approval_id)
            return _error(401, {"error": "invalid token"})
        await self.db.touch_push_device(device.device_id)
        approved = action == "approve"
        if approved and not (device.one_tap_approve and req.require == "any_trusted"):
            # Not consumed: the same notification may still Deny.
            return _error(409, {"open": f"/a/{quote(approval_id, safe='')}"})
        if approval_id not in self._pending:  # resolved while we read the device
            return _error(410, {"error": "already resolved"})
        try:
            self._tokens.redeem(token, approval_id)
        except TokenRejected as e:  # a concurrent tap won
            logger.info("Push action refused for %s: %s", approval_id, e.reason)
            return _error(401, {"error": "invalid token"})
        answer = Answer(
            approved,
            self.name,
            f"push:{device.label}:notification",
            proof={"kind": "push_action", "device_id": device.device_id} if approved else None,
        )
        status = await self._sink.answer(approval_id, answer)
        if status is AnswerStatus.ACCEPTED:
            return web.json_response({"ok": True, "approved": approved})
        if status is AnswerStatus.REJECTED:
            return _error(409, {"error": "answer rejected"})
        return _error(410, {"error": "already resolved"})
