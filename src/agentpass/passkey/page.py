"""The approval page: an aiohttp app on loopback, reached through `tailscale serve`.

Anything on the host can reach this page, but only the owner's passkey can complete an
Approve. Agent bearer tokens are never consulted: the page has no notion of them.
"""

from __future__ import annotations

import hmac
import logging
import secrets
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from aiohttp import web
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from agentpass.approval.channel import Answer, AnswerStatus
from agentpass.config import LOOPBACK_HOSTS, ConfigError
from agentpass.models import AuditEntry
from agentpass.passkey import assets
from agentpass.passkey.store import EnrolmentTokens, PasskeyStore
from agentpass.passkey.verify import (
    AssertionRejected,
    approval_challenge,
    expires_iso,
    verify_approval_assertion,
    verify_registration,
)

logger = logging.getLogger("agentpass.passkey")

FAILURE_LIMIT = 5
FAILURE_WINDOW = 300.0
CSRF_COOKIE = "ap_csrf"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


@dataclass
class PasskeyConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8206
    rp_id: str = ""
    origin: str = ""
    store_path: str = ""  # default: <storage data dir>/passkeys.json

    @property
    def enroll_path(self) -> str:
        return str(Path(self.store_path).with_name("passkey-enroll.json"))

    @classmethod
    def from_mapping(cls, raw: Any, storage_path: str) -> PasskeyConfig:
        raw = raw or {}
        if not isinstance(raw, dict):
            raise ConfigError("passkey must be a mapping")
        cfg = cls(
            enabled=bool(raw.get("enabled", False)),
            host=str(raw.get("host", "127.0.0.1")),
            port=int(raw.get("port", 8206)),
            rp_id=str(raw.get("rp_id", "")),
            origin=str(raw.get("origin", "")).rstrip("/"),
            store_path=str(raw.get("store_path") or Path(storage_path).parent / "passkeys.json"),
        )
        cfg.validate()
        return cfg

    @classmethod
    def from_config_file(cls, config_path: str) -> PasskeyConfig:
        """Read the `passkey` and `storage` keys without env substitution."""
        try:
            raw = yaml.safe_load(Path(config_path).read_text())
        except (OSError, yaml.YAMLError) as e:
            raise ConfigError(f"cannot read {config_path}: {e}") from e
        raw = raw if isinstance(raw, dict) else {}
        storage = raw.get("storage")
        storage_path = storage.get("path") if isinstance(storage, dict) else None
        return cls.from_mapping(raw.get("passkey"), str(storage_path or "./data/agentpass.db"))

    def validate(self) -> None:
        if self.host not in LOOPBACK_HOSTS:
            raise ConfigError(f"passkey.host must be a loopback address, got: {self.host!r}")
        parts = urlsplit(self.origin)
        if not parts.hostname:
            raise ConfigError("passkey.origin is required, e.g. https://gate.your-tailnet.ts.net")
        if parts.scheme != "https" and not (
            parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS
        ):
            raise ConfigError("passkey.origin must be https (WebAuthn needs a secure origin)")
        if parts.path or parts.query or parts.fragment:
            raise ConfigError("passkey.origin must be scheme://host[:port] only")
        host = parts.hostname
        if not self.rp_id or not (host == self.rp_id or host.endswith("." + self.rp_id)):
            raise ConfigError("passkey.rp_id must equal the origin host or a parent domain of it")


@dataclass
class PendingApproval:
    """What the page needs to show and verify one approval."""

    approval_id: str
    agent_id: str
    tool: str
    args: dict[str, Any]
    risk: str
    expires_at: float
    signature: str = ""
    require: str = "any_trusted"
    extra: dict[str, Any] = field(default_factory=dict)

    def challenge(self) -> bytes:
        return approval_challenge(
            self.approval_id, self.agent_id, self.tool, self.args, self.expires_at
        )


AnswerFn = Callable[[str, Answer], Awaitable[AnswerStatus]]


def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status)


def _http(status: int, reason: str) -> web.HTTPException:
    cls = {
        400: web.HTTPBadRequest,
        403: web.HTTPForbidden,
        404: web.HTTPNotFound,
        409: web.HTTPConflict,
        410: web.HTTPGone,
        421: web.HTTPMisdirectedRequest,
        429: web.HTTPTooManyRequests,
    }[status]
    return cls(text=reason, content_type="text/plain")


class ApprovalPage:
    def __init__(
        self,
        config: PasskeyConfig,
        store: PasskeyStore,
        tokens: EnrolmentTokens,
        *,
        db: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.store = store
        self.tokens = tokens
        self.db = db
        self.clock = clock
        self.pending: dict[str, PendingApproval] = {}
        self.answer: AnswerFn | None = None
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._reg_challenges: dict[str, bytes] = {}  # enrolment token -> challenge
        self._netloc = urlsplit(config.origin).netloc

    # --- app wiring ---

    def build_app(self) -> web.Application:
        app = web.Application(middlewares=[self._guard])
        app.router.add_get("/", self._index)
        app.router.add_get("/enroll", self._enroll_page)
        app.router.add_get("/static/app.js", self._asset(assets.APP_JS, "text/javascript"))
        app.router.add_get("/static/app.css", self._asset(assets.APP_CSS, "text/css"))
        app.router.add_get("/api/session", self._session)
        app.router.add_get("/api/pending", self._list_pending)
        app.router.add_post("/api/approvals/{id}/challenge", self._challenge)
        app.router.add_post("/api/approvals/{id}/approve", self._approve)
        app.router.add_post("/api/approvals/{id}/deny", self._deny)
        app.router.add_post("/api/enroll/options", self._enroll_options)
        app.router.add_post("/api/enroll/verify", self._enroll_verify)
        return app

    @web.middleware
    async def _guard(self, request: web.Request, handler: Any) -> web.StreamResponse:
        """Exact-origin enforcement, CSRF for writes, and security headers."""
        try:
            if request.host != self._netloc:
                raise _http(421, "wrong host")
            if request.method not in ("GET", "HEAD"):
                if request.headers.get("Origin") != self.config.origin:
                    raise _http(403, "wrong origin")
                cookie = request.cookies.get(CSRF_COOKIE, "")
                header = request.headers.get("X-CSRF", "")
                if not cookie or not hmac.compare_digest(cookie, header):
                    raise _http(403, "csrf check failed")
            response = await handler(request)
        except web.HTTPException as exc:
            self._harden(exc)
            raise
        self._harden(response)
        return response

    @staticmethod
    def _harden(response: web.StreamResponse) -> None:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"

    # --- helpers ---

    @staticmethod
    def source(request: web.Request) -> str:
        peer = request.remote or "unknown"
        forwarded = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "")
        forwarded = forwarded.split(",")[0].strip()
        return f"{forwarded} (via {peer})" if forwarded else peer

    def _throttled(self, source: str) -> bool:
        window = self._failures[source]
        now = self.clock()
        while window and window[0] <= now - FAILURE_WINDOW:
            window.popleft()
        return len(window) >= FAILURE_LIMIT

    async def _reject(
        self,
        request: web.Request,
        approval_id: str,
        reason: str,
        pending: PendingApproval | None = None,
        status: int = 403,
    ) -> web.HTTPException:
        source = self.source(request)
        self._failures[source].append(self.clock())
        logger.warning("approval_rejected id=%s source=%s reason=%s", approval_id, source, reason)
        if self.db is not None:
            await self.db.log_audit(
                AuditEntry(
                    request_id=approval_id,
                    tool_name=pending.tool if pending else "",
                    args=pending.args if pending else {},
                    signature=pending.signature if pending else "",
                    decision="ask",
                    resolution="approval_rejected",
                    resolved_by=f"passkey:{source}",
                    execution_result={"reason": reason},
                    agent_id=pending.agent_id if pending else "",
                )
            )
        return _http(status, reason)

    def _live(self, approval_id: str) -> PendingApproval | None:
        p = self.pending.get(approval_id)
        if p is not None and p.expires_at <= self.clock():
            return None
        return p

    # --- static ---

    def _asset(self, body: str, ctype: str) -> Callable[[web.Request], Awaitable[web.Response]]:
        async def handler(_: web.Request) -> web.Response:
            return web.Response(text=body, content_type=ctype)

        return handler

    async def _index(self, _: web.Request) -> web.Response:
        return web.Response(text=assets.INDEX_HTML, content_type="text/html")

    async def _enroll_page(self, _: web.Request) -> web.Response:
        return web.Response(text=assets.ENROLL_HTML, content_type="text/html")

    async def _session(self, _: web.Request) -> web.Response:
        """Issue a CSRF token. It grants nothing: every Approve still needs a signature."""
        token = secrets.token_urlsafe(24)
        response = _json({"csrf": token})
        response.set_cookie(
            CSRF_COOKIE, token, httponly=True, secure=True, samesite="Strict", path="/"
        )
        return response

    # --- approvals ---

    async def _list_pending(self, _: web.Request) -> web.Response:
        now = self.clock()
        items = [
            {
                "approval_id": p.approval_id,
                "agent": p.agent_id,
                "tool": p.tool,
                "args": p.args,
                "risk": p.risk,
                "expires_at": expires_iso(p.expires_at),
                "expires_in": max(0, int(p.expires_at - now)),
                "require": p.require,
            }
            for p in self.pending.values()
            if p.expires_at > now
        ]
        return _json({"pending": items, "enrolled": len(self.store.list())})

    async def _challenge(self, request: web.Request) -> web.Response:
        pending = self._live(request.match_info["id"])
        if pending is None:
            raise _http(404, "no such pending approval")
        creds = self.store.list()
        if not creds:
            raise _http(409, "no passkey enrolled")
        options = generate_authentication_options(
            rp_id=self.config.rp_id,
            challenge=pending.challenge(),
            allow_credentials=[PublicKeyCredentialDescriptor(id=_b64d(c.id)) for c in creds],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return web.Response(text=options_to_json(options), content_type="application/json")

    async def _approve(self, request: web.Request) -> web.Response:
        approval_id = request.match_info["id"]
        source = self.source(request)
        if self._throttled(source):
            raise _http(429, "too many failed attempts")
        pending = self.pending.get(approval_id)
        if pending is None:
            raise await self._reject(request, approval_id, "no such pending approval", None, 404)
        if pending.expires_at <= self.clock():
            raise await self._reject(request, approval_id, "approval expired", pending, 410)
        try:
            body = await request.json()
        except Exception:
            body = None
        credential = body.get("credential") if isinstance(body, dict) else None
        try:
            verified = verify_approval_assertion(
                self.store,
                credential,
                challenge=pending.challenge(),
                rp_id=self.config.rp_id,
                origin=self.config.origin,
            )
        except AssertionRejected as e:
            raise await self._reject(request, approval_id, e.reason, pending) from e
        return await self._deliver(
            pending,
            True,
            f"passkey:{verified.credential_id}",
            {
                "kind": "webauthn",
                "credential_id": verified.credential_id,
                "sign_count": verified.new_sign_count,
                "challenge": bytes_to_base64url(verified.challenge),
            },
        )

    async def _deny(self, request: web.Request) -> web.Response:
        """Denying is always safe, so it needs no signature."""
        pending = self.pending.get(request.match_info["id"])
        if pending is None:
            raise _http(404, "no such pending approval")
        return await self._deliver(pending, False, f"passkey-page:{self.source(request)}", None)

    async def _deliver(
        self, pending: PendingApproval, approved: bool, approver: str, proof: dict | None
    ) -> web.Response:
        if self.answer is None:
            raise _http(409, "approval channel not running")
        # Drop first so a concurrent second submit cannot answer twice.
        if self.pending.pop(pending.approval_id, None) is None:
            raise _http(409, "already resolved")
        try:
            status = await self.answer(
                pending.approval_id, Answer(approved, "passkey", approver, proof)
            )
        except Exception:
            self.pending.setdefault(pending.approval_id, pending)
            raise
        if status is AnswerStatus.REJECTED:
            raise _http(403, "answer rejected")
        if status is not AnswerStatus.ACCEPTED:
            raise _http(409, "already resolved")
        return _json({"ok": True, "approved": approved})

    # --- enrolment ---

    async def _enroll_options(self, request: web.Request) -> web.Response:
        source = self.source(request)
        if self._throttled(source):
            raise _http(429, "too many failed attempts")
        body = await _body(request)
        token = body.get("token")
        if not isinstance(token, str) or not self.tokens.is_valid(token):
            raise await self._reject(request, "enroll", "invalid or expired enrolment token")
        options = generate_registration_options(
            rp_id=self.config.rp_id,
            rp_name="agentpass",
            user_name="owner",
            user_id=secrets.token_bytes(16),
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=_b64d(c.id)) for c in self.store.list()
            ],
        )
        self._reg_challenges[token] = options.challenge
        return web.Response(text=options_to_json(options), content_type="application/json")

    async def _enroll_verify(self, request: web.Request) -> web.Response:
        source = self.source(request)
        if self._throttled(source):
            raise _http(429, "too many failed attempts")
        body = await _body(request)
        token = body.get("token")
        challenge = self._reg_challenges.get(token) if isinstance(token, str) else None
        if challenge is None or not self.tokens.is_valid(token):
            raise await self._reject(request, "enroll", "invalid or expired enrolment token")
        label = body.get("label")
        try:
            cred = verify_registration(
                body.get("credential"),
                challenge=challenge,
                rp_id=self.config.rp_id,
                origin=self.config.origin,
                label=label if isinstance(label, str) else "",
            )
        except AssertionRejected as e:
            raise await self._reject(request, "enroll", e.reason) from e
        if not self.tokens.consume(token):  # one winner if two submits race
            raise await self._reject(request, "enroll", "invalid or expired enrolment token")
        self._reg_challenges.pop(token, None)
        self.store.add(cred)
        logger.info("passkey enrolled id=%s source=%s", cred.id, source)
        return _json({"ok": True, "credential_id": cred.id})


async def _body(request: web.Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise _http(400, "invalid JSON") from None
    if not isinstance(body, dict):
        raise _http(400, "invalid JSON")
    return body


def _b64d(value: str) -> bytes:
    return base64url_to_bytes(value)
