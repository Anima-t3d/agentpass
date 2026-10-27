"""Token providers: how a service gets its Authorization header (DESIGN 10.1)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import tempfile
import time
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiohttp
import yaml

from agentpass.services.base import ServiceUnauthorizedError

logger = logging.getLogger(__name__)

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
REFRESH_MARGIN = 120  # refresh when fewer than this many seconds remain
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")

Notifier = Callable[[str], Awaitable[None]]


class TokenRefreshError(Exception):
    """A refresh failed for a reason other than invalid_grant (network, 5xx)."""


class TokenProvider(ABC):
    """Supplies auth headers for one service."""

    @abstractmethod
    async def header(self) -> dict[str, str]:
        """Return the headers to send on the next request."""

    @property
    def needs_consent(self) -> bool:
        return False

    async def on_unauthorized(self, used: dict[str, str]) -> bool:
        """Called on a 401. Return True if a retry with a fresh header is worthwhile."""
        return False


class StaticBearer(TokenProvider):
    """A fixed header, e.g. ``Authorization: Bearer <token>``."""

    def __init__(self, token: str, header_name: str = "Authorization", bearer: bool = True) -> None:
        self._headers = {header_name: f"Bearer {token}" if bearer else token}

    async def header(self) -> dict[str, str]:
        return dict(self._headers)


# --- Token store ---


@dataclass
class StoredToken:
    refresh_token: str
    access_token: str = ""
    expires_at: float = 0.0
    scopes: list[str] = field(default_factory=list)
    obtained_at: float = 0.0
    needs_consent: bool = False  # deviation from DESIGN 10.2: persisted so `auth status` sees it

    def to_dict(self) -> dict[str, Any]:
        return {
            "refresh_token": self.refresh_token,
            "access_token": self.access_token,
            "expires_at": self.expires_at,
            "scopes": self.scopes,
            "obtained_at": self.obtained_at,
            "needs_consent": self.needs_consent,
        }


def check_name(kind: str, value: str) -> str:
    if not _NAME_RE.fullmatch(value):
        raise ValueError(f"Invalid {kind} {value!r}: use lowercase letters, digits, '-' and '_'")
    return value


class TokenStore:
    """``<dir>/<provider>-<account>.json``, mode 0600, written atomically."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def path(self, provider: str, account: str) -> Path:
        check_name("provider", provider)
        check_name("account", account)
        return self.directory / f"{provider}-{account}.json"

    def load(self, provider: str, account: str) -> StoredToken | None:
        try:
            raw = json.loads(self.path(provider, account).read_text())
        except FileNotFoundError:
            return None
        return StoredToken(
            refresh_token=raw["refresh_token"],
            access_token=raw.get("access_token", ""),
            expires_at=float(raw.get("expires_at", 0)),
            scopes=list(raw.get("scopes", [])),
            obtained_at=float(raw.get("obtained_at", 0)),
            needs_consent=bool(raw.get("needs_consent", False)),
        )

    def ensure_writable(self) -> None:
        """Create the directory and prove we can write to it; raises OSError."""
        self.directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".probe.", suffix=".tmp")
        os.close(fd)
        os.unlink(tmp)

    def save(self, provider: str, account: str, token: StoredToken) -> Path:
        target = self.path(provider, account)
        self.directory.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.directory, 0o700)
        # mkstemp creates the file 0600; the temp file lives in the target dir so
        # the rename is atomic.
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=f".{target.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(token.to_dict(), f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        dir_fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return target

    def delete(self, provider: str, account: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.path(provider, account).unlink()

    def accounts(self) -> list[tuple[str, str]]:
        found = []
        for p in sorted(self.directory.glob("*.json")):
            provider, _, account = p.stem.partition("-")
            if account:
                found.append((provider, account))
        return found


def load_client_secrets(path: str | Path, provider: str) -> tuple[str, str]:
    """Read ``<provider>: {client_id, client_secret}`` from secrets.yaml."""
    try:
        raw = yaml.safe_load(Path(path).read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ValueError(f"Cannot read secrets file {path}: {type(e).__name__}") from None
    section = raw.get(provider) if isinstance(raw, dict) else None
    if not isinstance(section, dict) or not section.get("client_id"):
        raise ValueError(f"{path} has no '{provider}' client_id/client_secret")
    return str(section["client_id"]), str(section.get("client_secret", ""))


# --- OAuth2 refresh ---


class OAuth2Refresh(TokenProvider):
    """Refreshing OAuth2 bearer token backed by a TokenStore."""

    def __init__(
        self,
        *,
        store: TokenStore,
        provider: str,
        account: str,
        secrets_file: str | Path,
        token_url: str = GOOGLE_TOKEN_URL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._provider = provider
        self._account = account
        self._secrets_file = secrets_file
        self._token_url = token_url
        self._clock = clock
        self._lock = asyncio.Lock()
        self._token: StoredToken | None = None
        self._loaded = False
        self._notifier: Notifier | None = None
        self._notified = False

    @property
    def needs_consent(self) -> bool:
        self._ensure_loaded()
        return self._token is None or self._token.needs_consent

    def consent_command(self) -> str:
        scopes = ",".join(
            s.removeprefix("https://www.googleapis.com/auth/")
            for s in (self._token.scopes if self._token else [])
        )
        cmd = f"agentpass auth {self._provider} --account {self._account}"
        return f"{cmd} --scopes {scopes}" if scopes else cmd

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._token = self._store.load(self._provider, self._account)
            self._loaded = True

    def _fresh(self) -> bool:
        t = self._token
        return bool(t and t.access_token and t.expires_at - self._clock() >= REFRESH_MARGIN)

    async def header(self) -> dict[str, str]:
        self._ensure_loaded()
        if self.needs_consent:
            raise ServiceUnauthorizedError(self._account)
        if not self._fresh():
            async with self._lock:
                if not self._fresh():  # single flight: the first waiter refreshes
                    await self._refresh()
        assert self._token is not None
        return {"Authorization": f"Bearer {self._token.access_token}"}

    async def on_unauthorized(self, used: dict[str, str]) -> bool:
        self._ensure_loaded()
        async with self._lock:
            if self.needs_consent:
                return False
            assert self._token is not None
            if used.get("Authorization") != f"Bearer {self._token.access_token}":
                return True  # someone already refreshed since this request was built
            await self._refresh()
            return True

    async def _refresh(self) -> None:
        """Caller holds the lock."""
        assert self._token is not None
        client_id, client_secret = load_client_secrets(self._secrets_file, self._provider)
        form = {
            "grant_type": "refresh_token",
            "refresh_token": self._token.refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        try:
            async with (
                aiohttp.ClientSession() as session,
                session.post(
                    self._token_url, data=form, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp,
            ):
                try:
                    data = await resp.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError):
                    data = {}
                status = resp.status
        except (aiohttp.ClientError, TimeoutError) as e:
            raise TokenRefreshError(type(e).__name__) from None

        if status == 400 and isinstance(data, dict) and data.get("error") == "invalid_grant":
            await self._mark_needs_consent()
            raise ServiceUnauthorizedError(self._account)
        if status != 200 or not isinstance(data, dict) or "access_token" not in data:
            raise TokenRefreshError(f"token endpoint returned {status}")

        now = self._clock()
        t = self._token
        t.access_token = data["access_token"]
        t.expires_at = now + float(data.get("expires_in", 3600))
        t.refresh_token = data.get("refresh_token", t.refresh_token)  # refresh tokens rotate
        if data.get("scope"):
            t.scopes = data["scope"].split()
        self._store.save(self._provider, self._account, t)

    async def _mark_needs_consent(self) -> None:
        assert self._token is not None
        self._token.needs_consent = True
        self._token.access_token = ""
        self._store.save(self._provider, self._account, self._token)
        await self._notify()

    def set_notifier(self, notifier: Notifier) -> None:
        """Wire the owner notification; sends one now if consent is already needed."""
        self._notifier = notifier
        self._ensure_loaded()
        if self._token is not None and self._token.needs_consent:
            asyncio.get_running_loop().create_task(self._notify())

    async def _notify(self) -> None:
        if self._notified or self._notifier is None:
            return
        self._notified = True  # one notification per process, no retry loop
        text = (
            f"{self._provider} account '{self._account}' needs consent again. "
            f"Run: {self.consent_command()}"
        )
        try:
            await self._notifier(text)
        except Exception:
            logger.warning("Could not send consent notification", exc_info=True)
