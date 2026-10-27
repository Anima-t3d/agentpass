"""Tests for OAuth2 token providers, the token store and the Google consent flow.

All network traffic goes to local fake servers; every secret is generated here.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import secrets
import stat
from urllib.parse import parse_qs, urlparse

import pytest
import yaml
from aiohttp import web
from aiohttp.test_utils import TestServer

from agentpass.config import AuthConfig, ServiceConfig, load_tools_file
from agentpass.services import consent
from agentpass.services.auth import (
    OAuth2Refresh,
    StaticBearer,
    StoredToken,
    TokenStore,
)
from agentpass.services.base import ServiceUnauthorizedError
from agentpass.services.http import GenericHTTPService, HTTPServiceError


class Fake:
    """Fake Google: a token endpoint, a revoke endpoint and an API host."""

    def __init__(self) -> None:
        self.token_calls: list[dict[str, str]] = []
        self.api_calls: list[str] = []
        self.revoke_calls: list[dict[str, str]] = []
        self.token_status = 200
        self.token_error = ""
        self.revoke_status = 200
        self.valid_access: set[str] = set()
        self.always_401 = False
        self.counter = 0
        self.grant_scope = "https://www.googleapis.com/auth/gmail.modify"
        self.server: TestServer | None = None

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_post("/token", self.token)
        app.router.add_post("/revoke", self.revoke)
        app.router.add_get("/api/{tail:.*}", self.api)
        return app

    async def token(self, request: web.Request) -> web.Response:
        form = dict(await request.post())
        self.token_calls.append(form)
        await asyncio.sleep(0.02)  # widen the race window for the single-flight test
        if self.token_status != 200:
            body = {"error": self.token_error} if self.token_error else {}
            return web.json_response(body, status=self.token_status)
        self.counter += 1
        access = f"access-{self.counter}-{secrets.token_hex(4)}"
        self.valid_access.add(access)
        return web.json_response(
            {
                "access_token": access,
                "expires_in": 3600,
                "refresh_token": f"rotated-{self.counter}-{secrets.token_hex(4)}",
                "scope": self.grant_scope,
            }
        )

    async def revoke(self, request: web.Request) -> web.Response:
        self.revoke_calls.append(dict(await request.post()))
        return web.Response(status=self.revoke_status)

    async def api(self, request: web.Request) -> web.Response:
        self.api_calls.append(request.headers.get("Authorization", ""))
        bearer = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if self.always_401 or bearer not in self.valid_access:
            return web.json_response({"error": "nope"}, status=401)
        return web.json_response({"ok": True})

    @property
    def url(self) -> str:
        assert self.server is not None
        return f"http://127.0.0.1:{self.server.port}"


@pytest.fixture
async def fake():
    f = Fake()
    f.server = TestServer(f.app())
    await f.server.start_server()
    yield f
    await f.server.close()


@pytest.fixture
def secrets_file(tmp_path):
    path = tmp_path / "secrets.yaml"
    path.write_text(
        yaml.safe_dump(
            {"google": {"client_id": secrets.token_hex(8), "client_secret": secrets.token_hex(8)}}
        )
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def store(tmp_path):
    return TokenStore(tmp_path / "data" / "tokens")


def _token(now: float, *, expires_in: float, access: str = "old-access") -> StoredToken:
    return StoredToken(
        refresh_token="refresh-" + secrets.token_hex(8),
        access_token=access,
        expires_at=now + expires_in,
        scopes=["https://www.googleapis.com/auth/gmail.modify"],
        obtained_at=now,
    )


def _provider(fake, store, secrets_file, **kw) -> OAuth2Refresh:
    return OAuth2Refresh(
        store=store,
        provider="google",
        account="personal",
        secrets_file=secrets_file,
        token_url=f"{fake.url}/token",
        **kw,
    )


# --- StaticBearer ---


async def test_static_bearer_header():
    assert await StaticBearer("abc").header() == {"Authorization": "Bearer abc"}
    assert await StaticBearer("k", "X-Api-Key", bearer=False).header() == {"X-Api-Key": "k"}
    assert not StaticBearer("abc").needs_consent
    assert await StaticBearer("abc").on_unauthorized({}) is False


# --- Refresh behaviour ---


async def test_no_refresh_when_fresh(fake, store, secrets_file):
    import time

    store.save("google", "personal", _token(time.time(), expires_in=3600))
    p = _provider(fake, store, secrets_file)
    assert await p.header() == {"Authorization": "Bearer old-access"}
    assert fake.token_calls == []


async def test_refresh_when_under_120_seconds_remain(fake, store, secrets_file):
    import time

    old = _token(time.time(), expires_in=100)
    store.save("google", "personal", old)
    p = _provider(fake, store, secrets_file)
    header = await p.header()
    assert len(fake.token_calls) == 1
    call = fake.token_calls[0]
    assert call["grant_type"] == "refresh_token" and call["refresh_token"] == old.refresh_token
    assert header["Authorization"].removeprefix("Bearer ") in fake.valid_access
    saved = store.load("google", "personal")
    assert saved.refresh_token != old.refresh_token  # rotated and persisted
    assert saved.expires_at > time.time() + 3000


async def test_refresh_at_expiry_with_injected_clock(fake, store, secrets_file):
    now = [1_000_000.0]
    store.save("google", "personal", _token(now[0], expires_in=3600))
    p = _provider(fake, store, secrets_file, clock=lambda: now[0])
    await p.header()
    assert fake.token_calls == []
    now[0] += 3600 - 119
    await p.header()
    assert len(fake.token_calls) == 1


async def test_single_flight_under_concurrency(fake, store, secrets_file):
    import time

    store.save("google", "personal", _token(time.time(), expires_in=0))
    p = _provider(fake, store, secrets_file)
    headers = await asyncio.gather(*(p.header() for _ in range(20)))
    assert len(fake.token_calls) == 1
    assert len({h["Authorization"] for h in headers}) == 1


# --- GenericHTTPService integration ---


def _service(fake, store, secrets_file, tmp_path) -> GenericHTTPService:
    tools = load_tools_file("tools/gmail.yaml", "gmail")
    auth = AuthConfig(
        type="oauth2",
        provider="google",
        account="personal",
        token_dir=str(store.directory),
        secrets_file=str(secrets_file),
        token_url=f"{fake.url}/token",
    )
    cfg = ServiceConfig(name="gmail", url=f"{fake.url}/api", auth=auth, tools=tools)
    return GenericHTTPService(cfg)


async def test_401_triggers_exactly_one_refresh_and_retry(fake, store, secrets_file, tmp_path):
    import time

    store.save("google", "personal", _token(time.time(), expires_in=3600, access="revoked"))
    svc = _service(fake, store, secrets_file, tmp_path)
    try:
        result = await svc.execute("gmail_list_labels", {})
    finally:
        await svc.close()
    assert result == {"ok": True}
    assert len(fake.token_calls) == 1
    assert len(fake.api_calls) == 2 and fake.api_calls[0] == "Bearer revoked"


async def test_repeated_401_does_not_loop(fake, store, secrets_file, tmp_path):
    import time

    store.save("google", "personal", _token(time.time(), expires_in=3600))
    fake.always_401 = True
    svc = _service(fake, store, secrets_file, tmp_path)
    try:
        with pytest.raises(HTTPServiceError):
            await svc.execute("gmail_list_labels", {})
    finally:
        await svc.close()
    assert len(fake.api_calls) == 2
    assert len(fake.token_calls) == 1


async def test_invalid_grant_marks_needs_consent(fake, store, secrets_file, tmp_path):
    import time

    stored = _token(time.time(), expires_in=0)
    store.save("google", "personal", stored)
    fake.token_status, fake.token_error = 400, "invalid_grant"
    svc = _service(fake, store, secrets_file, tmp_path)
    sent: list[str] = []

    async def notifier(text: str) -> None:
        sent.append(text)

    svc.provider.set_notifier(notifier)
    try:
        with pytest.raises(ServiceUnauthorizedError):
            await svc.execute("gmail_list_labels", {})
        assert svc.provider.needs_consent
        assert await svc.health_check() is False
        with pytest.raises(ServiceUnauthorizedError):
            await svc.execute("gmail_list_labels", {})
    finally:
        await svc.close()
    assert len(fake.token_calls) == 1  # no retry loop
    assert fake.api_calls == []
    assert store.load("google", "personal").needs_consent
    assert sent == [
        "google account 'personal' needs consent again. "
        "Run: agentpass auth google --account personal --scopes gmail.modify"
    ]
    assert stored.refresh_token not in sent[0]


async def test_transient_refresh_failure_is_not_needs_consent(fake, store, secrets_file, tmp_path):
    import time

    store.save("google", "personal", _token(time.time(), expires_in=0))
    fake.token_status = 503
    svc = _service(fake, store, secrets_file, tmp_path)
    try:
        with pytest.raises(HTTPServiceError):
            await svc.execute("gmail_list_labels", {})
    finally:
        await svc.close()
    assert not svc.provider.needs_consent


async def test_pipeline_reports_service_unauthorized_without_detail():
    from unittest.mock import AsyncMock

    from agentpass.pipeline import ServiceUnauthorized
    from agentpass.server import ERROR_CODES, SERVICE_UNAUTHORIZED
    from tests.test_pipeline import _make

    p, _, executor, _, _ = await _make()
    executor.execute = AsyncMock(side_effect=ServiceUnauthorizedError("secret-detail"))
    with pytest.raises(ServiceUnauthorized) as ei:
        await p.process("agent-a", "t", {})
    assert "secret-detail" not in ei.value.message
    assert ERROR_CODES[ServiceUnauthorized] == SERVICE_UNAUTHORIZED == -32009


# --- Token store ---


def test_store_file_is_0600_and_dir_private(store):
    path = store.save("google", "personal", _token(0, expires_in=10))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(store.directory).st_mode) == 0o700
    assert path.name == "google-personal.json"
    assert set(json.loads(path.read_text())) >= {
        "refresh_token",
        "access_token",
        "expires_at",
        "scopes",
        "obtained_at",
    }


def test_store_overwrite_keeps_0600_and_leaves_no_temp_files(store):
    for i in range(3):
        path = store.save("google", "personal", _token(i, expires_in=10))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert [p.name for p in store.directory.iterdir()] == ["google-personal.json"]


def test_store_write_is_atomic(store, monkeypatch):
    original = _token(0, expires_in=10)
    store.save("google", "personal", original)

    def boom(*_a, **_k):
        raise OSError("disk gone")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        store.save("google", "personal", _token(1, expires_in=10))
    monkeypatch.undo()
    assert store.load("google", "personal").refresh_token == original.refresh_token
    assert [p.name for p in store.directory.iterdir()] == ["google-personal.json"]


@pytest.mark.parametrize("bad", ["../x", "a/b", "", "A", ".hidden"])
def test_store_rejects_path_tricks(store, bad):
    with pytest.raises(ValueError):
        store.path("google", bad)


# --- Consent flow ---


def _pasted(url: str, *, state: str | None = None, code: str = "auth-code") -> str:
    q = parse_qs(urlparse(url).query)
    return f"http://127.0.0.1:1/?state={state or q['state'][0]}&code={code}"


async def _consent(fake, store, secrets_file, scopes, *, state_override=None, lines=None):
    printed: list[str] = lines if lines is not None else []

    def input_fn(_prompt: str) -> str:
        url = next(line for line in printed if line.startswith("https://"))
        return _pasted(url.strip(), state=state_override)

    return await consent.run_google_consent(
        store=store,
        secrets_file=secrets_file,
        account="personal",
        scopes_csv=scopes,
        input_fn=input_fn,
        print_fn=printed.append,
        token_url=f"{fake.url}/token",
    )


async def test_consent_url_has_pkce_state_offline_and_prompt(fake, store, secrets_file):
    lines: list[str] = []
    await _consent(fake, store, secrets_file, "gmail.modify,calendar", lines=lines)
    url = next(line for line in lines if line.startswith("https://accounts.google.com")).strip()
    q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    assert q["code_challenge_method"] == "S256"
    assert q["access_type"] == "offline" and q["prompt"] == "consent"
    assert q["redirect_uri"] == "http://127.0.0.1:1/"
    assert q["scope"].split() == [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/calendar",
    ]
    assert "include_granted_scopes" not in q
    assert any("http://127.0.0.1:1/" in line and "paste" in line.lower() for line in lines)
    # PKCE: the verifier sent to the token endpoint hashes to the challenge in the URL
    verifier = fake.token_calls[0]["code_verifier"]
    digest = hashlib.sha256(verifier.encode()).digest()
    assert base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == q["code_challenge"]
    assert fake.token_calls[0]["code"] == "auth-code"


async def test_consent_writes_store_and_prints_granted_scopes(fake, store, secrets_file):
    lines: list[str] = []
    token = await _consent(fake, store, secrets_file, "gmail.modify", lines=lines)
    saved = store.load("google", "personal")
    assert saved.refresh_token == token.refresh_token
    assert stat.S_IMODE(os.stat(store.path("google", "personal")).st_mode) == 0o600
    assert any("gmail.modify" in line for line in lines[-2:])
    assert token.refresh_token not in "\n".join(lines)


async def test_consent_rejects_state_mismatch(fake, store, secrets_file):
    with pytest.raises(consent.ConsentError, match="State mismatch"):
        await _consent(fake, store, secrets_file, "gmail.modify", state_override="forged")
    assert fake.token_calls == []
    assert store.load("google", "personal") is None


async def test_incremental_consent_keeps_earlier_scopes(fake, store, secrets_file):
    await _consent(fake, store, secrets_file, "gmail.modify")
    first = store.load("google", "personal")
    lines: list[str] = []
    fake.grant_scope = (
        "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/calendar"
    )
    await _consent(fake, store, secrets_file, "calendar", lines=lines)
    url = next(line for line in lines if line.startswith("https://accounts.google.com")).strip()
    q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    assert q["include_granted_scopes"] == "true"
    assert set(q["scope"].split()) == set(fake.grant_scope.split())
    second = store.load("google", "personal")
    assert set(second.scopes) == set(fake.grant_scope.split())
    assert second.refresh_token != first.refresh_token


async def test_reconsent_clears_needs_consent(fake, store, secrets_file):
    import time

    t = _token(time.time(), expires_in=0)
    t.needs_consent = True
    store.save("google", "personal", t)
    await _consent(fake, store, secrets_file, "gmail.modify")
    assert store.load("google", "personal").needs_consent is False


def test_status_lists_accounts(store):
    import time

    t = _token(time.time(), expires_in=600)
    t.needs_consent = True
    store.save("google", "personal", t)
    (line,) = consent.auth_status(store)
    assert line.startswith("google/personal: scopes=https://www.googleapis.com/auth/gmail.modify")
    assert "needs_consent=true" in line and "expires in" in line
    assert t.refresh_token not in line and t.access_token not in line


async def test_revoke_deletes_file_after_upstream_revoke(fake, store):
    t = _token(0, expires_in=10)
    store.save("google", "personal", t)
    await consent.revoke(store, "google", "personal", revoke_url=f"{fake.url}/revoke")
    assert fake.revoke_calls == [{"token": t.refresh_token}]
    assert store.load("google", "personal") is None


async def test_revoke_keeps_file_when_upstream_fails(fake, store):
    store.save("google", "personal", _token(0, expires_in=10))
    fake.revoke_status = 500
    with pytest.raises(consent.ConsentError):
        await consent.revoke(store, "google", "personal", revoke_url=f"{fake.url}/revoke")
    assert store.load("google", "personal") is not None


# --- Tool definitions ---


@pytest.mark.parametrize("name", ["gmail", "calendar", "drive"])
def test_google_tool_files_load_and_are_narrow(name):
    tools = load_tools_file(f"tools/{name}.yaml", name)
    assert tools
    for t in tools:
        assert t.name.startswith(name + "_")
        assert t.request is not None and t.request.path.startswith(
            ("/gmail/", "/calendar/", "/drive/")
        )
        assert t.request.method in ("GET", "POST")


def test_auth_cli_status_and_parse(tmp_path, capsys):
    from agentpass.__main__ import parse_args, run_auth

    TokenStore(tmp_path / "data" / "tokens").save("google", "personal", _token(0, expires_in=10))
    config = tmp_path / "config.yaml"
    db_path = str(tmp_path / "data" / "a.db")
    config.write_text(yaml.safe_dump({"storage": {"type": "sqlite", "path": db_path}}))
    args = parse_args(["auth", "status", "--config", str(config)])
    assert run_auth(args) == 0
    assert "google/personal" in capsys.readouterr().out
    args = parse_args(["auth", "google", "--account", "x", "--scopes", "calendar"])
    assert (args.auth_command, args.account, args.scopes) == ("google", "x", "calendar")


def _auth_args(*extra):
    from agentpass.__main__ import parse_args

    return parse_args(["auth", "status", *extra])


def test_auth_store_substitutes_env_in_flow_sequence(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import run_auth

    monkeypatch.setenv("GUARDIAN_USER_ID", "42")
    TokenStore(tmp_path / "data" / "tokens").save("google", "personal", _token(0, expires_in=10))
    config = tmp_path / "config.yaml"
    config.write_text(
        f"allowed_users: [${{GUARDIAN_USER_ID}}]\nstorage:\n  path: {tmp_path}/data/a.db\n"
    )
    assert run_auth(_auth_args("--config", str(config))) == 0
    assert "google/personal" in capsys.readouterr().out


def test_auth_unparsable_explicit_config_errors_without_fallback(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import run_auth

    monkeypatch.chdir(tmp_path)
    config = tmp_path / "bad.yaml"
    config.write_text("storage: [unclosed\n")
    assert run_auth(_auth_args("--config", str(config))) == 1
    err = capsys.readouterr().err
    assert "--data-dir" in err
    assert not (tmp_path / "data").exists()


def test_auth_missing_storage_path_or_unset_var_errors(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import run_auth

    monkeypatch.delenv("NOPE_UNSET", raising=False)
    config = tmp_path / "c.yaml"
    config.write_text("gateway: {}\n")
    assert run_auth(_auth_args("--config", str(config))) == 1
    config.write_text("storage:\n  path: ${NOPE_UNSET}/a.db\n")
    assert run_auth(_auth_args("--config", str(config))) == 1
    assert run_auth(_auth_args("--config", str(tmp_path / "missing.yaml"))) == 1
    assert capsys.readouterr().err.count("--data-dir") == 3


def test_auth_default_data_dir_only_without_any_config(tmp_path, monkeypatch, capsys):
    from agentpass.__main__ import run_auth

    monkeypatch.chdir(tmp_path)
    assert run_auth(_auth_args()) == 0
    (tmp_path / "config.yaml").write_text("gateway: {}\n")
    assert run_auth(_auth_args()) == 1
    assert "--data-dir" in capsys.readouterr().err


def test_auth_google_unwritable_dir_fails_before_url(tmp_path, capsys):
    from agentpass.__main__ import parse_args, run_auth

    blocker = tmp_path / "blocker"
    blocker.write_text("not a dir")
    secrets = tmp_path / "secrets.yaml"
    secrets.write_text(yaml.safe_dump({"google": {"client_id": "id", "client_secret": "sec"}}))
    args = parse_args(
        ["auth", "google", "--account", "x", "--scopes", "calendar",
         "--data-dir", str(blocker), "--secrets", str(secrets)]
    )  # fmt: skip
    assert run_auth(args) == 1
    captured = capsys.readouterr()
    assert "accounts.google.com" not in captured.out
    assert "not writable" in captured.err


# --- calendar_list_events request URL ---


async def _calendar_urls(args):
    seen: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        seen.append(str(request.rel_url))
        return web.json_response({"items": []})

    app = web.Application()
    app.router.add_get("/{tail:.*}", handler)
    async with TestServer(app) as server:
        tools = load_tools_file("tools/calendar.yaml", "calendar")
        cfg = ServiceConfig(
            name="calendar", url=str(server.make_url("")).rstrip("/"), auth=AuthConfig(type="none")
        )
        cfg.tools = tools
        svc = GenericHTTPService(cfg)
        try:
            await svc.execute("calendar_list_events", args)
        finally:
            await svc.close()
    return seen


async def test_calendar_list_events_url_has_time_min_and_encodes_plus():
    (url,) = await _calendar_urls(
        {"calendar_id": "primary", "time_min": "2026-10-27T00:00:00+08:00", "max_results": 50}
    )
    assert url.startswith("/calendar/v3/calendars/primary/events?")
    assert "timeMin=2026-10-27T00:00:00%2B08:00" in url
    assert "+08" not in url
    assert "timeMax" not in url
    assert "maxResults=50" in url and "singleEvents=true" in url and "orderBy=startTime" in url


def test_calendar_list_events_validation():
    tools = {t.name: t for t in load_tools_file("tools/calendar.yaml", "calendar")}
    pats = {k: v.validate for k, v in tools["calendar_list_events"].args.items()}

    ok = re.compile(pats["time_min"])
    assert ok.fullmatch("2026-10-27T00:00:00Z")
    assert ok.fullmatch("2026-10-27T00:00:00.123+08:00")
    assert not ok.fullmatch("tomorrow")
    assert not ok.fullmatch("2026-10-27")
    assert tools["calendar_list_events"].args["time_min"].required
