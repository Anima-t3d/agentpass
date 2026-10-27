"""Google OAuth consent flow and `agentpass auth` commands (DESIGN 10.3)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from agentpass.services.auth import (
    GOOGLE_REVOKE_URL,
    GOOGLE_TOKEN_URL,
    StoredToken,
    TokenStore,
    load_client_secrets,
)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
REDIRECT_URI = "http://127.0.0.1:1/"
SCOPE_PREFIX = "https://www.googleapis.com/auth/"


class ConsentError(Exception):
    """The consent flow failed; the message is safe to print."""


def resolve_scopes(csv: str) -> list[str]:
    """Expand short names (gmail.modify) to full scope URLs, dropping duplicates."""
    out: list[str] = []
    for part in csv.split(","):
        part = part.strip()
        if not part:
            continue
        full = part if part.startswith("https://") else SCOPE_PREFIX + part
        if full not in out:
            out.append(full)
    if not out:
        raise ConsentError("--scopes is empty")
    return out


def new_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_auth_url(
    *,
    client_id: str,
    scopes: list[str],
    state: str,
    challenge: str,
    incremental: bool,
    auth_url: str = GOOGLE_AUTH_URL,
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    if incremental:
        params["include_granted_scopes"] = "true"
    return f"{auth_url}?{urlencode(params)}"


def parse_redirect(pasted: str, expected_state: str) -> str:
    """Return the authorization code from the pasted redirect URL, checking state."""
    query = parse_qs(urlparse(pasted.strip()).query)
    if "error" in query:
        raise ConsentError(f"Google returned an error: {query['error'][0]}")
    state = query.get("state", [""])[0]
    if not hmac.compare_digest(state.encode(), expected_state.encode()):
        raise ConsentError("State mismatch: this URL does not belong to this consent attempt")
    code = query.get("code", [""])[0]
    if not code:
        raise ConsentError("No authorization code in the pasted URL")
    return code


async def _post_form(url: str, form: dict[str, str]) -> tuple[int, dict]:
    try:
        async with (
            aiohttp.ClientSession() as session,
            session.post(url, data=form, timeout=aiohttp.ClientTimeout(total=15)) as resp,
        ):
            try:
                data = await resp.json(content_type=None)
            except (aiohttp.ContentTypeError, ValueError):
                data = {}
            return resp.status, data if isinstance(data, dict) else {}
    except (aiohttp.ClientError, TimeoutError) as e:
        raise ConsentError(f"Could not reach {urlparse(url).netloc}: {type(e).__name__}") from None


async def run_google_consent(
    *,
    store: TokenStore,
    secrets_file: str | Path,
    account: str,
    scopes_csv: str,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[[str], None] = print,
    token_url: str = GOOGLE_TOKEN_URL,
    auth_url: str = GOOGLE_AUTH_URL,
    clock: Callable[[], float] = time.time,
) -> StoredToken:
    try:
        client_id, client_secret = load_client_secrets(secrets_file, "google")
    except ValueError as e:
        raise ConsentError(str(e)) from None
    requested = resolve_scopes(scopes_csv)
    try:  # fail before the consent URL is shown, so a bad dir can't waste the consent
        store.ensure_writable()
    except OSError as e:
        raise ConsentError(
            f"token directory {store.directory} is not writable: {e}; "
            "pass --data-dir to choose another"
        ) from None
    existing = store.load("google", account)
    scopes = list(requested)
    if existing:  # incremental consent: keep what was already granted
        scopes += [s for s in existing.scopes if s not in scopes]

    state = secrets.token_urlsafe(32)
    verifier, challenge = new_pkce()
    url = build_auth_url(
        client_id=client_id,
        scopes=scopes,
        state=state,
        challenge=challenge,
        incremental=existing is not None,
        auth_url=auth_url,
    )
    print_fn("Open this URL in any browser and approve access:\n")
    print_fn(url + "\n")
    print_fn(
        f"Google will then redirect to {REDIRECT_URI} and the browser will show a\n"
        "connection error. That is expected. Copy the FULL address from the browser's\n"
        f"address bar (it starts with {REDIRECT_URI}?state=...) and paste it below.\n"
    )
    code = parse_redirect(input_fn("Paste the redirect URL: "), state)

    status, data = await _post_form(
        token_url,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": verifier,
        },
    )
    if status != 200 or "access_token" not in data:
        raise ConsentError(f"Token exchange failed (HTTP {status}: {data.get('error', 'unknown')})")
    refresh = data.get("refresh_token") or (existing.refresh_token if existing else "")
    if not refresh:
        raise ConsentError("Google returned no refresh token; revoke the app's access and retry")

    now = clock()
    token = StoredToken(
        refresh_token=refresh,
        access_token=data["access_token"],
        expires_at=now + float(data.get("expires_in", 3600)),
        scopes=data["scope"].split() if data.get("scope") else scopes,
        obtained_at=now,
    )
    store.save("google", account, token)
    print_fn("Granted scopes:")
    for s in token.scopes:
        print_fn(f"  {s}")
    return token


def auth_status(store: TokenStore, clock: Callable[[], float] = time.time) -> list[str]:
    lines = []
    for provider, account in store.accounts():
        t = store.load(provider, account)
        if t is None:
            continue
        remaining = int(t.expires_at - clock())
        expiry = f"expires in {remaining}s" if remaining > 0 else "access token expired"
        lines.append(
            f"{provider}/{account}: scopes={','.join(t.scopes)} {expiry} "
            f"needs_consent={str(t.needs_consent).lower()}"
        )
    return lines


async def revoke(
    store: TokenStore, provider: str, account: str, revoke_url: str = GOOGLE_REVOKE_URL
) -> None:
    """Revoke upstream, then delete the file. A failed upstream call keeps the file."""
    token = store.load(provider, account)
    if token is None:
        raise ConsentError(f"No token for {provider}/{account}")
    status, _ = await _post_form(revoke_url, {"token": token.refresh_token})
    if status not in (200, 400):  # 400: already revoked or expired upstream
        raise ConsentError(f"Revoke failed (HTTP {status}); the local token was kept")
    store.delete(provider, account)
