"""Passkey storage: enrolled public keys and one-time enrolment tokens.

Both files hold public material or hashes only, are written atomically and are 0600.
The CLI (`passkey enroll`) and the gateway are separate processes, so read-modify-write
cycles take an flock on a sidecar lock file.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ENROLMENT_TTL_SECONDS = 600


@dataclass
class Credential:
    """One enrolled passkey. `public_key` is the COSE key, base64url."""

    id: str
    public_key: str
    sign_count: int = 0
    transports: list[str] = field(default_factory=list)
    created_at: str = ""
    label: str = ""


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")  # created 0600
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    return data if isinstance(data, dict) else {}


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)  # closing releases the lock


class PasskeyStore:
    """Enrolled credentials, `<data dir>/passkeys.json`."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def list(self) -> list[Credential]:
        return [Credential(**c) for c in _read(self.path).get("credentials", [])]

    def get(self, credential_id: str) -> Credential | None:
        return next((c for c in self.list() if c.id == credential_id), None)

    def add(self, cred: Credential) -> None:
        with _locked(self.path):
            data = _read(self.path)
            creds = [c for c in data.get("credentials", []) if c["id"] != cred.id]
            creds.append(asdict(cred))
            _atomic_write(self.path, {"credentials": creds})

    def advance_sign_count(self, credential_id: str, new_count: int) -> None:
        """Store a verified, higher counter. Never lowers it."""
        with _locked(self.path):
            data = _read(self.path)
            for c in data.get("credentials", []):
                if c["id"] == credential_id and new_count > c["sign_count"]:
                    c["sign_count"] = new_count
            _atomic_write(self.path, data)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class EnrolmentTokens:
    """One-time enrolment tokens. Only SHA-256 hashes are stored, with an expiry."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def issue(self, ttl: int = ENROLMENT_TTL_SECONDS, now: float | None = None) -> str:
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with _locked(self.path):
            live = {h: e for h, e in _read(self.path).items() if e > now}
            live[_digest(token)] = now + ttl
            _atomic_write(self.path, live)
        return token

    def is_valid(self, token: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        expiry = _read(self.path).get(_digest(token))
        return isinstance(expiry, int | float) and expiry > now

    def consume(self, token: str, now: float | None = None) -> bool:
        """Atomically spend a token. True only for the one caller that wins."""
        now = time.time() if now is None else now
        with _locked(self.path):
            data = _read(self.path)
            expiry = data.pop(_digest(token), None)
            _atomic_write(self.path, {h: e for h, e in data.items() if e > now})
        return isinstance(expiry, int | float) and expiry > now


def utc_now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
