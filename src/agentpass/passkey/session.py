"""Page sessions from a passkey sign-in.

A session lets the page list pending approvals (and, later, history and devices). It
never approves anything: every Approve still needs its own assertion over that
approval's challenge. Sessions and login challenges live in memory only, so a restart
signs everyone out.
"""

from __future__ import annotations

import secrets
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

SESSION_COOKIE = "agentpass_session"
IDLE_TTL = 12 * 3600
ABSOLUTE_TTL = 7 * 86400
CHALLENGE_TTL = 120
MAX_CHALLENGES = 256  # outstanding login challenges; the oldest go first
MAX_SESSIONS = 256


@dataclass
class Session:
    token: str
    credential_id: str
    created: float
    last: float


class SessionStore:
    def __init__(
        self,
        idle: int = IDLE_TTL,
        absolute: int = ABSOLUTE_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.idle = idle
        self.absolute = absolute
        self.clock = clock
        self._challenges: OrderedDict[bytes, float] = OrderedDict()  # challenge -> issued
        self._sessions: OrderedDict[str, Session] = OrderedDict()

    # --- login challenges ---

    def new_challenge(self) -> bytes:
        """32 random bytes, accepted once by `consume_challenge` within CHALLENGE_TTL."""
        now = self.clock()
        self._prune_challenges(now)
        while len(self._challenges) >= MAX_CHALLENGES:
            self._challenges.popitem(last=False)
        challenge = secrets.token_bytes(32)
        self._challenges[challenge] = now
        return challenge

    def consume_challenge(self, challenge: bytes) -> bool:
        issued = self._challenges.pop(challenge, None)
        return issued is not None and self.clock() - issued < CHALLENGE_TTL

    def _prune_challenges(self, now: float) -> None:
        for c, issued in list(self._challenges.items()):
            if now - issued >= CHALLENGE_TTL:
                del self._challenges[c]

    # --- sessions ---

    def create(self, credential_id: str) -> str:
        now = self.clock()
        for token, s in list(self._sessions.items()):
            if not self._alive(s, now):
                del self._sessions[token]
        while len(self._sessions) >= MAX_SESSIONS:
            self._sessions.popitem(last=False)
        token = secrets.token_urlsafe(32)
        self._sessions[token] = Session(token, credential_id, now, now)
        return token

    def get(self, token: str) -> Session | None:
        """The live session for `token`, its idle timer refreshed; None if absent or expired."""
        session = self._sessions.get(token) if token else None
        if session is None:
            return None
        now = self.clock()
        if not self._alive(session, now):
            del self._sessions[token]
            return None
        session.last = now
        return session

    def drop(self, token: str) -> None:
        self._sessions.pop(token, None)

    def _alive(self, s: Session, now: float) -> bool:
        return now - s.last < self.idle and now - s.created < self.absolute
