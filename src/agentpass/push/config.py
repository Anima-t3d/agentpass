"""Configuration of the Web Push approval channel (``passkey.push``)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentpass.config import ConfigError

DEFAULT_TIMEOUT = 10.0


@dataclass
class PushConfig:
    enabled: bool = False
    vapid_key_path: str = ""  # default: <storage data dir>/push-vapid.pem
    subject: str = ""  # VAPID contact, "mailto:..." or "https://..."
    timeout: float = DEFAULT_TIMEOUT  # seconds per push request

    @classmethod
    def from_mapping(cls, raw: Any, storage_path: str) -> PushConfig:
        raw = raw or {}
        if not isinstance(raw, dict):
            raise ConfigError("passkey.push must be a mapping")
        try:
            timeout = float(raw.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            raise ConfigError("passkey.push.timeout must be a number of seconds") from None
        cfg = cls(
            enabled=bool(raw.get("enabled", False)),
            vapid_key_path=str(
                raw.get("vapid_key_path") or Path(storage_path).parent / "push-vapid.pem"
            ),
            subject=str(raw.get("subject", "")),
            timeout=timeout,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.enabled:
            return
        if not self.subject.startswith(("mailto:", "https://")):
            raise ConfigError(
                "passkey.push.subject is required and must start with mailto: or https://"
            )
        if not 0 < self.timeout <= 60:
            raise ConfigError("passkey.push.timeout must be between 0 and 60 seconds")
