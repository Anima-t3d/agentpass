"""Models for push-subscribed devices."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PushDevice:
    """A browser/device subscribed to Web Push for approval notifications."""

    device_id: str
    label: str
    endpoint: str
    p256dh: str
    auth: str
    one_tap_approve: bool
    credential_id: str
    created_at: str
    last_seen: str
