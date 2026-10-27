"""Wiring the passkey channel into the approval stack.

These are the checks the two cards could not write apart: that a configured
`type: passkey` channel is built as an ApprovalChannel with the webauthn proof,
and that a rule requiring a passkey is satisfied only by that channel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

import pytest

from agentpass.approval import Answer, build_channels
from agentpass.approval.channel import ApprovalChannel
from agentpass.approval.coordinator import satisfies
from agentpass.config import ChannelConfig, ConfigError, _load_channels
from agentpass.passkey.page import PasskeyConfig


class RecordingChannel(ApprovalChannel):
    """Stand-in for a configured Telegram channel: trusted, no WebAuthn proof."""

    name = "telegram"
    trust = "trusted"
    proof_kinds: ClassVar[set[str]] = {"telegram_callback"}

    async def start(self, sink) -> None:
        self.sink = sink

    async def stop(self) -> None:
        return None

    async def send(self, req):
        from agentpass.approval.channel import ChannelHandle

        return ChannelHandle(channel=self.name, ref={"approval_id": req.approval_id})

    async def finalize(self, handle, outcome=None) -> None:
        return None


@dataclass
class FakeConfig:
    channels: list[ChannelConfig] = field(default_factory=list)
    passkey: PasskeyConfig | None = None


def _passkey_config(tmp_path) -> PasskeyConfig:
    return PasskeyConfig(
        enabled=True,
        host="127.0.0.1",
        port=8206,
        rp_id="localhost",
        origin="https://localhost",
        store_path=str(tmp_path / "passkeys.json"),
    )


def test_passkey_channel_entry_is_parsed(tmp_path):
    entries = _load_channels({"channels": [{"name": "page", "type": "passkey"}]})
    assert entries[0].type == "passkey"
    # The page settings come from the top-level `passkey` block, filled in by load_config.
    assert entries[0].passkey is None


def test_unknown_channel_type_is_rejected():
    with pytest.raises(ConfigError, match="Unsupported channel type"):
        _load_channels({"channels": [{"name": "x", "type": "carrier-pigeon"}]})


def test_build_channels_builds_a_passkey_channel(tmp_path):
    cfg = FakeConfig(
        channels=[ChannelConfig(name="page", type="passkey", passkey=_passkey_config(tmp_path))],
        passkey=_passkey_config(tmp_path),
    )
    channels = build_channels(cfg)
    assert [c.name for c in channels] == ["passkey"]
    assert isinstance(channels[0], ApprovalChannel)
    assert channels[0].proof_kinds == {"webauthn"}
    assert channels[0].trust == "trusted"


def test_require_passkey_needs_the_passkey_channel(tmp_path):
    """A passkey requirement refuses a Telegram approval and accepts a WebAuthn one."""
    page = build_channels(
        FakeConfig(
            channels=[
                ChannelConfig(name="page", type="passkey", passkey=_passkey_config(tmp_path))
            ],
            passkey=_passkey_config(tmp_path),
        )
    )[0]
    telegram = RecordingChannel()

    approve_by_telegram = Answer(
        approved=True, channel="telegram", approver_id="owner", proof={"kind": "telegram_callback"}
    )
    approve_by_passkey = Answer(
        approved=True, channel="passkey", approver_id="owner", proof={"kind": "webauthn"}
    )
    deny_by_telegram = Answer(approved=False, channel="telegram", approver_id="owner")

    assert satisfies(telegram, approve_by_telegram, "passkey") is False
    assert satisfies(page, approve_by_passkey, "passkey") is True
    # denying is always safe from a trusted channel (DESIGN 3.4)
    assert satisfies(telegram, deny_by_telegram, "passkey") is True
    # a webauthn answer without proof evidence does not count
    assert satisfies(page, Answer(True, "passkey", "owner", proof=None), "passkey") is False
