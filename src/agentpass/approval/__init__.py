"""Approval channels and the coordinator that arbitrates them (DESIGN 4)."""

from agentpass.approval.channel import (
    Answer,
    AnswerStatus,
    ApprovalChannel,
    ApprovalOutcome,
    ApprovalReason,
    ApprovalRequest,
    ApprovalSink,
    ChannelHandle,
    NoChannelError,
    RememberOffer,
)
from agentpass.approval.coordinator import ApprovalCoordinator


def build_channels(config, db=None) -> list[ApprovalChannel]:
    """Build the configured approval channels (``config.channels``).

    *db* is passed to channels that audit (the passkey page records rejected
    assertions). It is optional so a config-only test can build channels.
    """
    channels: list[ApprovalChannel] = []
    page = getattr(config, "passkey", None)
    origin = page.origin if page and page.enabled else None
    for entry in config.channels:
        if entry.type == "telegram":
            from agentpass.approval.telegram_channel import TelegramChannel

            channels.append(
                TelegramChannel(
                    entry.telegram, name=entry.name, trust=entry.trust, passkey_origin=origin
                )
            )
        elif entry.type == "passkey":
            from agentpass.passkey.channel import PasskeyChannel

            channels.append(PasskeyChannel(entry.passkey, db=db))
        elif entry.type in ("webhook", "command"):
            from agentpass.approval.notify_channel import NotifyChannel

            channels.append(NotifyChannel(entry.notify, name=entry.name, link_origin=origin))
        else:
            raise ValueError(f"Unsupported channel type: {entry.type!r}")
    return channels


__all__ = [
    "Answer",
    "AnswerStatus",
    "ApprovalChannel",
    "ApprovalCoordinator",
    "ApprovalOutcome",
    "ApprovalReason",
    "ApprovalRequest",
    "ApprovalSink",
    "ChannelHandle",
    "NoChannelError",
    "RememberOffer",
    "build_channels",
]
