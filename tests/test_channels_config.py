"""Config: `channels` list/mapping and the single `messenger` shorthand."""

from __future__ import annotations

import textwrap

import pytest

from agentpass.config import ConfigError, load_config
from tests.test_config import VALID_CONFIG_YAML, _tools_dir  # noqa: F401 (fixture)

MESSENGER_BLOCK = textwrap.dedent("""\
    messenger:
      type: "telegram"
      telegram:
        token: "bot-token"
        chat_id: -100123
        allowed_users: [111, 222]
""")

LIST_CHANNELS = textwrap.dedent("""\
    channels:
      - name: telegram
        type: telegram
        token: "bot-token"
        chat_id: -100123
        allowed_users: [111, 222]
      - name: spare
        type: telegram
        trust: notify
        telegram: { token: "t2", chat_id: 5, allowed_users: [5] }
""")

MAP_CHANNELS = textwrap.dedent("""\
    channels:
      telegram:
        type: telegram
        trust: trusted
        token: "bot-token"
        chat_id: -100123
        allowed_users: [111, 222]
""")


def _load(tmp_path, block):
    text = VALID_CONFIG_YAML.replace(MESSENGER_BLOCK, block)
    assert block in text
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return load_config(str(path))


def test_messenger_shorthand_is_one_channel(tmp_path, _tools_dir):  # noqa: F811
    cfg = _load(tmp_path, MESSENGER_BLOCK)
    [channel] = cfg.channels
    assert (channel.name, channel.type, channel.trust) == ("telegram", "telegram", "trusted")
    assert channel.telegram.allowed_users == [111, 222]
    assert cfg.messenger.telegram is channel.telegram  # old attribute keeps working


def test_channels_list_with_per_channel_settings(tmp_path, _tools_dir):  # noqa: F811
    cfg = _load(tmp_path, LIST_CHANNELS)
    assert [(c.name, c.trust, c.telegram.chat_id) for c in cfg.channels] == [
        ("telegram", "trusted", -100123),
        ("spare", "notify", 5),
    ]
    assert cfg.messenger.telegram.token == "bot-token"


def test_channels_mapping_form(tmp_path, _tools_dir):  # noqa: F811
    [channel] = _load(tmp_path, MAP_CHANNELS).channels
    assert channel.name == "telegram" and channel.telegram.token == "bot-token"


@pytest.mark.parametrize(
    ("block", "message"),
    [
        (MESSENGER_BLOCK + LIST_CHANNELS, "not both"),
        (LIST_CHANNELS.replace("trust: notify", "trust: maybe"), "trust must be one of"),
        (LIST_CHANNELS.replace("name: spare", "name: telegram"), "Duplicate channel name"),
        (
            LIST_CHANNELS.replace("type: telegram\n    trust", "type: slack\n    trust"),
            "Unsupported channel type",
        ),
        ("channels: []\n", "non-empty"),
        (LIST_CHANNELS.replace("allowed_users: [111, 222]", "allowed_users: []"), "non-empty"),
    ],
)
def test_bad_channels_are_rejected(tmp_path, _tools_dir, block, message):  # noqa: F811
    with pytest.raises(ConfigError, match=message):
        _load(tmp_path, block)
