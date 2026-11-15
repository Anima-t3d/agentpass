import base64

import pytest

from agentpass.push.tokens import ActionTokens, TokenRejected


class Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


def _b64d(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _reason(fn, *args):
    with pytest.raises(TokenRejected) as info:
        fn(*args)
    return info.value.reason


def test_token_redeems_once():
    tokens = ActionTokens(clock=Clock())
    token = tokens.issue("a1", "dev1", 2000)
    assert tokens.redeem(token, "a1") == "dev1"
    assert _reason(tokens.redeem, token, "a1") == "used"


def test_peek_does_not_consume():
    tokens = ActionTokens(clock=Clock())
    token = tokens.issue("a1", "dev1", 2000)
    assert tokens.peek(token, "a1") == "dev1"
    assert tokens.peek(token, "a1") == "dev1"
    assert tokens.redeem(token, "a1") == "dev1"
    assert _reason(tokens.peek, token, "a1") == "used"


def test_token_bound_to_approval():
    tokens = ActionTokens(clock=Clock())
    token = tokens.issue("a1", "dev1", 2000)
    assert _reason(tokens.redeem, token, "a2") == "bad signature"


def test_token_bound_to_device():
    tokens = ActionTokens(clock=Clock())
    raw = _b64d(tokens.issue("a1", "dev1", 2000))
    # layout: nonce(16) | expires(8) | len(1) | device | mac(32)
    forged = raw[:24] + bytes([4]) + b"dev2" + raw[-32:]
    assert _reason(tokens.redeem, _b64e(forged), "a1") == "bad signature"


def test_expired_token():
    clock = Clock()
    tokens = ActionTokens(clock=clock)
    token = tokens.issue("a1", "dev1", 1500)
    clock.now = 1499
    assert tokens.peek(token, "a1") == "dev1"
    clock.now = 1500
    assert _reason(tokens.redeem, token, "a1") == "expired"


def test_tokens_from_previous_key_are_refused():
    old = ActionTokens(clock=Clock())
    token = old.issue("a1", "dev1", 2000)
    assert _reason(ActionTokens(clock=Clock()).redeem, token, "a1") == "bad signature"


@pytest.mark.parametrize("junk", ["", "!!!", "AAAA", _b64e(b"x" * 60)])
def test_malformed(junk):
    assert _reason(ActionTokens(clock=Clock()).redeem, junk, "a1") == "malformed"


def test_truncated_token_is_malformed():
    tokens = ActionTokens(clock=Clock())
    raw = _b64d(tokens.issue("a1", "dev1", 2000))
    assert _reason(tokens.redeem, _b64e(raw[:-1]), "a1") == "malformed"


def test_tampered_expiry_is_bad_signature():
    tokens = ActionTokens(clock=Clock())
    raw = bytearray(_b64d(tokens.issue("a1", "dev1", 2000)))
    raw[16:24] = (10**9).to_bytes(8, "big")
    assert _reason(tokens.redeem, _b64e(bytes(raw)), "a1") == "bad signature"


def test_forget_drops_bookkeeping_per_approval():
    tokens = ActionTokens(clock=Clock())
    t1 = tokens.issue("a1", "dev1", 2000)
    t2 = tokens.issue("a2", "dev1", 2000)
    tokens.redeem(t1, "a1")
    tokens.redeem(t2, "a2")
    tokens.forget("a1")
    assert tokens.redeem(t1, "a1") == "dev1"  # callers check approval state
    assert _reason(tokens.redeem, t2, "a2") == "used"
    tokens.forget("unknown")


def test_long_device_id_rejected_at_issue():
    tokens = ActionTokens(clock=Clock())
    with pytest.raises(ValueError):
        tokens.issue("a1", "d" * 256, 2000)
    assert tokens.redeem(tokens.issue("a1", "é" * 100, 2000), "a1") == "é" * 100


def test_tokens_are_unique():
    tokens = ActionTokens(clock=Clock())
    assert tokens.issue("a1", "d", 2000) != tokens.issue("a1", "d", 2000)
