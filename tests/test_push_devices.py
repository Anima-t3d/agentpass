"""Push devices API: subscribe, list, rename, delete, and the one-tap approve setting.

Enabling one-tap lets a notification tap approve ``any_trusted`` requests, so it needs a
fresh passkey assertion over a challenge bound to that device. Disabling needs none.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest
from aiohttp.test_utils import TestClient, TestServer

from agentpass.db import Database
from agentpass.passkey.channel import PasskeyChannel
from agentpass.passkey.page import FAILURE_LIMIT
from agentpass.passkey.session import CHALLENGE_TTL
from agentpass.push.channel import PushChannel
from agentpass.push.routes import default_label
from agentpass.push.webpush import generate_vapid_key, save_vapid_key
from tests.push_helpers import Subscriber, b64e
from tests.test_passkey import HOST, ORIGIN, Authenticator, Sink, b64d, rejections
from tests.test_passkey import Env as PageEnv
from tests.test_push_channel import FakeTransport, _config, _req, until

ANDROID_CHROME = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Mobile Safari/537.36"
)
DEVICE_FIELDS = {"device_id", "label", "one_tap_approve", "created_at", "last_seen", "push_host"}


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now


class Env(PageEnv):
    n = 0

    async def call(self, method, path, body=None, *, csrf=True, session=True, headers=None):
        h = {"Host": HOST}
        if method != "GET":
            h["Origin"] = ORIGIN
            if csrf:
                h["X-CSRF"] = self.csrf
        if cookie := self.cookies(csrf=csrf, session=session):
            h["Cookie"] = cookie
        h.update(headers or {})
        kw = {} if method == "GET" else {"json": body if body is not None else {}}
        return await self.client.request(method, path, headers=h, **kw)

    async def subscribe(self, sub=None, label=None, headers=None):
        await self.sign_in()
        if sub is None:
            Env.n += 1
            sub = Subscriber(f"https://push.example.com/send/secret-path-{Env.n}")
        body = {
            "subscription": {
                "endpoint": sub.endpoint,
                "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
            }
        }
        if label is not None:
            body["label"] = label
        r = await self.call("POST", "/api/push/subscribe", body, headers=headers)
        assert r.status == 200, await r.text()
        return (await r.json())["device_id"], sub

    async def one_tap_options(self, device_id):
        r = await self.call("POST", f"/api/push/devices/{device_id}/one-tap/options")
        assert r.status == 200, await r.text()
        return await r.json()

    async def set_one_tap(self, device_id, body):
        return await self.call("POST", f"/api/push/devices/{device_id}/one-tap", body)

    async def one_tap(self, device_id) -> bool:
        return (await self.db.get_push_device(device_id)).one_tap_approve


@pytest.fixture
async def env(tmp_path):
    cfg = _config(tmp_path)
    save_vapid_key(generate_vapid_key(), cfg.push.vapid_key_path)
    db = Database(str(tmp_path / "agentpass.db"))
    await db.initialize()
    clock = Clock()
    passkey = PasskeyChannel(cfg, db=db)
    passkey.page.answer = Sink().answer
    transport = FakeTransport()
    push = PushChannel(cfg.push, page=passkey.page, db=db, transport=transport, clock=clock)
    await push.start(AsyncMock())
    client = TestClient(TestServer(passkey.page.build_app()))
    await client.start_server()
    r = await client.get("/api/session", headers={"Host": HOST})
    e = Env(passkey, client, None, db, Authenticator(), (await r.json())["csrf"])
    e.push, e.transport, e.clock = push, transport, clock
    yield e
    await client.close()
    await push.stop()
    await db.close()


# --- subscribe ---


async def test_subscribe_requires_session(env):
    sub = Subscriber("https://push.example.com/send/1")
    body = {
        "subscription": {"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": sub.auth}}
    }
    r = await env.call("POST", "/api/push/subscribe", body)
    assert r.status == 401 and await r.json() == {"error": "sign in"}
    await env.sign_in()
    assert (await env.call("POST", "/api/push/subscribe", body, csrf=False)).status == 403
    assert await env.db.list_push_devices() == []


async def test_subscribe_stores_device_for_the_session_credential(env):
    device_id, sub = await env.subscribe(headers={"User-Agent": ANDROID_CHROME})
    device = await env.db.get_push_device(device_id)
    assert device.credential_id == env.store.list()[0].id
    assert device.label == "Chrome on Android" and device.one_tap_approve is False
    assert (device.endpoint, device.p256dh, device.auth) == (sub.endpoint, sub.p256dh, sub.auth)
    # the same browser subscribing again keeps its device id (and settings)
    await env.db.set_push_device(device_id, one_tap_approve=True)
    again, _ = await env.subscribe(sub)
    assert again == device_id and await env.one_tap(device_id) is True
    assert len(await env.db.list_push_devices()) == 1


async def test_subscribe_label_is_clipped(env):
    device_id, _ = await env.subscribe(label="  " + "L" * 100 + "  ")
    assert (await env.db.get_push_device(device_id)).label == "L" * 60
    device_id, _ = await env.subscribe(label="   ")
    assert (await env.db.get_push_device(device_id)).label == "Browser"


def _bad_subscriptions():
    sub = Subscriber("https://push.example.com/send/1")
    keys = {"p256dh": sub.p256dh, "auth": sub.auth}
    return [
        {"endpoint": "http://push.example.com/send/1", "keys": keys},
        {"endpoint": "https:///send/1", "keys": keys},
        {"endpoint": "push.example.com/send/1", "keys": keys},
        {"endpoint": "https://push.example.com/" + "a" * 2048, "keys": keys},
        {"endpoint": 5, "keys": keys},
        {"endpoint": sub.endpoint, "keys": {"p256dh": b64e(b"\x04" * 64), "auth": sub.auth}},
        {"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh, "auth": b64e(b"a" * 15)}},
        {"endpoint": sub.endpoint, "keys": {"p256dh": "not base64!", "auth": sub.auth}},
        {"endpoint": sub.endpoint, "keys": {"p256dh": sub.p256dh}},
        {"endpoint": sub.endpoint},
        "nope",
    ]


@pytest.mark.parametrize("subscription", _bad_subscriptions())
async def test_subscribe_rejects_non_https_endpoint(env, subscription):
    await env.sign_in()
    r = await env.call("POST", "/api/push/subscribe", {"subscription": subscription})
    assert r.status == 400, await r.text()
    assert await env.db.list_push_devices() == []


async def test_subscribe_rejects_non_string_label(env):
    await env.sign_in()
    sub = Subscriber("https://push.example.com/send/1")
    body = {
        "subscription": {
            "endpoint": sub.endpoint,
            "keys": {"p256dh": sub.p256dh, "auth": sub.auth},
        },
        "label": 7,
    }
    assert (await env.call("POST", "/api/push/subscribe", body)).status == 400


@pytest.mark.parametrize(
    ("ua", "label"),
    [
        (ANDROID_CHROME, "Chrome on Android"),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
            "Edge on Windows",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
            "Firefox on Linux",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36",
            "Chrome on macOS",
        ),
        (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
            "Safari on iOS",
        ),
        ("", "Browser"),
        ("curl/8.0", "Browser"),
    ],
)
def test_default_label_from_user_agent(ua, label):
    assert default_label(ua) == label


# --- list, rename, delete ---


async def test_device_list_hides_keys(env):
    device_id, sub = await env.subscribe(label="Pixel 8")
    r = await env.call("GET", "/api/push/devices")
    assert r.status == 200
    text = await r.text()
    [item] = (await r.json())["devices"]
    assert set(item) == DEVICE_FIELDS
    assert item["device_id"] == device_id and item["label"] == "Pixel 8"
    assert item["push_host"] == "push.example.com" and item["one_tap_approve"] is False
    for secret in ("secret-path", sub.p256dh, sub.auth, "credential"):
        assert secret not in text
    assert (await env.call("GET", "/api/push/devices", session=False)).status == 401


async def test_label_is_clipped_before_escaping_and_never_cut_mid_escape(env):
    device_id, _ = await env.subscribe(label="x" * 58 + "\u202e" * 5 + "tail")
    label = (await env.db.get_push_device(device_id)).label
    assert len(label) <= 60
    assert label == "x" * 58  # the 60-char clip keeps two bidi marks; neither escape fits
    device_id, _ = await env.subscribe(label="x" * 50 + "\u202e" + "y" * 40)
    label = (await env.db.get_push_device(device_id)).label
    assert label == "x" * 50 + "\\u202e" + "y" * 4 and len(label) == 60


async def test_rename_device(env):
    device_id, _ = await env.subscribe(label="old")
    r = await env.call("PATCH", f"/api/push/devices/{device_id}", {"label": " Pixel‮ 8 " + "x" * 80})
    assert r.status == 200, await r.text()
    label = (await env.db.get_push_device(device_id)).label
    assert label.startswith("Pixel\\u202e 8 x") and len(label) == 60
    for body in ({"label": "  "}, {"label": 3}, {}):
        assert (await env.call("PATCH", f"/api/push/devices/{device_id}", body)).status == 400
    assert (await env.call("PATCH", "/api/push/devices/nope", {"label": "x"})).status == 404
    r = await env.call("PATCH", f"/api/push/devices/{device_id}", {"label": "x"}, csrf=False)
    assert r.status == 403


async def test_delete_device_stops_pushes(env):
    gone, gone_sub = await env.subscribe()
    kept, kept_sub = await env.subscribe()
    r = await env.call("DELETE", f"/api/push/devices/{gone}", csrf=False)
    assert r.status == 403
    r = await env.call("DELETE", f"/api/push/devices/{gone}")
    assert r.status == 200, await r.text()
    assert (await env.call("DELETE", f"/api/push/devices/{gone}")).status == 404
    assert [d.device_id for d in await env.db.list_push_devices()] == [kept]
    await env.push.send(_req())
    await until(lambda: env.transport.calls)
    assert [c[0] for c in env.transport.calls] == [kept_sub.endpoint]
    assert gone_sub.endpoint not in str(env.transport.calls)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/push/devices"),
        ("POST", "/api/push/devices/{id}/one-tap/options"),
        ("POST", "/api/push/devices/{id}/one-tap"),
        ("PATCH", "/api/push/devices/{id}"),
        ("DELETE", "/api/push/devices/{id}"),
    ],
)
async def test_device_routes_need_session_and_csrf(env, method, path):
    device_id, _ = await env.subscribe()
    path = path.format(id=device_id)
    body = {"enabled": False, "label": "x"}
    r = await env.call(method, path, body, session=False)
    assert r.status == 401
    if method != "GET":
        assert (await env.call(method, path, body, csrf=False)).status == 403
    assert await env.db.get_push_device(device_id) is not None


# --- one-tap ---


async def test_enable_one_tap_with_fresh_assertion(env):
    device_id, _ = await env.subscribe()
    options = await env.one_tap_options(device_id)
    assert len(b64d(options["challenge"])) == 32
    assert options["userVerification"] == "required" and options["rpId"] == "gate.example.ts.net"
    assert [c["id"] for c in options["allowCredentials"]] == [env.store.list()[0].id]
    assert options["challenge"] != (await env.one_tap_options(device_id))["challenge"]
    before = env.store.list()[0].sign_count
    r = await env.set_one_tap(
        device_id, {"enabled": True, "credential": env.auth.assert_(options["challenge"])}
    )
    assert r.status == 200, await r.text()
    assert await r.json() == {"enabled": True}
    assert await env.one_tap(device_id) is True
    assert env.store.list()[0].sign_count > before


async def test_enable_one_tap_without_assertion_is_refused(env):
    device_id, _ = await env.subscribe()
    for body in (
        {"enabled": True},
        {"enabled": True, "credential": None},
        {"enabled": True, "credential": {"id": "x"}},
    ):
        r = await env.set_one_tap(device_id, body)
        assert r.status == 403, await r.text()
    env.channel.page._failures.clear()  # stay under the throttle for the rest
    # a sign-in challenge is not an enable challenge
    login = await env.login_assertion()
    assert (await env.set_one_tap(device_id, {"enabled": True, "credential": login})).status == 403
    # nor is an approval's challenge
    await env.channel.send(_req("A1"))
    r = await env.call("POST", "/api/approvals/A1/challenge")
    approval = env.auth.assert_((await r.json())["challenge"])
    assert (
        await env.set_one_tap(device_id, {"enabled": True, "credential": approval})
    ).status == 403
    # nor a challenge the page never issued
    forged = env.auth.assert_(b64e(b"\x01" * 32))
    assert (await env.set_one_tap(device_id, {"enabled": True, "credential": forged})).status == 403
    assert await env.one_tap(device_id) is False
    assert len(await rejections(env.db)) == 6


async def test_enable_one_tap_with_assertion_for_other_device_is_refused(env):
    phone, _ = await env.subscribe()
    laptop, _ = await env.subscribe()
    options = await env.one_tap_options(phone)
    assertion = env.auth.assert_(options["challenge"])
    r = await env.set_one_tap(laptop, {"enabled": True, "credential": assertion})
    assert r.status == 403
    assert await env.one_tap(laptop) is False and await env.one_tap(phone) is False
    # the challenge was spent by the attempt: it cannot be used for the phone either
    r = await env.set_one_tap(
        phone, {"enabled": True, "credential": env.auth.assert_(options["challenge"])}
    )
    assert r.status == 403 and await env.one_tap(phone) is False


async def test_enable_one_tap_challenge_is_single_use_and_expires(env):
    device_id, _ = await env.subscribe()
    options = await env.one_tap_options(device_id)
    assertion = env.auth.assert_(options["challenge"])
    assert (
        await env.set_one_tap(device_id, {"enabled": True, "credential": assertion})
    ).status == 200
    await env.set_one_tap(device_id, {"enabled": False})
    r = await env.set_one_tap(device_id, {"enabled": True, "credential": assertion})
    assert r.status == 403 and await env.one_tap(device_id) is False
    options = await env.one_tap_options(device_id)
    env.clock.now += CHALLENGE_TTL + 1
    r = await env.set_one_tap(
        device_id, {"enabled": True, "credential": env.auth.assert_(options["challenge"])}
    )
    assert r.status == 403 and await env.one_tap(device_id) is False


async def test_enable_one_tap_with_bad_signature_is_refused(env):
    device_id, _ = await env.subscribe()
    options = await env.one_tap_options(device_id)
    other = Authenticator()
    other.cred_id = env.auth.cred_id  # same id, wrong key
    r = await env.set_one_tap(
        device_id, {"enabled": True, "credential": other.assert_(options["challenge"])}
    )
    assert r.status == 403 and await env.one_tap(device_id) is False


async def test_enable_one_tap_failures_are_throttled(env):
    device_id, _ = await env.subscribe()
    for _ in range(FAILURE_LIMIT):
        assert (await env.set_one_tap(device_id, {"enabled": True})).status == 403
    options_r = await env.call("POST", f"/api/push/devices/{device_id}/one-tap/options")
    assert options_r.status == 429
    assert (await env.set_one_tap(device_id, {"enabled": True})).status == 429
    # turning it off is never throttled
    assert (await env.set_one_tap(device_id, {"enabled": False})).status == 200


async def test_disable_one_tap_needs_no_assertion(env):
    device_id, _ = await env.subscribe()
    await env.db.set_push_device(device_id, one_tap_approve=True)
    r = await env.set_one_tap(device_id, {"enabled": False})
    assert r.status == 200, await r.text()
    assert await r.json() == {"enabled": False}
    assert await env.one_tap(device_id) is False


async def test_one_tap_bad_bodies_and_unknown_device(env):
    device_id, _ = await env.subscribe()
    for body in ({}, {"enabled": "yes"}, {"enabled": 1}):
        assert (await env.set_one_tap(device_id, body)).status == 400
    assert (await env.set_one_tap("nope", {"enabled": False})).status == 404
    assert (await env.set_one_tap("nope", {"enabled": True})).status == 404
    r = await env.call("POST", "/api/push/devices/nope/one-tap/options")
    assert r.status == 404
    assert await env.one_tap(device_id) is False


async def test_one_tap_setting_reaches_the_push_payload(env):
    device_id, sub = await env.subscribe()
    options = await env.one_tap_options(device_id)
    r = await env.set_one_tap(
        device_id, {"enabled": True, "credential": env.auth.assert_(options["challenge"])}
    )
    assert r.status == 200
    await env.push.send(_req())
    await until(lambda: env.transport.calls)
    assert env.transport.bodies(sub)[0]["one_tap"] is True
