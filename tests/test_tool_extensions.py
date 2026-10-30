"""Tool YAML extensions: arg types, request shape, schema, GitHub tools and rules."""

from __future__ import annotations

import textwrap
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentpass.agents import generate_token, load_agents
from agentpass.config import (
    AuthConfig,
    ConfigError,
    ServiceConfig,
    ToolDefinition,
    load_tools_file,
)
from agentpass.engine import Evaluation, PermissionEngine, build_signature, validate_args
from agentpass.models import Decision
from agentpass.pipeline import Pipeline
from agentpass.registry import REDACTED, build_registry
from agentpass.schema import args_to_json_schema, tool_annotations
from agentpass.services.http import GenericHTTPService, HTTPServiceError

# --- helpers ---


def _tools(tmp_path, text: str, name: str = "svc") -> list[ToolDefinition]:
    p = tmp_path / "tools.yaml"
    p.write_text(textwrap.dedent(text))
    return load_tools_file(str(p), name)


def _registry(tmp_path, text: str):
    tools = _tools(tmp_path, text)
    svc = ServiceConfig(
        name="svc", url="http://svc", auth=AuthConfig(type="bearer", token="x"), tools=tools
    )
    return build_registry({"svc": svc}), svc


def _resp(json_data=None, raw: bytes | None = None, content_length=None):
    resp = AsyncMock()
    resp.status = 200
    resp.json = AsyncMock(return_value=json_data if json_data is not None else {})
    resp.content_length = content_length
    resp.content.read = AsyncMock(return_value=raw if raw is not None else b"{}")
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


async def _run(svc_cfg: ServiceConfig, tool: str, args: dict, method="get", response=None):
    svc = GenericHTTPService(svc_cfg)
    session = MagicMock()
    session.closed = False
    fn = MagicMock(return_value=response or _resp())
    setattr(session, method, fn)
    svc._session = session
    result = await svc.execute(tool, args)
    return result, fn


MAIL = """
    tools:
      send:
        signature: "{to}"
        args:
          to: { type: string, required: true, validate: "[^@\\\\s]+@[^@\\\\s]+" }
          subject: { type: string, max_length: 20 }
          body: { type: text, max_length: 100 }
          note: { type: string, signature: false }
          limit: { type: integer, min: 1, max: 100, default: 25 }
          format: { type: enum, values: [full, metadata], default: metadata }
          labels: { type: array, items: { type: string, validate: "[A-Za-z0-9_-]+" }, max_items: 2 }
          opts: { type: object }
          flag: { type: boolean }
          ratio: { type: number, min: 0, max: 1 }
        request:
          method: POST
          path: "/send"
"""

# --- loading ---


def test_arg_fields_are_parsed(tmp_path):
    (tool,) = _tools(tmp_path, MAIL)
    a = tool.args
    assert a["to"].type == "string" and a["to"].required
    assert a["body"].type == "text" and a["body"].signature is False  # text never in signature
    assert a["note"].signature is False and a["subject"].signature is True
    assert (a["limit"].min, a["limit"].max, a["limit"].default) == (1, 100, 25)
    assert a["format"].values == ["full", "metadata"]
    assert a["labels"].items.validate == "[A-Za-z0-9_-]+" and a["labels"].max_items == 2


@pytest.mark.parametrize(
    "arg, msg",
    [
        ("{ type: bogus }", "unknown type"),
        ("{ type: enum }", "values"),
        ("{ type: array }", "items"),
        ("{ type: integer, validate: 'x' }", "validate only applies"),
        ("{ type: string, min: 1 }", "min only applies"),
        ("{ type: string, validate: '(' }", "Invalid regex"),
        ("{ type: integer, default: 'x' }", "Invalid default"),
        ("{ type: integer, min: 5, default: 1 }", "Invalid default"),
        ("{ type: string, required: true, default: x }", "required arg cannot have a default"),
        ("{ type: array, items: { type: array, items: { type: string } } }", "scalar"),
        ("{ type: string, signature: maybe }", "signature must be"),
    ],
)
def test_bad_arg_definitions_rejected(tmp_path, arg, msg):
    with pytest.raises(ConfigError, match=msg):
        _tools(tmp_path, f"tools:\n  t:\n    args:\n      a: {arg}\n")


@pytest.mark.parametrize(
    "body, msg",
    [
        ('signature: "{b}"\n    args: { b: { type: text } }', "exempt from the signature"),
        ('signature: "{b}"\n    args: { a: {} }', "undeclared"),
        ("args: { a: {} }\n    request: { path: '/x/{zz}' }", "undeclared"),
        ("args: { a: {} }\n    request: { path: '/x/{a}' }", "must be required"),
        ("args: { a: {} }\n    request: { path: '/x', query: { q: '{zz}' } }", "undeclared"),
        (
            "args: { a: {} }\n    request: { path: '/x', headers: { Authorization: x } }",
            "not allowed",
        ),
        ("args: { a: {} }\n    request: { path: '/x', headers: { cookie: x } }", "not allowed"),
        ("args: { a: {} }\n    request: { path: '/x', headers: { HOST: x } }", "not allowed"),
        ("args: { a: {} }\n    request: { path: '/x', body: { include: [zz] } }", "undeclared"),
        (
            "args: { a: {} }\n    request: { path: '/x', body: {include: [a]}, body_exclude: [a] }",
            "mutually exclusive",
        ),
        (
            "args: { a: {} }\n    request: { path: '/x', body: { multipart: [a] } }",
            "include and map",
        ),
        ("args: { a: {} }\n    audit: { redact_args: [zz] }", "undeclared"),
        ("args: { a: {} }\n    audit: { store_result: some }", "store_result"),
        ("risk: extreme", "risk"),
        ("request: { path: '/x' }\n    response: { type: xml }", "response type"),
        ("request: { path: '/x' }\n    response: { max_bytes: 0 }", "max_bytes"),
    ],
)
def test_bad_tool_definitions_rejected(tmp_path, body, msg):
    with pytest.raises(ConfigError, match=msg):
        _tools(tmp_path, f"tools:\n  t:\n    {body}\n")


def test_request_extras_parsed(tmp_path):
    (tool,) = _tools(
        tmp_path,
        """
        tools:
          t:
            args: { a: {}, b: {} }
            request:
              method: post
              path: "/x"
              query: { q: "{a}" }
              headers: { If-Match: "{b}" }
              body: { include: [a], map: { raw: "{b}" } }
              timeout: 20
            response: { type: text, max_bytes: 10 }
            audit: { redact_args: [a], store_result: none }
            risk: high
        """,
    )
    r = tool.request
    assert r.method == "POST" and r.timeout == 20 and r.has_body_spec
    assert r.body_include == ["a"] and r.body_map == {"raw": "{b}"}
    assert (tool.response.type, tool.response.max_bytes) == ("text", 10)
    assert (tool.redact_args, tool.store_result, tool.risk) == (["a"], "none", "high")


# --- validation ---


@pytest.fixture()
def mail(tmp_path):
    return _registry(tmp_path, MAIL)[0]


def test_undeclared_args_rejected(mail):
    with pytest.raises(ValueError, match="Unknown argument: extra"):
        validate_args("send", {"to": "a@b.c", "extra": 1}, mail)


def test_required_missing(mail):
    with pytest.raises(ValueError, match="Missing required"):
        validate_args("send", {}, mail)


def test_validate_is_fullmatch(mail):
    validate_args("send", {"to": "a@b.c"}, mail)
    with pytest.raises(ValueError, match="Invalid value for to"):
        validate_args("send", {"to": "a@b.c extra"}, mail)  # a search would match
    with pytest.raises(ValueError):
        validate_args("send", {"to": "x\na@b.c"}, mail)


@pytest.mark.parametrize(
    "bad", ["a*@b.c", "a?@b.c", "a[1]@b.c", "a(1)@b.c", "a,b@c.d", "a\x01@b.c"]
)
def test_forbidden_chars_rejected_on_signature_args(mail, bad):
    with pytest.raises(ValueError):
        validate_args("send", {"to": bad}, mail)


def test_forbidden_chars_allowed_in_free_text_and_non_signature_args(mail):
    validate_args(
        "send",
        {
            "to": "a@b.c",
            "body": "Hi (all), *bold* [x]? \x01\n",
            "note": "a, (b) *",
            "subject": "f(x)",
        },
        mail,
    )


def test_forbidden_chars_in_nested_signature_value_rejected(tmp_path):
    reg, _ = _registry(
        tmp_path, "tools:\n  t:\n    signature: '{a}'\n    args: { a: { type: object } }\n"
    )
    with pytest.raises(ValueError, match="forbidden"):
        validate_args("t", {"a": {"k": "v*"}}, reg)
    with pytest.raises(ValueError, match="scalar"):  # signature args are scalars
        validate_args("t", {"a": {"k": "v"}}, reg)


def test_unregistered_tool_still_checks_every_arg():
    with pytest.raises(ValueError, match="forbidden"):
        validate_args("other", {"k": ["ok", {"n": "x*"}]})


@pytest.mark.parametrize(
    "args",
    [
        {"subject": "x" * 21},
        {"body": "x" * 101},
        {"body": 5},
        {"limit": 0},
        {"limit": 101},
        {"limit": 1.5},
        {"limit": True},
        {"limit": "5"},
        {"format": "raw"},
        {"format": 1},
        {"labels": ["a", "b", "c"]},
        {"labels": ["bad label"]},
        {"labels": "a"},
        {"opts": [1]},
        {"opts": {1: 2}},
        {"flag": "true"},
        {"flag": 1},
        {"ratio": 1.5},
        {"ratio": float("nan")},
    ],
)
def test_typed_constraints_rejected(mail, args):
    with pytest.raises(ValueError):
        validate_args("send", {"to": "a@b.c", **args}, mail)


def test_typed_values_accepted(mail):
    validate_args(
        "send",
        {
            "to": "a@b.c",
            "limit": 100,
            "ratio": 1,
            "format": "full",
            "labels": ["a_b", "c-d"],
            "opts": {"x": [1]},
            "flag": False,
        },
        mail,
    )


def test_defaults_applied_only_to_the_executed_args(mail):
    args = {"to": "a@b.c"}
    full = mail.apply_defaults("send", args)
    assert full["limit"] == 25 and full["format"] == "metadata"
    assert args == {"to": "a@b.c"}  # input untouched; signature built from it stays stable
    assert build_signature("send", args, mail) == "send(a@b.c)"


# --- HA signature golden test (guards against a silent policy change) ---

HA_GOLDEN = [
    ("ha_get_state", {"entity_id": "sensor.temp"}, "ha_get_state(sensor.temp)"),
    ("ha_get_states", {}, "ha_get_states"),
    ("ha_get_services", {}, "ha_get_services"),
    ("ha_get_history", {"entity_id": "sensor.temp"}, "ha_get_history(sensor.temp)"),
    ("ha_get_logbook", {"entity_id": "light.bedroom"}, "ha_get_logbook(light.bedroom)"),
    ("ha_get_config", {}, "ha_get_config"),
    ("ha_render_template", {"template": "{{ states }}"}, "ha_render_template({{ states }})"),
    (
        "ha_call_service",
        {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"},
        "ha_call_service(light.turn_on, light.bedroom)",
    ),
    (
        "ha_call_service",
        {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom", "brightness": 128},
        "ha_call_service(light.turn_on, light.bedroom)",  # service data never changes it
    ),
    (
        "ha_call_service",
        {"domain": "homeassistant", "service": "restart"},
        "ha_call_service(homeassistant.restart)",
    ),
    ("ha_fire_event", {"event_type": "my.event"}, "ha_fire_event(my.event)"),
]


@pytest.fixture(scope="module")
def ha_registry():
    tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
    svc = ServiceConfig(
        name="homeassistant",
        url="http://ha",
        auth=AuthConfig(type="bearer", token="x"),
        tools=tools,
    )
    return build_registry({"homeassistant": svc})


@pytest.mark.parametrize("tool, args, expected", HA_GOLDEN)
def test_ha_signatures_are_byte_identical(ha_registry, tool, args, expected):
    assert build_signature(tool, args, ha_registry) == expected


def test_ha_golden_covers_every_tool(ha_registry):
    assert {t for t, _, _ in HA_GOLDEN} == {t.name for t in ha_registry.all_tools()}


def test_ha_signature_templates_unchanged(ha_registry):
    templates = {t.name: t.signature for t in ha_registry.all_tools()}
    assert templates == {
        "ha_get_state": "{entity_id}",
        "ha_get_states": "",
        "ha_get_services": "",
        "ha_get_history": "{entity_id}",
        "ha_get_logbook": "{entity_id}",
        "ha_get_config": "",
        "ha_render_template": "{template}",
        "ha_call_service": "{domain}.{service}, {entity_id}",
        "ha_fire_event": "{event_type}",
    }


@pytest.mark.parametrize(
    "tool, entity, key, path",
    [
        ("ha_get_history", "sensor.t", "filter_entity_id", "/api/history/period"),
        ("ha_get_logbook", "sensor.t", "entity", "/api/logbook"),
    ],
)
async def test_ha_query_migration(ha_registry, tool, entity, key, path):
    cfg = ServiceConfig(
        name="homeassistant",
        url="http://ha",
        auth=AuthConfig(type="bearer", token="x"),
        tools=ha_registry.all_tools(),
    )
    _, fn = await _run(cfg, tool, {"entity_id": entity}, response=_resp([]))
    assert fn.call_args[0][0] == f"http://ha{path}"
    assert fn.call_args[1]["params"] == {key: entity}


async def test_ha_call_service_restores_typed_service_data(ha_registry):
    cfg = ServiceConfig(
        name="homeassistant",
        url="http://ha",
        auth=AuthConfig(type="bearer", token="x"),
        tools=ha_registry.all_tools(),
    )
    args = {
        "domain": "light",
        "service": "turn_on",
        "entity_id": "light.bedroom",
        "brightness": 128,
        "rgb_color": [1, 2, 3],
    }
    validate_args("ha_call_service", args, ha_registry)
    _, fn = await _run(cfg, "ha_call_service", args, method="post", response=_resp([]))
    assert fn.call_args[1]["json"] == {
        "entity_id": "light.bedroom",
        "brightness": 128,
        "rgb_color": [1, 2, 3],
    }
    for bad in ({"brightness": 256}, {"rgb_color": [1, 2, 3, 4]}, {"brightness": "x"}):
        with pytest.raises(ValueError):
            validate_args(
                "ha_call_service", {"domain": "light", "service": "x", **bad}, ha_registry
            )


# --- request shape ---

SHAPE = """
    tools:
      get:
        args:
          id: { type: string, required: true }
          rest: { type: string, required: true }
          format: { type: enum, values: [full, metadata] }
          limit: { type: integer }
          ids: { type: array, items: { type: string } }
          etag: { type: string }
          verbose: { type: boolean }
        request:
          method: GET
          path: "/m/{id}"
          query:
            format: "{format}"
            maxResults: "{limit}"
            ids: "{ids}"
            verbose: "{verbose}"
            pre: "v-{etag}"
          headers: { If-Match: "{etag}", X-Static: "1" }
      tree:
        args: { rest: { type: string, required: true } }
        request: { method: GET, path: "/files/{rest:path}/x" }
      post:
        args:
          id: { type: string, required: true }
          a: { type: string }
          b: { type: text }
          c: { type: string }
          q: { type: string }
        request:
          method: POST
          path: "/p/{id}"
          query: { q: "{q}" }
          body: { include: [a, b], map: { raw: "{c}", combo: "{a}-{c}" } }
      legacy:
        args: { id: { type: string, required: true }, a: { type: string }, q: { type: string } }
        request: { method: POST, path: "/l/{id}", query: { q: "{q}" } }
      ok:
        request: { method: GET, path: "/ok", timeout: 7 }
"""


@pytest.fixture()
def shape(tmp_path):
    return ServiceConfig(
        name="svc",
        url="http://svc/",
        auth=AuthConfig(type="bearer", token="x"),
        tools=_tools(tmp_path, SHAPE),
    )


async def test_query_entries_dropped_when_arg_absent(shape):
    _, fn = await _run(shape, "get", {"id": "1", "rest": "r"})
    params = fn.call_args[1]["params"]
    assert params is None  # nothing interpolated as an empty string
    # StaticBearer now supplies the Authorization header per request
    assert "headers" in fn.call_args[1]
    assert fn.call_args[1]["headers"] == {"X-Static": "1", "Authorization": "Bearer x"}


async def test_query_and_headers_rendered(shape):
    _, fn = await _run(
        shape,
        "get",
        {
            "id": "1",
            "rest": "r",
            "format": "full",
            "limit": 5,
            "ids": ["a", "b"],
            "etag": "e1",
            "verbose": True,
        },
    )
    kw = fn.call_args[1]
    assert kw["params"] == {
        "format": "full",
        "maxResults": "5",
        "ids": ["a", "b"],
        "verbose": "true",
        "pre": "v-e1",
    }
    # the provider's header rides on top of the tool's own headers
    assert kw["headers"] == {"If-Match": "e1", "X-Static": "1", "Authorization": "Bearer x"}


async def test_header_value_cannot_inject_lines(shape):
    with pytest.raises(HTTPServiceError, match="Invalid header"):
        await _run(shape, "get", {"id": "1", "rest": "r", "etag": "x\r\nHost: evil"})


@pytest.mark.parametrize(
    "value, encoded",
    [("a/b", "a%2Fb"), ("a?b#c", "a%3Fb%23c"), ("%2e%2e", "%252e%252e"), ("a b", "a%20b")],
)
async def test_path_value_is_one_encoded_segment(shape, value, encoded):
    _, fn = await _run(shape, "get", {"id": value, "rest": "r"})
    assert fn.call_args[0][0] == f"http://svc/m/{encoded}"


@pytest.mark.parametrize("value", ["", ".", ".."])
async def test_path_segment_rejects_empty_and_dots(shape, value):
    with pytest.raises(HTTPServiceError, match="Invalid path argument"):
        await _run(shape, "get", {"id": value, "rest": "r"})


async def test_path_multi_segment(shape):
    _, fn = await _run(shape, "tree", {"rest": "src/a b/c?.py"})
    assert fn.call_args[0][0] == "http://svc/files/src/a%20b/c%3F.py/x"


@pytest.mark.parametrize("value", ["../etc", "a/../b", "a/./b", "a//b", "/a", "a/", "..", ""])
async def test_path_multi_segment_rejects_traversal(shape, value):
    with pytest.raises(HTTPServiceError, match="Invalid path argument"):
        await _run(shape, "tree", {"rest": value})


async def test_body_include_and_map(shape):
    _, fn = await _run(
        shape,
        "post",
        {"id": "1", "a": "A", "b": "B (x)", "c": "C", "q": "Q"},
        method="post",
    )
    kw = fn.call_args[1]
    assert kw["json"] == {"a": "A", "b": "B (x)", "raw": "C", "combo": "A-C"}
    assert kw["params"] == {"q": "Q"}


async def test_body_map_dropped_when_arg_absent(shape):
    _, fn = await _run(shape, "post", {"id": "1", "a": "A"}, method="post")
    assert fn.call_args[1]["json"] == {"a": "A"}  # no raw, no combo, nothing empty


async def test_legacy_body_excludes_args_used_in_path_and_query(shape):
    _, fn = await _run(shape, "legacy", {"id": "1", "a": "A", "q": "Q"}, method="post")
    assert fn.call_args[1]["json"] == {"a": "A"}


async def test_timeout_applied(shape):
    _, fn = await _run(shape, "ok", {})
    assert fn.call_args[1]["timeout"].total == 7


# --- response ---


def _resp_cfg(tmp_path, response: str):
    tools = _tools(
        tmp_path,
        f"tools:\n  t:\n    request: {{ method: GET, path: /x }}\n    response: {response}\n",
    )
    return ServiceConfig(
        name="svc", url="http://svc", auth=AuthConfig(type="bearer", token="x"), tools=tools
    )


async def test_response_max_bytes_enforced(tmp_path):
    cfg = _resp_cfg(tmp_path, "{ max_bytes: 10 }")
    with pytest.raises(HTTPServiceError, match="too large"):
        await _run(cfg, "t", {}, response=_resp(raw=b"x" * 11))
    with pytest.raises(HTTPServiceError, match="too large"):
        await _run(cfg, "t", {}, response=_resp(raw=b"{}", content_length=999))
    result, _ = await _run(cfg, "t", {}, response=_resp(raw=b'{"a": 1}'))
    assert result == {"a": 1}


async def test_response_types(tmp_path):
    result, _ = await _run(
        _resp_cfg(tmp_path, "{ type: text, max_bytes: 99, wrap: w }"),
        "t",
        {},
        response=_resp(raw=b"hi"),
    )
    assert result == {"w": {"text": "hi"}}
    result, _ = await _run(
        _resp_cfg(tmp_path, "{ type: binary, max_bytes: 99 }"),
        "t",
        {},
        response=_resp(raw=b"\x00\x01"),
    )
    assert result == {"base64": "AAE=", "size": 2}
    result, _ = await _run(_resp_cfg(tmp_path, "{ type: none }"), "t", {})
    assert result == {}
    with pytest.raises(HTTPServiceError, match="invalid JSON"):
        await _run(_resp_cfg(tmp_path, "{ max_bytes: 9 }"), "t", {}, response=_resp(raw=b"nope"))


# --- audit redaction ---

AUDIT = """
    tools:
      note:
        signature: "{id}"
        args:
          id: { required: true }
          body: { type: text }
        request: { method: POST, path: "/n/{id}", body: { include: [body] } }
        audit: { redact_args: [body], store_result: truncated }
      quiet:
        request: { method: GET, path: "/q" }
        audit: { store_result: none }
"""


def test_registry_redacts_and_truncates(tmp_path):
    reg, _ = _registry(tmp_path, AUDIT)
    assert reg.redact_args("note", {"id": "1", "body": "secret"}) == {"id": "1", "body": REDACTED}
    assert reg.redact_args("note", {"id": "1"}) == {"id": "1"}
    assert reg.audit_result("quiet", {"a": 1}) is None
    small = {"a": 1}
    assert reg.audit_result("note", small) == small
    big = reg.audit_result("note", {"a": "x" * 5000})
    assert set(big) == {"truncated"} and len(big["truncated"]) == 2000


async def test_pipeline_audit_and_pending_rows_are_redacted(tmp_path):
    reg, _ = _registry(tmp_path, AUDIT)
    engine = MagicMock(spec=PermissionEngine)
    engine.evaluate.return_value = Evaluation(Decision.ALLOW)
    executor = AsyncMock()
    executor.execute.return_value = {"ok": True}
    db = AsyncMock()
    p = Pipeline(engine=engine, executor=executor, coordinator=AsyncMock(), db=db, registry=reg)
    await p.process("a", "note", {"id": "1", "body": "private text"})
    assert db.log_audit.call_args[0][0].args == {"id": "1", "body": REDACTED}
    # the executor still receives the real value
    assert executor.execute.call_args[0][1]["body"] == "private text"


# --- schema ---


def test_schema_helper_emits_types_and_constraints(tmp_path):
    (tool,) = _tools(tmp_path, MAIL)
    s = args_to_json_schema(tool.args)
    props = s["properties"]
    assert s["additionalProperties"] is False and s["required"] == ["to"]
    assert props["to"]["pattern"] == "^(?:[^@\\s]+@[^@\\s]+)$"
    assert props["subject"] == {"type": "string", "maxLength": 20}
    assert props["limit"] == {"type": "integer", "minimum": 1, "maximum": 100, "default": 25}
    assert props["format"] == {"enum": ["full", "metadata"], "default": "metadata"}
    assert props["labels"]["items"]["type"] == "string" and props["labels"]["maxItems"] == 2
    assert props["opts"] == {"type": "object"} and props["flag"] == {"type": "boolean"}
    assert props["ratio"]["type"] == "number"


def test_schema_missing_type_is_string(tmp_path):
    (tool,) = _tools(tmp_path, "tools:\n  t:\n    args:\n      a: { required: true }\n")
    assert args_to_json_schema(tool.args)["properties"]["a"] == {"type": "string"}


def test_annotations_from_method_and_risk(tmp_path):
    tools = {
        t.name: t
        for t in _tools(
            tmp_path,
            """
            tools:
              r: { request: { method: GET, path: /x } }
              w: { request: { method: POST, path: /x } }
              d: { request: { method: DELETE, path: /x } }
              h: { request: { method: POST, path: /x }, risk: high }
            """,
        )
    }
    assert tool_annotations(tools["r"]) == {"readOnlyHint": True, "destructiveHint": False}
    assert tool_annotations(tools["w"]) == {"readOnlyHint": False, "destructiveHint": False}
    assert tool_annotations(tools["d"])["destructiveHint"] is True
    assert tool_annotations(tools["h"])["destructiveHint"] is True


# --- GitHub tools and rules ---


@pytest.fixture(scope="module")
def gh_registry():
    tools = load_tools_file("tools/github.yaml", "github")
    svc = ServiceConfig(
        name="github",
        url="https://api.github.com",
        auth=AuthConfig(type="bearer", token="x"),
        tools=tools,
    )
    return build_registry({"github": svc}), svc


@pytest.fixture(scope="module")
def gh_engine(gh_registry, tmp_path_factory):
    agents = tmp_path_factory.mktemp("agents")
    _, token_hash = generate_token("bot")
    (agents / "bot.yaml").write_text(
        f'id: bot\ntoken_hash: "{token_hash}"\nextends: [github]\nrules: []\n'
    )
    loaded = load_agents(agents, "policy")
    identity = next(iter(loaded._agents.values())) if hasattr(loaded, "_agents") else None
    assert identity is not None
    return PermissionEngine(identity.permissions, gh_registry[0])


REPO = {"owner": "octo", "repo": "hello-world"}
GH_CASES = {
    "allow": [
        ("gh_list_repos", {}),
        ("gh_get_repo", REPO),
        ("gh_list_issues", REPO),
        ("gh_get_issue", {**REPO, "number": 1}),
        ("gh_list_issue_comments", {**REPO, "number": 1}),
        ("gh_list_pulls", REPO),
        ("gh_get_pull", {**REPO, "number": 2}),
        ("gh_list_workflow_runs", REPO),
        ("gh_get_workflow_run", {**REPO, "run_id": 9}),
        ("gh_get_branch", {**REPO, "branch": "main"}),
        ("gh_get_contents", {**REPO, "path": "docs/a.md"}),
    ],
    "ask": [
        ("gh_create_issue", {**REPO, "title": "t"}),
        ("gh_create_issue_comment", {**REPO, "number": 1, "body": "hi (there), *x*"}),
        ("gh_create_pull", {**REPO, "title": "t", "head": "feat/x", "base": "main"}),
        ("gh_dispatch_workflow", {**REPO, "workflow": "ci.yml", "ref": "main"}),
        ("gh_create_branch", {**REPO, "branch": "feat/x", "sha": "a" * 40}),
        (
            "gh_put_contents",
            {**REPO, "branch": "feat/x", "path": "a.md", "message": "m", "content": "eA=="},
        ),
        ("gh_update_issue", {**REPO, "number": 1, "state": "closed"}),
        ("gh_update_pull", {**REPO, "number": 2, "title": "t"}),
    ],
    "deny": [
        ("gh_delete_repo", REPO),
        ("gh_update_branch_protection", {**REPO, "branch": "main", "enforce_admins": True}),
        ("gh_add_collaborator", {**REPO, "username": "mallory"}),
        ("gh_create_deploy_key", {**REPO, "key": "ssh-ed25519 AAAA"}),
        ("gh_delete_deploy_key", {**REPO, "key_id": 3}),
        (
            "gh_set_actions_secret",
            {**REPO, "secret_name": "TOKEN", "encrypted_value": "x", "key_id": "1"},
        ),
    ],
}


@pytest.mark.parametrize(
    "tool, args, expected",
    [(t, a, d) for d, cases in GH_CASES.items() for t, a in cases],
)
def test_github_default_rules(gh_registry, gh_engine, tool, args, expected):
    reg = gh_registry[0]
    validate_args(tool, args, reg)
    assert gh_engine.evaluate(tool, args).decision.value == expected


def test_every_github_tool_has_a_policy_case(gh_registry):
    covered = {t for cases in GH_CASES.values() for t, _ in cases}
    assert covered == {t.name for t in gh_registry[0].all_tools()}


def test_github_signatures(gh_registry):
    reg = gh_registry[0]
    assert build_signature("gh_get_repo", REPO, reg) == "gh_get_repo(octo/hello-world)"
    assert build_signature("gh_get_issue", {**REPO, "number": 7}, reg) == (
        "gh_get_issue(octo/hello-world, 7)"
    )
    # free text is not part of the signature
    sig = build_signature("gh_create_issue", {**REPO, "title": "x (y), *z*"}, reg)
    assert sig == "gh_create_issue(octo/hello-world)"


@pytest.mark.parametrize(
    "tool, args",
    [
        ("gh_get_repo", {"owner": "octo", "repo": "../x"}),
        ("gh_get_repo", {"owner": "octo", "repo": ".."}),
        ("gh_get_repo", {"owner": "octo/evil", "repo": "r"}),
        ("gh_get_repo", {"owner": "octo", "repo": "r*"}),
        ("gh_get_repo", {"owner": "octo", "repo": "r", "path": "/user"}),
        ("gh_get_issue", {**REPO, "number": 0}),
        ("gh_get_issue", {**REPO, "number": "1"}),
        ("gh_list_issues", {**REPO, "state": "bogus"}),
        ("gh_list_issues", {**REPO, "per_page": 101}),
        ("gh_dispatch_workflow", {**REPO, "workflow": "../x.yml", "ref": "main"}),
        ("gh_create_issue", {**REPO}),
        ("gh_create_issue", {**REPO, "title": "t", "labels": ["a"] * 11}),
    ],
)
def test_github_args_rejected(gh_registry, tool, args):
    with pytest.raises(ValueError):
        validate_args(tool, args, gh_registry[0])


def test_no_generic_github_tool(gh_registry):
    for tool in gh_registry[0].all_tools():
        assert "/repos/{owner}/{repo}" in tool.request.path or tool.request.path == "/user/repos"
        assert not any(a in ("url", "endpoint", "method") for a in tool.args)
        if "path" in tool.args:  # only a file path inside the repo, under /contents/
            assert tool.request.path.endswith("/contents/{path:path}")


async def test_github_request_shape(gh_registry):
    _, cfg = gh_registry
    args = gh_registry[0].apply_defaults("gh_list_issues", REPO)
    _, fn = await _run(cfg, "gh_list_issues", args, response=_resp([]))
    kw = fn.call_args[1]
    assert fn.call_args[0][0] == "https://api.github.com/repos/octo/hello-world/issues"
    assert kw["params"] == {"state": "open", "per_page": "30", "page": "1"}
    assert kw["headers"]["Accept"] == "application/vnd.github+json"
    _, fn = await _run(
        cfg,
        "gh_create_issue",
        {**REPO, "title": "t", "body": "b (c)"},
        method="post",
    )
    assert fn.call_args[1]["json"] == {"title": "t", "body": "b (c)"}


async def test_github_branch_protection_path_traversal_rejected(gh_registry):
    _, cfg = gh_registry
    args = {**REPO, "branch": "../../x", "enforce_admins": True}
    with pytest.raises(HTTPServiceError, match="Invalid path argument"):
        await _run(cfg, "gh_update_branch_protection", args, method="put")
    _, fn = await _run(
        cfg,
        "gh_update_branch_protection",
        {**REPO, "branch": "release/1.x", "enforce_admins": True},
        method="put",
    )
    assert fn.call_args[0][0].endswith("/branches/release/1.x/protection")
