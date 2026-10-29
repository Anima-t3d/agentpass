"""Tests for agentpass.services.http — Generic HTTP service handler."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from agentpass.config import (
    AuthConfig,
    ErrorMapping,
    HealthCheckConfig,
    ServiceConfig,
    ToolDefinition,
    load_tools_file,
)
from agentpass.services.http import GenericHTTPService, HTTPServiceError

# --- Test helpers ---


def _make_ha_config(base_url: str = "http://ha-test:8123") -> ServiceConfig:
    """Build a ServiceConfig with HA tools loaded from the tools YAML file."""
    tools = load_tools_file("tools/homeassistant.yaml", "homeassistant")
    return ServiceConfig(
        name="homeassistant",
        url=base_url,
        auth=AuthConfig(type="bearer", token="test-token"),
        health=HealthCheckConfig(method="GET", path="/api/", expect_status=200),
        tools=tools,
        errors=[
            ErrorMapping(status=401, message="Service authentication failed (HA token expired?)"),
            ErrorMapping(status=404, message="Entity not found"),
        ],
    )


def _mock_response(*, status: int = 200, json_data: dict | list | None = None, text: str = ""):
    """Create a mock aiohttp response as an async context manager."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data if json_data is not None else {})
    resp.text = AsyncMock(return_value=text)
    # Make it usable as async context manager
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _mock_session() -> MagicMock:
    """Create a MagicMock aiohttp session that won't be replaced by _get_session."""
    session = MagicMock()
    session.closed = False
    return session


# --- TestGenericHTTPServiceGetState ---


class TestGenericHTTPServiceGetState:
    async def test_get_state_url_and_auth(self):
        """Correct URL built and Bearer auth header used."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        json_data = {"entity_id": "sensor.temp", "state": "22.5"}
        session.get = MagicMock(return_value=_mock_response(json_data=json_data))
        svc._session = session

        result = await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

        session.get.assert_called_once()
        call_args = session.get.call_args
        assert call_args[0][0] == "http://ha-test:8123/api/states/sensor.temp"
        assert result == json_data

    async def test_get_state_returns_raw_json(self):
        """ha_get_state has no response.wrap, so raw JSON is returned."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        json_data = {"entity_id": "sensor.temp", "state": "22.5", "attributes": {"unit": "C"}}
        session.get = MagicMock(return_value=_mock_response(json_data=json_data))
        svc._session = session

        result = await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

        # No wrapping -- raw result
        assert result == json_data
        assert "states" not in result


# --- TestGenericHTTPServiceGetStates ---


class TestGenericHTTPServiceGetStates:
    async def test_get_states_url(self):
        """GET /api/states endpoint."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(json_data=[]))
        svc._session = session

        await svc.execute("ha_get_states", {})

        session.get.assert_called_once()
        call_url = session.get.call_args[0][0]
        assert call_url == "http://ha-test:8123/api/states"

    async def test_get_states_wraps_response(self):
        """Returns {"states": [...]} because response.wrap is "states"."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        json_data = [{"entity_id": "sensor.temp", "state": "22.5"}]
        session.get = MagicMock(return_value=_mock_response(json_data=json_data))
        svc._session = session

        result = await svc.execute("ha_get_states", {})

        assert result == {"states": json_data}


# --- TestGenericHTTPServiceCallService ---


class TestGenericHTTPServiceCallService:
    async def test_call_service_url(self):
        """POST /api/services/{domain}/{service}."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.post = MagicMock(return_value=_mock_response(json_data=[]))
        svc._session = session

        await svc.execute(
            "ha_call_service",
            {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"},
        )

        session.post.assert_called_once()
        call_url = session.post.call_args[0][0]
        assert call_url == "http://ha-test:8123/api/services/light/turn_on"

    async def test_call_service_body_excludes_domain_service(self):
        """Body only has entity_id and other args (domain/service excluded)."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.post = MagicMock(return_value=_mock_response(json_data=[]))
        svc._session = session

        await svc.execute(
            "ha_call_service",
            {
                "domain": "light",
                "service": "turn_on",
                "entity_id": "light.bedroom",
                "brightness": 128,
                "color_name": "blue",
            },
        )

        call_kwargs = session.post.call_args[1]
        body = call_kwargs["json"]
        assert body["entity_id"] == "light.bedroom"
        assert body["brightness"] == 128
        assert "color_name" not in body  # undeclared args are never forwarded
        # domain and service should NOT be in the body
        assert "domain" not in body
        assert "service" not in body

    async def test_call_service_wraps_response(self):
        """Returns {"result": [...]} because response.wrap is "result"."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        json_data = [{"entity_id": "light.bedroom", "state": "on"}]
        session.post = MagicMock(return_value=_mock_response(json_data=json_data))
        svc._session = session

        result = await svc.execute(
            "ha_call_service",
            {"domain": "light", "service": "turn_on", "entity_id": "light.bedroom"},
        )

        assert result == {"result": json_data}


# --- TestGenericHTTPServiceFireEvent ---


class TestGenericHTTPServiceFireEvent:
    async def test_fire_event_url(self):
        """POST /api/events/{event_type}."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        json_data = {"message": "Event fired."}
        session.post = MagicMock(return_value=_mock_response(json_data=json_data))
        svc._session = session

        await svc.execute(
            "ha_fire_event",
            {"event_type": "custom_event", "data_key": "data_value"},
        )

        session.post.assert_called_once()
        call_url = session.post.call_args[0][0]
        assert call_url == "http://ha-test:8123/api/events/custom_event"

    async def test_fire_event_body_excludes_event_type(self):
        """Body only contains non-excluded args."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.post = MagicMock(return_value=_mock_response(json_data={}))
        svc._session = session

        await svc.execute(
            "ha_fire_event",
            {"event_type": "my_event", "key1": "val1", "key2": "val2"},
        )

        call_kwargs = session.post.call_args[1]
        body = call_kwargs["json"]
        assert body == {"key1": "val1", "key2": "val2"}
        assert "event_type" not in body


# --- TestGenericHTTPServiceErrors ---


class TestGenericHTTPServiceErrors:
    async def test_401_uses_error_mapping(self):
        """401 triggers the configured error mapping message."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=401, text="Unauthorized"))
        svc._session = session

        with pytest.raises(HTTPServiceError, match="HA token expired"):
            await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

    async def test_404_uses_error_mapping(self):
        """404 triggers the configured error mapping message."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=404, text="Not Found"))
        svc._session = session

        with pytest.raises(HTTPServiceError, match="Entity not found"):
            await svc.execute("ha_get_state", {"entity_id": "sensor.nonexistent"})

    async def test_500_uses_default_error(self):
        """500 has no mapping, falls through to default 'API error 500: ...'."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.post = MagicMock(
            return_value=_mock_response(status=500, text="Internal Server Error")
        )
        svc._session = session

        with pytest.raises(HTTPServiceError, match="API error 500"):
            await svc.execute(
                "ha_call_service",
                {"domain": "light", "service": "turn_on", "entity_id": "light.x"},
            )

    async def test_unknown_tool_raises(self):
        """An unregistered tool name raises HTTPServiceError."""
        svc = GenericHTTPService(_make_ha_config())

        with pytest.raises(HTTPServiceError, match="Unknown tool"):
            await svc.execute("nonexistent_tool", {"entity_id": "sensor.temp"})


# --- TestGenericHTTPServiceAuth ---


class TestGenericHTTPServiceAuth:
    async def test_bearer_auth(self):
        """Bearer auth sets Authorization header on the session."""
        config = _make_ha_config()
        svc = GenericHTTPService(config)
        session = svc._get_session()

        assert session._default_headers["Authorization"] == "Bearer test-token"
        await session.close()

    async def test_header_auth(self):
        """Custom header auth sets the specified header on the session."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="header", header_name="X-Api-Key", token="my-api-key"),
            tools=[],
        )
        svc = GenericHTTPService(config)
        session = svc._get_session()

        assert session._default_headers["X-Api-Key"] == "my-api-key"
        await session.close()

    async def test_query_auth(self):
        """Query auth appends token as a query parameter to each request."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="query", query_param="api_key", token="my-key"),
            tools=load_tools_file("tools/homeassistant.yaml", "custom"),
        )
        svc = GenericHTTPService(config)
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(json_data={}))
        svc._session = session

        await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

        call_kwargs = session.get.call_args[1]
        assert call_kwargs["params"]["api_key"] == "my-key"

    async def test_basic_auth(self):
        """Basic auth uses aiohttp.BasicAuth on the session."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="basic", username="user", password="pass"),
            tools=[],
        )
        svc = GenericHTTPService(config)
        session = svc._get_session()

        assert session._default_auth is not None
        assert session._default_auth.login == "user"
        assert session._default_auth.password == "pass"
        await session.close()


# --- TestGenericHTTPServiceHealth ---


class TestGenericHTTPServiceHealth:
    async def test_health_check_success(self):
        """Returns True when health endpoint returns expected status."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=200))
        svc._session = session

        result = await svc.health_check()
        assert result is True

        call_url = session.get.call_args[0][0]
        assert call_url == "http://ha-test:8123/api/"

    async def test_health_check_failure(self):
        """Returns False when health endpoint returns non-expected status."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=503))
        svc._session = session

        result = await svc.health_check()
        assert result is False

    async def test_health_check_custom_path(self):
        """Uses the configured health check path, not hardcoded."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="bearer", token="tok"),
            health=HealthCheckConfig(method="GET", path="/healthz", expect_status=200),
            tools=[],
        )
        svc = GenericHTTPService(config)
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=200))
        svc._session = session

        result = await svc.health_check()
        assert result is True

        call_url = session.get.call_args[0][0]
        assert call_url == "http://example.com/healthz"

    async def test_health_check_connection_error(self):
        """Returns False when service is unreachable."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(
            side_effect=aiohttp.ClientConnectorError(
                connection_key=MagicMock(),
                os_error=OSError("Connection refused"),
            )
        )
        svc._session = session

        result = await svc.health_check()
        assert result is False

    async def test_health_check_uses_5_second_timeout(self):
        """Health check uses a 5-second timeout."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=200))
        svc._session = session

        await svc.health_check()

        call_kwargs = session.get.call_args[1]
        timeout = call_kwargs["timeout"]
        assert timeout.total == 5

    async def test_health_check_custom_method(self):
        """Health check uses the configured HTTP method (e.g., POST)."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="bearer", token="tok"),
            health=HealthCheckConfig(method="POST", path="/health", expect_status=200),
            tools=[],
        )
        svc = GenericHTTPService(config)
        session = _mock_session()
        session.post = MagicMock(return_value=_mock_response(status=200))
        svc._session = session

        result = await svc.health_check()
        assert result is True

        session.post.assert_called_once()


# --- TestGenericHTTPServiceMisc ---


class TestGenericHTTPServiceMisc:
    async def test_close_session(self):
        """Closing the service closes the aiohttp session."""
        svc = GenericHTTPService(_make_ha_config())
        session = svc._get_session()
        assert not session.closed

        await svc.close()
        assert svc._session is None

    async def test_close_is_idempotent(self):
        """Closing without a session (or twice) is safe."""
        svc = GenericHTTPService(_make_ha_config())
        await svc.close()
        await svc.close()

    async def test_path_interpolation(self):
        """Static method correctly replaces {key} placeholders."""
        result = GenericHTTPService._interpolate_path(
            "/api/states/{entity_id}", {"entity_id": "sensor.temp"}
        )
        assert result == "/api/states/sensor.temp"

    async def test_path_interpolation_multiple_placeholders(self):
        """Multiple placeholders are replaced."""
        result = GenericHTTPService._interpolate_path(
            "/api/services/{domain}/{service}",
            {"domain": "light", "service": "turn_on"},
        )
        assert result == "/api/services/light/turn_on"

    async def test_path_interpolation_missing_key(self):
        """Missing key in args is an error, not an empty segment."""
        with pytest.raises(HTTPServiceError):
            GenericHTTPService._interpolate_path("/api/states/{entity_id}", {})

    async def test_body_no_exclude(self):
        """All args appear in body when no body_exclude is set."""
        from agentpass.config import RequestDefinition

        tool = ToolDefinition(
            name="test_tool",
            service_name="test",
            request=RequestDefinition(method="POST", path="/test"),
            # no body_exclude
        )
        body = GenericHTTPService._build_body(tool, {"a": 1, "b": 2, "c": 3})
        assert body == {"a": 1, "b": 2, "c": 3}

    async def test_response_no_wrap(self):
        """Raw response when tool has no response.wrap defined."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        json_data = {"entity_id": "sensor.temp", "state": "22.5"}
        session.get = MagicMock(return_value=_mock_response(json_data=json_data))
        svc._session = session

        # ha_get_state has no response.wrap
        result = await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})
        assert result == json_data

    async def test_service_unreachable(self):
        """aiohttp.ClientError is wrapped in HTTPServiceError with 'unreachable'."""
        svc = GenericHTTPService(_make_ha_config())
        session = _mock_session()
        session.get = MagicMock(side_effect=aiohttp.ClientError("some error"))
        svc._session = session

        with pytest.raises(HTTPServiceError, match=r"(?i)unreachable"):
            await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

    async def test_tool_without_request_definition_raises(self):
        """A tool with no request definition raises HTTPServiceError."""
        config = ServiceConfig(
            name="test",
            url="http://example.com",
            auth=AuthConfig(type="bearer", token="tok"),
            tools=[
                ToolDefinition(name="no_request", service_name="test"),
            ],
        )
        svc = GenericHTTPService(config)

        with pytest.raises(HTTPServiceError, match="no request definition"):
            await svc.execute("no_request", {})

    async def test_trailing_slash_stripped(self):
        """Trailing slash on base URL is stripped to avoid double slashes."""
        svc = GenericHTTPService(_make_ha_config(base_url="http://ha-test:8123/"))
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(json_data={}))
        svc._session = session

        await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

        call_url = session.get.call_args[0][0]
        assert call_url == "http://ha-test:8123/api/states/sensor.temp"

    async def test_get_session_reuses_existing(self):
        """_get_session returns the same session when not closed."""
        svc = GenericHTTPService(_make_ha_config())
        session1 = svc._get_session()
        session2 = svc._get_session()
        assert session1 is session2
        await session1.close()

    async def test_get_session_creates_new_if_closed(self):
        """_get_session creates a new session if the previous one was closed."""
        svc = GenericHTTPService(_make_ha_config())
        session1 = svc._get_session()
        await session1.close()

        session2 = svc._get_session()
        assert session2 is not session1
        assert not session2.closed
        await session2.close()

    async def test_error_mapping_with_templates(self):
        """Error mapping message supports {status} and {body} templates."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="bearer", token="tok"),
            tools=load_tools_file("tools/homeassistant.yaml", "custom"),
            errors=[
                ErrorMapping(
                    status=422,
                    message="Validation failed: status={status}, body={body}",
                ),
            ],
        )
        svc = GenericHTTPService(config)
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=422, text="bad input"))
        svc._session = session

        with pytest.raises(HTTPServiceError, match=r"status=422.*body=bad input"):
            await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

    async def test_no_error_mapping_401_default(self):
        """Without error mapping, 401 falls through to default auth error."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="bearer", token="tok"),
            tools=load_tools_file("tools/homeassistant.yaml", "custom"),
            errors=[],  # no mappings
        )
        svc = GenericHTTPService(config)
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=401, text="Unauthorized"))
        svc._session = session

        with pytest.raises(HTTPServiceError, match="authentication failed"):
            await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})

    async def test_no_error_mapping_404_default(self):
        """Without error mapping, 404 falls through to default not-found error."""
        config = ServiceConfig(
            name="custom",
            url="http://example.com",
            auth=AuthConfig(type="bearer", token="tok"),
            tools=load_tools_file("tools/homeassistant.yaml", "custom"),
            errors=[],  # no mappings
        )
        svc = GenericHTTPService(config)
        session = _mock_session()
        session.get = MagicMock(return_value=_mock_response(status=404, text="Not Found"))
        svc._session = session

        with pytest.raises(HTTPServiceError, match="not found"):
            await svc.execute("ha_get_state", {"entity_id": "sensor.temp"})


class TestLookupRedirects:
    async def test_lookup_does_not_follow_redirects(self):
        """A 3xx from a preview lookup is a failure, and the redirect is never followed."""
        from aiohttp import web
        from aiohttp.test_utils import TestServer

        hits: list[str] = []

        async def moved(_: web.Request) -> web.Response:
            hits.append("moved")
            raise web.HTTPFound("/elsewhere")

        async def elsewhere(_: web.Request) -> web.Response:
            hits.append("elsewhere")
            return web.json_response({"leaked": True})

        app = web.Application()
        app.router.add_get("/api/states/x", moved)
        app.router.add_get("/elsewhere", elsewhere)
        async with TestServer(app) as server:
            svc = GenericHTTPService(_make_ha_config(str(server.make_url(""))))
            with pytest.raises(HTTPServiceError, match="HTTP 302"):
                await svc.lookup("/api/states/x", {})
            await svc.close()
        assert hits == ["moved"]
