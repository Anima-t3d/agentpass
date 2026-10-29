"""Generic HTTP service handler -- executes YAML-defined tool requests."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import quote

import aiohttp

from agentpass.config import ServiceConfig, ToolDefinition
from agentpass.services.auth import (
    OAuth2Refresh,
    StaticBearer,
    TokenProvider,
    TokenRefreshError,
    TokenStore,
)
from agentpass.services.base import ServiceHandler, ServiceUnauthorizedError

_REF_RE = re.compile(r"\{(\w+)(?::path)?\}")
_ABSENT = object()


class HTTPServiceError(Exception):
    """Raised when a generic HTTP service call fails."""


class HTTPUnauthorizedError(HTTPServiceError, ServiceUnauthorizedError):
    """The service answered 401 to the gateway's own credentials."""


class GenericHTTPService(ServiceHandler):
    """Service handler that executes YAML-defined HTTP tool requests.

    Each tool is defined in a YAML file with its HTTP method, path template,
    body exclusions, and response wrapping.  This handler resolves those
    definitions at runtime so that adding a new service or tool requires
    only YAML -- no Python code.
    """

    def __init__(self, config: ServiceConfig) -> None:
        self._config = config
        self._base_url = config.url.rstrip("/")
        self._session: aiohttp.ClientSession | None = None
        # Index tools by name for fast lookup
        self._tools: dict[str, ToolDefinition] = {t.name: t for t in config.tools}
        self._provider = self._build_provider(config)

    @staticmethod
    def _build_provider(config: ServiceConfig) -> TokenProvider | None:
        auth = config.auth
        if auth.type == "bearer":
            return StaticBearer(auth.token)
        if auth.type == "header":
            return StaticBearer(auth.token, auth.header_name, bearer=False)
        if auth.type == "oauth2":
            kwargs = {"token_url": auth.token_url} if auth.token_url else {}
            return OAuth2Refresh(
                store=TokenStore(auth.token_dir),
                provider=auth.provider,
                account=auth.account,
                secrets_file=auth.secrets_file,
                **kwargs,
            )
        return None  # query/basic auth is handled by the session / per request

    @property
    def provider(self) -> TokenProvider | None:
        return self._provider

    def _get_session(self) -> aiohttp.ClientSession:
        """Return existing session or create new one with auth headers."""
        if self._session is None or self._session.closed:
            headers: dict[str, str] = {}
            auth_obj: aiohttp.BasicAuth | None = None

            if self._config.auth.type == "bearer":
                headers["Authorization"] = f"Bearer {self._config.auth.token}"
            elif self._config.auth.type == "header":
                headers[self._config.auth.header_name] = self._config.auth.token
            elif self._config.auth.type == "basic":
                auth_obj = aiohttp.BasicAuth(self._config.auth.username, self._config.auth.password)
            # query auth is handled per-request in _execute_request

            self._session = aiohttp.ClientSession(headers=headers, auth=auth_obj)
        return self._session

    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool request based on its YAML definition."""
        tool = self._tools.get(tool_name)
        if tool is None:
            raise HTTPServiceError(f"Unknown tool: {tool_name}")
        if tool.request is None:
            raise HTTPServiceError(f"Tool {tool_name} has no request definition")

        session = self._get_session()
        try:
            return await self._execute_request(session, tool, args)
        except HTTPServiceError:
            raise
        except TokenRefreshError as exc:
            raise HTTPServiceError("Service authentication failed") from exc
        except aiohttp.ClientError as exc:
            raise HTTPServiceError(f"Service unreachable: {self._config.name} ({exc})") from exc

    async def _execute_request(
        self,
        session: aiohttp.ClientSession,
        tool: ToolDefinition,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        """Build and send the HTTP request defined by the tool."""
        req = tool.request
        # 1. Interpolate path template
        path = self._interpolate_path(req.path, args)
        url = f"{self._base_url}{path}"

        # 2. Query params: tool templates, then query auth
        params = self._build_query(req.query, args)
        if self._config.auth.type == "query":
            params[self._config.auth.query_param] = self._config.auth.token

        # 3. Headers (Authorization/Host/Cookie are rejected at load time)
        headers = self._build_headers(req.headers, args)

        # 4. Body
        body: dict[str, Any] | None = None
        if req.method in ("POST", "PUT", "PATCH") or (req.has_body_spec and req.method != "GET"):
            body = self._build_body(tool, args)

        # 5. Make request. Tool headers first, then the provider's header on top.
        # The provider is asked on every request; on a 401 the request is retried
        # once with a refreshed header, never in a loop.
        method_fn = getattr(session, req.method.lower())
        for attempt in (0, 1):
            request_headers = dict(headers)
            if self._provider is not None:
                request_headers.update(await self._provider.header())
            kwargs: dict[str, Any] = {"json": body, "params": params or None}
            if request_headers:
                kwargs["headers"] = request_headers
            if req.timeout is not None:
                kwargs["timeout"] = aiohttp.ClientTimeout(total=req.timeout)
            async with method_fn(url, **kwargs) as resp:
                if (
                    resp.status == 401
                    and attempt == 0
                    and self._provider is not None
                    and await self._provider.on_unauthorized(request_headers)
                ):
                    continue
                await self._check_response(resp)
                data = await self._read_response(resp, tool)

                # 6. Response wrapping
                if tool.response and tool.response.wrap:
                    return {tool.response.wrap: data}
                return data
        raise HTTPServiceError("Service authentication failed")  # unreachable

    async def lookup(
        self,
        path: str,
        args: dict[str, Any],
        *,
        query: dict[str, str] | None = None,
        timeout: float = 2.0,
        max_bytes: int = 262144,
    ) -> Any:
        """GET ``path`` on this service for an approval preview and return the parsed JSON.

        Same credentials and URL building as a normal call (the host is the service's own,
        path values are percent-encoded per segment). GET only, with its own timeout and
        a hard cap on the body. Failures carry the status or a fixed reason, never the body.
        """
        url = f"{self._base_url}{self._interpolate_path(path, args)}"
        params = self._build_query(query, args)
        if self._config.auth.type == "query":
            params[self._config.auth.query_param] = self._config.auth.token
        session = self._get_session()
        try:
            for attempt in (0, 1):
                headers = await self._provider.header() if self._provider is not None else {}
                async with session.get(
                    url,
                    params=params or None,
                    headers=headers or None,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=False,  # a redirect could leave the service's own host
                ) as resp:
                    if (
                        resp.status == 401
                        and attempt == 0
                        and self._provider is not None
                        and await self._provider.on_unauthorized(headers)
                    ):
                        continue
                    if not 200 <= resp.status < 300:
                        raise HTTPServiceError(f"HTTP {resp.status}")
                    if resp.content_length is not None and resp.content_length > max_bytes:
                        raise HTTPServiceError("response too large")
                    raw = await resp.content.read(max_bytes + 1)
                    if len(raw) > max_bytes:
                        raise HTTPServiceError("response too large")
                    try:
                        return json.loads(raw) if raw else {}
                    except ValueError:
                        raise HTTPServiceError("response is not JSON") from None
        except TokenRefreshError as exc:
            raise HTTPServiceError("authentication failed") from exc
        except aiohttp.ClientError as exc:
            raise HTTPServiceError("service unreachable") from exc
        raise HTTPServiceError("authentication failed")

    @staticmethod
    async def _read_response(resp: aiohttp.ClientResponse, tool: ToolDefinition) -> Any:
        """Read the body according to ``response.type`` and ``response.max_bytes``."""
        rdef = tool.response
        rtype = rdef.type if rdef else "json"
        if rtype == "none":
            return {}
        max_bytes = rdef.max_bytes if rdef else None
        if max_bytes is None and rtype == "json":
            return await resp.json()
        if resp.content_length is not None and max_bytes and resp.content_length > max_bytes:
            raise HTTPServiceError("Response too large")
        raw = await resp.content.read(max_bytes + 1 if max_bytes else -1)
        if max_bytes and len(raw) > max_bytes:
            raise HTTPServiceError("Response too large")
        if rtype == "json":
            try:
                return json.loads(raw)
            except ValueError:
                raise HTTPServiceError("Service returned invalid JSON") from None
        if rtype == "text":
            return {"text": raw.decode("utf-8", errors="replace")}
        return {"base64": base64.b64encode(raw).decode("ascii"), "size": len(raw)}

    @staticmethod
    def _scalar(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    @classmethod
    def _render(cls, template: str, args: dict[str, Any]) -> Any:
        """Render a template over args, or return _ABSENT if a referenced arg is absent.

        A template that is exactly ``{name}`` yields the typed value; anything
        else is interpolated as a string.
        """
        refs = _REF_RE.findall(template)
        if any(r not in args or args[r] is None for r in refs):
            return _ABSENT
        whole = _REF_RE.fullmatch(template)
        if whole:
            return args[whole.group(1)]
        return _REF_RE.sub(lambda m: cls._scalar(args[m.group(1)]), template)

    @classmethod
    def _build_query(
        cls, query: dict[str, str] | None, args: dict[str, Any]
    ) -> dict[str, str | list[str]]:
        params: dict[str, str | list[str]] = {}
        for key, template in (query or {}).items():
            value = cls._render(template, args)
            if value is _ABSENT:
                continue  # dropped, never interpolated as an empty string
            if isinstance(value, list):
                params[key] = [cls._scalar(v) for v in value]
            else:
                params[key] = cls._scalar(value)
        return params

    @classmethod
    def _build_headers(cls, headers: dict[str, str] | None, args: dict[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, template in (headers or {}).items():
            value = cls._render(template, args)
            if value is _ABSENT:
                continue
            text = cls._scalar(value)
            if "\r" in text or "\n" in text:
                raise HTTPServiceError(f"Invalid header value: {key}")
            out[key] = text
        return out

    @staticmethod
    def _interpolate_path(path: str, args: dict[str, Any]) -> str:
        """Replace {arg} and {arg:path} placeholders in path with encoded values.

        ``{arg}`` is one percent-encoded segment.  ``{arg:path}`` may span
        several segments, each checked against empty, ``.`` and ``..`` and
        encoded separately.
        """

        def replacer(m: re.Match) -> str:
            key, multi = m.group(1), m.group(2) is not None
            if key not in args:
                raise HTTPServiceError(f"Missing path argument: {key}")
            val = str(args[key])
            segments = val.split("/") if multi else [val]
            for seg in segments:
                if seg in ("", ".", ".."):
                    raise HTTPServiceError(f"Invalid path argument: {key}")
            # Each segment is encoded on its own: "?", "#", "%" cannot escape
            return "/".join(quote(seg, safe="") for seg in segments)

        return re.sub(r"\{(\w+)(:path)?\}", replacer, path)

    @classmethod
    def _build_body(cls, tool: ToolDefinition, args: dict[str, Any]) -> dict[str, Any]:
        """Build the JSON body.

        With a ``body:`` spec only ``include`` args and ``map`` fields are sent.
        Otherwise every arg is sent except ``body_exclude`` and the args already
        consumed by the path, query or headers.
        """
        req = tool.request
        if req.has_body_spec:
            body = {k: args[k] for k in (req.body_include or []) if k in args}
            for key, template in (req.body_map or {}).items():
                value = cls._render(template, args)
                if value is not _ABSENT:
                    body[key] = value
            return body
        used = set(_REF_RE.findall(req.path))
        for mapping in (req.query, req.headers):
            for template in (mapping or {}).values():
                used.update(_REF_RE.findall(template))
        used.update(req.body_exclude or [])
        return {k: v for k, v in args.items() if k not in used}

    async def _check_response(self, resp: aiohttp.ClientResponse) -> None:
        """Check HTTP response status, using service-level error mappings."""
        if 200 <= resp.status < 300:
            return

        # Check service-level error mappings first
        for mapping in self._config.errors:
            if mapping.status == resp.status:
                body = await resp.text()
                msg = mapping.message.format(status=resp.status, body=body)
                raise HTTPServiceError(msg)

        # Default error handling (no mapping matched)
        if resp.status == 401:
            raise HTTPUnauthorizedError("Service authentication failed")
        if resp.status == 404:
            raise HTTPServiceError("Resource not found")
        body = await resp.text()
        raise HTTPServiceError(f"API error {resp.status}: {body}")

    async def health_check(self) -> bool:
        """Check service health using configured endpoint."""
        import logging

        try:
            if self._provider is not None and self._provider.needs_consent:
                return False
            session = self._get_session()
            health = self._config.health
            method_fn = getattr(session, health.method.lower())
            headers = await self._provider.header() if self._provider else None
            async with method_fn(
                f"{self._base_url}{health.path}",
                timeout=aiohttp.ClientTimeout(total=5),
                headers=headers,
            ) as resp:
                return resp.status == health.expect_status
        except Exception as e:
            logging.getLogger("agentpass.services.http").debug(
                "Health check failed for %s: %s", self._config.name, e
            )
            return False

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None
