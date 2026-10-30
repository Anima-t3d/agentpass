"""Shared helpers for the renderer tests: a routed lookup fake and mail builders."""

from __future__ import annotations

import base64
import json
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from agentpass.config import load_tools_file
from agentpass.preview import Preview, PreviewService, Unavailable
from agentpass.registry import ToolRegistry
from agentpass.services.base import ServiceHandler
from agentpass.services.http import HTTPServiceError

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text())


class RoutedLookup(ServiceHandler):
    """Answers a lookup by exact path template; a value that is an Exception is raised."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.paths: list[str] = []

    async def execute(self, tool_name, args):
        raise AssertionError("a preview must never execute a tool")

    async def lookup(self, path, args, *, query=None, timeout=2.0, max_bytes=262144):
        self.paths.append(path)
        for route, answer in self.routes.items():
            if path == route:
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise HTTPServiceError("HTTP 404")

    async def health_check(self):
        return True

    async def close(self):
        pass


def service(yaml_name: str, svc_name: str, routes: dict[str, Any] | None = None):
    tools = load_tools_file(f"tools/{yaml_name}.yaml", svc_name)
    registry = ToolRegistry({t.name: t for t in tools})
    fake = RoutedLookup(routes or {})
    return PreviewService(registry, {svc_name: fake}), fake


async def build(yaml_name: str, svc_name: str, tool: str, args: dict, routes=None) -> Preview:
    svc, _ = service(yaml_name, svc_name, routes)
    preview = await svc.build(tool, args)
    assert isinstance(preview, Preview), preview
    return preview


async def build_any(yaml_name, svc_name, tool, args, routes=None) -> Preview | Unavailable:
    svc, _ = service(yaml_name, svc_name, routes)
    result = await svc.build(tool, args)
    assert result is not None
    return result


def b64(text: str | bytes) -> str:
    data = text.encode() if isinstance(text, str) else text
    return base64.b64encode(data).decode()


def raw_mail(msg: EmailMessage | bytes) -> str:
    data = msg if isinstance(msg, bytes) else msg.as_bytes()
    return base64.urlsafe_b64encode(data).decode()


def mail(to="bob@example.com", subject="Hello", body="Hi Bob", **headers) -> EmailMessage:
    m = EmailMessage()
    m["From"] = headers.pop("From", "alice@example.com")
    if to:
        m["To"] = to
    m["Subject"] = subject
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    if body is not None:
        m.set_content(body)
    return m


def section(p: Preview, label: str):
    return next(s for s in p.sections if s.label == label)
