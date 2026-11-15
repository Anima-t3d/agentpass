"""Action execution dispatcher — routes tool requests to service handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentpass.services.base import ServiceHandler

if TYPE_CHECKING:
    from agentpass.registry import ToolRegistry


class ExecutionError(Exception):
    """Raised when tool dispatch or execution fails.

    ``public=True`` marks the message as fixed text that is safe to show the agent in
    a stored (polled) result. Without it a stored result only says "Execution failed".
    """

    def __init__(self, *args: object, public: bool = False) -> None:
        super().__init__(*args)
        self.public = public


class Executor:
    """Routes approved tool requests to service handlers."""

    def __init__(
        self,
        services: dict[str, ServiceHandler],
        registry: ToolRegistry | None = None,
    ) -> None:
        self._services = services
        self._registry = registry

    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool request to the appropriate service handler."""
        service_name = None
        if self._registry:
            service_name = self._registry.get_service_name(tool_name)

        if service_name is None:
            raise ExecutionError(f"Unknown tool: {tool_name}")
        handler = self._services.get(service_name)
        if handler is None:
            raise ExecutionError(f"Service not configured: {service_name}")
        return await handler.execute(tool_name, args)
