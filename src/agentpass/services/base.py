"""ServiceHandler abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ServiceHandler(ABC):
    """Interface for service integrations."""

    @abstractmethod
    async def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool call and return the result."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the service is reachable."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Clean up resources."""
        ...


class ServiceUnauthorizedError(Exception):
    """The service's credentials need owner action (e.g. OAuth consent).

    Carries no upstream detail; the pipeline reports a fixed message.
    """
