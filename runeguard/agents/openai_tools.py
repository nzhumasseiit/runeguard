from collections.abc import Callable
from typing import Any

from .base import GuardedAgent


class GuardedToolRegistry(GuardedAgent):
    """Registry for OpenAI function-calling style tool handlers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tools: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, func: Callable[..., Any]):
        self._tools[name] = func
        return func

    def call(self, name: str, **kwargs):
        if name not in self._tools:
            raise KeyError(f"unknown tool: {name}")

        return self.guarded_call(name, self._tools[name], **kwargs)
