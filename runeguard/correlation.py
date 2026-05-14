from __future__ import annotations

import hashlib
import os
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator


_current_turn: ContextVar["CorrelationContext | None"] = ContextVar(
    "runeguard_current_turn",
    default=None,
)


@dataclass(frozen=True)
class CorrelationContext:
    """Causal metadata for one agent turn."""

    turn_id: str
    agent: str = "unknown"
    parent_turn_id: str | None = None
    started_at: str = ""

    def as_record(self) -> dict:
        causal_chain = [self.turn_id]
        if self.parent_turn_id:
            causal_chain.insert(0, self.parent_turn_id)

        return {
            "turn_id": self.turn_id,
            "agent": self.agent,
            "parent_turn_id": self.parent_turn_id,
            "causal_chain": causal_chain,
            "started_at": self.started_at,
        }


def new_turn_id() -> str:
    return uuid.uuid4().hex


def current_turn() -> CorrelationContext | None:
    return _current_turn.get() or _context_from_environment()


@contextmanager
def agent_turn(
    *,
    agent: str = "unknown",
    turn_id: str | None = None,
    parent_turn_id: str | None = None,
) -> Iterator[CorrelationContext]:
    context = CorrelationContext(
        turn_id=turn_id or new_turn_id(),
        agent=agent,
        parent_turn_id=parent_turn_id,
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    token = _current_turn.set(context)
    try:
        yield context
    finally:
        _current_turn.reset(token)


def command_event_id(command: str | None = None, argv: list[str] | tuple[str, ...] | None = None) -> str:
    material = command or " ".join(argv or ())
    digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()
    return f"cmd_{digest[:16]}"


def annotate_record(record: dict, kwargs: dict | None = None) -> dict:
    context = current_turn()
    if context is None:
        return record

    kwargs = kwargs or {}
    correlation = context.as_record()
    if "command" in kwargs or "argv" in kwargs:
        correlation["event_id"] = command_event_id(
            kwargs.get("command"),
            kwargs.get("argv"),
        )
        correlation["spawned_by_turn"] = context.turn_id

    correlation["process"] = {
        "pid": os.getpid(),
        "ppid": os.getppid(),
    }
    record["correlation"] = correlation
    return record


def _context_from_environment() -> CorrelationContext | None:
    turn_id = os.environ.get("RUNEGUARD_TURN_ID")
    if not turn_id:
        return None

    return CorrelationContext(
        turn_id=turn_id,
        agent=os.environ.get("RUNEGUARD_AGENT", "unknown"),
        parent_turn_id=os.environ.get("RUNEGUARD_PARENT_TURN_ID") or None,
        started_at=os.environ.get("RUNEGUARD_TURN_STARTED_AT", ""),
    )
