"""Synchronous A2A room adapter: per-channel context/task tracking over
a2a_client.A2AJsonRpcClient. Never surfaces raw remote error bodies and
never retries automatically. Binds no network services itself.
"""
from __future__ import annotations

import asyncio
import os

_PAUSED = ("input-required", "auth-required")

_MISSING = ("A2A support requires the optional A2A extras: "
           "pip install -r requirements-a2a.txt")


def _a2a():
    """Lazily import the A2A client module (pulls in a2a-sdk)."""
    try:
        import a2a_client
        return a2a_client
    except ImportError as exc:  # pragma: no cover - env dependent
        raise RuntimeError(_MISSING) from exc


def _default_client_cls():
    return _a2a().A2AJsonRpcClient


# Test seam: monkeypatched to a fake client factory.
_client_cls = _default_client_cls


class A2ARoomAdapter:
    """Room-facing adapter: send(messages, channel) -> str, sync."""

    def __init__(self, agent_cfg: dict) -> None:
        config_error = _a2a().A2AClientConfigError
        rpc_url = (agent_cfg or {}).get("rpc_url")
        if not rpc_url:
            raise config_error("rpc_url is required for A2A transport")
        self.rpc_url = rpc_url
        allow_lan = agent_cfg.get("allow_lan", False)
        if not isinstance(allow_lan, bool):
            raise config_error(
                "allow_lan must be a boolean (true/false), got "
                f"{type(allow_lan).__name__}: {allow_lan!r}")
        kwargs: dict = {
            "allow_lan": allow_lan,
            "api_key_env": agent_cfg.get("api_key_env"),
        }
        for key in ("request_timeout", "total_timeout",
                    "poll_interval", "max_polls"):
            if key in agent_cfg:
                kwargs[key] = agent_cfg[key]
        self.client_kwargs = kwargs
        self._context_id: dict[str, str] = {}
        self._pending_task: dict[str, str] = {}

    # -- public ----------------------------------------------------------

    def validate(self) -> None:
        """Construct+close the client (URL/knob checks) and verify the
        configured credential env var exists. No network I/O."""
        config_error = _a2a().A2AClientConfigError
        client = _client_cls()(self.rpc_url, **self.client_kwargs)

        async def _close():
            await client.aclose()
        asyncio.run(_close())
        env = self.client_kwargs.get("api_key_env")
        if env and not os.environ.get(env):
            raise config_error(
                f"credential env var {env!r} is missing or empty")

    def send(self, messages: list[dict], channel: str) -> str:
        """Flatten messages, send once (no retry), return display text."""
        text = "\n".join(
            f"{m.get('role', 'user')}: {m.get('content', '')}"
            for m in messages)
        try:
            result = asyncio.run(self._send_async(text, channel))
        except Exception as exc:
            if isinstance(exc, _a2a().A2AClientError):
                # Sanitized: class name only, never the remote body.
                return f"[A2A error: {type(exc).__name__}]"
            raise
        self._track(channel, result)
        return self._display(result)

    # -- internals -------------------------------------------------------

    async def _send_async(self, text: str, channel: str):
        client = _client_cls()(self.rpc_url, **self.client_kwargs)
        try:
            return await client.send_text(
                text,
                context_id=self._context_id.get(channel),
                task_id=self._pending_task.get(channel))
        finally:
            await client.aclose()

    def _track(self, channel: str, result) -> None:
        state = getattr(result, "state", None)
        if getattr(result, "context_id", None):
            self._context_id[channel] = result.context_id
        if state in _PAUSED and getattr(result, "task_id", None):
            self._pending_task[channel] = result.task_id
        else:
            self._pending_task.pop(channel, None)

    def _display(self, result) -> str:
        state = getattr(result, "state", None)
        text = getattr(result, "text", None) or ""
        if state == "completed":
            return text if text else "[A2A completed: no text output]"
        return f"[A2A {state}] {text}"
