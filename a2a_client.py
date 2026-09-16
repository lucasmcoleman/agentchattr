"""Minimal, security-hardened A2A 1.0 JSON-RPC client.

Sends text to an EXPLICIT configured A2A 1.0 JSON-RPC endpoint and returns
the final text. Handles either an immediate ``Message`` reply or a bounded
polling ``Task`` (Send -> GetTask until terminal state or poll budget).

Wire format is derived from the installed ``a2a-sdk`` (1.1.2) protobuf
types -- NOT hand-invented:
  * JSON-RPC methods are ``SendMessage`` / ``GetTask`` (A2A 1.0), not the
    old ``message/send`` / ``tasks/get`` (0.3).
  * Params/results are protobuf-JSON (camelCase) produced/consumed with
    ``google.protobuf.json_format`` over ``a2a.types.a2a_pb2`` messages
    (SendMessageRequest / SendMessageResponse wrapper / GetTaskRequest /
    Task), including protobuf enums (ROLE_USER, TASK_STATE_*).

a2a-sdk is an OPTIONAL dependency: this module is only imported when
A2A transport is configured (see requirements-a2a.txt).

Security posture (enforced at construction and per-request):
  * URL allow-list: loopback numeric IPv4/IPv6 or literal ``localhost`` by
    default. ``allow_lan=True`` additionally allows RFC1918 IPv4 and ULA
    (fc00::/7) NUMERIC addresses only. DNS names other than ``localhost``
    are rejected outright -- documented limitation: this deliberately
    avoids DNS-rebinding (the address class can change between validation
    and connection if DNS were trusted).
  * Reject: userinfo, query strings, fragments, schemes other than
    http/https, and public / link-local / multicast / unspecified IPs.
  * Redirects are never followed: any 3xx fails closed.
  * Credentials come only from a configured environment variable. A
    missing (or empty) configured variable fails closed BEFORE any network
    I/O. The token is sent as a bearer header and is never echoed back.
  * Remote error bodies/messages are never surfaced: our exceptions carry
    only stable codes and class names. Internal exception chaining from
    untrusted messages is severed (``raise ... from None``) so secrets
    cannot leak via rendered tracebacks.
  * ``trust_env=False``: HTTP(S)_PROXY / netrc environment inheritance
    is disabled for the network client.
  * Bounded per-request HTTP timeouts and a bounded total task deadline.

Out of scope for this slice (per coordinator spec): agent-card discovery,
streaming (SSE), push notifications, public-network targets.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
from a2a.types import a2a_pb2
from google.protobuf import json_format
from jsonrpc.jsonrpc2 import JSONRPC20Request

__all__ = [
    "A2AClientError",
    "A2AClientConfigError",
    "A2AConnectionError",
    "A2ATimeoutError",
    "A2ARedirectError",
    "A2AAuthError",
    "A2AProtocolError",
    "A2ATaskError",
    "A2APollExhaustedError",
    "SendResult",
    "validate_rpc_url",
    "A2AJsonRpcClient",
]

# ---------------------------------------------------------------- errors


class A2AClientError(Exception):
    """Base for all errors raised by this client."""


class A2AClientConfigError(A2AClientError):
    """Configuration rejected before any network I/O (fail closed)."""


class A2AConnectionError(A2AClientError):
    """Transport-level failure (DNS refused, connection reset, HTTP 5xx...)."""


class A2ATimeoutError(A2AClientError):
    """HTTP request or total task deadline exceeded."""


class A2ARedirectError(A2AClientError):
    """Server answered with a redirect. Redirects are never followed."""


class A2AAuthError(A2AClientError):
    """Server rejected our credentials (HTTP 401/403)."""


class A2AProtocolError(A2AClientError):
    """Response was not valid A2A 1.0 JSON-RPC (bad JSON / bad protobuf)."""


class A2ATaskError(A2AClientError):
    """Server reported a JSON-RPC error; the task is FAILED.

    Carries only the numeric JSON-RPC code -- never the remote message.
    """

    def __init__(self, code: int) -> None:
        self.code = code
        self.state = "failed"
        super().__init__(f"agent task failed (JSON-RPC error code {code})")


class A2APollExhaustedError(A2AClientError):
    """Task stayed non-terminal beyond the configured poll budget."""

    def __init__(self, state: str, task_id: str | None) -> None:
        self.state = state
        self.task_id = task_id
        super().__init__(
            f"task did not reach a terminal state within poll budget "
            f"(last state: {state})"
        )


# ---------------------------------------------------------- URL validation

# Terminal or paused task states that END the polling loop with a result.
_TERMINAL_STATES = {
    "TASK_STATE_COMPLETED": "completed",
    "TASK_STATE_FAILED": "failed",
    "TASK_STATE_CANCELED": "canceled",
    "TASK_STATE_REJECTED": "rejected",
    "TASK_STATE_INPUT_REQUIRED": "input-required",
    "TASK_STATE_AUTH_REQUIRED": "auth-required",
}
# States that mean "still going; keep polling" (anything unspecified too).
_POLL_STATES = {"TASK_STATE_SUBMITTED": "submitted",
               "TASK_STATE_WORKING": "working"}


def _ip_allowed(host: str, allow_lan: bool) -> bool:
    """True if a NUMERIC host is permitted under the current policy."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # not numeric -> not allowed (DNS names rejected wholesale)
    if addr.is_loopback:
        return True
    if addr.is_unspecified or addr.is_link_local or addr.is_multicast:
        return False
    if not allow_lan:
        return False
    # LAN opt-in: RFC1918 IPv4 or ULA (fc00::/7) IPv6 only -- exact
    # ranges, NOT httpx-style 'is_private' which also admits CGNAT
    # (100.64/10), benchmarking (198.18/15) and other odd blocks.
    if addr.version == 4:
        return any(addr in net for net in _RFC1918)
    return addr in _ULA_V6


_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA_V6 = ipaddress.ip_network("fc00::/7")


def validate_rpc_url(url: str, *, allow_lan: bool = False) -> str:
    """Validate and normalize an explicit A2A RPC endpoint URL.

    Raises A2AClientConfigError on anything outside the allow-list.
    """
    try:
        parsed = httpx.URL(url)
    except Exception as exc:  # httpx.InvalidURL etc.
        raise A2AClientConfigError("invalid RPC URL") from None

    if parsed.scheme not in ("http", "https"):
        raise A2AClientConfigError(
            f"RPC URL scheme must be http or https, not {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise A2AClientConfigError("RPC URL must not contain userinfo")
    if parsed.query:
        raise A2AClientConfigError("RPC URL must not contain a query string")
    if parsed.fragment:
        raise A2AClientConfigError("RPC URL must not contain a fragment")

    host = parsed.host
    if not host:
        raise A2AClientConfigError("RPC URL must have a host")

    if host.lower() == "localhost":
        return url

    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise A2AClientConfigError(
            "RPC host must be a numeric IP or literal 'localhost' "
            "(DNS names are rejected to avoid DNS rebinding)") from None

    if _ip_allowed(host, allow_lan):
        return url
    raise A2AClientConfigError(
        "RPC host address is not permitted "
        "(loopback always; RFC1918/ULA only with allow_lan=True)")


# ------------------------------------------------------------- result type


@dataclass(frozen=True)
class SendResult:
    """Outcome of a send_text call.

    state: completed | failed | canceled | rejected | input-required |
           auth-required
    """

    state: str
    text: str | None = None
    task_id: str | None = None
    context_id: str | None = None


def _text_of_parts(parts) -> str:
    chunks = [p.text for p in parts if p.WhichOneof("content") == "text"]
    return "\n".join(c for c in chunks if c)


# -------------------------------------------------------------- client


def _validate_task(task) -> str:
    """Validate task identity/state; return the canonical state name.

    Rejects (as sanitized A2AProtocolError): empty task id, absent status,
    the unspecified zero state, and unknown enum values.  Unknown values
    parse without error but raise ValueError from Name(), so that is
    caught and mapped here -- never surfaced raw.
    """
    if not task.id:
        raise A2AProtocolError("task response is missing a task id")
    if not task.HasField("status"):
        raise A2AProtocolError("task response is missing a status")
    try:
        state_name = a2a_pb2.TaskState.Name(task.status.state)
    except ValueError:
        raise A2AProtocolError(
            "task status carries an unknown state value") from None
    if state_name not in _TERMINAL_STATES and state_name not in _POLL_STATES:
        # Covers TASK_STATE_UNSPECIFIED (zero) -- not a real state.
        raise A2AProtocolError(
            "task status state is unspecified or not a known A2A state")
    return state_name


class A2AJsonRpcClient:
    """Callable client for one explicit A2A 1.0 JSON-RPC endpoint.

    Parameters
    ----------
    rpc_url:
        Explicit endpoint (validated; no card discovery).
    allow_lan:
        Permit RFC1918 IPv4 / ULA IPv6 numeric hosts in addition to
        loopback/localhost.
    api_key_env:
        NAME of the environment variable holding the bearer token. If set
        and the variable is missing/empty, sends fail closed.
    request_timeout:
        Per-HTTP-request timeout (seconds).
    poll_interval:
        Delay between GetTask polls (seconds).
    max_polls:
        Hard cap on GetTask polls after a non-terminal SendMessage.
    total_timeout:
        Wall-clock deadline for the entire send_text operation.
    transport:
        Test seam: an httpx transport (e.g. httpx.MockTransport).
        Production callers leave this unset.
    """

    def __init__(
        self,
        rpc_url: str,
        *,
        allow_lan: bool = False,
        api_key_env: str | None = None,
        request_timeout: float = 30.0,
        poll_interval: float = 2.0,
        max_polls: int = 15,
        total_timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.rpc_url = validate_rpc_url(rpc_url, allow_lan=allow_lan)

        # Bounded-knob validation BEFORE building the HTTP client: all must
        # be finite numbers; timeouts must be > 0, poll_interval >= 0, and
        # max_polls a true int (not bool) >= 0. NaN/inf/None/str/bool fail
        # closed as config errors -- never reach httpx.
        def _num(name, val):
            if isinstance(val, bool) or not isinstance(val, (int, float)) \
                    or not math.isfinite(val):
                raise A2AClientConfigError(
                    f"{name} must be a finite number > 0, got {val!r}")

        def _num_nonneg(name, val):
            if isinstance(val, bool) or not isinstance(val, (int, float)) \
                    or not math.isfinite(val):
                raise A2AClientConfigError(
                    f"{name} must be a finite number >= 0, got {val!r}")

        _num("request_timeout", request_timeout)
        if request_timeout <= 0:
            raise A2AClientConfigError("request_timeout must be > 0")
        _num("total_timeout", total_timeout)
        if total_timeout <= 0:
            raise A2AClientConfigError("total_timeout must be > 0")
        _num_nonneg("poll_interval", poll_interval)
        if poll_interval < 0:
            raise A2AClientConfigError("poll_interval must be >= 0")
        if isinstance(max_polls, bool) or type(max_polls) is not int:
            raise A2AClientConfigError("max_polls must be an int >= 0")
        if max_polls < 0:
            raise A2AClientConfigError("max_polls must be >= 0")

        self.api_key_env = api_key_env
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.total_timeout = total_timeout
        # follow_redirects stays False; trust_env=False blocks proxy/netrc env.
        self._client = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(request_timeout),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- public API ------------------------------------------------------

    async def send_text(self, text: str, *, context_id: str | None = None,
                       task_id: str | None = None) -> SendResult:
        """Send text; return final result or raise a typed error.

        Preserves a supplied ``context_id`` on the outgoing message when
        the server echoes none; a server-provided context_id always wins.
        """
        try:
            async with asyncio.timeout(self.total_timeout):
                return await self._send_and_track(text, context_id, task_id)
        except asyncio.TimeoutError:
            raise A2ATimeoutError(
                f"A2A task exceeded total timeout ({self.total_timeout}s)"
            ) from None

    # -- internals -------------------------------------------------------

    async def _send_and_track(self, text: str,
                             context_id: str | None,
                             task_id: str | None) -> SendResult:
        headers = self._auth_headers()

        message = a2a_pb2.Message(
            role=a2a_pb2.Role.ROLE_USER,
            message_id=str(uuid.uuid4()),
            parts=[a2a_pb2.Part(text=text)],
        )
        if context_id:
            message.context_id = context_id
        if task_id:
            message.task_id = task_id
        request = a2a_pb2.SendMessageRequest(message=message)

        result = await self._rpc("SendMessage", request, headers)
        response = self._parse(result, a2a_pb2.SendMessageResponse)

        which = response.WhichOneof("payload")
        if which == "message":
            reply_ctx = response.message.context_id or (context_id or None)
            return SendResult(state="completed",
                             text=_text_of_parts(response.message.parts),
                             context_id=reply_ctx,
                             task_id=response.message.task_id or None)
        if which != "task":
            raise A2AProtocolError(
                "SendMessage response contained neither message nor task")

        task = response.task
        state_name = _validate_task(task)
        state = _TERMINAL_STATES.get(state_name)
        # Server-provided context wins; caller's is the fallback until one
        # ever appears.  Polls that omit context_id keep the last known one.
        tracked_ctx = task.context_id or (context_id or None)
        if state is not None:
            return self._result_from_task(task, state, tracked_ctx)

        # Still working/submitted: bounded polling via GetTask, always for
        # the ORIGINAL task id (never whatever a poll returned).
        original_id = task.id
        last_state = state_name  # used when max_polls == 0
        for _ in range(self.max_polls):
            await asyncio.sleep(self.poll_interval)
            get_req = a2a_pb2.GetTaskRequest(id=original_id)
            poll = await self._rpc("GetTask", get_req, headers)
            polled = self._parse(poll, a2a_pb2.Task)
            polled_state = _validate_task(polled)
            last_state = polled_state
            if polled.id != original_id:
                raise A2AProtocolError(
                    "GetTask response task id does not match the "
                    "requested task")
            if polled.context_id:
                tracked_ctx = polled.context_id
            state = _TERMINAL_STATES.get(polled_state)
            if state is not None:
                return self._result_from_task(polled, state, tracked_ctx)

        raise A2APollExhaustedError(_POLL_STATES[last_state], original_id)

    @staticmethod
    def _result_from_task(task, state: str,
                         fallback_context: str | None) -> SendResult:
        # Collect nonempty text from ALL artifacts, in order — not just
        # the first one; servers may split a response across artifacts.
        chunks = [_text_of_parts(art.parts) for art in task.artifacts]
        text = "\n".join(c for c in chunks if c) or None
        if not text and task.status.HasField("message"):
            text = _text_of_parts(task.status.message.parts) or None
        return SendResult(state=state,
                         text=text,
                         task_id=task.id or None,
                         context_id=task.context_id or fallback_context or None)

    def _auth_headers(self) -> dict[str, str]:
        # Every request carries the protocol version header, auth or not.
        headers = {"A2A-Version": "1.0"}
        if not self.api_key_env:
            return headers
        token = os.environ.get(self.api_key_env)
        if not token:
            # Fail closed BEFORE any network I/O. Name the variable
            # (not a secret); never include the value anywhere.
            raise A2AClientConfigError(
                f"configured credential environment variable "
                f"{self.api_key_env!r} is not set")
        headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _rpc(self, method: str, params_msg,
                  headers: dict[str, str]) -> dict[str, Any]:
        """One JSON-RPC round trip. Returns the raw 'result' dict."""
        rpc = JSONRPC20Request(
            method=method,
            params=json_format.MessageToDict(params_msg),
            _id=str(uuid.uuid4()),
        )
        try:
            response = await self._client.post(
                self.rpc_url, json=dict(rpc.data), headers=headers)
        except httpx.TimeoutException:
            raise A2ATimeoutError("A2A HTTP request timed out") from None
        except httpx.RequestError:
            # Sever chaining: httpx messages may embed URL details we
            # don't want re-rendered alongside secrets elsewhere.
            raise A2AConnectionError(
                "could not reach the A2A endpoint") from None

        status = response.status_code
        if 300 <= status < 400:
            raise A2ARedirectError(
                f"server answered HTTP {status}; redirects are disabled")
        if status in (401, 403):
            raise A2AAuthError(f"authentication failed (HTTP {status})")
        if status >= 400:
            raise A2AConnectionError(
                f"server returned HTTP {status} "
                f"for {method}")  # body deliberately unread

        try:
            body = response.json()
        except Exception:
            raise A2AProtocolError(
                "server response was not valid JSON") from None
        if not isinstance(body, dict):
            raise A2AProtocolError("JSON-RPC response was not an object")
        # Envelope strictness: version, matching id (must be present), and
        # exactly one of result/error. Anything else is malformed -- fail
        # closed with a sanitized error (never echo the remote body).
        has_id = "id" in body
        has_result = "result" in body
        has_error = "error" in body
        if (body.get("jsonrpc") != "2.0"
                or not has_id or body.get("id") != rpc.data["id"]
                or has_result == has_error):
            raise A2AProtocolError("malformed JSON-RPC response envelope")
        if has_error:
            err = body["error"]
            if not isinstance(err, dict):
                raise A2AProtocolError("JSON-RPC error was not an object")
            code = err.get("code")
            message = err.get("message")
            if type(code) is not int or not isinstance(message, str):
                raise A2AProtocolError("malformed JSON-RPC error object")
            raise A2ATaskError(code)
        return body["result"]

    @staticmethod
    def _parse(data: dict[str, Any], pb_type):
        try:
            return json_format.ParseDict(data, pb_type())
        except Exception:
            raise A2AProtocolError(
                "response did not match expected A2A protobuf schema"
            ) from None
