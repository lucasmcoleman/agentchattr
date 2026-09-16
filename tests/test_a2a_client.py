"""Tests for the minimal A2A 1.0 JSON-RPC client (a2a_client.py).

Protocol fixtures are built with the INSTALLED a2a-sdk protobuf types
(a2a.types.a2a_pb2) and validated by parsing them back through the SDK,
so the wire format (SendMessage / GetTask methods, SendMessageResponse
wrapper, camelCase JSON fields, protobuf enums) is never hand-invented.

Network layer: httpx.MockTransport -- a clearly labeled test seam, no real
sockets. The client accepts a `transport=` kwarg solely so tests can
inject it; production builds its own httpx.AsyncClient.
"""

import asyncio
import json
import math
import traceback

import pytest

# a2a-sdk is an OPTIONAL extra (requirements-a2a.txt). Skip this whole
# module cleanly when it is absent so base-only installs still collect and
# run the rest of the test suite without an ImportError at collection time.
pytest.importorskip(
    "a2a.types.a2a_pb2",
    reason=(
        "A2A client tests require the optional a2a-sdk extra. Install it "
        "with:  uv pip install --python <your-venv-python> "
        "-r requirements-a2a.txt   (or: pip install a2a-sdk==1.1.2)"
    ),
)

import httpx  # noqa: E402
from a2a.types import a2a_pb2 as a2a_types  # noqa: E402
from google.protobuf import json_format  # noqa: E402

import a2a_client as ac  # noqa: E402

SECRET = "s3cr3t-t0ken-DO-NOT-LEAK"
URL = "http://127.0.0.1:9000/rpc"


# ---------------------------------------------------------------- helpers

def ok_response(request_body, result):
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": request_body["id"], "result": result}
    )


def err_response(request_body, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return httpx.Response(
        200, json={"jsonrpc": "2.0", "id": request_body["id"], "error": error}
    )


def make_task(task_id="task-1", context_id="ctx-1", state="TASK_STATE_WORKING",
             status_text=None, artifact_text=None):
    status = a2a_types.TaskStatus(
        state=a2a_types.TaskState.Value(state))
    if status_text is not None:
        status.message.CopyFrom(a2a_types.Message(
            role=a2a_types.Role.ROLE_AGENT,
            message_id="status-msg-1",
            parts=[a2a_types.Part(text=status_text)],
        ))
    task = a2a_types.Task(id=task_id, context_id=context_id, status=status)
    if artifact_text is not None:
        art = task.artifacts.add()
        art.artifact_id = "art-1"
        art.parts.append(a2a_types.Part(text=artifact_text))
    return task


def send_resp_dict(task=None, message_text=None, context_id=None, task_id=None):
    resp = a2a_types.SendMessageResponse()
    if task is not None:
        resp.task.CopyFrom(task)
    if message_text is not None:
        msg = resp.message
        msg.role = a2a_types.Role.ROLE_AGENT
        msg.message_id = "agent-msg-1"
        msg.parts.append(a2a_types.Part(text=message_text))
        if context_id:
            msg.context_id = context_id
        if task_id:
            msg.task_id = task_id
    return json_format.MessageToDict(resp)


class CallLog:
    """Routes httpx.MockTransport calls by JSON-RPC method, records everything."""

    def __init__(self, route):
        self.requests = []   # httpx.Request objects
        self.bodies = []     # parsed JSON-RPC dicts
        self._route = route  # (method, call_index, body) -> httpx.Response
        self._counts = {}
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request):
        body = json.loads(request.content)
        self.requests.append(request)
        self.bodies.append(body)
        method = body["method"]
        idx = self._counts.get(method, 0)
        self._counts[method] = idx + 1
        return self._route(method, idx, body)


def client_with(route, **kwargs):
    log = CallLog(route)
    kwargs.setdefault("poll_interval", 0.01)
    kwargs.setdefault("max_polls", 3)
    client = ac.A2AJsonRpcClient(URL, transport=log.transport, **kwargs)
    return client, log


def run(coro):
    return asyncio.run(coro)


def assert_clean(exc):
    """Neither the error string nor the rendered traceback may contain SECRET."""
    assert SECRET not in str(exc)
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert SECRET not in rendered


# ------------------------------------------------------- url validation

BAD_URLS = [
    ("ftp://127.0.0.1/rpc", "wrong scheme"),
    ("//127.0.0.1/rpc", "no scheme"),
    ("http://user:pass@127.0.0.1/rpc", "userinfo"),
    ("http://127.0.0.1/rpc?target=http://evil", "query"),
    ("http://127.0.0.1/rpc#frag", "fragment"),
    ("http://localhost.evil.com/rpc", "lookalike dns name"),
    ("https://agent.internal.example/rpc", "dns name"),
    ("http://8.8.8.8/rpc", "public ipv4"),
    ("https://[2606:4700::1111]/rpc", "public ipv6"),
    ("http://169.254.169.254/latest/meta-data", "link-local cloud metadata"),
    ("http://[fe80::1]/rpc", "ipv6 link-local"),
    ("http://0.0.0.0/rpc", "unspecified v4"),
    ("http://[::]/rpc", "unspecified v6"),
    ("http://224.0.0.1/rpc", "multicast"),
    ("http://[ff02::1]/rpc", "ipv6 multicast"),
]


@pytest.mark.parametrize("bad_url, why", BAD_URLS)
def test_url_rejected(bad_url, why):
    with pytest.raises(ac.A2AClientConfigError):
        ac.validate_rpc_url(bad_url)
    with pytest.raises(ac.A2AClientConfigError):
        ac.validate_rpc_url(bad_url, allow_lan=True)


@pytest.mark.parametrize("good_url", [
    "http://127.0.0.1:9000/rpc",
    "http://localhost:9000/rpc",
    "HTTP://Localhost/rpc",
    "http://[::1]:8080/a2a",
])
def test_url_loopback_allowed(good_url):
    ac.validate_rpc_url(good_url)


LAN_URLS = [
    "http://192.168.0.29:8080/rpc",
    "http://10.1.2.3/rpc",
    "https://172.16.0.5/rpc",
    "http://[fd00::1]:9000/rpc",
    "http://[fc00::abc]/rpc",
]


@pytest.mark.parametrize("lan_url", LAN_URLS)
def test_lan_denied_by_default(lan_url):
    with pytest.raises(ac.A2AClientConfigError):
        ac.validate_rpc_url(lan_url)


@pytest.mark.parametrize("lan_url", LAN_URLS)
def test_lan_opt_in_allows(lan_url):
    ac.validate_rpc_url(lan_url, allow_lan=True)


def test_public_and_link_local_denied_even_with_lan_opt_in():
    for u in ("http://8.8.8.8/rpc", "http://169.254.169.254/rpc",
              "http://[fe80::2]/rpc", "http://[2001:4860:4860::8888]/rpc"):
        with pytest.raises(ac.A2AClientConfigError):
            ac.validate_rpc_url(u, allow_lan=True)


def test_client_constructor_validates_url():
    with pytest.raises(ac.A2AClientConfigError):
        ac.A2AJsonRpcClient("https://evil.example/rpc")


# ------------------------------------------------- correct 1.0 wire format

def test_send_message_wire_format_and_context_id():
    result = send_resp_dict(message_text="pong", context_id="ctx-42")

    def route(method, idx, body):
        assert method == "SendMessage"
        return ok_response(body, result)

    client, log = client_with(route)
    res = run(client.send_text("ping", context_id="ctx-42"))

    assert log.bodies[0]["method"] == "SendMessage"
    assert log.bodies[0]["jsonrpc"] == "2.0"
    params = log.bodies[0]["params"]
    # Outgoing payload must parse as the SDK's own SendMessageRequest type.
    parsed = json_format.ParseDict(params, a2a_types.SendMessageRequest())
    assert parsed.message.role == a2a_types.Role.ROLE_USER
    assert parsed.message.parts[0].text == "ping"
    assert parsed.message.context_id == "ctx-42"
    assert parsed.message.message_id  # client generated one
    # protobuf JSON camelCase, not snake_case
    assert "contextId" in params["message"]
    assert "context_id" not in params["message"]

    assert res.state == "completed"
    assert res.text == "pong"
    assert res.context_id == "ctx-42"
    # The fixture itself round-trips through the SDK type.
    rt = json_format.ParseDict(result, a2a_types.SendMessageResponse())
    assert rt.WhichOneof("payload") == "message"


def test_immediate_message_response():
    result = send_resp_dict(message_text="pong")

    def route(method, idx, body):
        return ok_response(body, result)

    client, log = client_with(route)
    res = run(client.send_text("ping"))
    assert res.state == "completed"
    assert res.text == "pong"
    assert res.task_id is None
    assert len(log.bodies) == 1  # immediate reply -> no polling


def test_working_then_completed_task():
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))
    completed_task = make_task(state="TASK_STATE_COMPLETED",
                              artifact_text="all done")
    completed = json_format.MessageToDict(completed_task)

    def route(method, idx, body):
        if method == "SendMessage":
            return ok_response(body, working)
        assert method == "GetTask"
        return ok_response(body, completed)

    client, log = client_with(route)
    res = run(client.send_text("do it"))
    assert [b["method"] for b in log.bodies] == ["SendMessage", "GetTask"]
    get_params = json_format.ParseDict(log.bodies[1]["params"],
                                      a2a_types.GetTaskRequest())
    assert get_params.id == "task-1"
    assert res.state == "completed"
    assert res.text == "all done"
    assert res.task_id == "task-1"
    assert res.context_id == "ctx-1"


def test_task_completed_via_status_message_when_no_artifact():
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))
    completed = json_format.MessageToDict(
        make_task(state="TASK_STATE_COMPLETED", status_text="done, no artifact"))

    def route(method, idx, body):
        return ok_response(body, working if method == "SendMessage" else completed)

    client, log = client_with(route)
    res = run(client.send_text("go"))
    assert res.state == "completed"
    assert res.text == "done, no artifact"


# -------------------------------------------------- terminal task states

@pytest.mark.parametrize("state,expected", [
    ("TASK_STATE_FAILED", "failed"),
    ("TASK_STATE_CANCELED", "canceled"),
    ("TASK_STATE_REJECTED", "rejected"),
    ("TASK_STATE_INPUT_REQUIRED", "input-required"),
    ("TASK_STATE_AUTH_REQUIRED", "auth-required"),
])
def test_nonterminal_states_returned_not_raised(state, expected):
    """A task that lands in a non-success terminal/paused state is a result
    the caller inspects (input-required is a normal A2A pause), not a crash."""
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))
    final = json_format.MessageToDict(
        make_task(state=state, status_text="agent says hi"))

    def route(method, idx, body):
        return ok_response(body, working if method == "SendMessage" else final)

    client, log = client_with(route)
    res = run(client.send_text("go"))
    assert res.state == expected
    assert res.text == "agent says hi"
    assert res.task_id == "task-1"


def test_task_that_never_finishes_hits_poll_bound():
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))
    still = json_format.MessageToDict(make_task(state="TASK_STATE_WORKING"))

    def route(method, idx, body):
        return ok_response(body, working if method == "SendMessage" else still)

    client, log = client_with(route, max_polls=2)
    with pytest.raises(ac.A2APollExhaustedError) as ei:
        run(client.send_text("go"))
    assert ei.value.state == "working"
    assert ei.value.task_id == "task-1"
    # 1 SendMessage + exactly 2 GetTask polls
    assert [b["method"] for b in log.bodies] == \
        ["SendMessage", "GetTask", "GetTask"]


# --------------------------------------------------------- error mapping

def test_jsonrpc_error_mapped_to_failed():
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))

    def route(method, idx, body):
        if method == "SendMessage":
            return ok_response(body, working)
        return err_response(body, -32603, "boom internal")

    client, log = client_with(route)
    with pytest.raises(ac.A2ATaskError) as ei:
        run(client.send_text("go"))
    assert ei.value.state == "failed"
    # Security spec: remote error body/message is NEVER echoed back.
    assert "boom internal" not in str(ei.value)
    assert "-32603" in str(ei.value)  # only the numeric code surfaces


def test_auth_error_http_401_maps_to_auth_required():
    def route(method, idx, body):
        return httpx.Response(401, text="nope")

    client, log = client_with(route)
    with pytest.raises(ac.A2AAuthError):
        run(client.send_text("go"))


def test_http_403_maps_to_auth_required():
    def route(method, idx, body):
        return httpx.Response(403, text="forbidden")

    client, log = client_with(route)
    with pytest.raises(ac.A2AAuthError):
        run(client.send_text("go"))


# ---------------------------------------------------------- credentials

def test_missing_env_var_fails_closed(monkeypatch):
    monkeypatch.delenv("A2A_TEST_TOKEN", raising=False)
    client, log = client_with(
        lambda m, i, b: ok_response(b, send_resp_dict(message_text="x")),
        api_key_env="A2A_TEST_TOKEN")
    with pytest.raises(ac.A2AClientConfigError) as ei:
        run(client.send_text("go"))
    assert "A2A_TEST_TOKEN" in str(ei.value)   # names the var (not secret)
    assert len(log.bodies) == 0               # never touched the network


def test_credentials_sent_as_bearer(monkeypatch):
    monkeypatch.setenv("A2A_TEST_TOKEN", SECRET)

    def route(method, idx, body):
        return ok_response(body, send_resp_dict(message_text="ok"))

    client, log = client_with(route, api_key_env="A2A_TEST_TOKEN")
    res = run(client.send_text("go"))
    assert res.text == "ok"
    assert log.requests[0].headers["authorization"] == f"Bearer {SECRET}"


def test_secret_never_leaks_into_error_messages(monkeypatch):
    """Remote error body echoing the secret must not surface in our errors."""
    monkeypatch.setenv("A2A_TEST_TOKEN", SECRET)

    def route(method, idx, body):
        return err_response(body, -32603, f"internal error {SECRET}")

    client, log = client_with(route, api_key_env="A2A_TEST_TOKEN")
    with pytest.raises(ac.A2ATaskError) as ei:
        run(client.send_text("go"))
    assert_clean(ei.value)


def test_secret_not_in_connection_error(monkeypatch):
    monkeypatch.setenv("A2A_TEST_TOKEN", SECRET)

    def route(method, idx, body):
        raise httpx.ConnectError(f"connection refused {SECRET}")

    client, log = client_with(route, api_key_env="A2A_TEST_TOKEN")
    with pytest.raises(ac.A2AConnectionError) as ei:
        run(client.send_text("go"))
    assert_clean(ei.value)


# ------------------------------------------------------------ redirects

@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_fail(status):
    def route(method, idx, body):
        return httpx.Response(status, headers={"location": "http://127.0.0.1:9999/evil"})

    client, log = client_with(route)
    with pytest.raises(ac.A2ARedirectError):
        run(client.send_text("go"))
    assert len(log.bodies) == 1  # we never followed


# ------------------------------------------------------------- timeouts

def test_network_timeout_raises_timeout():
    def route(method, idx, body):
        raise httpx.ReadTimeout("timed out")

    client, log = client_with(route)
    with pytest.raises(ac.A2ATimeoutError):
        run(client.send_text("go"))


def test_total_task_timeout_bounds_whole_operation():
    """Endless fast polling must be cut off by the total deadline."""
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))
    still = json_format.MessageToDict(make_task(state="TASK_STATE_WORKING"))

    def route(method, idx, body):
        return ok_response(body, working if method == "SendMessage" else still)

    client, log = client_with(route, poll_interval=0.01, max_polls=10_000,
                             total_timeout=0.15)
    with pytest.raises(ac.A2ATimeoutError):
        run(client.send_text("go"))
    assert len(log.bodies) < 100  # bounded, not 10k


# ------------------------------------------------- malformed responses

def test_malformed_result_is_client_error():
    def route(method, idx, body):
        # result that is not a valid SendMessageResponse
        return ok_response(body, {"nonsense": True})

    client, log = client_with(route)
    with pytest.raises(ac.A2AProtocolError):
        run(client.send_text("go"))


def test_non_json_body_is_client_error():
    def route(method, idx, body):
        return httpx.Response(200, text="<html>not json</html>")

    client, log = client_with(route)
    with pytest.raises(ac.A2AProtocolError):
        run(client.send_text("go"))


# ------------------------------------------------- proxy isolation

def test_no_environment_proxy_inheritance(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.evil:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil:3128")
    monkeypatch.setenv("http_proxy", "http://proxy.evil:3128")
    # Build WITHOUT injected transport -> exercises the real client build.
    client = ac.A2AJsonRpcClient(URL)
    try:
        mount = client._client._transport  # httpx.AsyncHTTPTransport
        # trust_env=False means httpx never reads HTTP(S)_PROXY / netrc.
        assert client._client.trust_env is False
        # Defense in depth: the proxy host must appear nowhere reachable
        # in the transport's configuration.
        import pickle
        try:
            blob = pickle.dumps(getattr(mount, "__dict__", {}))
        except Exception:
            blob = str(getattr(mount, "__dict__", {})).encode()
        assert b"proxy.evil" not in blob
        # And the client-level proxies mapping (if any) is empty.
        assert not getattr(client._client, "_mounts", {}) or all(
            "proxy.evil" not in str(v) for v in client._client._mounts.values()
        )
    finally:
        run(client.aclose())


# ------------------------------------------------- regression fixes

def test_version_header_on_send_and_gettask(monkeypatch):
    monkeypatch.setenv("A2A_TEST_KEY", SECRET)
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))
    done = json_format.MessageToDict(
        make_task(state="TASK_STATE_COMPLETED", artifact_text="fin"))

    def route(method, idx, body):
        return ok_response(body, working if method == "SendMessage" else done)

    client, log = client_with(route, api_key_env="A2A_TEST_KEY")
    try:
        result = run(client.send_text("go"))
        assert result.state == "completed"
        assert len(log.requests) == 2  # SendMessage + GetTask
        for req in log.requests:
            assert req.headers["A2A-Version"] == "1.0"
            assert req.headers["Authorization"] == f"Bearer {SECRET}"
    finally:
        run(client.aclose())


def test_all_artifact_text_collected():
    task = make_task(state="TASK_STATE_COMPLETED")
    for i, txt in (("art-a", "first chunk"), ("art-b", "second chunk")):
        art = task.artifacts.add()
        art.artifact_id = i
        art.parts.append(a2a_types.Part(text=txt))
    resp = send_resp_dict(task=task)

    def route(method, idx, body):
        return ok_response(body, resp)

    client, log = client_with(route)
    try:
        result = run(client.send_text("go"))
        assert result.text == "first chunk\nsecond chunk"
    finally:
        run(client.aclose())

# ------------------------------------------------ JSON-RPC envelope strictness

def raw_rpc(body):
    """Route every call to a handcrafted raw JSON body (200 OK).

    `body` may be a dict or a callable(request_body) -> dict so fixtures
    can echo the actual request id."""
    def route(method, idx, request_body):
        payload = body(request_body) if callable(body) else body
        return httpx.Response(200, json=payload)
    return client_with(route)


BAD_ENVELOPES = [
    pytest.param(lambda b: {"result": {}},
                "missing jsonrpc and id", id="no-jsonrpc-no-id"),
    pytest.param(lambda b: {"jsonrpc": "1.0", "id": b["id"], "result": {}},
                "wrong jsonrpc version", id="wrong-jsonrpc-version"),
    pytest.param(lambda b: {"jsonrpc": 2.0, "id": b["id"], "result": {}},
                "jsonrpc not a string", id="jsonrpc-not-string"),
    pytest.param(lambda b: {"jsonrpc": "2.0", "result": {}},
                "id key absent entirely", id="id-absent"),
    pytest.param(lambda b: {"jsonrpc": "2.0", "id": "someone-elses-id",
                           "result": {}},
                "id does not match request id", id="id-mismatch"),
    pytest.param(lambda b: {"jsonrpc": "2.0", "id": b["id"],
                           "result": send_resp_dict(message_text="x"),
                           "error": {"code": -32603, "message": "both"}},
                "result AND error present together", id="result-and-error"),
    pytest.param(lambda b: {"jsonrpc": "2.0", "id": b["id"]},
                "neither result nor error", id="neither-result-nor-error"),
]


@pytest.mark.parametrize("envelope, why", BAD_ENVELOPES)
def test_envelope_violations_are_protocol_errors(envelope, why):
    client, log = raw_rpc(envelope)
    try:
        with pytest.raises(ac.A2AProtocolError):
            run(client.send_text("go"))
    finally:
        run(client.aclose())


BAD_ERRORS = [
    pytest.param("not-a-dict", "error not an object", id="error-not-dict"),
    pytest.param({"message": "no code field"}, "code missing", id="code-missing"),
    pytest.param({"code": "-32603", "message": "string code"},
                "string code", id="code-string"),
    pytest.param({"code": True, "message": "bool code"},
                "bool code rejected", id="code-bool"),
    pytest.param({"code": 1.5, "message": "float code"},
                "non-integer code", id="code-float"),
    pytest.param({"code": -32603}, "message missing", id="message-missing"),
    pytest.param({"code": -32603, "message": 42},
                "message not a string", id="message-not-string"),
    pytest.param({"code": "x", "message": SECRET},
                "malformed error must not echo remote text", id="secret-suppressed"),
]


@pytest.mark.parametrize("err, why", BAD_ERRORS)
def test_malformed_error_object_is_protocol_error(err, why):
    client, log = raw_rpc(lambda b: {"jsonrpc": "2.0", "id": b["id"],
                                    "error": err})
    try:
        with pytest.raises(ac.A2AProtocolError) as ei:
            run(client.send_text("go"))
        assert_clean(ei.value)
    finally:
        run(client.aclose())


def test_valid_error_still_maps_to_task_error():
    """A spec-compliant error envelope keeps the existing A2ATaskError mapping
    with the numeric code surfaced and the remote message suppressed."""
    def route(method, idx, body):
        return err_response(body, -32000, f"remote said {SECRET}")

    client, log = client_with(route)
    try:
        with pytest.raises(ac.A2ATaskError) as ei:
            run(client.send_text("go"))
        assert ei.value.code == -32000
        assert ei.value.state == "failed"
        assert_clean(ei.value)
    finally:
        run(client.aclose())


# ------------------------------------------ task identity/state validation

MALFORMED_TASKS = [
    pytest.param({"status": {"state": "TASK_STATE_WORKING"}},
                 "reply with no task id", id="absent-id"),
    pytest.param({"id": "task-1"},
                 "reply with no status", id="absent-status"),
    pytest.param({"id": "task-1", "status": {"state": "TASK_STATE_UNSPECIFIED"}},
                 "unspecified (zero) state", id="zero-state"),
    pytest.param({"id": "task-1", "status": {"state": 999}},
                 "unknown enum value", id="unknown-state"),
]


@pytest.mark.parametrize("bad, why", MALFORMED_TASKS)
def test_invalid_initial_task_rejected_before_polling(bad, why):
    def route(method, idx, body):
        return ok_response(body, bad)

    client, log = client_with(route)
    try:
        with pytest.raises(ac.A2AProtocolError):
            run(client.send_text("go"))
        assert len(log.bodies) == 1  # rejected up front; never polled
    finally:
        run(client.aclose())


@pytest.mark.parametrize("bad, why", MALFORMED_TASKS + [
    pytest.param({"id": "task-impostor", "contextId": "ctx-x",
                 "status": {"state": "TASK_STATE_COMPLETED"},
                 "artifacts": [{"artifactId": "a",
                                "parts": [{"text": "stolen"}]}]},
                 "GetTask returns a different task id", id="switched-id"),
])
def test_invalid_polled_task_rejected(bad, why):
    working = send_resp_dict(task=make_task(state="TASK_STATE_WORKING"))

    def route(method, idx, body):
        return ok_response(body, working if method == "SendMessage" else bad)

    client, log = client_with(route)
    try:
        with pytest.raises(ac.A2AProtocolError):
            run(client.send_text("go"))
    finally:
        run(client.aclose())


# caller always passes ctx-caller; server-side context handling is what varies
@pytest.mark.parametrize("init_ctx,poll_ctx,expected", [
    pytest.param("ctx-init", None, "ctx-init",
                 id="initial-server-context-wins-over-caller"),
    pytest.param(None, "ctx-poll", "ctx-poll",
                 id="last-known-poll-context-preserved"),
    pytest.param(None, None, "ctx-caller",
                 id="caller-context-when-server_never_provides_one"),
])
def test_context_preserved_through_contextless_completion_poll(
        init_ctx, poll_ctx, expected):
    init = make_task(state="TASK_STATE_WORKING", context_id=init_ctx or "")
    working = send_resp_dict(task=init)
    final = json_format.MessageToDict(
        make_task(state="TASK_STATE_COMPLETED", artifact_text="done",
                  context_id=""))  # completion poll omits contextId
    mid = None
    if poll_ctx:
        mid = json_format.MessageToDict(
            make_task(state="TASK_STATE_WORKING", context_id=poll_ctx))

    def route(method, idx, body):
        if method == "SendMessage":
            return ok_response(body, working)
        if mid is not None and idx == 0:
            return ok_response(body, mid)
        return ok_response(body, final)

    client, log = client_with(route)
    try:
        res = run(client.send_text("go", context_id="ctx-caller"))
        assert res.state == "completed"
        assert res.context_id == expected
        # every poll queried the FIXED original task id
        for b in log.bodies[1:]:
            assert b["method"] == "GetTask"
            assert b["params"]["id"] == "task-1"
    finally:
        run(client.aclose())


def test_envelope_binding_uses_actual_request_id():
    """Echoing a *previous* request's id (replay/desync) is rejected even
    though the shape is otherwise valid."""
    seen = []

    def route(method, idx, body):
        if idx == 0:
            seen.append(body["id"])
            return ok_response(body,
                              send_resp_dict(task=make_task(
                                  state="TASK_STATE_WORKING")))
        # GetTask reply carrying the SendMessage request's id instead.
        return {"jsonrpc": "2.0", "id": seen[0],
                "result": json_format.MessageToDict(
                    make_task(state="TASK_STATE_COMPLETED",
                             artifact_text="x"))}

    client, log = client_with(route)
    try:
        with pytest.raises(ac.A2AProtocolError):
            run(client.send_text("go"))
    finally:
        run(client.aclose())


# --------------------------------------------- constructor knob validation

BAD_TIMEOUT_KNOBS = [
    ("request_timeout", None),
    ("request_timeout", "30"),
    ("request_timeout", True),
    ("request_timeout", False),
    ("request_timeout", float("nan")),
    ("request_timeout", float("inf")),
    ("request_timeout", float("-inf")),
    ("request_timeout", 0),
    ("request_timeout", -1.0),
    ("total_timeout", None),
    ("total_timeout", "60"),
    ("total_timeout", True),
    ("total_timeout", float("nan")),
    ("total_timeout", float("inf")),
    ("total_timeout", 0),
    ("total_timeout", -0.5),
    ("poll_interval", None),
    ("poll_interval", "2"),
    ("poll_interval", True),
    ("poll_interval", float("nan")),
    ("poll_interval", float("inf")),
    ("poll_interval", -0.1),
    ("max_polls", None),
    ("max_polls", "3"),
    ("max_polls", 3.0),
    ("max_polls", True),
    ("max_polls", False),
    ("max_polls", -1),
    ("max_polls", float("nan")),
]


@pytest.mark.parametrize("knob,value", BAD_TIMEOUT_KNOBS)
def test_constructor_rejects_bad_timeout_knobs(knob, value):
    with pytest.raises(ac.A2AClientConfigError):
        ac.A2AJsonRpcClient(URL, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={})),
            **{knob: value})


def test_constructor_accepts_boundary_valid_knobs():
    """Zero-wait polling and zero polls stay legal; defaults untouched."""
    client = ac.A2AJsonRpcClient(URL,
                                transport=httpx.MockTransport(
                                    lambda request: httpx.Response(200, json={})),
                                request_timeout=0.5,
                                poll_interval=0.0,
                                max_polls=0,
                                total_timeout=1.5)
    try:
        assert client.poll_interval == 0.0
        assert client.max_polls == 0
        assert client.total_timeout == 1.5
    finally:
        run(client.aclose())

    # Defaults are exactly what they always were.
    d = ac.A2AJsonRpcClient(URL)
    try:
        assert d._client.timeout == httpx.Timeout(30.0)
        assert d.poll_interval == 2.0
        assert d.max_polls == 15
        assert d.total_timeout == 60.0
    finally:
        run(d.aclose())
