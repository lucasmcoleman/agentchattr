"""Tests for a2a_room.A2ARoomAdapter (fake client factory, no network)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import a2a_room

pytest.importorskip("a2a.types.a2a_pb2")
from a2a_client import A2AClientConfigError, A2AClientError


class FakeResult:
    def __init__(self, state, text=None, task_id=None, context_id=None):
        self.state, self.text = state, text
        self.task_id, self.context_id = task_id, context_id


class FakeClient:
    """Queue of FakeResult/error items consumed one per send_text call."""
    instances = []

    def __init__(self, rpc_url, **kwargs):
        self.rpc_url, self.kwargs = rpc_url, kwargs
        self.closed = False
        self.calls = []
        FakeClient.instances.append(self)

    async def send_text(self, text, *, context_id=None, task_id=None):
        self.calls.append({"text": text, "context_id": context_id,
                         "task_id": task_id})
        item = FakeClient.queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def aclose(self):
        self.closed = True


class BoomError(A2AClientError):
    pass


CFG = {"rpc_url": "http://127.0.0.1:9000/rpc"}


@pytest.fixture(autouse=True)
def fake_factory(monkeypatch):
    FakeClient.instances = []
    FakeClient.queue = []
    monkeypatch.setattr(a2a_room, "_client_cls", lambda: FakeClient)
    return FakeClient


def test_context_isolated_per_channel():
    FakeClient.queue = [
        FakeResult("completed", "a", task_id="t1", context_id="ctx-a"),
        FakeResult("completed", "b", task_id="t2", context_id="ctx-b"),
    ]
    room = a2a_room.A2ARoomAdapter(CFG)
    assert room.send([{"role": "user", "content": "hi"}], "chan-a") == "a"
    assert room.send([{"role": "user", "content": "yo"}], "chan-b") == "b"
    # chan-b's send must not carry chan-a's context/task.
    assert FakeClient.instances[1].calls[0]["context_id"] is None
    assert FakeClient.instances[1].calls[0]["task_id"] is None
    assert FakeClient.instances[0].calls[0]["text"] == "user: hi"
    assert FakeClient.instances[1].closed and FakeClient.instances[0].closed


def test_input_required_task_reused_then_cleared():
    FakeClient.queue = [
        FakeResult("input-required", "need key", task_id="t9",
                  context_id="ctx9"),
        FakeResult("completed", "done", task_id="t9", context_id="ctx9"),
        FakeResult("completed", "next", task_id="t10", context_id="ctx9"),
    ]
    room = a2a_room.A2ARoomAdapter(CFG)
    assert room.send([{"role": "user", "content": "x"}], "c") == \
        "[A2A input-required] need key"
    assert room.send([{"role": "user", "content": "key"}], "c") == "done"
    call2 = FakeClient.instances[1].calls[0]
    assert call2["task_id"] == "t9" and call2["context_id"] == "ctx9"
    room.send([{"role": "user", "content": "z"}], "c")
    assert FakeClient.instances[2].calls[0]["task_id"] is None


def test_close_and_error_sanitized(fake_factory):
    boom = BoomError("token=SECRET https://evil.example leaked")
    fake_factory.queue = [boom]
    room = a2a_room.A2ARoomAdapter(CFG)
    out = room.send([{"role": "user", "content": "hi"}], "c")
    assert out == "[A2A error: BoomError]"
    assert "SECRET" not in out and "evil" not in out
    assert fake_factory.instances[0].closed is True
    # completed with empty text -> explicit marker
    fake_factory.queue = [FakeResult("completed", "", context_id="ctx")]
    assert room.send([{"role": "user", "content": "hi"}], "c") == \
        "[A2A completed: no text output]"
    assert fake_factory.instances[1].closed is True


def test_missing_required_config():
    with pytest.raises(A2AClientConfigError):
        a2a_room.A2ARoomAdapter({})
    with pytest.raises(A2AClientConfigError):
        a2a_room.A2ARoomAdapter({"rpc_url": "", "api_key_env": "A2A_KEY"})


def test_bad_allow_lan_rejected():
    # bool("false") would silently enable LAN — non-bool must be rejected.
    with pytest.raises(A2AClientConfigError):
        a2a_room.A2ARoomAdapter(dict(CFG, allow_lan="false"))
    with pytest.raises(A2AClientConfigError):
        a2a_room.A2ARoomAdapter(dict(CFG, allow_lan=1))
    # Proper bool still works.
    assert a2a_room.A2ARoomAdapter(dict(CFG, allow_lan=False)).client_kwargs["allow_lan"] is False


def test_validate_checks_credential_env(tmp_path, monkeypatch):
    cfg = dict(CFG, api_key_env="A2A_TEST_KEY")
    monkeypatch.delenv("A2A_TEST_KEY", raising=False)
    with pytest.raises(A2AClientConfigError):
        a2a_room.A2ARoomAdapter(cfg).validate()
    monkeypatch.setenv("A2A_TEST_KEY", "s3cret")
    a2a_room.A2ARoomAdapter(cfg).validate()  # no raise
    assert FakeClient.instances[-1].closed is True
    assert FakeClient.instances[-1].kwargs.get("api_key_env") == "A2A_TEST_KEY"
