"""A2A wiring in wrapper_api: agent selection + trigger dispatch to adapter.

Runs main() with mocked registration/urlopen, heartbeat disabled, a temp
queue file, and KeyboardInterrupt after one queue cycle.
"""
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("a2a.types.a2a_pb2")

import a2a_room
import config_loader
import wrapper
import wrapper_api


def test_selectable_agents_includes_api_and_a2a():
    cfg = {"agents": {
        "cli1": {"type": "cli"},
        "local": {"type": "api", "base_url": "http://localhost:8189/v1"},
        "peer": {"type": "a2a", "rpc_url": "http://127.0.0.1:9000/rpc"},
        "plain": {},
    }}
    assert wrapper_api.selectable_agents(cfg) == ["local", "peer"]
    assert wrapper_api.selectable_agents({}) == []


def test_trigger_routes_to_adapter_send_with_channel(monkeypatch, tmp_path, capsys):
    cfg = {
        "server": {"port": 8399, "data_dir": str(tmp_path)},
        "agents": {
            "bot": {"type": "a2a", "rpc_url": "http://127.0.0.1:9000/rpc",
                    "label": "Bot"},
        },
    }

    class FakeResp:
        def __init__(self, data):
            self._data = json.dumps(data).encode()
        def read(self):
            return self._data
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    sent = []

    def fake_urlopen(req, timeout=None):
        url = getattr(req, "full_url", str(req))
        if "/api/messages" in url:
            return FakeResp([{"sender": "alice", "text": "hello bot"}])
        if "/api/send" in url:
            sent.append(json.loads(req.data))
        return FakeResp({"ok": True})

    class NoThread:
        def __init__(self, *a, **k):
            pass
        def start(self):
            pass

    sent_to_adapter = []

    def spy_send(self, messages, channel):
        sent_to_adapter.append((channel, messages))
        return "pong from a2a"

    class FakeA2AClient:
        def __init__(self, rpc_url, **kwargs):
            self.rpc_url, self.kwargs = rpc_url, kwargs
        async def aclose(self):
            pass

    monkeypatch.setattr(config_loader, "load_config", lambda root=None: cfg)
    monkeypatch.setattr(wrapper, "_register_instance",
                       lambda port, base, label=None: {"name": "bot",
                                                     "token": "tk",
                                                     "slot": 1})
    monkeypatch.setattr(wrapper_api.threading, "Thread", NoThread)
    monkeypatch.setattr(wrapper_api.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(a2a_room, "_client_cls", lambda: FakeA2AClient)
    monkeypatch.setattr(a2a_room.A2ARoomAdapter, "send", spy_send)

    queue_file = tmp_path / "bot_queue.jsonl"
    sleeps = {"n": 0}
    real_sleep = wrapper_api.time.sleep
    main_thread = threading.main_thread()

    def fake_sleep(sec):
        # time.sleep is a shared module — only drive the wrapper loop
        # (main thread); other live threads keep real sleep semantics.
        if threading.current_thread() is not main_thread:
            return real_sleep(sec)
        sleeps["n"] += 1
        if sleeps["n"] == 1:
            # Queue one trigger on a non-default channel, then stop the loop.
            queue_file.write_text(json.dumps({"channel": "work"}) + "\n",
                                 encoding="utf-8")
        else:
            raise KeyboardInterrupt

    monkeypatch.setattr(wrapper_api.time, "sleep", fake_sleep)
    monkeypatch.setattr(sys, "argv", ["wrapper_api.py", "bot"])

    wrapper_api.main()

    # The adapter was reached exactly once, on the triggering channel.
    assert [c for c, _ in sent_to_adapter] == ["work"]
    messages = sent_to_adapter[0][1]
    assert any("hello bot" in m.get("content", "") for m in messages)
    # The adapter's reply went back out on the same channel.
    assert sent == [{"text": "pong from a2a", "channel": "work"}]
    out = capsys.readouterr().out
    assert "A2A 1.0 endpoint: http://127.0.0.1:9000/rpc" in out
    assert "/chat/completions" not in out
