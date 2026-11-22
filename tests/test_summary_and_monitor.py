from types import SimpleNamespace

import pytest

from percy.agents.summary import SummaryError, build_user_message, summarize
from percy.config import Settings
from percy.monitor.daemon import Monitor
from percy.security.checks import Finding


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def fake_client(stop_reason="end_turn", text="All good."):
    response = SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)])
    messages = FakeMessages(response)
    return SimpleNamespace(beta=SimpleNamespace(messages=messages)), messages


FINDINGS = [Finding("router-telnet", "high", "Telnet is open", "seen on AA:BB:CC:DD:EE:FF", "Turn it off")]


def test_summary_request_shape():
    client, messages = fake_client()
    assert summarize(FINDINGS, {"router": "x"}, None, client=client) == "All good."
    kw = messages.kwargs
    assert kw["model"] == "claude-opus-5-5"
    assert kw["fallbacks"] == "default" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert kw["output_config"] == {"effort": "medium"}
    assert "thinking" not in kw and "temperature" not in kw
    assert "AA:BB:CC:DD:EE:FF" not in kw["messages"][0]["content"]  # MACs shortened


def test_summary_refusal_and_missing_key():
    client, _ = fake_client(stop_reason="refusal", text="")
    with pytest.raises(SummaryError, match="declined"):
        summarize(FINDINGS, {}, None, client=client)
    with pytest.raises(SummaryError, match="API key"):
        summarize(FINDINGS, {}, None)


def test_activity_only_sent_when_given():
    assert "network_activity" not in build_user_message(FINDINGS, {})


def test_monitor_alerts_once_and_again_after_fix(store, monkeypatch):
    sent = []
    monitor = Monitor(Settings(), store, notifier=lambda t, b, u: sent.append((t, u)))
    high = Finding("router-telnet", "high", "Telnet is open", "d", "f")
    low = Finding("router-ssh", "low", "SSH open", "d", "f")
    monitor._alert_new((high, low))
    monitor._alert_new((high, low))
    assert sent == [("Percy: Telnet is open", True)]  # low severity never notifies, no repeats
    monitor._alert_new(())
    monitor._alert_new((high,))
    assert len(sent) == 2
    assert any(kind == "alert" for _ts, kind, _m in store.events())


def test_monitor_keeps_alert_memory_when_check_was_partial(store):
    sent = []
    monitor = Monitor(Settings(), store, notifier=lambda t, b, u: sent.append(t))
    telnet = Finding("router-telnet", "high", "Telnet is open", "d", "f")
    monitor._alert_new((telnet,))
    monitor._alert_new((), degraded=True)   # router unreachable this time
    monitor._alert_new((telnet,))           # back again: not a new problem
    assert sent == ["Percy: Telnet is open"]


def test_monitor_step_survives_activity_errors(store, monkeypatch):
    monitor = Monitor(Settings(), store, alerts=False)
    calls = []
    monkeypatch.setattr(monitor, "tick_activity", lambda: (_ for _ in ()).throw(AttributeError("bad page")))
    monkeypatch.setattr(monitor, "tick_check", lambda: calls.append("check") or [])
    monitor.step()
    assert calls == ["check"]


def test_monitor_respects_notify_setting(store):
    sent = []
    monitor = Monitor(Settings(notify=False), store, notifier=lambda *a: sent.append(a))
    monitor._alert_new((Finding("router-dmz", "high", "DMZ", "d", "f"),))
    assert sent == [] and store.events()
