"""Wall deadlines include HTTP waits, validation feedback and role retries."""
import threading
import time
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from app.services.agent_infra import AgentSpec, AgentTool, AnthropicProtocolChatClient, DeepSeekChatClient
from app.services.unified.agent_base import UnifiedToolLoopAgent, UsageMeter
from app.services.unified.graph import RunContext, _agent_deadline, _run_specialist


class Report(BaseModel):
    value: str


def test_blocked_http_returns_on_deadline_and_late_tools_never_run():
    release = threading.Event()
    finished = threading.Event()
    invoked = []

    class Client:
        def complete(self, messages, tools=None):
            release.wait(3)
            finished.set()
            return {"tool_calls": [{"id": "late", "name": "read", "arguments": {}}]}

    tool = AgentTool("read", "read only", {}, lambda db: invoked.append(True))
    agent = UnifiedToolLoopAgent(AgentSpec("test", "test", Report, tools=[tool]), Client())
    started = time.monotonic()
    try:
        result = agent.run(None, "context", deadline_s=0.08)
        assert result.status == "timeout"
        assert time.monotonic() - started < 0.6
    finally:
        release.set()
        assert finished.wait(1)
    assert not invoked


def test_validation_feedback_shares_remaining_deadline_and_counts_once():
    budgets = []

    class Client:
        def complete_with_timeout(self, messages, tools=None, *, timeout_s):
            budgets.append(timeout_s)
            time.sleep(0.03)
            return {"content": '{"value":"ok"}' if len(budgets) > 1 else '{}',
                    "usage": {"total_tokens": 1}}

    meter = UsageMeter()
    result = UnifiedToolLoopAgent(AgentSpec("test", "test", Report), Client(), meter).run(
        None, "context", deadline_s=1)
    assert result.status == "succeeded"
    assert 0 < budgets[1] < budgets[0] <= 1
    assert result.llm_calls == meter.calls == 2


def test_feedback_request_cannot_outlive_deadline():
    class Client:
        calls = 0

        def complete(self, messages, tools=None):
            self.calls += 1
            if self.calls > 1:
                time.sleep(0.2)
            return {"content": '{}'}

    result = UnifiedToolLoopAgent(AgentSpec("test", "test", Report), Client()).run(
        None, "context", deadline_s=0.05)
    assert result.status == "timeout"


def test_evidence_retry_does_not_reset_role_budget():
    class Session:
        def close(self):
            pass

    class Client:
        calls = 0

        def complete(self, messages, tools=None):
            self.calls += 1
            time.sleep(0.05 if self.calls == 1 else 0.2)
            return {"content": '{"value":"unverified"}'}

    client = Client()
    ctx = RunContext(db_factory=Session, trace_id="", client_factory=lambda: client,
                     agent_budget_s=0.09)
    started = time.monotonic()
    output, reason = _run_specialist(ctx, AgentSpec("test", "test", Report), "context",
                                     validate_fn=lambda output: ["bad evidence"])
    assert output is None and reason
    assert time.monotonic() - started < 0.4


def test_expired_run_does_not_grant_minimum_extra_time():
    ctx = RunContext(db_factory=lambda: None, trace_id="", run_deadline_s=0)
    assert _agent_deadline(ctx) == 0


@pytest.mark.parametrize("kind", [DeepSeekChatClient, AnthropicProtocolChatClient])
def test_sdk_timeout_is_capped_and_internal_retries_disabled(kind):
    client = kind(model="test", api_key="test", base_url="https://example.invalid", timeout=400)
    options = {}

    def create(**kwargs):
        if kind is DeepSeekChatClient:
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content='{}', tool_calls=[]))])
        return SimpleNamespace(content=[], usage=None)

    def with_options(**kwargs):
        options.update(kwargs)
        return SimpleNamespace(messages=SimpleNamespace(create=create),
                               chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

    client._client = SimpleNamespace(with_options=with_options)
    client.complete_with_timeout([{"role": "user", "content": "test"}], timeout_s=0.2)
    assert options == {"timeout": 0.2, "max_retries": 0}
