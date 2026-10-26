"""Isolated usage regressions: run directly; no app, DB, SDK or model startup.

    python backend/tests/test_truncated_response_metering.py
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pydantic import BaseModel

from app.services.agent_infra import AgentSpec, AnthropicProtocolChatClient, ModelResponseError
from app.services.unified.agent_base import (
    AgentDeadlineExceeded, BudgetExceeded, UnifiedToolLoopAgent, UsageMeter,
)


USAGE = {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


class Output(BaseModel):
    answer: str


class LegacyClient:
    """Intentionally has no timeout keyword or complete_with_timeout method."""

    def __init__(self, *outcomes):
        self.outcomes = iter(outcomes)
        self.calls = 0

    def complete(self, messages, tools=None):
        self.calls += 1
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def normal_response(content='{"answer":"ok"}', usage=USAGE):
    return {"content": content, "tool_calls": [], "usage": usage}


def rejection(usage=USAGE):
    return ModelResponseError("model_output_truncated", usage=usage,
                              model="fake-model", stop_reason="max_tokens")


def fake_anthropic(stop_reason="max_tokens", usage=True):
    """Bypass the SDK constructor; create() is an in-memory fake only."""
    response = SimpleNamespace(
        stop_reason=stop_reason, model="returned-model",
        content=[SimpleNamespace(type="text", text='{"answer":"valid-but-truncated"}')],
    )
    if usage:
        response.usage = SimpleNamespace(input_tokens=11, output_tokens=7)
    sdk = Mock()
    sdk.messages.create.return_value = response
    sdk.with_options.return_value = sdk
    client = AnthropicProtocolChatClient.__new__(AnthropicProtocolChatClient)
    client._model = "requested-model"
    client._timeout = 60
    client._max_tokens = 100
    client._thinking = None
    client._reasoning_effort = None
    client._client = sdk
    return client


def agent(client, meter=None, retries=0):
    spec = AgentSpec(name="asset", role="test", output_model=Output, llm_retries=retries)
    return UnifiedToolLoopAgent(spec, client, meter=meter, role="asset")


class TruncatedResponseMeteringTests(unittest.TestCase):
    def setUp(self):
        # No retries need a real backoff, network, devices or database connections.
        for target, value in (
            ("app.services.unified.agent_base._RETRY_BACKOFF_S", 0),
            ("socket.socket.connect", Mock(side_effect=AssertionError("network forbidden"))),
            ("sqlite3.connect", Mock(side_effect=AssertionError("database forbidden"))),
        ):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_anthropic_extracts_usage_before_rejecting_even_valid_json(self):
        client = fake_anthropic()
        with self.assertRaises(ModelResponseError) as caught:
            client.complete([{"role": "user", "content": "test"}])
        error = caught.exception
        self.assertIsInstance(error, ValueError)
        self.assertTrue(error.response_received)
        self.assertEqual(error.usage, USAGE)
        self.assertEqual(error.model, "returned-model")
        self.assertEqual(error.stop_reason, "max_tokens")
        self.assertFalse(hasattr(error, "content"))

    def test_truncated_response_counted_once_but_failed_and_unusable(self):
        meter = UsageMeter()
        runner = agent(fake_anthropic(), meter)
        result = runner.run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.output)
        self.assertIn("model_output_truncated", result.error)
        self.assertEqual(result.llm_calls, 1)
        self.assertEqual(result.llm_usage, USAGE)
        self.assertEqual((meter.calls, meter.requests), (1, 1))
        self.assertEqual(meter.usage, USAGE)
        self.assertEqual(meter.role_usage, {"asset": 18})
        self.assertEqual(meter.role_calls, {"asset": 1})
        self.assertEqual(runner.request_log[0]["status"], "failed")
        self.assertTrue(runner.request_log[0]["response_received"])
        self.assertEqual(runner.request_log[0]["usage"], USAGE)
        self.assertEqual(runner.request_log[0]["stop_reason"], "max_tokens")
        self.assertEqual(runner.request_log[0]["model"], "returned-model")

    def test_anthropic_normal_response_counted_only_once(self):
        meter = UsageMeter()
        runner = agent(fake_anthropic(stop_reason="end_turn"), meter)
        result = runner.run(None, "test")
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.output, {"answer": "valid-but-truncated"})
        self.assertEqual((result.llm_calls, meter.calls, meter.requests), (1, 1, 1))
        self.assertEqual(result.llm_usage, USAGE)
        self.assertEqual(meter.usage, USAGE)
        self.assertEqual(runner.request_log[0]["status"], "succeeded")

    def test_timeout_does_not_invent_usage(self):
        meter = UsageMeter()
        runner = agent(LegacyClient(TimeoutError("timeout")), meter)
        result = runner.run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.output)
        self.assertEqual((result.llm_calls, meter.calls, meter.requests), (0, 0, 1))
        self.assertEqual(result.llm_usage, {})
        self.assertIsNone(meter.as_dict()["usage"])
        self.assertNotIn("usage", runner.request_log[0])

    def test_unmarked_error_with_usage_is_not_counted(self):
        error = ValueError("not a response")
        error.usage = USAGE
        error.response_received = True
        meter = UsageMeter()
        result = agent(LegacyClient(error), meter).run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertEqual((result.llm_calls, meter.calls), (0, 0))
        self.assertEqual(meter.usage, {})

    def test_wall_deadline_does_not_count_late_response(self):
        release = threading.Event()
        completed = threading.Event()

        class SlowClient:
            def complete(self, messages, tools=None):
                release.wait(2)
                completed.set()
                return normal_response()

        meter = UsageMeter()
        runner = agent(SlowClient(), meter)
        try:
            with self.assertRaises(AgentDeadlineExceeded):
                runner._complete([], None, time.monotonic() + 0.02)
        finally:
            release.set()
            self.assertTrue(completed.wait(2))
        self.assertEqual((runner._calls, meter.calls, meter.requests), (0, 0, 1))
        self.assertEqual(meter.usage, {})
        self.assertEqual(runner.request_log[0]["status"], "timeout")

    def test_received_truncation_without_usage_counts_call_not_estimated_tokens(self):
        meter = UsageMeter()
        runner = agent(fake_anthropic(usage=False), meter)
        result = runner.run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertEqual((result.llm_calls, meter.calls), (1, 1))
        self.assertEqual(result.llm_usage, {})
        self.assertIsNone(meter.as_dict()["usage"])
        self.assertIsNone(runner.request_log[0]["usage"])
        self.assertTrue(runner.request_log[0]["response_received"])

    def test_partial_usage_does_not_fabricate_missing_fields(self):
        partial = {"prompt_tokens": None, "completion_tokens": 7, "total_tokens": None}
        meter = UsageMeter()
        result = agent(LegacyClient(rejection(partial)), meter).run(None, "test")
        self.assertEqual(result.llm_usage, {"completion_tokens": 7})
        self.assertEqual(meter.usage, {"completion_tokens": 7})

    def test_truncation_charges_role_budget_and_blocks_the_next_dispatch(self):
        client = LegacyClient(rejection(), normal_response())
        meter = UsageMeter(role_token_limits={"asset": 18})
        result = agent(client, meter, retries=1).run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.stop_reason, "max_tokens")
        next_result = agent(client, meter).run(None, "another investigation")
        self.assertEqual(next_result.status, "degraded")
        self.assertIsNone(result.output)
        self.assertEqual(client.calls, 1)
        self.assertEqual((result.llm_calls, meter.requests), (1, 1))
        self.assertEqual(meter.as_dict()["role_budgets_exhausted"], ["asset"])
        self.assertFalse(meter.as_dict()["budget_exceeded"])
        with self.assertRaises(BudgetExceeded):
            meter.reserve_request("asset")
        meter.ensure_budget("runtime")

    def test_truncation_charges_run_token_budget_and_blocks_next_dispatch(self):
        client = LegacyClient(rejection(), normal_response())
        meter = UsageMeter(max_tokens=18)
        result = agent(client, meter, retries=1).run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.stop_reason, "max_tokens")
        self.assertEqual(agent(client, meter).run(None, "next").status, "degraded")
        self.assertIsNone(result.output)
        self.assertEqual(client.calls, 1)
        self.assertEqual(meter.as_dict()["budget_exhausted_kind"], "tokens")
        with self.assertRaises(BudgetExceeded):
            meter.ensure_budget("runtime")

    def test_run_call_budget_still_blocks_dispatch_after_truncation(self):
        client = LegacyClient(rejection(), normal_response())
        meter = UsageMeter(max_llm_calls=1)
        result = agent(client, meter, retries=1).run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.stop_reason, "max_tokens")
        self.assertEqual(agent(client, meter).run(None, "next").status, "degraded")
        self.assertEqual((client.calls, meter.calls, meter.requests), (1, 1, 1))
        self.assertEqual(meter.as_dict()["budget_exhausted_kind"], "calls")

    def test_truncation_is_terminal_even_with_retry_allowance(self):
        client = LegacyClient(rejection(), normal_response())
        meter = UsageMeter()
        runner = agent(client, meter, retries=1)
        result = runner.run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.output)
        self.assertEqual(result.stop_reason, "max_tokens")
        self.assertEqual(result.attempts, 1)
        self.assertEqual((client.calls, result.llm_calls, meter.calls, meter.requests), (1, 1, 1, 1))
        self.assertEqual(meter.usage, USAGE)
        self.assertEqual([r["status"] for r in runner.request_log], ["failed"])

    def test_transport_retry_preserves_unknown_usage_and_counts_actual_response_once(self):
        client = LegacyClient(TimeoutError("transient timeout"), normal_response())
        meter = UsageMeter()
        runner = agent(client, meter, retries=1)
        result = runner.run(None, "test")
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.output, {"answer": "ok"})
        self.assertEqual(result.attempts, 2)
        self.assertEqual((client.calls, result.llm_calls, meter.calls, meter.requests), (2, 1, 1, 2))
        self.assertEqual(meter.usage, USAGE)
        self.assertEqual([r["status"] for r in runner.request_log], ["failed", "succeeded"])

    def test_legacy_client_without_usage_remains_compatible(self):
        meter = UsageMeter()
        response = {"content": '{"answer":"legacy"}', "tool_calls": []}
        result = agent(LegacyClient(response), meter).run(None, "test")
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(result.output, {"answer": "legacy"})
        self.assertEqual((result.llm_calls, meter.calls), (1, 1))
        self.assertEqual(result.llm_usage, {})
        self.assertIsNone(meter.as_dict()["usage"])

    def test_output_validation_still_rejects_invalid_normal_responses(self):
        client = LegacyClient(normal_response('{"answer":123}'), normal_response('{"answer":123}'))
        meter = UsageMeter()
        result = agent(client, meter).run(None, "test")
        self.assertEqual(result.status, "failed")
        self.assertIsNone(result.output)
        self.assertIn("结构化校验失败", result.error)
        self.assertEqual((result.llm_calls, meter.calls), (2, 2))


if __name__ == "__main__":
    unittest.main(verbosity=2)
