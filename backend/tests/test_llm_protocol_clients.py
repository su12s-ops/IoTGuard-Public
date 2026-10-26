"""LLM 协议切换专项（Stage 9B 后续：DeepSeek → BigModel GLM-5.3-Flash）。

覆盖 AnthropicProtocolChatClient 的 OpenAI 风格消息 ↔ Anthropic Messages
协议转换、工具调用往返、usage 映射，以及 build_llm_client 的协议分发。
全部使用离线桩对象，不触网。
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.services.agent_infra import (
    AnthropicProtocolChatClient,
    DeepSeekChatClient,
    build_llm_client,
)


def make_client() -> AnthropicProtocolChatClient:
    return AnthropicProtocolChatClient(model="glm-5.3-flash", api_key="test-key",
                                       base_url="https://example.invalid/api/anthropic")


class TestMessageConversion:
    def test_tool_result_and_followup_text_share_one_user_turn(self):
        client = make_client()
        _, turns = client._convert_messages([
            {"role": "assistant", "tool_calls": [{"id": "c", "function": {"name": "read", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "c", "content": '{"value":1}'},
            {"role": "user", "content": "Now give the final JSON."},
        ])
        assert [turn["role"] for turn in turns] == ["assistant", "user"]
        assert [block["type"] for block in turns[-1]["content"]] == ["tool_result", "text"]

    def test_system_extracted_and_turns_alternate(self):
        client = make_client()
        system, turns = client._convert_messages([
            {"role": "system", "content": "系统提示"},
            {"role": "user", "content": "你好"},
            {"role": "assistant", "content": "答复"},
            {"role": "user", "content": "继续"},
        ])
        assert system == "系统提示"
        assert [t["role"] for t in turns] == ["user", "assistant", "user"]
        assert turns[0]["content"] == "你好"

    def test_assistant_tool_calls_become_tool_use_blocks(self):
        client = make_client()
        system, turns = client._convert_messages([
            {"role": "system", "content": "s"},
            {"role": "user", "content": "查一下"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "call-1", "type": "function",
                 "function": {"name": "query_inventory",
                              "arguments": json.dumps({"package": "curl"})}}]},
        ])
        blocks = turns[-1]["content"]
        assert turns[-1]["role"] == "assistant"
        assert blocks[0]["type"] == "tool_use"
        assert blocks[0]["id"] == "call-1"
        assert blocks[0]["name"] == "query_inventory"
        assert blocks[0]["input"] == {"package": "curl"}

    def test_consecutive_tool_results_merge_into_one_user_turn(self):
        client = make_client()
        system, turns = client._convert_messages([
            {"role": "system", "content": "s"},
            {"role": "user", "content": "查两项"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "a", "type": "function",
                 "function": {"name": "t1", "arguments": "{}"}},
                {"id": "b", "type": "function",
                 "function": {"name": "t2", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "a", "content": "{\"ok\": 1}"},
            {"role": "tool", "tool_call_id": "b", "content": "{\"ok\": 2}"},
        ])
        assert [t["role"] for t in turns] == ["user", "assistant", "user"]
        results = [block for block in turns[-1]["content"] if block["type"] == "tool_result"]
        assert [r["tool_use_id"] for r in results] == ["a", "b"]
        assert json.loads(results[0]["content"]) == {"ok": 1}

    def test_malformed_history_tool_arguments_are_rejected(self):
        client = make_client()
        with pytest.raises(ValueError, match="invalid_tool_arguments_in_history"):
            client._convert_messages([
                {"role": "user", "content": "x"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "c", "type": "function",
                     "function": {"name": "t", "arguments": "{broken json"}}]},
            ])


class TestCompleteParsing:
    def test_reasoning_only_cap_is_attributed_and_not_retried_unchanged(self):
        from pydantic import BaseModel
        from app.services.agent_infra import AgentSpec
        from app.services.unified.agent_base import UnifiedToolLoopAgent, UsageMeter
        class Report(BaseModel):
            answer: int
        calls=[]
        class SDK:
            def __init__(self): self.messages=self
            def with_options(self, **kwargs): return self
            def create(self, **kwargs):
                calls.append(kwargs)
                return SimpleNamespace(model="glm-5.3-flash", stop_reason="max_tokens",
                    content=[SimpleNamespace(type="thinking",thinking="opaque private content")],
                    usage=SimpleNamespace(input_tokens=9165,output_tokens=8192))
        client=make_client();client._client=SDK();client._max_tokens=8192
        meter=UsageMeter(max_llm_calls=8)
        agent=UnifiedToolLoopAgent(AgentSpec("role","role",Report,llm_retries=2),client,meter=meter)
        result=agent.run(None,"actual material",deadline_s=3)
        assert result.status=="failed" and result.stop_reason=="max_tokens"
        assert len(calls)==1 and meter.calls==1 and meter.usage["total_tokens"]==17357
        record=agent.request_log[0]
        assert record["failure_source"]=="provider_response"
        assert record["response_metadata"]["text_chars"]==0
        assert record["response_metadata"]["truncation_kind"]=="reasoning_only_output_budget_exhausted"
        assert "opaque private content" not in json.dumps(record)

    def test_agent_preserves_signed_thinking_blocks_across_tool_roundtrip(self):
        from copy import deepcopy
        from pydantic import BaseModel
        from app.services.agent_infra import AgentSpec, AgentTool
        from app.services.unified.agent_base import UnifiedToolLoopAgent
        class Report(BaseModel):
            answer: int
        captured = []
        blocks = [SimpleNamespace(type="thinking", thinking="opaque", signature="signature-do-not-change"),
                  SimpleNamespace(type="tool_use", id="read-1", name="read", input={})]
        class SDK:
            def __init__(self):
                self.messages = self
            def with_options(self, **options):
                return self
            def create(self, **kwargs):
                captured.append(deepcopy(kwargs))
                return SimpleNamespace(content=blocks if len(captured) == 1 else [SimpleNamespace(type="text", text='{"answer":42}')],
                    usage=SimpleNamespace(input_tokens=10, output_tokens=5), stop_reason="tool_use" if len(captured) == 1 else "end_turn")
        client = make_client()
        client._client = SDK()
        spec = AgentSpec("role", "role", Report, tools=[AgentTool("read", "read", {}, lambda db: {"value":42})], max_tool_rounds=2, llm_retries=0)
        result = UnifiedToolLoopAgent(spec, client).run(None, "Read then answer", deadline_s=3)
        assert result.status == "succeeded" and result.output == {"answer":42}
        assistant = next(turn for turn in captured[1]["messages"] if turn["role"] == "assistant")
        assert assistant["content"] == [vars(block) for block in blocks]
        assert captured[1]["messages"][-1]["content"][0]["tool_use_id"] == "read-1"

    @pytest.mark.parametrize("stop_reason", ["refusal", "pause_turn"])
    def test_unfinished_or_refused_response_is_not_accepted_as_report(self, stop_reason):
        from app.services.agent_infra import ModelResponseError
        client = make_client()
        class Messages:
            def create(self, **kwargs):
                return SimpleNamespace(content=[SimpleNamespace(type="text", text='{"answer":42}')],
                    usage=SimpleNamespace(input_tokens=10, output_tokens=5), stop_reason=stop_reason)
        client._client = SimpleNamespace(messages=Messages())
        with pytest.raises(ModelResponseError) as failure:
            client.complete([{"role":"user", "content":"test"}])
        assert failure.value.stop_reason == stop_reason and failure.value.usage["total_tokens"] == 15

    def _patch_create(self, client, blocks, usage):
        class _Messages:
            def create(self, **kwargs):
                captured.update(kwargs)
                return SimpleNamespace(content=blocks, usage=usage)

        captured: dict = {}
        client._client = SimpleNamespace(messages=_Messages())
        return captured

    def test_text_and_tool_use_blocks_parsed(self):
        client = make_client()
        captured = self._patch_create(
            client,
            blocks=[SimpleNamespace(type="thinking", thinking="推理过程"),
                    SimpleNamespace(type="text", text='{"verdict": "ok"}'),
                    SimpleNamespace(type="tool_use", id="tu-1", name="query",
                                    input={"q": 1})],
            usage=SimpleNamespace(input_tokens=10, output_tokens=5))
        response = client.complete(
            [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}],
            tools=[{"name": "query", "description": "d",
                    "parameters": {"type": "object", "properties": {}}}])
        # thinking 不进入 content；text 拼接为 content；tool_use 还原为工具调用
        assert response["content"] == '{"verdict": "ok"}'
        assert response["tool_calls"] == [{"id": "tu-1", "name": "query",
                                           "arguments": {"q": 1}}]
        assert response["usage"] == {"prompt_tokens": 10, "completion_tokens": 5,
                                     "total_tokens": 15}
        # 请求侧：system 独立、max_tokens 必填、工具转 input_schema
        assert captured["system"] == "s"
        assert captured["max_tokens"] > 0
        assert captured["tools"][0]["input_schema"] == {"type": "object", "properties": {}}

    def test_thinking_only_response_is_explicit_protocol_failure(self):
        client = make_client()
        self._patch_create(client, blocks=[SimpleNamespace(type="thinking", thinking="only")],
                           usage=None)
        from app.services.agent_infra import ModelResponseError
        with pytest.raises(ModelResponseError, match="no_actionable_content") as failure:
            client.complete([{"role": "user", "content": "u"}])
        assert failure.value.response_received and failure.value.usage is None


class TestDispatchFactory:
    def test_anthropic_protocol_selected(self, monkeypatch):
        from app import config
        monkeypatch.setattr(config, "DEEPSEEK_API_KEY", "k")
        monkeypatch.setattr(config, "DEEPSEEK_MODEL", "glm-5.3-flash")
        monkeypatch.setattr(config, "DEEPSEEK_BASE_URL", "https://open.bigmodel.cn/api/anthropic")
        monkeypatch.setattr(config, "DEEPSEEK_API_PROTOCOL", "anthropic")
        assert isinstance(build_llm_client(), AnthropicProtocolChatClient)

    def test_openai_protocol_default(self, monkeypatch):
        from app import config
        monkeypatch.setattr(config, "DEEPSEEK_API_KEY", "k")
        monkeypatch.setattr(config, "DEEPSEEK_MODEL", "deepseek-v4-flash")
        monkeypatch.setattr(config, "DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        monkeypatch.setattr(config, "DEEPSEEK_API_PROTOCOL", "openai")
        assert isinstance(build_llm_client(), DeepSeekChatClient)

    def test_unknown_protocol_fails_fast(self, monkeypatch):
        from app import config
        monkeypatch.setattr(config, "DEEPSEEK_API_KEY", "k")
        monkeypatch.setattr(config, "DEEPSEEK_API_PROTOCOL", "grpc")
        with pytest.raises(RuntimeError, match="不支持的 DEEPSEEK_API_PROTOCOL"):
            build_llm_client()

    def test_missing_key_raises(self, monkeypatch):
        from app import config
        monkeypatch.setattr(config, "DEEPSEEK_API_KEY", "")
        with pytest.raises(RuntimeError, match="DEEPSEEK_API_KEY"):
            build_llm_client()


def test_glm_openai_thinking_and_reasoning_fields_are_transported():
    captured = {}
    client = DeepSeekChatClient(model="glm-5.3-flash", api_key="test", base_url="https://example.invalid/v4")
    client._thinking = {"type": "enabled"}
    def create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(model="glm-5.3-flash", usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            choices=[SimpleNamespace(finish_reason="tool_calls", message=SimpleNamespace(content=None, reasoning_content="opaque", tool_calls=[
                SimpleNamespace(id="t", function=SimpleNamespace(name="read", arguments='{"q":1}'))]))])
    client._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    result = client.complete([{"role":"user", "content":"test"}])
    assert captured["extra_body"]["thinking"] == {"type":"enabled"}
    assert result["reasoning_content"] == "opaque" and result["stop_reason"] == "tool_calls"
    assert result["tool_calls"][0]["arguments"] == {"q":1}


def test_bounded_glm53_profile_uses_supported_thinking_controls():
    from app.services.agent_infra import configure_bounded_model_profile
    client = make_client()
    configure_bounded_model_profile(client)
    assert client._thinking == {"type":"enabled"} and client._reasoning_effort == "low"
    captured = TestCompleteParsing()._patch_create(client,
        blocks=[SimpleNamespace(type="text",text='{"ok":true}')], usage=None)
    client.complete([{"role":"user","content":"test"}])
    assert captured["thinking"] == {"type":"enabled"}
    assert captured["extra_body"] == {"reasoning_effort":"low"}


@pytest.mark.parametrize("arguments", ['{broken', '[1,2]'])
def test_glm_openai_invalid_tool_arguments_never_become_empty_invocation(arguments):
    from app.services.agent_infra import ModelResponseError
    client = DeepSeekChatClient(model="glm-5.3-flash", api_key="test", base_url="https://example.invalid/v4")
    def create(**kwargs):
        return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            choices=[SimpleNamespace(finish_reason="tool_calls", message=SimpleNamespace(content=None, tool_calls=[
                SimpleNamespace(id="t", function=SimpleNamespace(name="read", arguments=arguments))]))])
    client._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    with pytest.raises(ModelResponseError, match="model_tool_call_invalid") as failure:
        client.complete([{"role":"user", "content":"test"}])
    assert failure.value.usage["total_tokens"] == 15
