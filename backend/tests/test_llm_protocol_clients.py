"""LLM 协议切换专项（Stage 9B 后续：DeepSeek → BigModel GLM-5.3-Flash）。

覆盖 AnthropicProtocolChatClient 的 OpenAI 风格消息 ↔ Anthropic Messages
协议转换、工具调用往返、usage 映射，以及 build_llm_client 的协议分发。
全部使用离线桩对象，不触网。
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.services.agents.base import (
    AnthropicProtocolChatClient,
    DeepSeekChatClient,
    build_llm_client,
)


def make_client() -> AnthropicProtocolChatClient:
    return AnthropicProtocolChatClient(model="glm-5.3-flash", api_key="test-key",
                                       base_url="https://example.invalid/api/anthropic")


class TestMessageConversion:
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

    def test_malformed_tool_arguments_fall_back_to_empty_object(self):
        client = make_client()
        _, turns = client._convert_messages([
            {"role": "user", "content": "x"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": "c", "type": "function",
                 "function": {"name": "t", "arguments": "{broken json"}}]},
        ])
        assert turns[-1]["content"][0]["input"] == {}


class TestCompleteParsing:
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

    def test_all_text_empty_returns_none_content(self):
        client = make_client()
        self._patch_create(client, blocks=[SimpleNamespace(type="thinking", thinking="only")],
                           usage=None)
        response = client.complete([{"role": "user", "content": "u"}])
        assert response["content"] is None
        assert response["tool_calls"] == []
        assert response["usage"] is None


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


class TestSystemBClientBranch:
    def test_anthropic_branch_builds_autogen_client(self, monkeypatch):
        from app import config
        from app.services import event_review_pipeline as pipeline
        monkeypatch.setattr(pipeline, "DEEPSEEK_API_PROTOCOL", "anthropic")
        client = pipeline._create_model_client()
        from autogen_ext.models.anthropic import AnthropicChatCompletionClient
        assert isinstance(client, AnthropicChatCompletionClient)

    def test_openai_branch_unchanged(self, monkeypatch):
        from app.services import event_review_pipeline as pipeline
        monkeypatch.setattr(pipeline, "DEEPSEEK_API_PROTOCOL", "openai")
        monkeypatch.setattr(pipeline, "DEEPSEEK_API_KEY", "offline-test-key")
        monkeypatch.setattr(pipeline, "DEEPSEEK_MODEL", "deepseek-v4-flash")
        monkeypatch.setattr(pipeline, "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
        client = pipeline._create_model_client()
        from autogen_ext.models.openai import OpenAIChatCompletionClient
        assert isinstance(client, OpenAIChatCompletionClient)
