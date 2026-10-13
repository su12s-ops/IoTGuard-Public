"""真实最小四智能体群聊诊断：验证 selector 与 4 智能体是否能走完并输出裁定。"""
import asyncio
import sys

sys.path.insert(0, '/app')

from app.services.agent_group_chat import (
    _create_model_client,
    DATA_QUALITY_PROMPT,
    IMPACT_ASSESSMENT_PROMPT,
    RUNTIME_ATTRIBUTION_PROMPT,
    COORDINATOR_PROMPT,
    FINAL_VERDICT_MARKER,
)


async def main():
    from autogen_agentchat.agents import AssistantAgent
    from autogen_agentchat.teams import SelectorGroupChat
    from autogen_core import CancellationToken

    client = _create_model_client()
    token = CancellationToken()

    data_quality = AssistantAgent(name="data_quality_agent", system_message=DATA_QUALITY_PROMPT, model_client=client, description="数据质量审核专家")
    impact = AssistantAgent(name="impact_assessment_agent", system_message=IMPACT_ASSESSMENT_PROMPT, model_client=client, description="漏洞影响研判专家")
    runtime_attr = AssistantAgent(name="runtime_attribution_agent", system_message=RUNTIME_ATTRIBUTION_PROMPT, model_client=client, description="运行时归因验证专家")
    coordinator = AssistantAgent(name="decision_coordinator_agent", system_message=COORDINATOR_PROMPT, model_client=client, description="处置决策协调者")

    team = SelectorGroupChat(
        participants=[coordinator, data_quality, impact, runtime_attr],
        model_client=client,
        max_turns=10,
        allow_repeated_speaker=False,
    )

    task = "## 最小研判诊断\n\n以下是候选风险（非最终结论）：\n```json\n{\"inventory\": {\"assets\": [{\"asset_id\": 1, \"hostname\": \"diag-vm\", \"os\": \"Ubuntu 22.04\"}]}, \"candidate_objects\": [{\"object_id\": \"asset-1-CVE-DIAG-1\", \"cve_id\": \"CVE-DIAG-1\", \"package_name\": \"openssl\", \"installed_version\": \"1.0\", \"fixed_version\": \"1.1\", \"candidate_score\": 60, \"candidate_level\": \"High\"}]}\n```\n请按顺序：data_quality_agent 核验数据质量 → impact_assessment_agent 研判影响 → runtime_attribution_agent 关联运行时 → decision_coordinator_agent 输出结构化裁定。"
    print("=== START RUN_STREAM ===")
    turn = 0
    try:
        async for event in team.run_stream(task=task, cancellation_token=token):
            etype = getattr(event, "type", "")
            if etype in ("TextMessage", "UserTextMessage"):
                turn += 1
                print(f"[turn {turn}] {getattr(event, 'source', '?')}: {str(getattr(event, 'content', ''))[:100]}")
            elif etype == "TaskResult":
                print(f"=== TASK RESULT: {len(getattr(event, 'messages', []))} messages ===")
                for msg in getattr(event, "messages", []):
                    print(f"  - {getattr(msg, 'source', '?')}: {str(getattr(msg, 'content', ''))[:80]}")
    except Exception as exc:
        import traceback
        print(f"=== EXCEPTION: {type(exc).__name__}: {exc}")
        traceback.print_exc()
    finally:
        await client.close()
    print("=== DONE ===")


if __name__ == "__main__":
    asyncio.run(main())
