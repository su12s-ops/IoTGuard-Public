"""分层判定：契约通过（PASS）必须与研判成功分开。

回归对象：2026-10-20 两个真环境运行的报告是全局 PASS，但 runtime/vulnerability/
decision 三角色降级、candidate_intents 为空——「契约通过」被当成了「研判成功」。
"""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "agent_blackbox", ROOT / "scripts" / "agent_blackbox.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bb = _load()


def _degraded_detail():
    return {
        "status": "completed",
        "degraded_roles": ["runtime_analyst", "vulnerability_analyst", "decision_planner"],
        "stage_status": {"prepare": "succeeded", "analyze_runtime": "failed",
                         "analyze_vulnerability": "failed", "decide": "failed"},
        "final": {"candidate_intents": [], "plan_execution_mode": "no_action",
                  "harness_feedback": {"status": "no_action"}},
        "decision": {},
    }


def _good_detail():
    return {
        "status": "completed",
        "degraded_roles": [],
        "stage_status": {"prepare": "succeeded", "decide": "succeeded"},
        "final": {"candidate_intents": [{"intent_id": "I-1"}],
                  "plan_execution_mode": "pending_approval"},
        "decision": {"verdicts": [{"object_id": "risk-1", "confidence": 0.8}]},
    }


def test_contract_only_scope_is_pass_but_analysis_not_run():
    rec = bb.Recorder()
    rec.check("contract", "健康检查", True)
    rec.check("authz", "无令牌被拒", True)
    verdicts = bb.classify_verdicts(rec, {"contract", "authz"}, detail={})
    assert verdicts["overall"] == "pass"
    assert verdicts["layers"]["contract"]["status"] == "pass"
    assert verdicts["layers"]["analysis"]["status"] == "not_run"
    assert "analysis" not in verdicts["executed"]
    # 报告必须说清「契约通过 ≠ 研判成功」
    assert "不代表研判" in verdicts["note"]


def test_completed_run_with_degraded_roles_is_not_a_pass():
    rec = bb.Recorder()
    rec.check("contract", "健康检查", True)
    rec.check("agent", "运行最终状态", True)
    rec.info("agent", "降级角色", "runtime_analyst,decision_planner")
    verdicts = bb.classify_verdicts(rec, {"contract", "agent"}, detail=_degraded_detail())
    assert verdicts["layers"]["contract"]["status"] == "pass"
    assert verdicts["layers"]["analysis"]["status"] == "degraded"
    assert verdicts["overall"] == "degraded"
    reasons = " ".join(verdicts["analysis"]["reasons"])
    assert "degraded_roles=" in reasons
    assert "no_usable_output" in reasons
    assert verdicts["analysis"]["candidate_intents"] == 0


def test_analysis_succeeds_with_real_output():
    rec = bb.Recorder()
    rec.check("agent", "运行最终状态", True)
    rec.check("embedding", "候选意图进入运行结论", True)
    verdicts = bb.classify_verdicts(rec, {"agent", "embedding"}, detail=_good_detail())
    assert verdicts["layers"]["analysis"]["status"] == "pass"
    assert verdicts["overall"] == "pass"
    assert verdicts["analysis"]["candidate_intents"] == 1


def test_failed_check_still_dominates():
    rec = bb.Recorder()
    rec.check("contract", "健康检查", False)
    rec.check("agent", "运行最终状态", True)
    verdicts = bb.classify_verdicts(rec, {"contract", "agent"}, detail=_good_detail())
    assert verdicts["overall"] == "fail"
    assert verdicts["layers"]["contract"]["failed"] == ["contract/健康检查"]


def test_exit_codes_separate_degraded_from_failed():
    assert bb.EXIT_CODES == {"pass": 0, "degraded": 3, "fail": 1}


def test_reports_carry_layer_verdicts(tmp_path):
    rec = bb.Recorder()
    rec.check("contract", "健康检查", True)
    rec.check("agent", "运行最终状态", True)
    detail = _degraded_detail()
    verdicts = bb.classify_verdicts(rec, {"contract", "agent"}, detail=detail)
    meta = {"version": "agent-blackbox-v2", "base_url": "http://127.0.0.1:8000",
            "started_at": "2026-10-21T00:00:00", "duration_s": 1.0,
            "asset_id": 1, "risk_id": 28}
    json_path, md_path = bb.write_reports(meta, rec, tmp_path, "20261021T000000", verdicts)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["verdict"] == "degraded"
    assert payload["verdicts"]["layers"]["analysis"]["status"] == "degraded"
    markdown = md_path.read_text(encoding="utf-8")
    assert "分层判定" in markdown and "研判面=**degraded**" in markdown
    assert "契约通过 ≠ 研判成功" in markdown
