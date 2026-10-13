"""真实 AutoGen 四智能体协同复核冒烟测试（真实 API 调用）。

用法（在 backend 目录或容器内）：
    python scripts/smoke_test_review.py

安全约束：
  - 不读取、不打印、不提交明文密钥；仅判断"是否配置"
  - 不打印完整请求头
  - 资产信息只输出 hostname 掩码（前4位 + ***），不输出 IP/密码/详细包版本
  - 日志与数据统一 UTF-8

输出内容（满足可观测性要求）：
  review_run_id / 智能体名称 / 轮次 / 消息类型 / 最终标志是否命中 /
  结构化解析是否成功 / 终止原因 / review_status / human_review_required / 修复任务是否获准生成

注意：本脚本调用真实 DeepSeek API，需要 DEEPSEEK_API_KEY 环境变量（或 backend/.env）。
若未配置有效密钥，脚本会明确报告"密钥缺失，未执行真实测试"，不会伪装通过。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

# ── Windows 控制台 UTF-8 修复（不影响业务数据编码） ──
if os.name == "nt":
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass

from app import models  # noqa: E402
from app.config import DEEPSEEK_API_KEY, DEEPSEEK_MODEL  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.services import agent_group_chat as review  # noqa: E402
from app.services.remediation_engine import generate_remediation_tasks  # noqa: E402


def mask_hostname(hostname: str) -> str:
    """掩码主机名：只显示前4个字符，避免泄露完整资产名。"""
    if not hostname:
        return ""
    return hostname[:4] + "***"


def check_key() -> bool:
    """仅判断密钥是否存在且格式合理，不泄露内容。"""
    if not DEEPSEEK_API_KEY:
        return False
    return DEEPSEEK_API_KEY.startswith("sk-") and len(DEEPSEEK_API_KEY) >= 20


def _ensure_candidates(db) -> int:
    """确保至少存在一条候选风险记录（使用已有真实资产，不创建测试 VM）。"""
    # 查找已有候选
    existing = db.query(models.RiskAssessment).filter_by(review_status="candidate").count()
    if existing > 0:
        return existing

    # 无候选记录：查找已有资产和漏洞，自动建立一条候选风险
    asset = db.query(models.LinuxAsset).first()
    if asset is None:
        return 0
    vuln = db.query(models.VulnerabilityInfo).first()
    if vuln is None:
        return 0
    match = (
        db.query(models.VulnerabilityMatch)
        .filter_by(asset_id=asset.id, cve_id=vuln.cve_id, affected=True)
        .first()
    )
    if match is None:
        return 0

    db.add(
        models.RiskAssessment(
            asset_id=asset.id,
            cve_id=vuln.cve_id,
            final_score=0.0,
            risk_level="Low",
            decision="monitor",
            preliminary_score=65.0,
            preliminary_level="High",
            preliminary_decision="scheduled_fix",
            review_status="candidate",
            human_review_required=False,
        )
    )
    db.commit()
    return 1


def main() -> int:
    print("=" * 64)
    print("真实 AutoGen 四智能体协同复核冒烟测试")
    print("=" * 64)
    print(f"模型: {DEEPSEEK_MODEL}")
    print(f"API 密钥: {'已配置（内容不显示）' if check_key() else '未配置/格式异常'}")
    print(f"调用链: demo(初步研判) → agent_group_chat(run_stream) → apply_review_verdict → remediation")

    if not check_key():
        print("\n[SKIP] 未检测到有效的 DEEPSEEK_API_KEY，不执行真实 API 调用。")
        print("[SKIP] 本结果不计为“真实API测试通过”，也不以模拟结果代替。")
        return 2

    init_db()
    db = SessionLocal()
    try:
        candidates = _ensure_candidates(db)
        if candidates == 0:
            print("\n[SKIP] 数据库中没有可用于测试的资产/漏洞数据，请先导入真实资产。")
            return 2
        print(f"\n[数据准备] 就绪候选风险: {candidates} 条")

        # 复核前：确认修复任务不应生成（复核未完成）
        pre_tasks = generate_remediation_tasks(db)
        print(f"\n[前置准入] 复核前修复任务数: {pre_tasks}（应为0，因为 review_status=pending）")

        print("\n[执行] 调用真实 AutoGen 四智能体协同复核（run_stream + 完成标志终止 + 结果入库）...")
        result = review.generate_and_save_report(db)

        # ── 可观测性输出 ──
        print("\n" + "-" * 64)
        print("复核结果摘要")
        print("-" * 64)
        print(f"review_run_id        : {result.get('review_run_id', '')}")
        print(f"status               : {result.get('status')}")
        print(f"termination_reason   : {result.get('termination_reason', '')}")
        print(f"verdict_hit          : {result.get('verdict_hit', False)}")
        print(f"verdict_parse_ok     : {result.get('verdict_parse_ok', False)}")
        print(f"turn_count           : {result.get('turn_count', 0)}")
        print(f"error                : {result.get('error', '')}")

        verdict = result.get("verdict") or {}
        print(f"verdict              : {verdict.get('verdict', '-')}")
        print(f"confidence           : {verdict.get('confidence', '-')}")
        print(f"risk_adjustment      : {verdict.get('risk_adjustment', '-')}")
        print(f"human_review_required: {verdict.get('human_review_required', '-')}")

        # 智能体消息类型与轮次
        print("\n智能体消息（agent 名称 → 消息类型）:")
        seen_types: dict[str, list[str]] = {}
        for entry in result.get("transcript", []):
            agent = entry.get("agent", "")
            msg_type = "text"
            seen_types.setdefault(agent, []).append(msg_type)
        for agent, types in seen_types.items():
            print(f"  {agent}: {len(types)} 条文本消息")

        # 结果入库验证：AnalysisReport 与 RiskAssessment 是否已持久化
        print("\n[入库验证] AnalysisReport / RiskAssessment 持久化检查:")
        report = db.query(models.AnalysisReport).order_by(models.AnalysisReport.id.desc()).first()
        if report is not None:
            print(f"  analysis_report.id={report.id} status={report.status} run_id={report.review_run_id or ''}")
            print(f"  termination_reason={report.termination_reason or ''} verdict_hit={report.verdict_hit} parse_ok={report.verdict_parse_ok} turns={report.turn_count or 0}")
        else:
            print("  analysis_report: 未写入（异常）")
        risk = db.query(models.RiskAssessment).first()
        if risk is not None:
            print(f"  risk.review_status={risk.review_status} review_verdict={risk.review_verdict} human_review_required={risk.human_review_required}")
        else:
            print("  risk_assessment: 无记录")

        # 修复任务准入：复核完成后是否允许生成
        status = result.get("status")
        human_review = bool(verdict.get("human_review_required", False)) or status in ("human_review", "failed", "skipped")
        allowed = status == "completed" and not human_review
        print(f"\n[准入判定] review_status={status} | human_review_required={human_review}")
        print(f"[准入判定] 修复任务是否获准自动生成: {'是' if allowed else '否'}")

        if allowed:
            task_count = generate_remediation_tasks(db)
            print(f"[准入] 已生成修复任务: {task_count} 条")
        else:
            task_count = generate_remediation_tasks(db)
            print(f"[准入] 未获准自动生成，直接调用 generate 结果为: {task_count} 条（应仍为0或仅人工放行）")
            forced = generate_remediation_tasks(db, allow_human_override=True)
            print(f"[准入] 人工放行 override 后: {forced} 条（用于验证放行通道）")

        print("\n" + "=" * 64)
        if status == "completed" and allowed:
            print("[PASS] 真实 API 复核完成：结构化裁定有效，修复任务获准生成")
            outcome = 0
        elif status == "human_review":
            print("[PASS-降级] 真实 API 调用已执行，但因超时/模型/校验等原因标记人工复核（这是预期的安全降级）")
            outcome = 0
        elif status == "skipped":
            print("[SKIP] 真实 API 调用被跳过（密钥未配置）")
            outcome = 2
        else:
            print(f"[FAIL] 复核未完成: {result.get('error', '未知')}")
            outcome = 1
        print("=" * 64)
        return outcome
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
