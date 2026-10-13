"""端到端关键流程验证（模拟数据，不依赖真实模型密钥）：
1. 结构化裁定解析（含完成标志、代码围栏、噪声文本）
2. 校验逻辑（合法/非法裁定）
3. 失败降级（human_review 标记）
4. 复核裁定应用（confirmed/upgraded/downgraded → final_score 固定规则）
5. 修复任务准入（复核未完成不生成 / 复核完成生成 / 人工放行）
"""
import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models
from app.database import Base
from app.services import agent_group_chat as review
from app.services.remediation_engine import generate_remediation_tasks

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def main():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()

    print("== 1. 结构化裁定解析 ==")
    # 完成标志 + 纯 JSON
    ok_marker = "[[FINAL_VERDICT]]\n" + json.dumps({
        "verdict": "upgraded", "confidence": 0.9, "risk_adjustment": 15,
        "evidence_ids": ["asset-1-CVE-1"], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "KEV 高危且公网暴露"
    })
    parsed = review._extract_verdict_json(ok_marker)
    check("完成标志解析", parsed is not None and parsed["verdict"] == "upgraded")

    # 代码围栏包裹
    fenced = "```json\n[[FINAL_VERDICT]]\n" + json.dumps({
        "verdict": "confirmed", "confidence": 0.8, "risk_adjustment": 0,
        "evidence_ids": [], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "ok"
    }) + "\n```"
    parsed = review._extract_verdict_json(fenced)
    check("代码围栏解析", parsed is not None and parsed["verdict"] == "confirmed")

    # 噪声文本（先解释再输出）
    noisy = "综合以上意见，我认为应当升级处理。\n[[FINAL_VERDICT]]\n" + json.dumps({
        "verdict": "downgraded", "confidence": 0.7, "risk_adjustment": -10,
        "evidence_ids": [], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "证据不足支持当前等级"
    })
    parsed = review._extract_verdict_json(noisy)
    check("噪声文本解析", parsed is not None and parsed["verdict"] == "downgraded")

    print("== 2. 校验逻辑 ==")
    valid_payload = {
        "verdict": "confirmed", "confidence": 0.9, "risk_adjustment": 0,
        "evidence_ids": [], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "合理"
    }
    ok, err = review._validate_verdict(valid_payload)
    check("合法裁定通过", ok and err == "")

    bad_verdict = dict(valid_payload, verdict="maybe")
    ok, err = review._validate_verdict(bad_verdict)
    check("非法裁定拒绝", not ok and "verdict" in err)

    bad_adj = dict(valid_payload, verdict="upgraded", risk_adjustment=999)
    ok, err = review._validate_verdict(bad_adj)
    check("超额调整拒绝", not ok and "risk_adjustment" in err)

    bad_conf = dict(valid_payload, confidence=2.5)
    ok, err = review._validate_verdict(bad_conf)
    check("非法置信度拒绝", not ok and "confidence" in err)

    print("== 3. 失败降级 ==")
    seed_asset = models.LinuxAsset(hostname="verify-host", distribution="ubuntu", os_version="22.04")
    db.add(seed_asset)
    db.flush()
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2099-0101", title="T", description="D", cvss_score=8.0,
        cvss_severity="High", affected_package="openssl", fixed_version="3.0.2-0ubuntu1.18"
    ))
    db.add(models.VulnerabilityMatch(
        asset_id=seed_asset.id, cve_id="CVE-2099-0101", package_name="openssl",
        installed_version="3.0.2-0ubuntu1.10", fixed_version="3.0.2-0ubuntu1.18",
        affected=True
    ))
    db.add(models.RiskAssessment(
        asset_id=seed_asset.id, cve_id="CVE-2099-0101",
        final_score=70.0, risk_level="High", decision="scheduled_fix",
        preliminary_score=70.0, preliminary_level="High",
        preliminary_decision="scheduled_fix", review_status="pending",
        human_review_required=False
    ))
    db.commit()

    # 模拟超时/校验失败 → human_review
    review.apply_review_verdict(db, None, status="human_review")
    risk = db.query(models.RiskAssessment).one()
    check("失败降级标记人工复核", risk.human_review_required is True)
    check("失败降级不产生最终结论", risk.final_score == 0.0 and risk.preliminary_score == 70.0)

    # 人工复核状态下不生成任务
    count = generate_remediation_tasks(db)
    check("人工复核状态不生成任务", count == 0)

    print("== 4. 复核裁定应用（固定规则） ==")
    # upgraded：70 + 15 = 85
    review.apply_review_verdict(db, {
        "verdict": "upgraded", "confidence": 0.9, "risk_adjustment": 15,
        "evidence_ids": [], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "up"
    }, status="completed")
    risk = db.query(models.RiskAssessment).one()
    check("upgraded 分数上调", risk.final_score == 85.0 and risk.risk_level == "Critical")
    check("复核状态已更新", risk.review_status == "completed" and risk.review_verdict == "upgraded")

    # 复核完成后可生成任务
    count = generate_remediation_tasks(db)
    check("复核完成后生成任务", count == 1)
    task = db.query(models.RemediationTask).one()
    check("任务命令来自模板", "sudo apt" in task.remediation_command)

    # 重置为人工复核，验证人工放行
    db.query(models.RemediationTask).delete()
    db.commit()
    review.apply_review_verdict(db, None, status="human_review")
    count = generate_remediation_tasks(db, allow_human_override=True)
    check("人工审批放行生成任务", count == 1)
    task = db.query(models.RemediationTask).one()
    check("任务备注标记人工放行", "人工审批放行" in task.mitigation)

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    db.close()
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
