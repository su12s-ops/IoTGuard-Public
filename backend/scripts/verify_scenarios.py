"""五场景流程语义验证（模拟数据，不依赖真实模型密钥）：
场景一：版本命中但发行版已安全回补 → 影响智能体识别回补，最终结论不得确认未修复高危
场景二：版本命中+服务运行+端口暴露，无eBPF异常 → 可确认或保持高优先级，写明"暂未发现明确利用迹象"
场景三：存在eBPF异常但无法与CVE可靠关联 → 运行时标记弱相关，不得直接输出"已被利用"
场景四：关键证据缺失或智能体执行失败 → 安全降级为证据不足/人工复核，不生成虚假结论
场景五：完整研判成功 → 候选→证据→四智能体→裁定→校验→最终结论写入→整改清单可生成
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


def make_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    db = Session()
    asset = models.LinuxAsset(
        hostname="scenario-vm", ip_address="10.0.0.5", distribution="ubuntu",
        os_version="22.04", exposure_level="public", business_level="core",
    )
    db.add(asset)
    db.flush()
    db.add(models.VulnerabilityInfo(
        cve_id="CVE-2099-1001", title="S", description="D", cvss_score=9.0,
        cvss_severity="Critical", affected_package="openssl", fixed_version="3.0.2-0ubuntu1.18",
    ))
    db.add(models.VulnerabilityMatch(
        asset_id=asset.id, cve_id="CVE-2099-1001", package_name="openssl",
        installed_version="3.0.2-0ubuntu1.10", fixed_version="3.0.2-0ubuntu1.18", affected=True,
    ))
    db.commit()
    return db, asset


def seed_candidate(db, asset, preliminary=70.0):
    db.add(models.RiskAssessment(
        asset_id=asset.id, cve_id="CVE-2099-1001",
        final_score=0.0, risk_level="Low", decision="monitor",
        preliminary_score=preliminary, preliminary_level="High",
        preliminary_decision="scheduled_fix", preliminary_reason="候选基线",
        review_status="candidate", human_review_required=False,
    ))
    db.commit()


def main():
    print("=== 场景一：版本命中但发行版已安全回补 ===")
    db, asset = make_db()
    seed_candidate(db, asset, 70.0)
    # 影响智能体识别到已回补（fixed_version 存在）→ 协调智能体裁定 downgraded
    review.apply_review_verdict(db, {
        "verdict": "downgraded", "confidence": 0.8, "risk_adjustment": -30,
        "evidence_ids": ["asset-1-CVE-2099-1001"], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "发行版已提供安全回补版本，漏洞影响降低",
    }, status="completed")
    risk = db.query(models.RiskAssessment).one()
    check("回补后最终结论降级", risk.final_score == 40.0 and risk.risk_level == "Medium")
    check("研判状态 completed", risk.review_status == "completed" and risk.review_verdict == "downgraded")
    check("整改清单可生成", generate_remediation_tasks(db) == 1)
    db.close()

    print("=== 场景二：版本命中+服务暴露+无eBPF异常 ===")
    db, asset = make_db()
    seed_candidate(db, asset, 75.0)
    # 无运行时异常，但服务暴露 → 协调智能体保持确认/高优先级，写明暂未发现利用迹象
    review.apply_review_verdict(db, {
        "verdict": "confirmed", "confidence": 0.75, "risk_adjustment": 0,
        "evidence_ids": ["asset-1-CVE-2099-1001"], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "公网暴露服务运行受影响版本；暂未发现明确利用迹象，但不因无异常而否定漏洞",
    }, status="completed")
    risk = db.query(models.RiskAssessment).one()
    check("无异常仍确认高危", risk.final_score == 75.0 and risk.risk_level == "High")
    check("理由写明暂未发现利用", "暂未发现明确利用迹象" in (risk.review_reason or ""))
    check("整改清单可生成", generate_remediation_tasks(db) == 1)
    db.close()

    print("=== 场景三：存在eBPF异常但无法可靠关联CVE ===")
    db, asset = make_db()
    seed_candidate(db, asset, 60.0)
    # 运行时智能体标记弱相关 → 协调智能体不得直接输出"已被利用"，要求补充证据
    review.apply_review_verdict(db, {
        "verdict": "insufficient_evidence", "confidence": 0.4, "risk_adjustment": 0,
        "evidence_ids": ["asset-1-CVE-2099-1001"], "conflicts": ["异常事件与CVE因果关系不成立"],
        "missing_evidence": ["进程调用链证据", "网络连接时间线"],
        "human_review_required": True, "reason": "存在运行时异常但无法与CVE建立可靠关联，需人工核查",
    }, status="human_review")
    risk = db.query(models.RiskAssessment).one()
    check("弱关联标记人工复核", risk.human_review_required is True)
    check("不生成虚假最终结论", risk.final_score == 0.0 and risk.risk_level == "Low")
    check("未获准自动生成整改", generate_remediation_tasks(db) == 0)
    db.close()

    print("=== 场景四：关键证据缺失/智能体执行失败 ===")
    db, asset = make_db()
    seed_candidate(db, asset, 65.0)
    review.apply_review_verdict(db, None, status="failed")
    risk = db.query(models.RiskAssessment).one()
    check("失败降级为人工复核", risk.human_review_required is True and risk.review_status == "failed")
    check("不生成虚假结论", risk.final_score == 0.0)
    check("未生成整改", generate_remediation_tasks(db) == 0)
    db.close()

    print("=== 场景五：完整研判成功 ===")
    db, asset = make_db()
    seed_candidate(db, asset, 55.0)
    # 协调智能体 upgraded → 后端校验 → 最终结论写入
    review.apply_review_verdict(db, {
        "verdict": "upgraded", "confidence": 0.85, "risk_adjustment": 20,
        "evidence_ids": ["asset-1-CVE-2099-1001"], "conflicts": [], "missing_evidence": [],
        "human_review_required": False, "reason": "KEV在野利用+公网暴露核心系统，风险应上调",
    }, status="completed")
    risk = db.query(models.RiskAssessment).one()
    check("升级后最终结论写入", risk.final_score == 75.0 and risk.risk_level == "High")
    check("候选与最终区分", risk.preliminary_score == 55.0 and risk.final_score == 75.0)
    check("整改清单可生成", generate_remediation_tasks(db) == 1)
    db.close()

    print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
