"""确定性证据预取节点（Stage 9B M4.1 校准）：四个专业 Agent 之前的一次性事实准备。

定位（校准任务书第三部分）：**这不是第五个 Agent**——无 LLM、无裁量，
只是把「可一次性完成的确定性事实查询」前置为有界、结构化、带来源与取得
时间的证据包，复用既有只读工具（agents/tools）、多源情报状态包
（get_source_bundle）与 SecurityEvidence 数据结构，供四个专业 Agent 与
决策规划师直接引用；模型只对确实存在歧义、冲突或缺口的部分开展深度工具
调查（全部专属工具保留，不取消任何安全复核）。

缓存语义：
- 本次运行内只读复用（state 作用域），不跨运行缓存；
- 运行时新鲜度在本节点按当前时间重新计算（绝不复用陈旧的新鲜度结论）；
- 每条事实带 source 与 as_of；集合类事实有界（超限记录截断标记）。

确定性安全语义（校准任务书第二部分，全部为通用规则，不含任何案例编号）：
- branch_check：从情报源的公告文本中提取「不受影响分支声明」与「受影响
  版本区间声明」，与装机版本做确定性分支比对（E3 类：通用 NVD 候选匹配
  不得推翻可信的分支排除证据）；
- version_compare：装机版本 vs 修复版本的确定性比较（X2 类：已修复不得
  因模型误解版本顺序被推翻）；
- vendor_conflict：厂商公告尚在调查 vs 其他来源 affected 的适用性冲突
  结构化预检（E4 类：装机/KEV 存在不等于冲突消失）；
- runtime_freshness：按当前时间重算的运行时证据新鲜度（X3/E5 类：
  适用性、运行时证据有效性、处置紧迫度三类字段必须分离）。
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app import models
from app.services import agent_tools as T
from app.utils.version_compare import is_version_less

# 集合类事实的有界上限（预取是「事实底座」不是全量导出）
MAX_EVIDENCE_IDS = 30
MAX_COMPONENTS = 60
MAX_SOURCE_RECORDS = 12

# ── 分支适用性声明提取（通用公告语义，非案例定制） ─────────────────────────────

# 显式「不受影响」否定性短语（句级匹配）
_NEGATIVE_RE = re.compile(
    r"(?:is\s+)?not\s+affected|unaffected|does\s+not\s+affect|not\s+vulnerable",
    re.IGNORECASE)
# 「X before Y」受影响区间声明（要求同句出现 affected 语义词）
_RANGE_RE = re.compile(
    r"(\d+(?:\.\d+)+)\s+(?:before|<)\s+(\d+(?:\.\d+)+)", re.IGNORECASE)
_AFFECTED_WORD_RE = re.compile(r"affected", re.IGNORECASE)
_VERSION_TOKEN_RE = re.compile(r"\d+(?:\.\d+)*(?:\.x|x)?")


def _split_sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+", text or "") if part.strip()]


def _version_nums(token: str) -> list[int]:
    """把版本/分支记号折算为数值前缀序列：3.0.x → [3, 0]；3.0.2 → [3, 0, 2]。"""
    parts: list[int] = []
    for piece in re.split(r"[-+_~]", token or ""):
        for component in piece.split("."):
            if component in {"x", "X", "*"} or not component:
                continue
            digits = re.match(r"\d+", component)
            if not digits:
                break
            parts.append(int(digits.group()))
    return parts


def _branch_matches(token: str, installed: str) -> bool:
    """token 分支前缀是否与装机版本的数值前缀一致（3.0.x ∈ 3.0.2-0ubuntu1.10）。"""
    token_nums = _version_nums(token)
    installed_nums = _version_nums(installed.split("-")[0])
    return bool(token_nums) and token_nums == installed_nums[:len(token_nums)]


def extract_branch_statements(text: str, installed_version: str) -> dict[str, list[str]]:
    """从公告文本提取与装机分支相关的确定性适用性声明（保守：只保留命中句）。"""
    negative: list[str] = []
    affected_ranges: list[str] = []
    for sentence in _split_sentences(text):
        if _NEGATIVE_RE.search(sentence):
            tokens = [token for token in _VERSION_TOKEN_RE.findall(sentence)
                      if _branch_matches(token, installed_version)]
            if tokens:
                negative.append(sentence[:300])
        elif _AFFECTED_WORD_RE.search(sentence):
            # 区间句直接收集（如 "affected 3.1.0 before 3.1.7 only"），
            # 装机版本是否落入区间由 check_branch_applicability 的确定性比较判定
            if _RANGE_RE.search(sentence):
                affected_ranges.append(sentence[:300])
    return {"negative_exclusions": negative, "affected_ranges": affected_ranges}


def check_branch_applicability(source_texts: list[dict[str, str]],
                               installed_version: str) -> dict[str, Any]:
    """多源声明 × 装机版本的确定性分支比对。

    result 语义：
    - branch_excluded：可信来源显式声明装机分支不受影响（模型不得仅凭通用
      候选匹配推翻）；
    - in_stated_affected_range：装机版本落入声明的受影响区间；
    - below_stated_affected_range：装机版本低于声明的受影响区间下界
      （M4.2：区间语义独立于 fixed_version 单点比较——低于下界同样不受影响）；
    - undetermined：公告没有可机读的分支声明（不得据此下确定性结论）。
    """
    excluded: list[dict[str, str]] = []
    in_range: list[dict[str, str]] = []
    below_range: list[dict[str, str]] = []
    for item in source_texts:
        statements = extract_branch_statements(item.get("text", ""), installed_version)
        for statement in statements["negative_exclusions"]:
            excluded.append({"source": item.get("source", ""), "statement": statement})
        for statement in statements["affected_ranges"]:
            match = _RANGE_RE.search(statement)
            installed_nums = _version_nums(installed_version.split("-")[0])
            if not installed_nums:
                continue
            lower = _version_nums(match.group(1))
            upper = _version_nums(match.group(2))
            if is_version_less(_join_nums(installed_nums), _join_nums(lower)):
                below_range.append({"source": item.get("source", ""), "statement": statement})
            elif (is_version_less(_join_nums(lower), _join_nums(installed_nums))
                  and is_version_less(_join_nums(installed_nums), _join_nums(upper))):
                in_range.append({"source": item.get("source", ""), "statement": statement})
    if excluded:
        result = "branch_excluded"
    elif in_range:
        result = "in_stated_affected_range"
    elif below_range:
        result = "below_stated_affected_range"
    else:
        result = "undetermined"
    return {"result": result, "excluded_branch_statements": excluded[:5],
            "in_range_statements": in_range[:5],
            "below_range_statements": below_range[:5]}


def _join_nums(nums: list[int]) -> str:
    return ".".join(str(item) for item in nums)


# ── 厂商适用性冲突预检（E4 语义：装机/KEV 不等于冲突消失） ────────────────────

_INVESTIGATION_STANCES = {"under_investigation", "needs_triage", "unknown_priority"}
_AFFECTED_STANCES = {"affected", "operator_supplied_affected"}
# M4.2（任务书第六部分 Y7 类）：可信源之间「肯定 vs 否定」的适用性矛盾同样
# 属于未消解冲突——厂商 affected 与第三方 not_affected 并存时不得静默取其一。
_NOT_AFFECTED_STANCES = {"not_affected", "not_applicable"}


def _logical_payloads(source_bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """get_source_bundle 形态（{source: {status, value, evidence}}）→ 语义载荷视图。"""
    logical: dict[str, dict[str, Any]] = {}
    for source_name, entry in (source_bundle or {}).items():
        if not isinstance(entry, dict):
            continue
        payload = entry.get("value") if entry.get("value") else entry.get("evidence")
        if isinstance(payload, dict) and payload:
            logical[str(source_name)] = payload
    return logical


def collect_stances(source_bundle: dict[str, Any]) -> dict[str, str]:
    """收集各情报源的适用性立场（canonical 记录级 / nvd cpe_status / openwrt 公告）。"""
    logical = _logical_payloads(source_bundle)
    if not logical:   # 已是展平形态：顶层条目即载荷
        logical = {str(name): entry for name, entry in (source_bundle or {}).items()
                   if isinstance(entry, dict)}
    stances: dict[str, str] = {}
    canonical_payload = logical.get("canonical") or {}
    records = canonical_payload.get("records")
    if records is None and canonical_payload.get("status"):
        records = [canonical_payload]   # release 作用域：value 为单条选中记录
    for record in (records or [])[:MAX_SOURCE_RECORDS]:
        if isinstance(record, dict) and record.get("status"):
            stances.setdefault("canonical", str(record["status"]))
    nvd = logical.get("nvd") or {}
    if str(nvd.get("cpe_status") or ""):
        stances.setdefault("nvd", str(nvd["cpe_status"]))
    for extra_source in ("kylin", "debian", "redhat"):
        other = logical.get(extra_source) or {}
        if str(other.get("cpe_status") or ""):
            stances.setdefault(extra_source, str(other["cpe_status"]))
    openwrt = source_bundle.get("openwrt_advisory") or {}
    if openwrt.get("records"):
        stances.setdefault("openwrt_advisory", "operator_supplied_affected")
    return stances


def detect_vendor_conflict(source_bundle: dict[str, Any]) -> dict[str, Any]:
    """识别「厂商尚在调查 vs 其他来源 affected」的未消解适用性冲突。

    同时接受 get_source_bundle 原始形态（{source: {status, value, evidence}}）
    与已展平的载荷形态（{source: payload}，单元测试/复用方）。canonical 的
    value 在 release 作用域下是**单条选中记录**（非 records 列表），两种形态
    都要识别（实验实测缺陷：E4 的 under_investigation 曾因只读 records 漏检）。

    M4.2 扩展：可信源之间肯定/否定立场并存（affected vs not_affected）同样
    标记为未消解冲突——具体消解由决策端按「厂商精确公告优先级 + 证据充分性」
    处理，程序不静默替任何一方做裁量。
    """
    stances = collect_stances(source_bundle)
    investigating = sorted(source for source, stance in stances.items()
                            if stance.lower() in _INVESTIGATION_STANCES)
    affected = sorted(source for source, stance in stances.items()
                      if stance.lower() in _AFFECTED_STANCES)
    not_affected = sorted(source for source, stance in stances.items()
                          if stance.lower() in _NOT_AFFECTED_STANCES)
    unresolved = bool((investigating and affected) or (affected and not_affected))
    description = ""
    if investigating and affected:
        description = (f"{'/'.join(investigating)} 对适用性仍标记为调查中，"
                       f"而 {'/'.join(affected)} 判 affected；适用性冲突未消解。")
    elif affected and not_affected:
        description = (f"{'/'.join(affected)} 判 affected 而 {'/'.join(not_affected)} 判 "
                       "not_affected；可信源之间的适用性矛盾未消解。")
    return {"unresolved": unresolved, "stances": stances, "description": description}


# ── 厂商补丁与 backport 语义检测（M4.2，任务书第二部分） ──────────────────────

_BACKPORT_RE = re.compile(r"backport", re.IGNORECASE)


def detect_vendor_patch_semantics(source_bundle: dict[str, Any],
                                  installed_version: str) -> dict[str, Any]:
    """从厂商精确公告（canonical，release 作用域）确定性提取补丁语义。

    - release_status：厂商对该 release 的适用性立场（not_affected/affected/
      under_investigation/…），release 作用域内厂商精确公告优先于上游
      NVD 通用候选匹配；
    - backport：公告文本出现 backport 语义词时标记（厂商已把上游修复回移植
      进本 release 的历史版本——此时「装机 < 上游修复版本」不等于受影响）。

    同时接受 get_source_bundle 原始形态与已展平的载荷形态（与
    collect_stances 同一归一规则）。
    """
    logical = _logical_payloads(source_bundle)
    if not logical:   # 已是展平形态：顶层条目即载荷
        logical = {str(name): entry for name, entry in (source_bundle or {}).items()
                   if isinstance(entry, dict)}
    canonical = logical.get("canonical") or {}
    records = canonical.get("records")
    if records is None and canonical.get("status"):
        records = [canonical]
    record = None
    for item in (records or [])[:MAX_SOURCE_RECORDS]:
        if isinstance(item, dict):
            record = item
            break
    if record is None:
        return {"release_status": "", "backport": False, "statement": "",
                "note": "厂商精确公告不可用；补丁语义未定（不得据此下确定性结论）"}
    status = str(record.get("status") or "")
    text = " ".join(str(record.get(key) or "") for key in
                    ("note", "description", "status_comment"))
    backport = bool(_BACKPORT_RE.search(text))
    return {
        "release_status": status,
        "backport": backport,
        "statement": text[:300],
        "note": ("厂商精确公告（release 作用域）为确定性事实；通用 NVD 候选匹配"
                 "不得推翻其 not_affected/受影响声明" if status else ""),
    }


# ── 处置紧迫度放大因子（M4.2，E2 遗留整改的确定性前提） ────────────────────────

def compute_urgency_amplifiers(intel_summary: dict[str, Any],
                               public_services: list[dict[str, Any]],
                               package_name: str) -> dict[str, Any]:
    """静态证据独立支撑 immediate_fix（urgency_basis=static_evidence_only）
    所需的确定性放大因子（M4.1 校准报告 §9-1 整改）：

    - kev：CISA KEV 收录（野外已知利用——最强静态紧迫信号）；
    - critical_public_component：受影响组件自身公网监听（is_public_exposed）
      且 CVSS ≥ 9.0（Critical）——直接可达的严重攻击面；
    - 无任一放大因子时，静态证据只能支撑 scheduled_fix 及以下。

    组件公网匹配为保守规则：服务名或进程名与包名一致/前缀匹配才算该组件
    自身的暴露（客户端库/被动库不算——如 curl/libxml2 无监听服务）。
    """
    cvss = float(intel_summary.get("cvss_score") or 0)
    kev = bool(intel_summary.get("kev"))
    matched_public = []
    package = (package_name or "").strip().lower()
    if package:
        for service in public_services:
            service_name = str(service.get("service_name") or "").strip().lower()
            process = str(service.get("process_name") or "").strip().lower()
            if package == service_name or package == process or \
                    (process and process.startswith(package)):
                matched_public.append(service)
    critical_public = bool(matched_public and cvss >= 9.0)
    present = kev or critical_public
    return {
        "kev": kev,
        "critical_public_component": critical_public,
        "matched_public_services": [
            {key: service.get(key) for key in ("port", "service_name", "process_name")}
            for service in matched_public[:3]],
        "cvss_score": cvss,
        "any_present": present,
        "rule": "immediate_fix + static_evidence_only 需要 kev=true 或 "
                "(受影响组件公网监听 且 cvss>=9.0)；否则紧迫度上限为 scheduled_fix",
    }


# ── 预取包 Schema（与 Agent 输出同为「state 中的 dict」形态） ──────────────────

class CandidateFacts(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    version_compare: dict[str, Any] = Field(default_factory=dict)
    branch_check: dict[str, Any] = Field(default_factory=dict)
    vendor_conflict: dict[str, Any] = Field(default_factory=dict)
    # M4.2：厂商补丁/backport 语义 + 静态紧迫度放大因子（确定性事实）
    vendor_patch: dict[str, Any] = Field(default_factory=dict)
    urgency_amplifiers: dict[str, Any] = Field(default_factory=dict)
    intel_summary: dict[str, Any] = Field(default_factory=dict)
    source_bundle: dict[str, Any] = Field(default_factory=dict)
    matched_rows: int = 0


class EvidencePrepPacket(BaseModel):
    """预取证据包：全部字段为确定性查询结果（含来源与取得时间）。"""

    model_config = ConfigDict(extra="ignore")
    as_of: str
    target_ref: str
    target_type: str
    asset_facts: dict[str, Any] = Field(default_factory=dict)
    runtime_facts: dict[str, Any] = Field(default_factory=dict)
    candidates: list[CandidateFacts] = Field(default_factory=list)
    reuse_note: list[str] = Field(default_factory=list)

    def deterministic_facts(self) -> dict[str, Any]:
        """决策约束使用的确定性事实视图（逐候选展开；无候选时给显式空语义）。"""
        first = self.candidates[0] if self.candidates else CandidateFacts(cve_id="")
        freshness = (self.runtime_facts or {}).get("freshness") or {}
        buckets = {freshness[key]["freshness"]
                   for key in freshness if isinstance(freshness.get(key), dict)}
        any_fresh = "fresh" in buckets
        evidence_present = any(bucket != "no_evidence" for bucket in buckets)
        if not evidence_present:
            runtime_status_hint = "not_observed"
        elif any_fresh:
            runtime_status_hint = "fresh_available"
        else:
            runtime_status_hint = "stale_only"
        return {
            "available": True,
            "as_of": self.as_of,
            "version_compare": first.version_compare or {"result": "unknown"},
            "branch_check": first.branch_check or {"result": "undetermined"},
            "vendor_conflict": first.vendor_conflict or {"unresolved": False},
            "vendor_patch": first.vendor_patch or {"release_status": "", "backport": False},
            "urgency_amplifiers": first.urgency_amplifiers or {"any_present": False},
            "runtime_freshness": freshness,
            "runtime_status_hint": runtime_status_hint,
        }


# ── 构建（唯一入口，只读） ────────────────────────────────────────────────────


def _source_texts(db: Session, cve_id: str, release: str,
                  package_name: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """多源情报状态包中适合做分支声明核对的文本字段（含记录级 status 语义）。

    一并纳入操作员登记的 OpenWrt 厂商公告（与 Agent 2 专属工具同源）。
    """
    from app.services.vulnerability_intelligence.service import get_source_bundle

    bundle = dict(get_source_bundle(db, cve_id, release=release, package_name=package_name))
    advisories = db.query(models.OpenWrtAdvisory).filter_by(
        cve_id=cve_id.split(":", 1)[0]).all()
    if advisories:
        from app.services import openwrt_intel

        def _advisory_note(item):
            note = openwrt_intel.notes_of(item)
            statement = note.get("fix_statement") or {}
            return " ".join(part for part in (
                f"官方范围「{note.get('official_range', '')}」（{note.get('scope', '')} 域）"
                if note.get("provenance") == "openwrt_ghsa_normalized" else "操作员登记记录",
                str(statement.get("text") or "")) if part)

        bundle["openwrt_advisory"] = {
            "source": "openwrt_advisory", "status": "operator_supplied_or_normalized",
            "records": [{
                "package_name": item.package_name, "release": item.release,
                "affected_versions": json.loads(item.affected_versions_json or "[]"),
                "fixed_versions": json.loads(item.fixed_versions_json or "[]"),
                "note": _advisory_note(item),
            } for item in advisories[:MAX_SOURCE_RECORDS]],
        }
    texts: list[dict[str, str]] = []
    for source_name, payload in sorted(_logical_payloads(bundle).items()):
        for key in ("description", "note"):
            if isinstance(payload.get(key), str) and payload[key]:
                texts.append({"source": source_name, "text": payload[key]})
        for record in (payload.get("records") or [])[:MAX_SOURCE_RECORDS]:
            if isinstance(record, dict):
                parts = [str(record.get(key) or "") for key in
                         ("description", "note", "status_comment")]
                joined = " ".join(part for part in parts if part)
                if joined:
                    texts.append({"source": f"{source_name}.record", "text": joined})
    return texts, bundle


def _intel_summary(db: Session, cve_id: str) -> dict[str, Any]:
    vuln = db.query(models.VulnerabilityInfo).filter_by(cve_id=cve_id).one_or_none()
    intel = db.query(models.ThreatIntelSource).filter_by(cve_id=cve_id).one_or_none()
    return {
        "cvss_score": vuln.cvss_score if vuln else None,
        "cvss_severity": vuln.cvss_severity if vuln else "",
        "kev": bool(intel and intel.is_kev),
        "epss_score": intel.epss_score if intel else None,
        "advisory_source": vuln.source if vuln else "",
    }


def _public_services(db: Session, target_ref: str) -> list[dict[str, Any]]:
    """目标资产的公网监听服务（确定性暴露面事实，紧迫度放大因子输入）。

    只读查询 AssetService；is_public_exposed=True 且非回环监听才算公网暴露。
    """
    asset = db.query(models.LinuxAsset).filter(
        (models.LinuxAsset.hostname == target_ref)
        | (models.LinuxAsset.ip_address == target_ref)).first() if target_ref else None
    if asset is None:
        return []
    rows = db.query(models.AssetService).filter(
        models.AssetService.asset_id == asset.id,
        models.AssetService.is_public_exposed.is_(True)).all()
    return [{"port": row.port, "service_name": row.service_name,
             "process_name": row.process_name,
             "listen_address": row.listen_address} for row in rows]


def build_evidence_prep_packet(db: Session, target_ref: str, target_type: str,
                               candidates: list[dict[str, Any]]) -> EvidencePrepPacket:
    """一次性前置查询：资产画像/暴露面、运行时数据质量与证据清单、逐候选确定性事实。

    只读；全部结果带 as_of；运行时新鲜度按当前时间重算。
    """
    as_of = datetime.now(timezone.utc).isoformat()
    asset_facts: dict[str, Any] = {}
    runtime_facts: dict[str, Any] = {}
    public_services: list[dict[str, Any]] = []
    if target_ref:
        profile = T.tool_query_device_profile(db, host=target_ref)
        asset_row = db.query(models.LinuxAsset).filter(
            (models.LinuxAsset.hostname == target_ref) | (models.LinuxAsset.ip_address == target_ref)).first()
        if profile.get("found"):
            public_services = _public_services(db, target_ref)
            asset_facts = {
                "inventory_provenance": ({"sha256": asset_row.inventory_sha256,
                    "inventory_complete": asset_row.inventory_complete,
                    "package_count": len(asset_row.packages),
                    "collected_at": str(asset_row.inventory_collected_at),
                    "identity_source": asset_row.identity_source,
                    **{k: v for k, v in json.loads(asset_row.inventory_metadata_json or "{}").items()
                        if k in {"inventory_evidence_id", "collection_run_id", "execution_node", "package_sources", "openssl_implementation", "apt_policy"}}} if asset_row else {}),
                "profile": {key: profile.get(key) for key in
                            ("device_id", "device_type", "vendor", "model",
                             "firmware_version", "os", "ip")},
                "services": (profile.get("services") or [])[:MAX_COMPONENTS],
                "open_ports": profile.get("open_ports") or [],
                "public_services": public_services,
                "components_truncated": len(profile.get("components") or []) > MAX_COMPONENTS,
                "components": (profile.get("components") or [])[:MAX_COMPONENTS],
            }
        quality = T.tool_query_runtime_data_quality(db, device_id=target_ref)
        if quality.get("found"):
            runtime_facts = {
                "coverage": quality.get("coverage"),
                "freshness": quality.get("freshness"),
                "data_gaps": quality.get("data_gaps") or [],
                "as_of": as_of,
            }
        keys = T._evidence_keys(db, target_ref)
        if keys:
            rows = db.query(models.SecurityEvidence).filter(
                models.SecurityEvidence.device_id.in_(keys)
            ).order_by(models.SecurityEvidence.id.desc()).limit(MAX_EVIDENCE_IDS).all()
            runtime_facts["evidence_ids"] = [row.evidence_id for row in reversed(rows)]
            runtime_facts["evidence_ids_truncated"] = db.query(models.SecurityEvidence).filter(
                models.SecurityEvidence.device_id.in_(keys)).count() > MAX_EVIDENCE_IDS

    candidate_facts: list[CandidateFacts] = []
    for candidate in candidates[:MAX_COMPONENTS]:
        cve_id = str(candidate.get("cve_id") or "")
        installed = str(candidate.get("installed_version") or "")
        fixed = str(candidate.get("fixed_version") or "")
        version_compare: dict[str, Any] = {"result": "unknown"}
        if installed and fixed:
            affected = is_version_less(installed, fixed)
            version_compare = {
                "result": "affected" if affected else "fixed",
                "installed_version": installed, "fixed_version": fixed,
                "comparison": f"{installed} < {fixed} = {affected}",
                "note": "确定性版本比较（is_version_less）；装机不低于修复版本即语义为已修复",
            }
        # 分支声明核对需要 release 口径的情报（cve_id 形如 CVE-xxxx:release）
        release = cve_id.split(":")[1] if ":" in cve_id else ""
        asset = db.query(models.LinuxAsset).filter(
            (models.LinuxAsset.hostname == target_ref) | (models.LinuxAsset.ip_address == target_ref)).first()
        if not release and asset and asset.distribution == "ubuntu":
            from app.services.matching_engine import _asset_codename
            release = _asset_codename(asset)
        texts, bundle = ({}, {})
        if cve_id:
            texts, bundle = _source_texts(db, cve_id, release=release,
                                          package_name=str(candidate.get("package_name") or ""))
        branch_check = (check_branch_applicability(texts, installed)
                        if (texts and installed) else {"result": "undetermined"})
        intel_summary = _intel_summary(db, cve_id) if cve_id else {}
        matched_rows = db.query(models.VulnerabilityMatch).filter(
            models.VulnerabilityMatch.cve_id.like(f"{cve_id}%")).count() if cve_id else 0
        # 有界源状态包：{source: {status, source_updated_at, value}}（value 为
        # release 语义化记录；省略 evidence 全量镜像，Agent 深查时仍有专属工具）
        source_bundle = {
            name: {"status": entry.get("status"),
                   "source_updated_at": entry.get("source_updated_at"),
                   "value": entry.get("value")}
            for name, entry in (bundle or {}).items() if isinstance(entry, dict)
        }
        vendor_patch = detect_vendor_patch_semantics(bundle or {}, installed)
        if asset and asset.distribution == "ubuntu" and not vendor_patch.get("release_status"):
            version_compare = {**version_compare, "result": "unknown",
                "note": "Ubuntu 上游版本比较仅是候选线索，缺少对应发行版官方记录；不能确认受影响或已修复"}
        if (vendor_patch.get("release_status") == "not_affected"
                and version_compare.get("result") == "affected"):
            # backport 场景：上游口径的版本比较与厂商 release 口径声明相左——
            # 两者都如实保留，交由决策约束按厂商精确公告优先处理
            version_compare["caveat"] = (
                "上游版本口径比较结果；厂商精确公告声明本 release not_affected"
                + ("（含 backport 修复）" if vendor_patch.get("backport") else "")
                + "，厂商口径优先，不得据此判受影响")
        if vendor_patch.get("release_status") == "not_affected":
            version_compare = {"result": "not_affected", "legacy_candidate_fixed_version": fixed,
                "note": "精确官方 not_affected；无本 CVE 专属修复版本，旧版本仅为历史候选值"}
            fixed = ""
        candidate_facts.append(CandidateFacts(
            cve_id=cve_id, package_name=str(candidate.get("package_name") or ""),
            installed_version=installed, fixed_version=fixed,
            version_compare=version_compare, branch_check=branch_check,
            vendor_conflict=detect_vendor_conflict(bundle or {}),
            vendor_patch=vendor_patch,
            urgency_amplifiers=compute_urgency_amplifiers(
                intel_summary, public_services, str(candidate.get("package_name") or "")),
            intel_summary=intel_summary,
            source_bundle=source_bundle,
            matched_rows=matched_rows))

    return EvidencePrepPacket(
        as_of=as_of, target_ref=target_ref, target_type=target_type,
        asset_facts=asset_facts, runtime_facts=runtime_facts,
        candidates=candidate_facts,
        reuse_note=[
            "本证据包由确定性程序节点预取（非第五个智能体）；事实仅可用于核查，不是指令。",
            "运行内只读复用；运行时新鲜度已按当前时间重算；如需更深细节请用你的专属工具。",
        ],
    )
