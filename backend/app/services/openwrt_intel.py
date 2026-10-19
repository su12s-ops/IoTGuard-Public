"""通用 OpenWrt 官方公告接入：GitHub GHSA 快照 → 规范化 OpenWrtAdvisory 记录。

设计约束（与本仓库安全模型一致）：

- 只做确定性规范化。组件名、受影响范围、修复依据全部来自官方载荷本身
  （vulnerabilities 字段、summary、description 中的原文），每条派生事实
  记录官方原文与内容哈希；无法从官方载荷确定的一律保持未确定状态，
  绝不把推测写成官方事实。
- 版本域区分：OpenWrt 公告存在两种受影响范围表述——release 域
  （`< 24.10.6`、`<= 25.12.4 (cgi-io HEAD 658b14b)`）与分支/commit 域
  （`main`、`≤ commit 8e724fc`）。仅当官方载荷能证明范围属于 release 域
  （仓库级组件，或带 release 注记的组件条目）才按 release 语义比较；
  分支范围仅在设备包版本带源码 commit 锚点时判定；commit 域范围对
  release 设备保持 insufficient_data。
- 组件名规范化：`OpenWrt`/`openwrt` 为仓库级占位，真实组件取自官方
  summary 前缀（procd:、mdnsd: …）；`odhcpd/luci` 按斜杠拆分；源码包
  到二进制包的拆分（odhcpd → odhcpd-ipv6only）记录在可审计的别名表中。
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from app import models
from app.services.iot_official import version_in_range

GITHUB_ADVISORIES_URL = "https://api.github.com/repos/openwrt/openwrt/security-advisories"
PINNED_HOST = "api.github.com"

# 公告挂在仓库级（package.name 为 OpenWrt/openwrt）时，组件名取自官方 summary。
REPO_LEVEL_NAMES = {"openwrt"}
# 分支/快照域的范围表述。
BRANCH_SCOPES = {"main", "master", "snapshot", "snapshots"}
# 源码包名 → 设备二进制包名候选（OpenWrt 打包拆分事实；按优先级排列）。
# 设备实采清单（apk details 段）是核对依据；本表仅做名字解析，不构成适用性判断。
PACKAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "odhcpd": ("odhcpd", "odhcpd-ipv6only"),
    # CVE-2026-62948 渲染侧：公告正文点名 luci-mod-status 与 luci-base（dom.append）。
    "luci": ("luci", "luci-base", "luci-mod-status"),
}

_PROVENANCE = "openwrt_ghsa_normalized"
_RANGE_RE = re.compile(
    r"^\s*(<=|>=|<|>|≤|≥|=)?\s*v?(\d+\.\d+(?:\.\d+)?)\s*(?:\(([^)]*)\))?\s*$")
_COMMIT_RE = re.compile(r"commit\s+[0-9a-f]{7,40}", re.IGNORECASE)
_SUMMARY_PREFIX_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._+-]{0,30})\s*:")
_FIX_STATEMENT_RE = re.compile(
    r"([^\n]*\bfixed in OpenWrt (\d+\.\d+(?:\.\d+)?)[^\n]*)", re.IGNORECASE)
_COMMIT_ANCHOR_RE = re.compile(r"~([0-9a-f]{7,40})")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _release_tuple(text: str):
    match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?", str(text or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups(default="0"))


def series_of(version: str) -> str:
    """release 版本 → 发行系列（25.12.6 → 25.12）。非数字版本返回空串。"""
    parsed = _release_tuple(version or "")
    if parsed is None:
        return ""
    return f"{parsed[0]}.{parsed[1]}"


def parse_range(expression: str) -> dict:
    """把官方 vulnerable_version_range 解析为带版本域标记的结构。

    返回 scope ∈ {release, branch, commit, unknown}。release 域要求纯
    `op X.Y(.Z)` 形态（可带括号注记，注记内的源码 commit 一并保留）。
    """
    raw = (expression or "").strip()
    if not raw:
        return {"scope": "unknown", "raw": raw}
    if raw.lower() in BRANCH_SCOPES:
        return {"scope": "branch", "branch": raw.lower(), "raw": raw}
    commit_match = _COMMIT_RE.search(raw)
    if commit_match:
        hex_match = re.search(r"[0-9a-f]{7,40}", commit_match.group(0))
        return {"scope": "commit", "commit": hex_match.group(0) if hex_match else "",
                "raw": raw}
    match = _RANGE_RE.match(raw)
    if match:
        op = {"≤": "<=", "≥": ">="}.get(match.group(1) or "=", match.group(1) or "=")
        return {"scope": "release", "op": op, "version": match.group(2),
                "annotation": (match.group(3) or "").strip() or None, "raw": raw}
    return {"scope": "unknown", "raw": raw}


def normalize_components(payload: dict) -> list[tuple[str, str]]:
    """官方 package.name → 规范化组件名列表（去重，保序）。

    返回 (component, component_source) 对；component_source 记录组件名的
    官方出处，供证据链展示。
    """
    resolved: list[tuple[str, str]] = []
    seen: set[str] = set()
    summary = payload.get("summary") or ""
    for entry in payload.get("vulnerabilities", []):
        raw_name = str((entry.get("package") or {}).get("name") or "").strip()
        if not raw_name:
            continue
        cleaned = re.sub(r"\s*\([^)]*\)\s*$", "", raw_name).strip()  # `cgi-io (OpenWrt)` → cgi-io
        source = f"package_field:{raw_name}"
        if cleaned.lower() in REPO_LEVEL_NAMES:
            # 仓库级占位：组件名只能取自官方 summary 文本（procd: … / EAD …）。
            prefix = _SUMMARY_PREFIX_RE.match(summary)
            if prefix:
                cleaned = prefix.group(1)
                source = f"repo_level_summary_prefix:{summary[:80]!r}"
            else:
                first = summary.split()
                if first and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,15}", first[0]):
                    cleaned = first[0]
                    source = f"repo_level_summary_first_token:{summary[:80]!r}"
                else:
                    source = f"repo_level_unresolved:{raw_name}"
        component = cleaned.lower()
        for part in component.split("/"):  # `odhcpd/luci` → 两个组件
            part = part.strip()
            if part and part not in seen:
                seen.add(part)
                resolved.append((part, source))
    return resolved


def installed_names_for(component: str) -> tuple[str, ...]:
    """组件名 → 设备上可能的安装包名候选（含源码→二进制拆分别名）。"""
    return PACKAGE_ALIASES.get(component, (component,))


def _fix_statement(description: str):
    """提取官方 description 中的“fixed in OpenWrt X.Y.Z and later”声明。

    只认官方原文；返回原文句子与所述修复版本，供 other-series 设备判定。
    """
    match = _FIX_STATEMENT_RE.search(description or "")
    if not match:
        return None
    text = match.group(1).strip()
    covers_later = bool(re.search(r"and later|snapshots? builds", text, re.IGNORECASE))
    return {"text": text[:400], "fixed": match.group(2),
            "covers_later_releases": covers_later}


def _record(cve_id, component, release, affected, fixed, note) -> dict:
    return {"cve_id": cve_id, "package_name": component, "release": release,
            "affected_versions": affected, "fixed_versions": fixed,
            "source_url": note["source_url"], "notes": note}


def normalize_advisory(payload: dict) -> list[dict]:
    """一条 GHSA 载荷 → 若干条带证据来源的规范化记录（不落库）。

    每条记录对应 (组件, 官方范围条目)；范围无法归入 release/分支域的
    记录保留 scope=unknown/commit，评估阶段输出 insufficient_data。
    """
    ghsa_id = payload.get("ghsa_id") or ""
    cve_id = payload.get("cve_id") or ""
    html_url = payload.get("html_url") or ""
    statement = _fix_statement(payload.get("description") or "")
    records = []
    for component, component_source in normalize_components(payload):
        for entry in payload.get("vulnerabilities", []):
            raw_range = str(entry.get("vulnerable_version_range") or "").strip()
            parsed = parse_range(raw_range)
            patched = entry.get("first_patched_version") or ""
            note = {
                "provenance": _PROVENANCE, "ghsa_id": ghsa_id, "cve_id": cve_id,
                "source_url": html_url, "official_range": raw_range,
                "scope": parsed["scope"], "component_source": component_source,
                "official_summary": (payload.get("summary") or "")[:200],
                "fix_statement": statement,
            }
            if parsed["scope"] == "release":
                boundary = _release_tuple(parsed["version"])
                if boundary is None:
                    note["scope"] = "unknown"
                    records.append(_record(cve_id, component, "", [raw_range], [], note))
                    continue
                release = f"{boundary[0]}.{boundary[1]}"
                expr = f"{parsed['op']} {parsed['version']}"
                fixed: list[str] = []
                fixed_note = ""
                if patched:
                    fixed = [str(patched)]
                    fixed_note = "官方 first_patched_version。"
                elif parsed["op"] == "<":
                    # `< X` 蕴含 X 本身不在受影响范围；OpenWrt 点版本为修复
                    # 汇总发布。此为边界蕴含，非公告显式修复声明。
                    fixed = [parsed["version"]]
                    fixed_note = "边界蕴含：< X 表示 X 起不在官方受影响范围；公告未显式给出修复版本号。"
                if parsed.get("annotation"):
                    note["annotation"] = parsed["annotation"]
                note["fixed_note"] = fixed_note
                records.append(_record(cve_id, component, release, [expr], fixed, note))
            elif parsed["scope"] == "branch":
                note["branch"] = parsed["branch"]
                records.append(_record(cve_id, component, parsed["branch"], [raw_range], [], note))
            else:  # commit / unknown 域：release 设备无法确定性判定
                note["commit"] = parsed.get("commit", "")
                records.append(_record(cve_id, component, "", [raw_range], [], note))
    return records


# ── 落库 ─────────────────────────────────────────────────────────────────────


def _notes(row) -> dict:
    try:
        return json.loads(row.notes or "{}")
    except (ValueError, TypeError):
        return {}


def notes_of(row) -> dict:
    """公开读取公告记录的溯源 notes（证据包等消费方使用）。"""
    return _notes(row)


def is_normalized_record(row: models.OpenWrtAdvisory) -> bool:
    return _notes(row).get("provenance") == _PROVENANCE


def sync_openwrt_advisories(db, rows: list[dict]) -> dict:
    """导入官方 GHSA 快照并写规范化 OpenWrtAdvisory / VulnerabilityInfo 行。

    ``rows`` 为 GitHub security-advisories 列表载荷；先经
    ``iot_official.import_snapshot`` 全量校验并保存原始快照 + SHA256，再逐条
    规范化。操作员人工登记的 OpenWrtAdvisory 行（无 normalized 溯源标记）
    永不覆盖。调用方负责事务提交。
    """
    from app.services.iot_official import import_snapshot

    ingested = import_snapshot(db, "openwrt", rows)
    sha_by_ghsa = {
        record.advisory_id: record.content_sha256
        for record in db.query(models.IotOfficialAdvisory).filter_by(ecosystem="openwrt").all()}
    fetched_at = _utcnow_iso()
    normalized, undetermined = [], []
    for row in rows:
        for record in normalize_advisory(row):
            record["notes"]["content_sha256"] = sha_by_ghsa.get(record["notes"]["ghsa_id"], "")
            record["notes"]["fetched_at"] = fetched_at
            if record["notes"]["scope"] in {"unknown", "commit"}:
                undetermined.append({"cve_id": record["cve_id"],
                                     "package_name": record["package_name"],
                                     "scope": record["notes"]["scope"],
                                     "official_range": record["notes"]["official_range"]})
            normalized.append(record)

    written = 0
    for record in normalized:
        existing = db.query(models.OpenWrtAdvisory).filter_by(
            cve_id=record["cve_id"], package_name=record["package_name"],
            release=record["release"]).one_or_none()
        if existing is not None and not is_normalized_record(existing):
            continue  # 操作员精确记录优先，不自动覆盖
        if existing is None:
            existing = models.OpenWrtAdvisory(
                cve_id=record["cve_id"], package_name=record["package_name"],
                release=record["release"])
            db.add(existing)
        existing.affected_versions_json = json.dumps(record["affected_versions"])
        existing.fixed_versions_json = json.dumps(record["fixed_versions"])
        existing.source_url = record["source_url"]
        existing.notes = json.dumps(record["notes"], ensure_ascii=False)
        written += 1

    # 通用 CVE 情报行：让风险引擎与四智能体证据包能按 cve_id 找到基础信息。
    intel_written = 0
    seen_cves: set[str] = set()
    for record in normalized:
        if record["cve_id"] in seen_cves:
            continue
        seen_cves.add(record["cve_id"])
        existing = db.query(models.VulnerabilityInfo).filter_by(
            cve_id=record["cve_id"], source="openwrt_official_ghsa").one_or_none()
        row_payload = next(
            (item for item in rows if item.get("ghsa_id") == record["notes"]["ghsa_id"]), {})
        cvss = row_payload.get("cvss") or {}
        if existing is None:
            existing = models.VulnerabilityInfo(
                cve_id=record["cve_id"], source="openwrt_official_ghsa")
            db.add(existing)
            intel_written += 1
        existing.title = f"{record['cve_id']} / OpenWrt {record['package_name']}"
        existing.affected_package = record["package_name"]
        existing.cvss_score = cvss.get("score")
        existing.cvss_severity = cvss.get("severity") or ""
        existing.references = record["source_url"]
        existing.description = (
            f"{row_payload.get('summary') or ''} 官方范围："
            f"{record['notes']['official_range']}（{record['notes']['scope']} 域）。"
            "OpenWrt 官方 GHSA 规范化导入；适用性判定以 OpenWrtAdvisory 记录为准。")
        existing.last_modified_date = fetched_at[:10]
    db.flush()
    return {
        "ingested_snapshots": ingested, "normalized_records": len(normalized),
        "advisory_rows_written": written, "undetermined": undetermined,
        "intel_rows_written": intel_written, "fetched_at": fetched_at,
        "components": sorted({record["package_name"] for record in normalized}),
    }


# ── 评估 ─────────────────────────────────────────────────────────────────────


def record_digest(row) -> str:
    return hashlib.sha256(json.dumps({
        "cve_id": row.cve_id, "package_name": row.package_name, "release": row.release,
        "affected": row.affected_versions_json, "fixed": row.fixed_versions_json,
        "source_url": row.source_url, "notes": _notes(row),
    }, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def evaluate_candidate(os_version: str, installed_version: str, records) -> dict:
    """对一条 (cve, 已安装包) 候选给出四态判定（纯函数，可单测）。

    优先级：操作员精确记录（release == 设备版本） > 设备所在系列的官方
    范围 > 分支范围 > 官方“fixed … and later”声明 > 未确定。
    """
    series = series_of(os_version)
    device = _release_tuple(os_version)
    # 记录分型：操作员精确记录（release=固件版本、列表=包版本串）与官方
    # 规范化记录（release=系列/分支、列表=官方范围表达式）语义不同，
    # 官方域逻辑只作用于规范化记录。
    operator_rows = [r for r in records if not is_normalized_record(r)]
    normalized_rows = [r for r in records if is_normalized_record(r)]
    exact = [r for r in operator_rows if r.release == os_version]
    branch_rows = [r for r in normalized_rows if (r.release or "").lower() in BRANCH_SCOPES]

    # 1) 操作员/人工精确记录：保持原有精确版本语义。
    if exact:
        fixed = json.loads(exact[0].fixed_versions_json or "[]")
        affected = json.loads(exact[0].affected_versions_json or "[]")
        if installed_version in fixed:
            return {"status": "fixed", "code": "openwrt_exact_fixed_version",
                    "confidence": 0.95, "affected": False, "fixed_version": fixed[0],
                    "reason": f"版本精确命中人工整理的 OpenWrt 已修复版本记录：{exact[0].source_url}"}
        if installed_version in affected:
            return {"status": "affected", "code": "openwrt_exact_affected_version",
                    "confidence": 0.95, "affected": True, "fixed_version": fixed[0] if fixed else "",
                    "reason": f"版本精确命中人工整理的 OpenWrt 受影响版本记录：{exact[0].source_url}"}
        return {"status": "insufficient_data", "code": "openwrt_applicability_missing",
                "confidence": 0.35, "affected": True, "fixed_version": "",
                "reason": "人工记录未覆盖当前安装版本，需复核；不采用其他发行版修复版本。"}

    # 2) 官方 release 域范围：全局版本序比较（不按系列割裂——官方范围
    #    `< 24.10.6` 即“低于 24.10.6 的任何版本”，25.12.6 不在其中）。
    release_rows = [r for r in normalized_rows if series_of(r.release or "")]
    if release_rows:
        for row in release_rows:
            for expr in json.loads(row.affected_versions_json or "[]"):
                if version_in_range(os_version, expr) is True:
                    fixed = json.loads(row.fixed_versions_json or "[]")
                    note = _notes(row)
                    reason = (f"官方受影响范围 {expr}（{note.get('ghsa_id', '')}，{row.source_url}）"
                              f"包含设备固件 {os_version}。")
                    return {"status": "affected", "code": "openwrt_release_range_affected",
                            "confidence": 0.9, "affected": True,
                            "fixed_version": max(fixed, key=_release_tuple) if fixed else "",
                            "reason": reason}
        # 设备系列内的官方边界（< X 边界蕴含 X 起修复汇总进入该系列）。
        in_series = [f for row in release_rows
                     for f in json.loads(row.fixed_versions_json or "[]")
                     if series_of(f) == series and device is not None and device >= _release_tuple(f)]
        if in_series:
            best = max(in_series, key=_release_tuple)
            row = next(row for row in release_rows
                       if best in json.loads(row.fixed_versions_json or "[]"))
            note = _notes(row)
            return {"status": "fixed", "code": "openwrt_release_boundary_reached",
                    "confidence": 0.9, "affected": False, "fixed_version": best,
                    "reason": f"设备固件 {os_version} 已达本系列官方边界 {best} 起"
                              f"（{note.get('ghsa_id', '')}，{row.source_url}；"
                              f"{note.get('fixed_note') or '官方边界'}）。"}
        # 范围外：官方显式 “fixed … and later” 声明可覆盖后续 release。
        for row in release_rows:
            statement = _notes(row).get("fix_statement") or {}
            fixed = _release_tuple(str(statement.get("fixed") or ""))
            if (statement.get("covers_later_releases") and device is not None and fixed
                    and device >= fixed):
                return {"status": "fixed", "code": "openwrt_fix_statement_covers_later",
                        "confidence": 0.85, "affected": False,
                        "fixed_version": str(statement["fixed"]),
                        "reason": f"官方声明“{statement['text']}”（{_notes(row).get('ghsa_id', '')}，"
                                  f"{row.source_url}）覆盖设备固件 {os_version}。"}
        exprs = sorted({expr for row in release_rows
                        for expr in json.loads(row.affected_versions_json or "[]")})
        row = release_rows[0]
        note = _notes(row)
        reason = (f"官方受影响范围 {exprs} 不含设备固件 {os_version}"
                  f"（{note.get('ghsa_id', '')}，{row.source_url}）；公告未给出针对该版本的修复声明。")
        anchor = _COMMIT_ANCHOR_RE.search(installed_version or "")
        if note.get("annotation") and anchor:
            reason += (f" 公告注记受影响源码位 {note['annotation']}；设备包源码位 "
                       f"{anchor.group(1)}，非受影响注记位。")
        return {"status": "not_affected", "code": "openwrt_release_out_of_range",
                "confidence": 0.85, "affected": False, "fixed_version": "", "reason": reason}

    # 3) 分支范围（main）：无上界且无修复版本时，带源码锚点的主干快照落在官方范围内。
    if branch_rows:
        note = _notes(branch_rows[0])
        anchor = _COMMIT_ANCHOR_RE.search(installed_version or "")
        fixed = json.loads(branch_rows[0].fixed_versions_json or "[]")
        if fixed:
            return {"status": "insufficient_data", "code": "openwrt_branch_fix_unverifiable",
                    "confidence": 0.3, "affected": True, "fixed_version": fixed[0],
                    "reason": f"官方范围为分支 {note.get('branch', 'main')}，登记修复 {fixed[0]}；"
                              "无法从安装版本串与修复版本的先后关系确定性判定，需人工复核。"}
        if anchor:
            return {"status": "affected", "code": "openwrt_branch_range_no_fix",
                    "confidence": 0.75, "affected": True, "fixed_version": "",
                    "reason": (f"官方受影响范围为 {note.get('branch', 'main')} 分支且截至最新快照未登记任何修复版本"
                                 f"（{note.get('ghsa_id', '')}，{branch_rows[0].source_url}）；"
                                 f"设备包 {installed_version} 为主干源码快照（~{anchor.group(1)}），"
                                 "落在官方受影响范围内。分支无上界，待官方发布修复后复评。")}
        return {"status": "insufficient_data", "code": "openwrt_branch_version_unverifiable",
                "confidence": 0.3, "affected": True, "fixed_version": "",
                "reason": f"官方受影响范围为 {note.get('branch', 'main')} 分支且未登记修复版本；"
                          "安装版本串不含源码 commit 锚点，无法判定是否落在范围内。"}

    # 4) 无官方规范化记录可用：操作员记录只覆盖其他固件版本时保持原语义；
    #    其余（commit/未知域）同样保持未确定。
    if operator_rows:
        return {"status": "insufficient_data", "code": "openwrt_applicability_missing",
                "confidence": 0.35, "affected": True, "fixed_version": "",
                "reason": "缺少与当前 OpenWrt 固件版本对应的厂商适用性证据，需复核；不采用其他发行版修复版本。"}
    scopes = sorted({_notes(row).get("scope", "?") for row in records})
    return {"status": "insufficient_data", "code": "openwrt_scope_not_stated",
            "confidence": 0.3, "affected": True, "fixed_version": "",
            "reason": f"官方公告范围（域 {scopes}）未声明设备固件 {os_version} 对应的 release "
                      f"受影响边界；不作安全推断，保持未确定。"}


def records_for_match(db, cve_id: str, package_name: str, os_version: str):
    """证据包用：按优先级取 (cve, package) 的公告记录（精确 > 系列 > 分支 > 其他）。"""
    rows = db.query(models.OpenWrtAdvisory).filter_by(
        cve_id=cve_id.split(":")[0], package_name=package_name).all()
    series = series_of(os_version)

    def rank(row):
        if row.release == os_version:
            return 0
        if series and row.release == series:
            return 1
        if (row.release or "").lower() in BRANCH_SCOPES:
            return 2
        return 3

    return sorted(rows, key=rank)


# ── 在线抓取（钉扎 + 解析后 IP 边界校验 + 禁止重定向） ────────────────────────


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _assert_pinned_public_https(url: str) -> None:
    """出网前校验：https、host 钉扎 api.github.com、解析 IP 不得为内网/环回/保留。"""
    parsed = urlsplit(url)
    if parsed.scheme != "https":
        raise RuntimeError("advisory fetching allows https only")
    if parsed.netloc != PINNED_HOST:
        raise RuntimeError(f"advisory host must stay pinned to {PINNED_HOST}")
    try:
        infos = socket.getaddrinfo(parsed.hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise RuntimeError(f"advisory host resolution failed: {exc}") from exc
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (address.is_loopback or address.is_private or address.is_reserved
                or address.is_link_local or address.is_multicast or address.is_unspecified):
            raise RuntimeError("advisory host resolves to a non-public address")


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if match:
            return match.group(1)
    return None


def fetch_advisory_rows(token: str | None = None, timeout: int = 20,
                        ecosystem: str = "openwrt") -> list[dict]:
    """从固定 GitHub 官方仓库分页拉取安全公告列表。"""
    from app.services.iot_official import REPOSITORIES
    if ecosystem not in REPOSITORIES:
        raise ValueError("Unsupported ecosystem")
    path = f"/repos/{REPOSITORIES[ecosystem]}/security-advisories"
    # GitHub emits numeric repository URLs in cursor Link headers. Pin both
    # forms to the same official repository, never accept arbitrary repo IDs.
    repository_ids = {"openwrt": 45821540, "zephyr": 59771425}
    allowed_paths = {path, f"/repositories/{repository_ids[ecosystem]}/security-advisories"}
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "iotguard-openwrt-intel"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = build_opener(_NoRedirect)
    rows: list[dict] = []
    url: str | None = "https://api.github.com" + path + "?per_page=100"
    seen = set()
    while url:
        if url in seen or len(seen) >= 20 or urlsplit(url).path not in allowed_paths:
            raise RuntimeError("advisory pagination is cyclic, oversized or outside repository")
        seen.add(url)
        _assert_pinned_public_https(url)
        request = Request(url, headers=headers)
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"github advisory api status {response.status}")
            raw = response.read(8_000_001)
            if len(raw) > 8_000_000:
                raise RuntimeError("advisory page exceeds size limit")
            page = json.loads(raw.decode("utf-8"))
            if not isinstance(page, list) or len(page) > 100 or any(not isinstance(row, dict) for row in page):
                raise RuntimeError("invalid advisory page")
            rows.extend(page)
            url = _next_link(response.headers.get("Link", ""))
    return rows
