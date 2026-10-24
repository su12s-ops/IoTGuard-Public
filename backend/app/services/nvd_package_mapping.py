"""NVD → 发行版包名的映射语义（唯一事实来源）。

安全规则（修复「描述子串猜测包名」缺陷）：
- 只有 NVD CPE 的 vendor/product 精确映射（含 ``PACKAGE_ALIASES`` 显式发行版
  别名表）才可以产生 ``affected_package``；
- 没有 CPE 产品时一律返回未映射哨兵 ``UNMAPPED_PACKAGE``，禁止用描述/引用
  文本里的包名子串猜测（历史事故：vm2、WordPress SAML 插件、
  OpenSSH-for-Windows、openssl_encrypt 等公告被误映射到 openssl/openssh-server）。
- 下游 matching_engine 对未映射包名给出显式 ``not_applicable`` /
  ``affected_package_unmapped`` 结论，而不是静默变成 unknown/affected。
"""
from __future__ import annotations

UNMAPPED_PACKAGE = ""
UNMAPPED_PACKAGE_REASON = "no_exact_cpe_product_mapping"
# 历史数据中的未映射哨兵；matching_engine 与审计脚本使用同一集合。
UNMAPPED_PACKAGE_SENTINELS = frozenset({"", "unknown", "unmapped", "unmapped_nvd"})

# 维护脚本写入的不可选状态：NVD 包名来源无法精确复核，隔离在正式研判之外。
# 它不属于 REVIEWABLE_STATUSES，也不是 reanalysis_required（后者仍可被选择）。
QUARANTINED_MAPPING_STATUS = "quarantined_mapping"
QUARANTINED_MAPPING_REASON = "nvd_package_mapping_not_exactly_verifiable"


def is_unmapped_package(package_name: str | None) -> bool:
    """包名是否代表「NVD 未能精确映射到发行版包」。"""
    return str(package_name or "").strip().lower() in UNMAPPED_PACKAGE_SENTINELS


def cpe_package_names(affected_product: str | None) -> set[str]:
    """把 ``vendor:product, vendor:product`` 解析成已归一化的包名集合。

    **仅作诊断/佐证**：``VulnerabilityInfo.affected_product`` 是派生列，不能单独
    证明该 CVE 的 NVD 缓存仍保有 CPE 证据。判定是否可精确映射必须使用
    :func:`cpe_package_names_from_configurations` 读取 NVD 缓存里的 CPE。
    """
    from app.services.real_intel_collector import _normalize_package

    names: set[str] = set()
    for item in str(affected_product or "").split(","):
        item = item.strip()
        if not item:
            continue
        product = item.split(":")[-1].strip().lower()
        if product and product not in {"*", "-"}:
            names.add(_normalize_package(product))
    return names


def cpe_package_names_from_configurations(configurations) -> set[str]:
    """从 NVD v2 ``configurations`` 提取归一化包名（CPE 精确映射的唯一证据）。

    NVD 的 ``configurations[].nodes[].cpeMatch[].criteria`` 是包映射来源；
    若缓存里没有该结构（当前 ``NvdProvider.normalize`` 不保存 configurations），
    则任何包名都无法被证明为“精确映射”，审计脚本应判定为待隔离。
    """
    from app.services.real_intel_collector import (
        _normalize_package, _parse_cpe, _walk_cpe_matches,
    )

    names: set[str] = set()
    for match in _walk_cpe_matches(configurations or []):
        if match.get("vulnerable") is False:
            continue
        criteria = match.get("criteria") or match.get("cpe23Uri") or ""
        part, _vendor, product = _parse_cpe(criteria)
        if part not in {"a", "o"} or not product or product in {"*", "-"}:
            continue
        names.add(_normalize_package(product))
    return names
