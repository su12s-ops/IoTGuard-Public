"""eBPF 运行时事件的稳定身份（P0，纯函数、无 app 依赖）。

三层身份分离（修复审计缺陷 D1）：
1. 原始事件身份 event_fingerprint —— 只由事件自身声明的内容决定：
   设备锚点（事件内 hostname/nodename，缺省用发送侧声明的 hostname 提示）
   + 上游 boot_id（区分同主机名跨重启）
   + 原始报文 raw。**不含 asset_id**（资产归属是可变绑定，不参与身份），
   因此资产注册前后重复上传不会产生第二份记录；不同设备的相似事件因
   锚点/raw 内主机标识不同而不会误合并。
2. 采集来源身份 —— sensor_id + boot_id（转发器注入，见 identity_fields）。
3. 当前资产归属 —— RuntimeEvent/SecurityEvidence.asset_id，可回绑：
   先到先绑定，后续重复命中时若已有绑定缺失则补绑，绝不改写既有归属。

本模块同时被服务层（写入）与 database 迁移（历史指纹重算）引用，
必须保持零应用依赖，且算法一经发布不得变更（幂等连续性）。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# 事件报文中可自证设备身份的键（按优先级；Falco/Tetragon/自研路线均覆盖）
_ANCHOR_KEYS = ("hostname", "host", "node_name", "node.name")
_ANCHOR_OUTPUT_FIELD_KEYS = ()  # Falco output_fields 层级的键
_RAW_ANCHOR_KEYS = ("hostname", "host", "node_name", "node.name")
_TIME_KEYS = ("timestamp", "time")


def _as_plain_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def event_anchor(raw: dict[str, Any], hostname_hint: str = "") -> str:
    """设备锚点：优先事件自报身份；无自报时退回发送侧声明的 hostname 提示。

    返回空串表示无法确定来源设备（此类事件仅靠 raw 内容参与身份）。
    """
    raw = _as_plain_dict(raw)
    for key in _RAW_ANCHOR_KEYS:
        value = str(raw.get(key) or "").strip()
        if value:
            return value
    # Falco/Tetragon 风格：身份在 output_fields / source 嵌套层
    fields = _as_plain_dict(raw.get("output_fields"))
    for key in ("host.name", "hostname", "node.name"):
        value = str(fields.get(key) or "").strip()
        if value:
            return value
    source_field = _as_plain_dict(raw.get("source"))
    value = str(source_field.get("hostname") or "").strip()
    if value:
        return value
    return str(hostname_hint or "").strip()


def event_boot_id(raw: dict[str, Any]) -> str:
    raw = _as_plain_dict(raw)
    value = str(raw.get("boot_id") or "").strip()
    return value[:64]


def has_event_time(raw: dict[str, Any]) -> bool:
    raw = _as_plain_dict(raw)
    return any(str(raw.get(key) or "").strip() for key in _TIME_KEYS)


# 传输/上报层注入键：属于"采集与绑定元数据"，不属于原始事件内容，
# 参与身份基会破坏幂等（同一事件因上报时是否携带 asset_id/sensor_id
# 而指纹漂移——D1 深层根因）。计算基时剔除。
TRANSPORT_INJECTED_KEYS = ("asset_id", "sensor_id")


def _strip_transport_keys(raw: dict[str, Any]) -> dict[str, Any]:
    """剥离传输层注入键；并沿 "raw" 嵌套链递归剥离。

    归一化管线会把整包 payload 套进外层 raw（批量/单条路径存在双层归一化），
    传输键因此出现在嵌套 raw 里——那是管线 artifact，不是事件内容。
    仅递归 "raw" 键链：业务字段中的同名键属于事件自身内容，不剥离。
    """
    stripped = {key: value for key, value in raw.items() if key not in TRANSPORT_INJECTED_KEYS}
    nested = stripped.get("raw")
    if isinstance(nested, dict):
        stripped["raw"] = _strip_transport_keys(nested)
    return stripped


def stable_event_fingerprint(raw: dict[str, Any], hostname_hint: str = "") -> str:
    """计算稳定原始事件指纹。

    仅当事件携带时间戳时产生指纹（与历史行为一致：无时间戳的事件
    不具备可判重身份）；基={anchor, boot_id, raw 去传输键}，与资产
    绑定态、上报通道元数据均无关。
    """
    raw = _as_plain_dict(raw)
    if not has_event_time(raw):
        return ""
    basis = json.dumps({
        "anchor": event_anchor(raw, hostname_hint),
        "boot_id": event_boot_id(raw),
        "raw": _strip_transport_keys(raw),
    }, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
