// Device connection & software-inventory collection helpers.
// Pure functions so the state rules can be regression-tested without a browser.
// Credentials never appear here: connections carry environment-variable NAMES only.

const INVENTORY_COLLECTOR_TYPES = new Set(["openwrt_ssh", "linux_ssh"]);
const TERMINAL_STATUSES = new Set(["completed", "failed", "interrupted", "cancelled"]);
const NAIVE_UTC = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;

const ERROR_LABELS = {
  host_key_mismatch: "SSH 主机指纹不匹配，连接已被阻止",
  host_key_unconfigured: "尚未配置明确的 SSH 主机指纹",
  authentication_failed: "SSH 身份认证失败",
  authentication_not_attested: "采集节点未确认 SSH 认证成功",
  authentication_reference_invalid: "认证引用必须使用专用 LINUXGUARD_DEVICE_ 环境变量名",
  authentication_reference_missing: "后端尚未设置认证引用变量",
  authentication_type_unsupported: "不支持的认证方式",
  authentication_unsupported: "采集节点当前只接受无口令的本地密钥引用",
  key_reference_missing: "采集节点未设置私钥引用变量",
  key_reference_invalid: "私钥引用不是采集节点可读的绝对路径",
  key_reference_unavailable: "无法检查私钥引用文件",
  key_load_failed: "无法加载 SSH 私钥",
  ssh_connection_failed: "SSH 连接失败，请核对地址、网络与认证引用",
  collector_changed: "固定采集脚本已变化，请创建新的采集任务",
  collector_sha_mismatch: "采集脚本摘要与任务钉扎不一致",
  collector_output_too_large: "采集输出超过大小上限",
  collector_timeout: "采集超时，远端结束状态未知",
  collector_unsupported: "不支持的采集类型",
  collector_exit_failed: "固定采集脚本执行失败",
  connection_changed: "连接配置已变化，请创建新的采集任务",
  connection_disabled: "设备连接已禁用",
  executor_interrupted: "采集进程已中断，未重放 SSH",
  host_identity_not_attested: "未核验 SSH 主机指纹，结果未入库",
  inventory_validation_failed: "采集输出未通过格式/完整性校验，未覆盖已有清单",
  local_collection_failed: "本机固定采集脚本执行失败",
  node_changed: "执行节点已变化，请创建新的采集任务",
  node_identity_mismatch: "采集节点身份与登记资产不一致",
  node_platform_invalid: "采集必须在已登记的 Ubuntu/Linux 节点执行",
  output_encoding_invalid: "采集输出不是有效 UTF-8",
  output_integrity_failed: "采集输出摘要或字节数不一致",
  plan_changed: "采集计划摘要无效",
  runtime_log_device_identity_mismatch: "运行时日志中的设备身份与资产不一致",
  target_not_authorized: "目标地址不在授权网段内",
  username_invalid: "SSH 用户名格式无效"
};

export function isTerminalRun(status) {
  return TERMINAL_STATUSES.has(String(status || ""));
}

export function isActiveRun(run) {
  return Boolean(run && !isTerminalRun(run.status));
}

export function isInventoryRun(run) {
  return Boolean(run && INVENTORY_COLLECTOR_TYPES.has(String(run.collector_type || "")));
}

export function inventoryRuns(runs) {
  return (Array.isArray(runs) ? runs : []).filter(isInventoryRun);
}

export function connectionsForAsset(connections, assetId) {
  const id = Number(assetId);
  if (!Number.isFinite(id)) return [];
  return (Array.isArray(connections) ? connections : []).filter((row) => Number(row?.asset_id) === id);
}

export function connectionForAsset(connections, assetId) {
  return connectionsForAsset(connections, assetId)[0] || null;
}

export function parseBackendTime(value) {
  if (!value) return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  let text = String(value).trim();
  if (!text) return null;
  // Backend timestamps are naive UTC; JavaScript would otherwise read them as local time.
  if (NAIVE_UTC.test(text)) text = text.replace(" ", "T") + "Z";
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatBackendTime(value, fallback = "—") {
  const date = parseBackendTime(value);
  return date ? date.toLocaleString("zh-CN", { hour12: false }) : fallback;
}

export function timeAgoText(value) {
  const date = parseBackendTime(value);
  if (!date) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

export function runDuration(run) {
  if (!run) return "—";
  const start = parseBackendTime(run.started_at || run.created_at);
  const end = parseBackendTime(run.completed_at) || (isTerminalRun(run.status) ? null : new Date());
  if (!start || !end) return "—";
  const seconds = Math.max(0, (end.getTime() - start.getTime()) / 1000);
  if (seconds < 60) return `${seconds.toFixed(1)} 秒`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${Math.round(seconds % 60)} 秒`;
  return `${Math.floor(seconds / 3600)} 小时 ${Math.round((seconds % 3600) / 60)} 分`;
}

export function runError(run) {
  if (!run) return null;
  const code = String(run.result?.error_code || "").trim();
  const raw = String(run.error || "").trim();
  const failedCall = (Array.isArray(run.tool_calls) ? run.tool_calls : [])
    .find((call) => call.status === "failed" && call.error);
  const callMessage = failedCall ? String(failedCall.error || "").trim() : "";
  const fallback = ERROR_LABELS[code] || (code.startsWith("collector_exit_") ? "固定采集脚本执行失败" : "");
  const message = raw || callMessage || fallback;
  if (!code && !message) return null;
  return { code, message: message || "采集失败，后端未记录具体原因" };
}

export function summarizeRuns(runs) {
  const list = inventoryRuns(runs).slice().sort((left, right) => {
    const a = parseBackendTime(left.created_at)?.getTime() || 0;
    const b = parseBackendTime(right.created_at)?.getTime() || 0;
    return b - a;
  });
  return {
    total: list.length,
    latest: list[0] || null,
    lastSuccess: list.find((run) => run.status === "completed") || null,
    lastFailure: list.find((run) => ["failed", "interrupted"].includes(run.status)) || null
  };
}

const CHECK_ORDER = [
  "asset_bound",
  "connection_enabled",
  "host_fingerprint_configured",
  "authorized_target",
  "collector_available",
  "node_platform",
  "remote_node_configured",
  "node_identity_configured",
  "authentication_reference_configured",
  "key_path_metadata",
  "passphrase_reference_configured"
];

const CHECK_META = {
  asset_bound: ["绑定资产", "连接必须绑定到已登记的 OpenWrt/Ubuntu 资产"],
  connection_enabled: ["连接启用", "连接未被禁用"],
  host_fingerprint_configured: ["主机指纹", "已配置 SHA256 主机公钥指纹"],
  authorized_target: ["授权目标", "目标地址在显式授权网段内"],
  collector_available: ["固定采集脚本", "只读 Collector 脚本在 API 侧存在"],
  node_platform: ["执行节点平台", "执行节点为 Linux/Ubuntu"],
  remote_node_configured: ["采集节点登记", "后端已登记 Linux 采集节点"],
  node_identity_configured: ["节点身份", "节点身份与后端登记一致"],
  authentication_reference_configured: ["认证引用", "认证环境变量已配置（只返回变量名）"],
  key_path_metadata: ["私钥路径元数据", "引用为可读绝对路径且文件不超过 64 KB"],
  passphrase_reference_configured: ["口令引用", "密钥口令引用已配置（如有）"]
};

export function preflightChecks(preflight) {
  const checks = preflight?.checks || {};
  const keys = [
    ...CHECK_ORDER.filter((key) => key in checks),
    ...Object.keys(checks).filter((key) => !CHECK_ORDER.includes(key))
  ];
  return keys.map((key) => {
    const meta = CHECK_META[key] || [key, "后端返回的附加检查项"];
    return { key, label: meta[0], note: meta[1], ok: Boolean(checks[key]) };
  });
}

export function inventoryState(asset, packageCount = null) {
  if (!asset) {
    return { valid: false, count: 0, label: "未登记资产", detail: "请先发现或登记资产，再配置连接。" };
  }
  const count = Number.isFinite(Number(packageCount))
    ? Number(packageCount)
    : Number(asset.component_count || 0);
  const complete = asset.inventory_complete === true;
  const valid = complete && count > 0;
  return {
    valid,
    count,
    label: valid ? "已取得有效软件清单" : "已发现设备，尚无有效软件清单",
    detail: valid
      ? `${count} 个组件；清单时间 ${formatBackendTime(asset.inventory_collected_at)}`
      : "设备登记/发现成功不等于取得可核验的软件清单；请查看采集任务终态。"
  };
}

export function collectionStatusText(status) {
  return {
    completed: "采集完成",
    failed: "采集失败",
    running: "采集中",
    queued_remote: "等待采集节点",
    pending: "已创建",
    interrupted: "已中断",
    cancelled: "已取消"
  }[String(status || "")] || (status ? String(status) : "未知");
}

export function collectionStatusTone(status) {
  if (status === "completed") return "low";
  if (["failed", "interrupted", "cancelled"].includes(status)) return "crit";
  if (["running", "queued_remote", "pending"].includes(status)) return "accent";
  return "muted";
}

export function runResultLabel(run) {
  if (!run) return "—";
  if (run.status === "completed") {
    const count = run.result?.package_count;
    return Number.isFinite(Number(count)) ? `${Number(count)} 个组件` : "已完成";
  }
  const error = runError(run);
  return error ? error.code || "失败" : collectionStatusText(run.status);
}

export function createRequestId(assetId) {
  const cryptoObject = globalThis.crypto;
  const suffix = cryptoObject?.randomUUID
    ? cryptoObject.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `ui-${Number(assetId) || "asset"}-${Date.now()}-${suffix}`.replace(/[^A-Za-z0-9_.-]/g, "").slice(0, 128);
}
