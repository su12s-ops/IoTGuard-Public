export const asNumber = (value, fallback = 0) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
};

export const num = (value, fallback = "—") => {
  const n = Number(value);
  return Number.isFinite(n) ? n.toLocaleString("zh-CN") : fallback;
};

export const pct = (value, digits = 0) => {
  const n = Number(value);
  return Number.isFinite(n) ? `${n.toFixed(digits)}%` : "—";
};

export const ratioPct = (value, digits = 0) => {
  const n = Number(value);
  return Number.isFinite(n) ? `${(n * 100).toFixed(digits)}%` : "—";
};

export const score = (value, digits = 2) => {
  const n = Number(value);
  return Number.isFinite(n) ? n.toFixed(digits) : "—";
};

export const cvss = (value) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return "—";
  return (n > 10 ? n / 10 : n).toFixed(1);
};

export const dateTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { hour12: false });
};

export const shortTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
};

export const timeAgo = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
};

export const levelLabel = (level) =>
  ({ Critical: "严重", High: "高危", Medium: "中危", Low: "低危" }[level] || level || "未分级");

export const levelTone = (level) =>
  ({ Critical: "crit", High: "high", Medium: "mid", Low: "low" }[level] || "muted");

export const statusLabel = (status) =>
  ({
    completed: "已完成",
    succeeded: "成功",
    running: "执行中",
    queued_remote: "已排队",
    pending: "待执行",
    pending_human_review: "待人工审查",
    human_reviewing: "审核中",
    reanalysis_required: "要求再研判",
    human_confirmed: "人工已确认",
    approved: "已审批",
    awaiting_approval: "待审批",
    awaiting_preflight: "待预演",
    preflight_failed: "预演未通过",
    needs_evidence: "待补证",
    verification_required: "需复查",
    verified: "复验通过",
    failed: "失败",
    blocked: "被阻断",
    interrupted: "已中断",
    cancelled: "已取消",
    rolled_back: "已回退",
    active: "有效",
    inactive: "历史归档",
    candidate: "候选",
    unassessed: "未评估",
    partial: "部分完成",
    degraded: "降级",
    no_candidates: "无候选",
    not_affected: "不受影响",
    potentially_affected: "可能受影响",
    confirmed_affected: "确认受影响",
    fixed: "已修复",
    insufficient_data: "证据不足",
    verified_runtime: "已验证",
    contextual: "上下文关联",
    not_observed: "未观测",
    waiting: "等待证据",
    online: "在线",
    offline: "离线",
    ready: "清单完整",
    incomplete: "清单待补",
    unknown: "未知"
  }[status] || status || "未知");

export const statusTone = (status) => {
  if (["failed", "blocked", "interrupted", "rolled_back", "degraded"].includes(status)) return "crit";
  if (["awaiting_approval", "awaiting_preflight", "preflight_failed", "needs_evidence", "verification_required", "pending_human_review", "human_reviewing", "reanalysis_required"].includes(status)) return "high";
  if (["completed", "succeeded", "approved", "verified", "human_confirmed", "ready", "fixed", "not_affected"].includes(status)) return "low";
  if (["running", "queued_remote", "pending"].includes(status)) return "accent";
  return "muted";
};

export const ecosystemLabel = (value) =>
  ({ openwrt: "OpenWrt", zephyr: "Zephyr", ubuntu: "Ubuntu", other_iot: "其他 IoT" }[value] || value || "未知");

export const riskLevelFromScore = (value) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return "unknown";
  const normalized = n > 10 ? n : n * 10;
  if (normalized >= 90) return "Critical";
  if (normalized >= 70) return "High";
  if (normalized >= 40) return "Medium";
  return "Low";
};

export const truncate = (value, length = 48) => {
  const text = String(value ?? "");
  return text.length > length ? `${text.slice(0, length)}…` : text;
};


