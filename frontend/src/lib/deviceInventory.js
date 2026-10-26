/**
 * 设备台账视图模型（纯函数，无副作用）。
 *
 * 输入有两种同构载荷：
 *   - 冻结快照 `src/data/devices-data.json`（由 _work/device_capture.py 生成）
 *   - 现场实测 `/api/devices/live`（由 _work/device_bridge.py 返回）
 * 归一化后交给 Devices.vue 渲染；缺失字段一律显示「未采集」，不补默认值。
 */

export const SERVICE_LABEL = {
  ssh: "SSH",
  http: "嵌入式 Web",
  https: "TLS Web",
  mqtt: "消息总线",
  rtsp: "视频流",
  unknown: "未识别协议"
};

export const SOURCE_LABEL = {
  device_identity_endpoint: "设备自报身份端点",
  banner_heuristic: "横幅指纹推断"
};

export const COMPONENT_TYPE_LABEL = {
  firmware: "固件",
  software: "软件",
  kernel: "内核"
};

export const COMPONENT_SOURCE_LABEL = {
  device_identity: "设备自报",
  service_banner: "服务横幅"
};

export function hasDevice(payload) {
  return Boolean(payload && payload.device && payload.device.model);
}

/** 归一化载荷；空载荷返回 { device: null, ... } 由调用方渲染「尚未接入」。 */
export function normalize(payload) {
  const raw = payload || {};
  return {
    device: raw.device || null,
    services: Array.isArray(raw.services) ? raw.services : [],
    components: Array.isArray(raw.components) ? raw.components : [],
    exposure: raw.exposure || null,
    provenance: raw.provenance || null,
    selfCheck: raw.self_check || raw.selfCheck || null,
    capturedAt: raw.captured_at || "",
    snapshotSha: raw.snapshot_sha256 || "",
    reqId: raw.req_id || "",
    pid: raw.pid ?? null,
    serverTime: raw.server_time || "",
    elapsedMs: Number(raw.elapsed_ms ?? (raw.provenance && raw.provenance.elapsed_ms) ?? 0),
    channel: raw.channel || ""
  };
}

export function serviceLabel(type) {
  return SERVICE_LABEL[type] || type || "未识别";
}

export function authLabel(state) {
  return {
    anonymous_accepted: "匿名接入",
    auth_required: "需认证",
    unknown: "未复核"
  }[state] || state || "未复核";
}

export function authTone(state) {
  if (state === "anonymous_accepted") return "crit";
  if (state === "auth_required") return "low";
  return "muted";
}

export function sourceLabel(source) {
  return SOURCE_LABEL[source] || source || "未记录";
}

export function componentTypeLabel(value) {
  return COMPONENT_TYPE_LABEL[value] || value || "—";
}

export function componentSourceLabel(value) {
  return COMPONENT_SOURCE_LABEL[value] || value || "—";
}

export function exposureTone(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return "muted";
  if (n >= 40) return "crit";
  if (n >= 24) return "high";
  if (n > 0) return "mid";
  return "low";
}

export function confidencePct(value) {
  const n = Number(value);
  return Number.isFinite(n) ? `${Math.round(n * 100)}%` : "—";
}

export function shortHash(value, keep = 10) {
  const text = String(value || "");
  if (!text) return "未记录";
  return text.length <= keep * 2 ? text : `${text.slice(0, keep)}…${text.slice(-4)}`;
}

export function msLabel(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? `${n} ms` : "—";
}

export function portList(services) {
  return (services || []).map((svc) => Number(svc.port)).filter(Number.isFinite).sort((a, b) => a - b);
}

export function portSetText(services) {
  const list = portList(services);
  return list.length ? list.join(" / ") : "未采集";
}

/**
 * 快照 ↔ 现场实测 逐字段对照。
 * 只有两侧都有值时才算一条对照；缺失一侧记为「未复核」，不当作一致。
 */
export function compare(snapshot, live) {
  const fields = [
    ["device_name", "设备名"],
    ["vendor", "厂商"],
    ["model", "型号"],
    ["firmware_version", "固件版本"],
    ["os", "系统"],
    ["device_type", "设备类型"],
    ["device_key", "台账键"]
  ];
  const rows = fields.map(([key, label]) => {
    const left = snapshot.device ? snapshot.device[key] : "";
    const right = live.device ? live.device[key] : "";
    const state = !left || !right ? "unverified" : left === right ? "same" : "diff";
    return { key, label, left: left || "—", right: right || "—", state };
  });
  const leftPorts = portSetText(snapshot.services);
  const rightPorts = portSetText(live.services);
  rows.push({
    key: "ports",
    label: "服务端口",
    left: leftPorts,
    right: rightPorts,
    state: leftPorts === "未采集" || rightPorts === "未采集" ? "unverified" : leftPorts === rightPorts ? "same" : "diff"
  });
  return {
    rows,
    diffCount: rows.filter((row) => row.state === "diff").length,
    unverifiedCount: rows.filter((row) => row.state === "unverified").length
  };
}
