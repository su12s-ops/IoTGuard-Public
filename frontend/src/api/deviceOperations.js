import { api } from "./index";
import { controlSession } from "./controlSession";
export { controlSession } from "./controlSession";

// Memory-only: credentials never enter localStorage or URLs.
const control = () => ({ headers: { "X-Control-Token": controlSession.token }, timeout: 660000 });
export function errorMessage(error) {
  const detail = error?.response?.data?.detail;
  if (Array.isArray(detail)) return detail.map(x => (x.loc?.slice(1).join(".") || "字段") + ": " + x.msg).join("；");
  if (detail && typeof detail.message === "string") return detail.message;
  return typeof detail === "string" ? detail : error?.message || "操作失败，请刷新后重试";
}
export const fetchDeviceCapabilities = () => api.get("/iot/capabilities").then(r => r.data);
export const fetchConnections = () => api.get("/iot/connections").then(r => r.data);
export const saveConnection = (data, id) => (id ? api.put("/iot/connections/" + id, data, control()) : api.post("/iot/connections", data, control())).then(r => r.data);
export const collectDevice = id => api.post("/iot/connections/" + id + "/collect", null, control()).then(r => r.data);
export const preflightConnection = id => api.get("/iot/connections/" + id + "/preflight", control()).then(r => r.data);
export const fetchCollectionRuns = () => api.get("/iot/collection-runs", control()).then(r => r.data);
export const createCollectionRun = (id, requestId) => api.post("/iot/connections/" + id + "/collection-runs", { request_id: requestId }, control()).then(r => r.data);
export const executeCollectionRun = id => api.post("/iot/collection-runs/" + id + "/execute", null, control()).then(r => r.data);
export const fetchCollectionRun = id => api.get("/iot/collection-runs/" + id, control()).then(r => r.data);
export const discoverDevices = data => api.post("/iot/discovery", data, control()).then(r => r.data);
export const fetchObservations = () => api.get("/iot/observations").then(r => r.data);
export const fetchOpenWrtAdvisories = () => api.get("/iot/advisories").then(r => r.data);
export const saveOpenWrtAdvisory = data => api.post("/iot/advisories", data, control()).then(r => r.data);
export const fetchHarnessRuns = () => api.get("/harness/runs").then(r => r.data);
export const fetchHarnessRun = id => api.get("/harness/runs/" + id).then(r => r.data);
export const fetchRepairArtifacts = () => api.get("/harness/artifacts").then(r => r.data);
export const createHarnessRun = data => api.post("/harness/runs", data, control()).then(r => r.data);
export const actOnHarnessRun = (id, action, data = null) => api.post("/harness/runs/" + id + "/" + action, data, control()).then(r => r.data);
export const recoverHarnessRuns = () => api.post("/harness/recover", null, control()).then(r => r.data);
export const fetchRuntimeTimeline = id => api.get("/runtime/assets/" + id + "/timeline").then(r => r.data);
export const compareRuntime = (id, params) => api.get("/runtime/assets/" + id + "/comparison", { params }).then(r => r.data);

// 智能设备清单（阶段一：发现 → 服务识别 → 组件识别）。
export const fetchDevices = () => api.get("/devices").then(r => r.data);
export const fetchDeviceDetail = deviceId => api.get("/devices/" + deviceId).then(r => r.data);
export const discoverDevice = data => api.post("/devices/discover", data, control()).then(r => r.data);
export const refreshDevice = deviceId => api.post("/devices/" + deviceId + "/refresh", null, control()).then(r => r.data);

// 四智能体编排与修复工作流（阶段三/四）。
export const fetchAgentSpecs = () => api.get("/agents/specs").then(r => r.data);
export const startAgentAnalysis = payload => api.post("/agents/analyze", payload, control()).then(r => r.data);
export const fetchAgentRuns = () => api.get("/agents/runs").then(r => r.data);
export const fetchAgentRun = runId => api.get("/agents/runs/" + runId).then(r => r.data);
export const startMqttWorkflow = payload => api.post("/remediation/workflow/mqtt-anonymous", payload, control()).then(r => r.data);
export const fetchWorkflowRuns = () => api.get("/remediation/workflow/runs").then(r => r.data);
export const fetchWorkflowRun = runId => api.get("/remediation/workflow/runs/" + runId).then(r => r.data);

// 统一任务追踪（第八阶段：四智能体 + Harness + 设备管线共用 Trace）。
export const fetchTraces = params => api.get("/traces", { params }).then(r => r.data);
export const fetchTraceSummary = () => api.get("/traces/summary").then(r => r.data);
export const fetchTraceDetail = traceId => api.get("/traces/" + traceId).then(r => r.data);
export const fetchTraceHarness = traceId => api.get("/traces/" + traceId + "/harness").then(r => r.data);
export const fetchTraceEvidence = traceId => api.get("/traces/" + traceId + "/evidence").then(r => r.data);
