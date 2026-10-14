import axios from "axios";
import { controlRequest, controlSession } from "./controlSession";

export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000/api";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000
});

// The Ubuntu collection profile protects readback as well as mutations.
api.interceptors.request.use(config => {
  if (controlSession.token) config.headers["X-Control-Token"] = controlSession.token;
  return config;
});

// 全局响应拦截器：统一处理错误，防止静默失败
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const detail =
      error?.response?.data?.detail ||
      error?.response?.data?.error?.detail ||
      (typeof error?.response?.data === "string" ? error.response.data : "") ||
      error?.message ||
      "未知网络错误";
    const status = error?.response?.status || 0;
    console.error(`[API Error] ${status ? `HTTP ${status}: ` : ""}${detail}`, {
      url: error?.config?.url,
      method: error?.config?.method,
    });
    // 重新抛出，让调用方可以进一步处理
    return Promise.reject(error);
  }
);

export const fetchSummary = () => api.get("/dashboard/summary").then((res) => res.data);
export const fetchHealth = () => api.get("/health", { timeout: 10000 }).then((res) => res.data);
export const fetchVulnerabilities = (params) => api.get("/vulnerabilities", { params }).then((res) => res.data);
export const fetchVulnerability = (cveId) => api.get(`/vulnerabilities/${encodeURIComponent(cveId)}`).then((res) => res.data);
export const syncRealVulnerabilities = (params) =>
  api.post("/vulnerabilities/sync-real", null, { params: { ...params, async_mode: true } }).then((res) => res.data);
export const syncUbuntuAssetIntelligence = (params) =>
  api.post("/vulnerabilities/sync-ubuntu-assets", null, { params: { ...params, async_mode: true } }).then((res) => res.data);
export const syncKylinAssetIntelligence = (params) =>
  api.post("/vulnerabilities/sync-kylin-assets", null, { params: { ...params, async_mode: true } }).then((res) => res.data);
export const fetchSyncJob = (jobId) => api.get(`/vulnerabilities/jobs/${jobId}`).then((res) => res.data);
export const fetchAssets = () => api.get("/assets").then((res) => res.data);
export const fetchAsset = (id) => api.get(`/assets/${id}`).then((res) => res.data);
export const uploadAsset = (file) => {
  const form = new FormData();
  form.append("file", file);
  return api.post("/assets/upload", form, controlRequest()).then((res) => res.data);
};
export const runMatching = assetId => api.post("/matching/run", null, { ...controlRequest(), params: typeof assetId === "number" ? { asset_id: assetId } : {} }).then((res) => res.data);
export const fetchMatches = () => api.get("/matching/results").then((res) => res.data);
export const calculateRisk = () => api.post("/risk/calculate").then((res) => res.data);
export const fetchRiskRanking = () => api.get("/risk/ranking").then((res) => res.data);
export const generateRemediation = () => api.post("/remediation/generate").then((res) => res.data);
export const fetchRemediationTasks = () => api.get("/remediation/tasks").then((res) => res.data);
export const updateTaskStatus = (id, status) => api.patch(`/remediation/tasks/${id}`, { status }).then((res) => res.data);
export const fetchReportJson = () => api.get("/reports/summary.json").then((res) => res.data);
export const fetchReportMarkdown = () => api.get("/reports/summary.md").then((res) => res.data);
export const fetchReportArchives = () => api.get("/reports/archives").then((res) => res.data);
export const fetchWorkflowOverview = () => api.get("/workflow/overview").then((res) => res.data);
export const fetchDependencyGraph = () => api.get("/workflow/dependency-graph").then((res) => res.data);
export const fetchBehaviorChains = () => api.get("/workflow/behavior-chains").then((res) => res.data);
export const fetchBusinessReconstruction = () => api.get("/workflow/business-reconstruction").then((res) => res.data);
export const fetchEbpfEvents = (params) => api.get("/runtime/ebpf/events", { params }).then((res) => res.data);
export const fetchEbpfSummary = () => api.get("/runtime/ebpf/summary").then((res) => res.data);
export const fetchEbpfStatus = () => api.get("/runtime/ebpf/status").then((res) => res.data);
export const fetchEbpfCorrelations = () => api.get("/runtime/ebpf/correlations").then((res) => res.data);
export const fetchCveRuntimeEvidence = (cveId, assetId) =>
  api.get("/runtime/cve-evidence", { params: { cve_id: cveId, asset_id: assetId } }).then((res) => res.data);
export const uploadEbpfEvents = (file) => {
  const form = new FormData();
  form.append("file", file);
  return api.post("/runtime/ebpf/upload", form, controlRequest()).then((res) => res.data);
};
export const generateEbpfDemo = (params) => api.post("/runtime/ebpf/demo", null, { params, ...controlRequest() }).then((res) => res.data);
export const clearEbpfEvents = () => api.delete("/runtime/ebpf/events", controlRequest()).then((res) => res.data);
export const startDemo = () => api.post("/demo/start", null, controlRequest()).then((res) => res.data);
export const fetchDemoProgress = () => api.get("/demo/progress").then((res) => res.data);
export const fetchDemoTargets = () => api.get("/demo/targets", controlRequest()).then((res) => res.data);
export const updateDemoTargets = (targets) => api.put("/demo/targets", { targets }, controlRequest()).then((res) => res.data);
export const fetchAnalysisStatus = () => api.get("/analysis/status").then((res) => res.data);
export const fetchLatestAnalysis = () => api.get("/analysis/latest").then((res) => res.data);

export const currentReportUrls = {
  markdown: `${API_BASE}/reports/summary.md`,
  json: `${API_BASE}/reports/summary.json`,
  csv: `${API_BASE}/reports/summary.csv`
};

export const archiveViewUrl = (filename) => `${API_BASE}/reports/archives/${encodeURIComponent(filename)}`;
export const archiveDownloadUrl = (filename) =>
  `${API_BASE}/reports/archives/${encodeURIComponent(filename)}/download`;

// ========== 任务式风险研判接口 ==========
export const createReviewRun = (retryFailed = false) =>
  api.post("/analysis/runs", null, { params: { retry_failed: retryFailed } }).then((res) => res.data);
export const fetchReviewRun = (runId) => api.get(`/analysis/runs/${runId}`).then((res) => res.data);
export const fetchPreflight = () => api.get("/analysis/preflight").then((res) => res.data);
export const reviewRiskEvent = (riskId, decision, reason) =>
  api.post(`/analysis/risks/${riskId}/human-review`, { decision, reason }, controlRequest()).then((res) => res.data);
