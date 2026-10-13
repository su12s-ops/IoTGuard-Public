import { api } from "./index";
import { controlSession, errorMessage } from "./deviceOperations";

export { controlSession, errorMessage };

const control = () => ({ headers: { "X-Control-Token": controlSession.token }, timeout: 660000 });

// 互联网授权目标主动扫描（阶段六：登记 → 扫描 → 结果/审计）。
export const fetchScanCapabilities = () => api.get("/scans/capabilities").then(r => r.data);
export const fetchScanTargets = () => api.get("/scans/targets").then(r => r.data);
export const createScanTarget = data => api.post("/scans/targets", data, control()).then(r => r.data);
export const updateScanTarget = (id, data) => api.patch(`/scans/targets/${id}`, data, control()).then(r => r.data);
export const deleteScanTarget = id => api.delete(`/scans/targets/${id}`, control()).then(r => r.data);
export const startScan = data => api.post("/scans/runs", data, control()).then(r => r.data);
export const fetchScanRuns = (params = {}) => api.get("/scans/runs", { params }).then(r => r.data);
export const fetchScanRun = runId => api.get(`/scans/runs/${runId}`).then(r => r.data);
