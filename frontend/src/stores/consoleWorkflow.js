import { reactive } from "vue";
import { api } from "../api";

export const consoleState = reactive({ workflow: null, starting: false, resetting: false, error: "", selectedAssetId: 0, selectedAssetLabel: "全部接入设备" });
let fetching = false;
let revision = 0;

export async function refreshWorkflow() {
  if (fetching) return;
  fetching = true;
  const requestedRevision = revision;
  try {
    const { data } = await api.get("/console/current", { timeout: 15000 });
    if (requestedRevision !== revision) return;
    consoleState.workflow = data.workflow;
    consoleState.error = "";
  } catch (cause) {
    consoleState.error = cause?.response?.data?.detail || "后端进度读取失败，正在重试；运行状态以恢复连接后的结果为准。";
  } finally {
    fetching = false;
  }
}

export async function startWorkflow() {
  if (consoleState.starting || consoleState.resetting || ["running", "awaiting_review"].includes(consoleState.workflow?.status)) return;
  consoleState.starting = true;
  revision++;
  consoleState.error = "";
  try {
    const { data } = await api.post("/console/start", { asset_id: consoleState.selectedAssetId }, { timeout: 20000 });
    consoleState.workflow = data.workflow;
  } catch (cause) {
    consoleState.error = cause?.response?.data?.detail || "启动失败，请检查后端连接。";
  } finally {
    consoleState.starting = false;
  }
}

export function pollWorkflow() {
  refreshWorkflow();
  const timer = window.setInterval(refreshWorkflow, 3000);
  return () => window.clearInterval(timer);
}
