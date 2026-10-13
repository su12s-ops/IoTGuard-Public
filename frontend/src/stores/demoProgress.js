import { computed, reactive } from "vue";
import { fetchDemoProgress, startDemo } from "../api";

const DEFAULT_STEPS = [
  { step: "采集资产", agent: "collector" },
  { step: "采集运行时证据", agent: "collector" },
  { step: "同步 Ubuntu 情报", agent: "collector" },
  { step: "执行软件包命中分析", agent: "analysis" },
  { step: "初步风险研判", agent: "orchestrator" },
  { step: "风险研判与审计", agent: "analysis" },
  { step: "生成修复任务", agent: "orchestrator" }
];

export const demoState = reactive({
  running: false,
  currentStep: "",
  currentAgent: "",
  stepsDone: [],
  totalSteps: DEFAULT_STEPS.length,
  plannedSteps: DEFAULT_STEPS,
  error: "",
  startedAt: null,
  finishedAt: null
});

let pollTimer = null;
let onCompleteFns = [];

export const progressPct = computed(() =>
  Math.round((demoState.stepsDone.length / Math.max(demoState.totalSteps || demoState.plannedSteps.length || 1, 1)) * 100)
);

export const progressSteps = computed(() => {
  const done = demoState.stepsDone;
  const planned = demoState.plannedSteps?.length ? demoState.plannedSteps : DEFAULT_STEPS;
  return planned.map((step, index) => {
    const completed = done[index];
    if (completed) {
      const status = completed.status || "ok";
      const icons = { ok: "✔", warning: "⚠", error: "✘" };
      const states = { ok: "done", warning: "warn", error: "error" };
      return {
        name: step.step,
        agent: step.agent,
        state: states[status] || "done",
        icon: icons[status] || "✔",
        detail: completed.detail || ""
      };
    }
    if (index === done.length && demoState.running) {
      return { name: step.step, agent: step.agent, state: "current", icon: "…", detail: "执行中..." };
    }
    return { name: step.step, agent: step.agent, state: "pending", icon: "○", detail: "" };
  });
});

async function refresh() {
  try {
    const progress = await fetchDemoProgress();
    demoState.running = !!progress.running;
    demoState.currentStep = progress.current_step || "";
    demoState.currentAgent = progress.current_agent || "";
    demoState.stepsDone = progress.steps_done || [];
    demoState.plannedSteps = progress.planned_steps?.length ? progress.planned_steps : DEFAULT_STEPS;
    demoState.totalSteps = progress.total_steps || demoState.plannedSteps.length;
    demoState.error = progress.error || "";
    if (!progress.running && pollTimer) {
      stopPolling();
      demoState.finishedAt = Date.now();
      for (const fn of onCompleteFns) {
        try {
          await fn(progress);
        } catch (error) {}
      }
    }
    return progress;
  } catch (error) {
    return null;
  }
}

export function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(refresh, 2000);
}

export function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

export async function startCollection() {
  demoState.running = true;
  demoState.stepsDone = [];
  demoState.currentStep = "正在启动...";
  demoState.currentAgent = "";
  demoState.plannedSteps = DEFAULT_STEPS;
  demoState.totalSteps = DEFAULT_STEPS.length;
  demoState.error = "";
  demoState.startedAt = Date.now();
  demoState.finishedAt = null;
  try {
    await startDemo();
    startPolling();
  } catch (error) {
    demoState.running = false;
    demoState.currentStep = "";
    demoState.error = error?.response?.data?.detail || error?.message || "Failed to start workflow";
    throw error;
  }
}

export function onComplete(fn) {
  onCompleteFns.push(fn);
  return () => {
    onCompleteFns = onCompleteFns.filter((item) => item !== fn);
  };
}

refresh().then((progress) => {
  if (progress && progress.running) startPolling();
});
