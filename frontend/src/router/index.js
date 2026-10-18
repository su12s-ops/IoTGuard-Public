import { createRouter, createWebHistory } from "vue-router";

const Dashboard = () => import("../views/Dashboard.vue");
const AgentWorkflow = () => import("../views/AgentWorkflow.vue");
const CveWorkflowDetail = () => import("../views/CveWorkflowDetail.vue");
const RuntimeMonitor = () => import("../views/RuntimeMonitor.vue");
const VulnerabilityCenter = () => import("../views/VulnerabilityCenter.vue");
const AssetCenter = () => import("../views/AssetCenter.vue");
const RiskRanking = () => import("../views/RiskRanking.vue");
const Remediation = () => import("../views/Remediation.vue");
const ReportExport = () => import("../views/ReportExport.vue");

// 一级路由体现真实业务主线；旧入口保留重定向，避免历史链接失效。
const routes = [
  { path: "/", component: () => import("../views/IoTOverview.vue"), meta: { title: "物联网安全工作台" } },
  { path: "/soc", component: Dashboard, meta: { title: "SOC 安全总览" } },
  { path: "/assets", component: AssetCenter, meta: { title: "资产管理" } },
  { path: "/iot", component: () => import("../views/IoTWorkspace.vue"), meta: { title: "物联网接入" } },
  { path: "/devices", component: () => import("../views/DeviceCenter.vue"), meta: { title: "智能设备中心" } },
  { path: "/scans", component: () => import("../views/ScanCenter.vue"), meta: { title: "互联网扫描" } },
  { path: "/agent-ops", component: () => import("../views/AgentOps.vue"), meta: { title: "智能体分析与修复工作流" } },
  { path: "/device-tasks", component: () => import("../views/DeviceTasks.vue"), meta: { title: "智能体设备任务" } },
  { path: "/vulnerabilities", component: VulnerabilityCenter, meta: { title: "漏洞情报" } },
  { path: "/matching", redirect: { path: "/risk", query: { tab: "hits" } } },
  { path: "/risk", component: RiskRanking, meta: { title: "风险中心" } },
  { path: "/workflow", component: AgentWorkflow, meta: { title: "风险研判" } },
  { path: "/behavior-chain", redirect: "/risk" },
  { path: "/behavior-chain/detail", component: CveWorkflowDetail, meta: { title: "风险详情" } },
  { path: "/runtime", component: RuntimeMonitor, meta: { title: "运行时验证" } },
  { path: "/remediation", component: Remediation, meta: { title: "修复处置" } },
  { path: "/reports", component: ReportExport, meta: { title: "报告与归档" } },
  { path: "/:pathMatch(.*)*", redirect: "/" }
];

export default createRouter({
  history: createWebHistory(),
  routes
});
