import { createRouter, createWebHistory } from "vue-router";

const routes = [
  {
    path: "/",
    name: "overview",
    component: () => import("../views/Overview.vue"),
    meta: { title: "安全态势", root: "安全工作台" }
  },
  {
    path: "/assets",
    name: "assets",
    component: () => import("../views/Assets.vue"),
    meta: { title: "资产与发现", root: "安全工作台" }
  },
  {
    path: "/risks",
    name: "risks",
    component: () => import("../views/Risks.vue"),
    meta: { title: "漏洞与风险", root: "安全工作台" }
  },
  {
    path: "/risks/:id",
    name: "risk-detail",
    component: () => import("../views/RiskDetail.vue"),
    meta: { title: "风险详情", root: "漏洞与风险" }
  },
  {
    path: "/agents",
    name: "agents",
    component: () => import("../views/Agents.vue"),
    meta: { title: "智能研判", root: "安全工作台" }
  },
  {
    path: "/repairs",
    name: "repairs",
    component: () => import("../views/Repairs.vue"),
    meta: { title: "修复与验证", root: "安全工作台" }
  },
  {
    path: "/runtime",
    name: "runtime",
    component: () => import("../views/Runtime.vue"),
    meta: { title: "运行与审计", root: "安全工作台" }
  },
  {
    path: "/reports",
    name: "reports",
    component: () => import("../views/Reports.vue"),
    meta: { title: "报告与归档", root: "运营" }
  },
  {
    path: "/soc",
    name: "soc",
    component: () => import("../views/Soc.vue"),
    meta: { title: "SOC 态势大屏", root: "运营", bare: true }
  },

  // Old entry points are intentionally redirected; the old workbench is gone.
  { path: "/workbench/:pathMatch(.*)*", redirect: "/" },
  { path: "/iot", redirect: "/assets" },
  { path: "/devices", redirect: "/assets" },
  { path: "/scans", redirect: "/assets" },
  { path: "/assets/upload", redirect: "/assets" },
  { path: "/risk", redirect: "/risks" },
  { path: "/vulnerabilities", redirect: "/risks" },
  { path: "/matching", redirect: "/risks" },
  { path: "/behavior-chain", redirect: "/risks" },
  { path: "/behavior-chain/detail", redirect: "/risks" },
  { path: "/agent-ops", redirect: "/agents" },
  { path: "/workflow", redirect: "/agents" },
  { path: "/device-tasks", redirect: "/repairs" },
  { path: "/remediation", redirect: "/repairs" },
  { path: "/:pathMatch(.*)*", redirect: "/" }
];

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 })
});

router.afterEach((to) => {
  document.title = `IoTGuard · ${to.meta.title || "物联网安全工作台"}`;
});

export default router;
