import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (p) => fs.readFileSync(path.join(here, p), "utf8");
const sprite = read("bodies/_sprite.html");

const pages = {
  overview: { title: "安全态势", crumb: "安全态势", root: "安全工作台", active: "overview" },
  assets: { title: "资产与发现", crumb: "资产与发现", root: "安全工作台", active: "assets" },
  risks: { title: "漏洞与风险", crumb: "漏洞与风险", root: "安全工作台", active: "risks" },
  agents: { title: "智能研判", crumb: "智能研判", root: "安全工作台", active: "agents" },
  repairs: { title: "修复与验证", crumb: "修复与验证", root: "安全工作台", active: "repairs" },
  runtime: { title: "运行与审计", crumb: "运行与审计", root: "安全工作台", active: "runtime" },
  reports: { title: "报告与归档", crumb: "报告与归档", root: "运营", active: "reports" },
  "risk-detail": { title: "CVE-2026-63073", crumb: "CVE-2026-63073", root: "漏洞与风险", active: "risks" }
};

const navGroups = [
  ["工作台", [
    ["overview", "安全态势", "i-grid"],
    ["assets", "资产与发现", "i-server"],
    ["risks", "漏洞与风险", "i-bug", "49"],
    ["agents", "智能研判", "i-cpu"],
    ["repairs", "修复与验证", "i-wrench", "3"],
    ["runtime", "运行与审计", "i-activity"]
  ]],
  ["运营", [
    ["reports", "报告与归档", "i-file"],
    ["soc", "SOC 态势大屏", "i-monitor"]
  ]]
];

function nav(active) {
  return navGroups.map(([group, items]) => {
    const links = items.map(([key, text, icon, count]) => {
      const cls = key === active ? "active" : "";
      const num = count ? `<span class="nav-count${key === "risks" ? " hot" : ""}">${count}</span>` : "";
      return `<a class="${cls}" href="#"><svg class="icon"><use href="#${icon}"/></svg>${text}${num}</a>`;
    }).join("\n      ");
    return `<p class="nav-label">${group}</p>\n      ${links}`;
  }).join("\n      ");
}

function shell(meta, body) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>IoTGuard · ${meta.title}</title>
<link rel="stylesheet" href="theme.css">
</head>
<body data-theme="prism">
${sprite}

<div class="shell">
  <aside class="rail">
    <div class="brand">
      <span class="brand-mark">IG</span>
      <div><div class="brand-name">IoTGuard</div><div class="brand-sub">Security Console</div></div>
    </div>
    <div class="ws">
      <span class="ws-env">LAB</span>
      <div><div class="ws-name">物联网实验室</div><div class="ws-sub">4 台资产 · 3 个采集节点</div></div>
      <svg class="icon"><use href="#i-chev-down"/></svg>
    </div>
    <nav class="nav">
      ${nav(meta.active)}
    </nav>
    <div class="rail-foot">
      <div class="user">
        <span class="avatar">WY</span>
        <div><div class="user-name">王工</div><div class="user-role">安全工程师</div></div>
        <svg class="icon"><use href="#i-chev-right"/></svg>
      </div>
      <div class="rail-meta"><span>v0.2.0</span><span>working-tree</span></div>
    </div>
  </aside>

  <div class="frame">
    <header class="topbar">
      <div class="crumbs"><span>${meta.root}</span><svg class="icon"><use href="#i-chev-right"/></svg><b>${meta.crumb}</b></div>
      <div class="search"><svg class="icon"><use href="#i-search"/></svg><span>搜索 CVE、资产或任务</span><span class="kbd">Ctrl K</span></div>
      <div class="top-right">
        <div class="health">
          <span class="seg"><i class="dot ok"></i><b>服务</b></span>
          <span class="seg"><i class="dot warn"></i>节点 <b>1/2</b></span>
          <span class="seg"><i class="dot warn"></i>传感器 <b>1/3</b></span>
          <span class="seg"><i class="dot warn"></i>证据 <b>部分过期</b></span>
        </div>
        <button class="icon-btn"><svg class="icon"><use href="#i-lock"/></svg></button>
        <button class="icon-btn"><svg class="icon"><use href="#i-bell"/></svg><i class="ping"></i></button>
        <span class="top-avatar">WY</span>
      </div>
    </header>

    <main class="main">
${body}
    </main>
  </div>
</div>
</body>
</html>
`;
}

for (const [name, meta] of Object.entries(pages)) {
  const body = read(`bodies/${name}.html`);
  fs.writeFileSync(path.join(here, `${name}.html`), shell(meta, body));
  console.log("built", `${name}.html`);
}

const soc = read("bodies/soc.html");
fs.writeFileSync(path.join(here, "soc.html"), `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>IoTGuard · SOC 态势大屏</title><link rel="stylesheet" href="theme.css"></head>
<body data-theme="prism">
${sprite}
${soc}
</body>
</html>
`);
console.log("built soc.html");
