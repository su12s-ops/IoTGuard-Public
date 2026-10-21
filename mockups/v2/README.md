# IoTGuard · Desktop Concept v2 — 3 directions × 9 modules

上一版是一套方向；这一版按“更鲜艳、更有排版感、看全部模块”做了三个方向，每个方向都覆盖 9 个模块。

## 三个方向

| 方向 | 关键词 | 适合 |
|---|---|---|
| **PRISM** | 冷调渐变、大圆角、玻璃卡片、彩色图表 | 主工作台、对外演示；最像现代 SaaS |
| **EDITORIAL** | 奶油底、黑边框、衬线数字、朱红强调 | 报告、品牌、归档；最有“编辑部”气质 |
| **NOCTURNE** | 深色底、青色/柠檬绿、网格、等宽标签 | SOC 大屏、夜间值守；不建议全站使用 |

三版共用同一套信息架构，差异在色彩、字体、边框、密度和明暗，方便横向比较。如果你要的是三种**布局结构**不同的版本，那是下一轮的工作。

## 覆盖的 9 个模块

1. 安全态势
2. 资产与发现
3. 漏洞与风险
4. 风险详情 / 人工裁决
5. 智能研判
6. 修复与验证
7. 运行与审计
8. 报告与归档
9. SOC 态势大屏

每个方向 9 张，共 **27 张**全尺寸图：`shots/{theme}-{module}.png`（1440×960，2× 导出）。

## 先看哪里

- 三个方向的总览：`sheets/prism.png`、`sheets/editorial.png`、`sheets/nocturne.png`（每张是 9 模块 contact sheet）。
- 单屏细节：`shots/prism-risk-detail.png`、`shots/editorial-overview.png` 等。
- 浏览器打开：`prism` 页面默认用 Prism 主题；在控制台执行 `document.body.dataset.theme = "editorial"` 或 `"nocturne"` 可切换主题（同一份 HTML）。

## 文件

```text
theme.css          三套 token + 组件 + 主题覆盖
bodies/            9 个页面的内容片段（构建源）
build.mjs          把 bodies 包进导航/顶栏，生成 9 个 HTML
render.mjs         渲染 27 张桌面图到 shots/
sheet.html         三方向 contact sheet 模板
sheets.mjs         渲染 3 张 contact sheet
*.html             生成的 9 个可打开页面
shots/             27 张 1440×960 @2x
sheets/            3 张 2400×1840 contact sheet
```

重新生成：

```powershell
node mockups/v2/build.mjs
node mockups/v2/render.mjs
node mockups/v2/sheets.mjs
```

需要 `frontend/node_modules` 里的 Playwright，并使用本机 Edge；渲染脚本不依赖后端或网络。

## 说明

这是静态概念稿，数据按项目当前口径做的示意（4 台资产、49 条高风险、12,958 条情报、CVE-2026-63073 等），没有接 API，也不是最终实现。

我的建议：主产品用 **PRISM** 打底，吸收 **EDITORIAL** 的数字排版和报告页，SOC 用 **NOCTURNE** 的暗色；不建议全站 Nocturne。

实际前端已按 **EDITORIAL** 落地到 `frontend/src/`；本目录保留三方向静态稿，仅作设计参考。旧版单方向稿已随本次替换删除。
