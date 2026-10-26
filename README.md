# IoTGuard

面向 OpenWrt 与物联网设备的资产发现、漏洞匹配、四智能体研判和受控修复平台。

IoTGuard 将设备身份、软件清单、官方公告和运行时证据关联到同一风险对象，由资产调查、漏洞分析、运行时分析、决策规划四个角色生成可追踪的研判结果，再进入人工审核、修复审批与复验。后端使用 FastAPI、SQLAlchemy 和 LangGraph，前端使用 Vue 3 与 Vite。

[文档导航](docs/README.md) · [部署指南](docs/guides/deployment.md) · [技术架构](docs/architecture/overview.md) · [当前状态](docs/status.md)

## 主要能力

| 能力 | 内容 |
| --- | --- |
| 设备发现与台账 | 授权目标探测，SSH、HTTP、MQTT、RTSP 身份与服务识别，组件清单 |
| 官方情报与匹配 | OpenWrt、Zephyr、Ubuntu 等生态公告与版本匹配，区分候选、证据不足与已确认结论 |
| 四智能体研判 | 有界任务图、同设备报告复用、模型预算与耗时记录、证据引用校验、逐项人审 |
| 运行时取证 | Linux Falco/eBPF 与 OpenWrt logread，分别展示节点、传感器、证据新鲜度 |
| 修复与复验 | 计划绑定、作用域与审批检查、受控执行、回滚及修复后复采；设备写默认关闭 |
| 实验工作台 | 安全总览、资产发现、风险详情、智能研判、修复验证、运行监控 |
| 多设备模拟 | 一台 OpenWrt 内运行两台摄像头、温湿度传感器和插座模拟器，LAN 下独立 IP/MAC |

## 当前实验基线

截至 2026-10-26，当前平台仅登记一台 OpenWrt 实验网关，其 LAN 下四台模拟设备已通过 DHCP、HTTP 身份、MQTT 和摄像头画面检查。模拟器共享网关内核，身份明确标记 `simulation`，不代表四台独立虚拟机或真实固件。部署方式见 [OpenWrt LAN 实验](docs/guides/openwrt-lan.md)。

Zephyr QEMU 保留构建、身份识别与宿主固件切换能力；Ubuntu 承担 Linux 采集节点和对照环境。旧 OpenWrt-Lab 已关机、移出平台，其磁盘删除尚未完成。历史实验结论不替代当前运行验证，详见 [状态与开放问题](docs/status.md)。

本项目当前以模拟实验设备验证为主：模拟器覆盖 HTTP/MJPEG、MQTT、有限 RTSP、SSH/设备身份和 LAN 多设备隔离。现阶段没有真实硬件验收，也没有完成 24 小时连续运行验收；相关结论会在证据具备后单独更新，不从短时测试推导长期稳定性。

## 快速启动

需要 Git、Docker Engine / Docker Desktop 和 Docker Compose v2。在项目根目录执行：

```powershell
git clone https://github.com/su12s-ops/IoTGuard-Public.git
cd IoTGuard-Public
Copy-Item backend/.env.example backend/.env.docker
# 编辑 backend/.env.docker：填写控制令牌，需要模型时配置接口与密钥。
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://127.0.0.1:18080/api/health
```

打开工作台：<http://127.0.0.1:18080>。浏览器通过同源 `/api` 访问后端；后端端口只在 Compose 网络内使用。

首次启动为空库，需要配置设备连接、授权目标、采集节点和模型服务。Compose 启动平台前后端；设备、Linux 采集节点和内核传感器按 [部署指南](docs/guides/deployment.md)独立接入。真实密钥、数据库和虚拟磁盘不随仓库发布。

## 项目结构

```text
backend/       FastAPI、数据模型、四智能体、Harness 与后端测试
frontend/      Vue 3 控制台与浏览器测试
collector/     SSH 清单、logread、Falco 与原生 eBPF 采集
simulator/     单设备协议模拟与 OpenWrt LAN 多设备模拟
firmware/      Zephyr 应用、板级配置与 QEMU 启动入口
deploy/        虚拟机参数、依赖安装与系统服务模板
scripts/       本地启动、检查和维护工具
docs/          使用指南、架构、验证方法与历史记录
```

## 开发与验证

本地开发需要 Python 3.12+ 和 Node.js 24，启动方式见 [部署指南](docs/guides/deployment.md#本地开发)。

```powershell
python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
python -m pytest -q
npm --prefix frontend ci
npm --prefix frontend run build
node --test frontend/tests/*.test.js
# 使用本机已安装的 Microsoft Edge，不下载 Chromium 或其他浏览器
$env:PLAYWRIGHT_CHANNEL='msedge'
npm --prefix frontend run test:e2e
```

截至 2026-10-26，模拟设备关键测试 27 项、任务图测试 29 项、Edge 前端测试 8 项通过；前端构建、Node 测试和文档链接检查通过。完整后端回归为 1277 项通过、1 项并发调度测试在整套件中偶发波动，单独及文件级重跑通过。无告警、无匹配或任务 `completed` 均不能单独证明设备安全；eBPF 覆盖、设备漏洞适用性、真实硬件、长时间稳定性和人工业务接受仍需独立验证。

## 继续阅读

- [文档总览](docs/README.md)：按使用目的查找资料。
- [当前状态与限制](docs/status.md)：当前部署、已验证能力和未完成项。
- [架构与任务逻辑](docs/architecture/overview.md)：控制台、四角色、执行与证据链。
- [权限与修复边界](docs/reference/security-model.md)：设备身份、写域、审批与审计。
- [验证方法](docs/validation/testing.md)：本地、CI、协议模拟和现场检查。
- [参与维护](CONTRIBUTING.md)：命名、资料清理与提交规则。

本项目用于授权环境中的安全研究与教学。扫描与采集仅面向显式授权目标，设备写入须通过独立的身份、作用域与审批检查。
