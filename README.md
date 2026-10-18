# IoTGuard

**面向多类型物联网设备的多智能体漏洞检测、动态风险研判与安全修复平台。** 物联网设备是研究对象，漏洞检测与修复是核心业务，四智能体是创新方法；资产采集、Falco/eBPF 与 Harness 提供支撑，SOC 汇总呈现。Ubuntu 作为基础设施与对照环境。

当前定位、实现边界和设备验收要求以 [产品定位与验收基线](IOTGUARD_PRODUCT_POSITIONING.md) 为准。默认首页为物联网安全工作台，SOC 位于 `/soc`。OpenWrt 虚拟机与 Zephyr QEMU 的已测结果不能代替实体设备验收；Zephyr 自动固件更新尚未接通，整体闭环仍是部分实现。下述历史“最终交付”仅代表其报告限定范围。

IoT 设备更新实测（2026-10-18）：既有 OpenWrt 已升级至 25.12.6 并通过关机快照恢复；Zephyr 应用已更新至 0.3.0-iotguard，通过回退、崩溃恢复和平台复采。测试随机源与旧组件台账问题已处理。参见 [更新闭环报告](IOTGUARD_IOT_UPDATE_CLOSURE_REPORT.md)；官方公告覆盖仍待补齐，不能宣称漏洞清零。

最终交付（2026-10-18）：参见 [最终产品验收报告](IOTGUARD_FINAL_PRODUCT_ACCEPTANCE_REPORT.md)、[部署说明](DEPLOYMENT.md)、[技术架构](TECHNICAL_ARCHITECTURE.md)、[演示手册](IOTGUARD_FINAL_DEMO_GUIDE.md) 与 [回滚准备](IOTGUARD_FINAL_ROLLBACK_PLAN.md)。这些文件优先于历史阶段报告。正式验证入口为 `http://127.0.0.1:18080`，使用 nginx 生产 dist；设备在线、传感器健康与证据新鲜度分别判断。源风险126未修复，克隆风险127三包已修复，Mimosa仍为partial，修复后快照恢复未执行。

IoTGuard 从授权网段发现、设备指纹与组件识别、多源漏洞匹配，进入四智能体证据研判，再按设备能力选择带审批、回滚和复验的修复方式。eBPF 仅适用于具备相应内核与传感器条件的设备。

> 定位：实验/教学性质的安全工程项目。所有探测、扫描与修复能力均内置授权边界（网段白名单、控制令牌、主机指纹钉扎、审批哈希），默认不启用任何设备写操作。

## 系统架构

```
┌──────────────┐   HTTP/SSH隧道    ┌───────────────────────────────┐
│  前端 (Vue3)  │ ───────────────▶ │        后端 (FastAPI)          │
└──────────────┘                  │  路由层 routers/（17 个模块）    │
                                  │  服务层 services/               │
┌──────────────┐    SSH(paramiko) │   ├─ discovery_pipeline  发现闭环│
│ collector/   │ ◀─────────────── │   ├─ device_inventory    设备指纹│
│ eBPF/资产采集 │   固定脚本+SHA审计 │   ├─ matching_engine      CVE匹配│
└──────────────┘                  │   ├─ unified/ + review_common     │
                                  │   │    LangGraph 统一四角色       │
┌──────────────┐                  │   ├─ agent_harness       修复Harness│
│ simulator/   │ ◀── 真实协议探测 ── │   └─ ebpf_event_collector 证据层│
│ SmartCam-X1  │                  └───────────────┬───────────────┘
└──────────────┘                                  │ SQLAlchemy
                                          ┌───────▼───────┐
                                          │ SQLite (30+ 表) │
                                          └───────────────┘
```

## 目录说明

| 目录 | 内容 |
|---|---|
| `backend/` | FastAPI 后端：`app/routers`（API）、`app/services`（业务服务，含智能体/Harness/发现闭环）、`app/models.py`（30+ 表模型）、`tests/`（隔离 pytest 回归）、`scripts/`（初始化/联调/同步脚本） |
| `frontend/` | Vue 3 + Element Plus + ECharts 前端：16 个业务视图（资产/设备/扫描/智能体/风险/修复/报告），Playwright e2e |
| `collector/` | 设备侧采集脚本：bpftrace eBPF 探针（execve/tcp_connect/openat）、OpenWrt/Linux 只读资产采集器、Falco 规则 |
| `simulator/` | SmartCam-X1 摄像头模拟器：真实监听 SSH/MQTT/HTTP/RTSP 四协议，用于发现闭环联调 |
| `IOT_STAGE*.md` | 各阶段实施/验收/联调技术文档（已脱敏） |

## 运行环境

- 后端：Python 3.12+（开发机为 3.14），`pip install -r backend/requirements.txt`（测试另加 `requirements-test.txt`）
- 前端：Node 24 LTS，`npm ci`（Vue3 + Vite + Element Plus + ECharts + Playwright）
- 设备采集节点：Linux（Ubuntu）；OpenWrt 目标经 SSH（ed25519 密钥引用 + 主机指纹钉扎）

## 配置

复制模板并按需填写（**所有密钥仅通过环境变量提供，源码与模板不含任何真实凭据**）：

```bash
cp backend/.env.example backend/.env   # DeepSeek/NVD Key、控制令牌、发现网段白名单等
cp frontend/.env.example frontend/.env # 仅 API 地址
```

关键环境变量（见 `backend/.env.example` 注释）：`DEEPSEEK_API_KEY`、`NVD_API_KEY`、`LINUXGUARD_CONTROL_TOKEN`（设备操作令牌）、`LINUXGUARD_DISCOVERY_CIDRS`（授权扫描网段白名单）、`LINUXGUARD_ENABLE_DEVICE_REPAIR`（OpenWrt 设备写总开关，默认 0 关闭）。修复类写操作的完整权限契约（控制令牌域 / 采集节点令牌域 / 设备写开关 / 隔离克隆实验室写作用域）见 [Stage 10 写操作权限契约](IOTGUARD_STAGE10_WRITE_PERMISSION_CONTRACT.md)。

## Docker 部署（生产）

```bash
cp backend/.env.example backend/.env.docker   # 按需填写；绝不提交
docker compose up -d --build
# 前端(nginx 生产构建 + /api 反代): http://127.0.0.1:18080
# 后端 API: http://127.0.0.1:18000/api/health
```

- 前端镜像为多阶段构建：Vite 生产构建 `dist` → nginx 提供（SPA 路由刷新回退、`/api` 反代到后端）；**不由 Vite 开发服务器对外服务**。
- 后端镜像包含哈希钉扎的采集/修复脚本（`collector/`），非 root 运行，无特权；数据库在命名卷中，凭据不进入镜像（根 `.dockerignore` 拦截 `.env*`/密钥/运行数据）。
- 边界（重要）：Docker Compose 独立启动的是 **API + 前端**；**Linux 采集节点（Pull Runner）与 Falco/eBPF 传感器运行在外部 Linux 主机上**（`backend/scripts/collection_node_runner.py`、`collector/deploy/falco/`），经网络回连后端。后端容器不加载 eBPF、不持有设备凭据、绝无 privileged 需求。外部采集节点未启动不是后端故障。
- 系统状态展示区分四个独立层次（`GET /api/health` 的 `layers`）：**Backend Online / Collection Node Online / Sensor Healthy / Runtime Evidence Fresh**——后端在线不代表采集节点在线，更不代表传感器健康或运行时证据新鲜。

## 本地启动

```bash
# 后端（默认 sqlite:///<backend>/data/linuxguard.db，启动时自动建表与增量迁移）
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 前端
cd frontend && npm run dev    # http://localhost:5173

# SmartCam-X1 模拟器（发现闭环本地联调用）
python simulator/smartcam_x1.py --host 127.0.0.1 --http-port 8080 --ssh-port 22022 \
    --mqtt-port 21883 --rtsp-port 20554
```

## 测试

```bash
# 后端单元/集成（隔离 pytest 回归；当前规模 680+ 项，以提交时的 CI 输出为准）
cd backend && python -m pytest -q

# SmartCam 真实发现闭环联调（独立进程：真实模拟器 + 真实 HTTP API + 一次性临时库，
# 仅回环 127.0.0.0/25；证据写入 reports/discovery-live-*，不触碰业务库）
python backend/scripts/live_discovery_check.py

# 前端 e2e
cd frontend && npm run test:e2e
```

说明：`tests/conftest.py` 的审计钩子禁止回归测试访问真实网络与非测试数据库；依赖真实本机监听器的 4 个测试文件（`test_iot_device_upgrade/test_mqtt_remediation_workflow/test_scan_runs/test_scan_targets` 部分）需在指定环境以独立 profile 运行，常规回归显式排除（历史已知事项）。

## 当前已实现功能

- **资产发现闭环**：授权网段 TCP 扫描 → `DeviceObservation`（含处理状态机）→ 协议级指纹（SSH/HTTP(S)/RTSP/MQTT 真实报文 + 身份置信度）→ `IotDevice/Service/Component` 建档 → 设备级 CVE 匹配；DHCP 被动观察按 MAC 优先关联
- **多源 CVE 情报**：NVD / CISA KEV / EPSS / Canonical / 麒麟五源，源隔离缓存 + TTL + 内容指纹
- **双路线匹配引擎**：主机线（发行版适用性压制通用数据）与设备线（厂商公告精确版本优先，NVD 通用仅候选）；OpenWrt 精确版本匹配
- **唯一统一四智能体**：asset_investigator → vulnerability_analyst ∥ runtime_analyst → decision_planner；正式入口 `/api/analysis`，off/shadow 拒绝正式请求，没有旧 LLM fallback。风险对象级人审、只读授权补证、新 INV 再研判与 inactive 历史归档裁定见 [M5 迁移契约](IOTGUARD_M5_MIGRATION_CONTRACT_V2.md)
- **Agent Harness**：计划哈希审批、资产锁、工具调用预算、产物 SHA256 注册表、独立回滚、租约恢复；每次工具调用与 LLM 调用均有审计记录
- **eBPF 运行时取证**：bpftrace 探针（进程/网络/文件）→ 统一 SecurityEvidence 证据层 → 智能体消费；LSM 策略默认只观察
- **修复工作流**：确定性授权（高危自动结论永不放行）、MQTT 匿名接入真实修复状态机（备份→修复→重探→回滚）；设备侧修复默认关闭
- **互联网授权目标扫描**：双重授权（网段白名单 + 显式登记）→ 端口扫描 → 指纹 → CVE，全程审计留痕

## 当前产品方向

IoTGuard 的主体是**面向多类型物联网设备的智能漏洞检测与修复系统**。OpenWrt 与 Zephyr 是下一阶段的主要开发和验收对象；Ubuntu 用于控制面、采集节点和对照验证。

- **OpenWrt**：已有 VMware 实例的真实包清单与日志采集，优先补齐官方公告适用性、设备身份统一、实际修复与回退闭环。
- **Zephyr**：使用原 QEMU 固件实例，优先补齐内核与 Kconfig 构建证据、配置感知匹配，再开发固件更新与回退。
- **共用平台**：围绕上述两条设备链维护四智能体、证据、授权、审计与展示；暂停扩展 Ubuntu 漏洞专题和克隆实验。

当前两种 IoT 系统均运行在虚拟环境，尚不能视为实体硬件验收。详见 [设备状态报告](IOTGUARD_IOT_DEVICE_STATUS_REPORT.md) 与 [开发路线及验收标准](IOTGUARD_IOT_FIRST_ROADMAP.md)。
