# IoTGuard Stage 10 产品完成统一报告

日期：2026-10-17（Asia/Shanghai）。仓库：IoTGuard-Public。基线：`9ce6e60`（origin/main 核验一致，工作区干净起步）。

**四项核心问题总判定**：

| 核心项目 | 判定 | 真实证据 |
| --- | --- | --- |
| 真实修复闭环 | **blocked**（停在授权门禁；可自动化准备 100% 完成并经只读复核） | 克隆未创建、快照未恢复、apt 索引未刷新、dpkg 零写、双写开关全程 0；官方依据纠正完成（USN-8932-1）；授权包 `local-archive/stage10-work/authorization-request.json`（sha256 `8765d590…772db`）已刷新待批 |
| 实时监控 | **partially_completed**（1/2 传感器完整恢复并留真实证据；1/2 停在 VM root 授权点） | `openwrt-logread-1`：422 条新事件入库、当日时间戳 154 条、Runtime Analyst 实际消费（4 条 finding 引用当日事件）；`wyh-…:falco`：查明 10-14 被手动 stop，恢复命令已给出但需 VM sudo，未执行 |
| 研判效率 | **completed**（同输入真实前后对照达标或如实说明） | 风险 12 shadow：41m46s/19 次/325,405 tokens → **19m05s/10 次/216,674 tokens**（耗时 −54.3%、调用 −47.4%、tokens −33.4%）；结论一致、零降级 |
| 产品交付 | **completed** | 权限契约 + 全写端点认证核验；前后端生产级 Docker 构建运行验证通过；采集脚本完整性修复；文档一致性整理完成 |

实现提交：本报告随本轮统一提交进入仓库（commit hash 见提交记录/最终答复）。全程零设备写、零生产资产/风险 126 变更、生产双写开关恒为 0。

---

## 一、P0-1 权限契约与写接口审计 —— completed

**唯一正式契约**：`IOTGUARD_STAGE10_WRITE_PERMISSION_CONTRACT.md`（本轮新增，替代此前散布在 M4.5 设计/实验设计/代码之间的不一致描述）。

### 1.1 发现并修复的文档-代码矛盾（真实阻断项）

第一轮运行手册承诺"实验仅开 `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR`、设备开关恒 0"，但 `ubuntu_repair.py` 的 execute/claim 同时要求**双开关为 1**——按代码实验必须打开生产设备写开关（违反隔离原则），按文档实验根本无法执行。本轮修复：

- `LINUXGUARD_ENABLE_DEVICE_REPAIR` 收窄为 **OpenWrt 设备写专用域**（`agent_harness.install_registered_package`），Ubuntu 隔离克隆路径不再读取；
- Ubuntu 实验写 = `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=1` **且** 新增 `LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE`（逐资产白名单，**空 = fail-closed**）**且** 既有逐克隆许可文件（asset_id+machine_id_sha256+plan_hash+isolated_clone+restore_verified+snapshot_id+approved_by+expires_at）在后端与节点两侧独立成立；
- 节点侧 `collector/ubuntu_package_maintenance.py` 的 `permit()` 同步改为实验室开关单域（设备开关不再作为前置）；
- 后端 `queue()`/`claim()` 两处独立复核作用域。

测试：`test_backend_lab_write_scope_is_fail_closed` 明确断言"LAB=1 但作用域未声明 → 拒绝；**DEVICE_REPAIR=1 也不能解锁实验室写**；声明作用域后方可排队"。

### 1.2 全量写接口审计结论

逐路由枚举全部 POST/PUT/PATCH/DELETE 及有写副作用的端点（共 19 个路由文件）。**本轮发现 6 个此前无认证的真实写入口并全部补齐 `require_control`**：

| 端点 | 写副作用 | 修复 |
| --- | --- | --- |
| `POST /api/risk/calculate` | 重写 RiskAssessment | ✅ 补认证（配套测试适配） |
| `POST /api/remediation/generate` | 写 RemediationTask | ✅ 补认证 |
| `POST /api/vulnerabilities/sync-real` | 写情报库+消耗 NVD 配额+触发联动分析 | ✅ 补认证 |
| `POST /api/vulnerabilities/sync-ubuntu-assets` | 同上 | ✅ 补认证 |
| `POST /api/vulnerabilities/sync-kylin-assets` | 同上 | ✅ 补认证 |
| `POST /api/unified/analyze` | 发起真实 LLM shadow 运行（真实 Token 成本） | ✅ 补认证（on 模式下本就 409 fail-closed） |

其余全部写端点原有 `require_control`；采集节点端点（claim/results）走独立 `X-Collection-Node-Token` 域并强制"令牌所属节点＝声名节点"。**不是**通过新增一个统一字符串比较完成——沿用既有 `hmac.compare_digest` 常量时间比较与节点身份绑定机制。前端全局拦截器已自动附带令牌，交互不变；未解锁时明确 401/503。演示入口核查：`GET /demo/targets` 与 `POST /demo/start` 均已受令牌保护，`_bootstrap_targets` 仅从环境变量播种且仅在空表时。

回归：`tests/test_risk_engine.py`、`tests/test_unified_pipeline.py`、`tests/test_unified_investigation.py` 相应适配并**增强断言**（无令牌 → 401/503，有令牌 → 原语义）。

---

## 二、P0-2 真实 Ubuntu 漏洞修复闭环 —— blocked（停在授权门禁；准备与核验全部完成）

### 2.1 官方依据核验与纠正（本轮关键产出）

直接抓取官方原文 `https://ubuntu.com/security/cves/CVE-2026-94266.json` 并逐字段核验（content_sha256 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`，与库内原始记录 id=174 一致且跨次抓取稳定）：

| 通告 | 覆盖发行版 | noble/curl 修复版本 |
| --- | --- | --- |
| **USN-8927-1** | **仅 resolute** | **无** |
| **USN-8932-1** | trusty/xenial/bionic/focal/jammy/**noble** | **源包 curl `8.5.0-2ubuntu10.16`** + 6 个二进制包（curl、libcurl3t64-gnutls、libcurl4-doc、libcurl4-gnutls-dev、libcurl4-openssl-dev、libcurl4t64） |

**历史文档关联错误确认并纠正**：第一轮报告及 `ai_collaboration` 两处叙述把 noble 修复通告写作 USN-8927-1，实为 **USN-8932-1**。处理方式：原始记录保留，第一轮报告顶部新增显式纠正声明（保留原文）；库内核验确认**产品派生字段自始正确**（notice_fixes=`USN-8932-1`，`notices` 数组同时含两个 id 是对官方原文"该 CVE 被两个通告引用、作用域不同"的忠实回显，非错误）。最终修复计划的 `official.notices` 由代码从官方原文实时推导（仅纳入对 noble 携带该修复版本的通告），无需数据迁移；当前不存在已批准计划，审批哈希零失效影响。

noble 状态 `needed`、pocket `security`、目标 `8.5.0-2ubuntu10.15 → 8.5.0-2ubuntu10.16` 不变。

### 2.2 隔离克隆准备（只读复核全部通过，写操作停在门禁）

复用第一轮产物（未重设计）：`local-archive/stage10-work/` 下 `authorization-request.json`、`clone-identity.json`、`clone-operation-plan.md`（阶段 A–F）、`register-clone-runbook.md`、克隆专用 Ed25519 密钥对。本轮只读复核：

- `vmrun list`：两台 VM 运行（OpenWrt + Ubuntu 24.04 源机）；源机 **0 快照**、可达、身份未变；
- E 盘 312 GB 可用（全量克隆空间充足）；
- 预选地址 `192.168.183.110`：ping 无响应 + ARP 无条目 + DHCP 池（.128-254）外 → **无地址冲突**；
- 授权包刷新两次（本日 15:29 与 16:49），双开关核验 0、5 项门禁动作清单完整、`authorization_not_granted_by_this_package=true`。

**未执行（等待授权一/授权二）**：源 VM 软关机窗口、克隆创建、克隆身份重配置、联网准入、基准快照与恢复验证（`restore_verified` 只能在真实恢复验证后置 true）、克隆内官方 apt 索引刷新、四智能体克隆 formal 研判、Harness 克隆计划、dpkg 安装、自动复采与复评、回滚验证。**本报告不以任何模拟产物替代上述任何一项。**

---

## 三、P1-1 实时监控恢复 —— partially_completed

### 3.1 两个 stopped 传感器的真实查明（非数据库状态误报）

| 传感器 | 真实组件 | 停摆根因（从设备侧 journalctl 取证） |
| --- | --- | --- |
| `wyh-vmware-virtual-platform:falco`（资产1） | Ubuntu VM 内 `linuxguard-falco.service`（falco eBPF 探针 → 转发器批量上传，systemd 常驻） | **2026-10-14 21:12:05 操作员手动执行 `sudo systemctl stop linuxguard-falco`**（最后一条捕获事件就是这条停止命令），干净退出（drops=0、spool 空、16 事件已传）后未再启动；服务 enabled 但当前 inactive(dead)——**真实停摆** |
| `openwrt-logread-1`（资产2） | 拉取式 syslog 窗口采集（每次采集触发，非常驻探针） | 非故障：其心跳仅在采集时刷新，10-16 11:23 后无采集触发即过期——**拉取通道本身健康，需触发采集验证** |

### 3.2 已完成的真实恢复与证据

**采集节点通道**（恢复的前提）查明并修复两处真实缺陷：
1. 节点 Runner 的 HTTP 封装只捕获 `URLError`，后端重启产生的 `RemoteDisconnected`（`http.client.HTTPException`/OSError 族）直接杀死常驻循环——已补 `OSError/HTTPException` 捕获 + 服务循环兜底重试；
2. 实测验证：后端连续三次重启，节点从"重启即失联"变为**自动恢复在线**（`/api/health` 四态中 Collection Node Online 实测翻转）。

**`openwrt-logread-1` 恢复（完整）**：触发既有 `POST /api/iot/connections/1/collect-logs`（只读拉取，固定脚本 SHA256 入审计）→ **422 条新事件入库、769 条幂等去重**、当日时间戳事件 154 条（恢复前库内最新为 10-16 10:51）、心跳刷新。事件来源 `openwrt_logread`、设备 boot_id 与时间窗均在 `security_evidence` 可核。

**Runtime Analyst 实际消费新证据（任务书第 5 项）**：shadow 运行 `UA-20261017090833-0a6622`（OpenWrt 资产 surface，19m12s/12 次/154,352 tokens/零降级）——runtime_analyst 输出 10 条 finding，其中 **4 条引用当日恢复入库事件**（`SE-1da5b608…`@07:45:58、`SE-c607bc2a…`@07:40:23、`SE-3a3d371d…`@07:48:15、`SE-da598b5c…`@02:39:41），引用关系在库内逐条核验为 `source=openwrt_logread`、`created_at=2026-10-17 08:21`（本轮恢复拉取时刻）。结论如实标注 `stale_verified`/`freshness=mixed`，无伪造攻击、无伪装传感器正常状态。

**`wyh-…:falco` 恢复（停在授权点）**：恢复命令唯一且明确——VM 内 `sudo systemctl start linuxguard-falco`（或批准一次 VM 重启，服务已 enabled 会自启）。VM 的 sudo 需交互口令、root SSH 密钥登录被拒、本地归档无该凭据——**未执行、未绕过、未把 stopped 改成 running**。

### 3.3 四态产品展示

`GET /api/health` 新增 `layers`：**backend_online / collection_node（configured+online+last_seen）/ sensors（逐传感器状态与心跳年龄）/ runtime_evidence（fresh+最新事件年龄）**——四层互相独立，停止的传感器与过期证据不会被 200 响应掩盖。拉取式传感器诚实引入 `reporting`（最近窗口成功）语义，不冒充常驻 running。前端顶栏从单一"系统在线"改为分层展示（后端在线 · 采集节点在线/离线 · 传感器 x/y · 运行时证据新鲜/过期）。新增回归 `test_health_reports_four_independent_layers`。

---

## 四、P1-2 四智能体效率优化 —— completed（同输入真实对照）

### 4.1 基线剖析（M5 保留的真实运行记录）

正式风险 126 `UA-5daea17f`（03:13:35→04:02:19）：48m45s、29 次 LLM、441,460 tokens（267,478P+173,982C）。逐阶段定位三处真实浪费：
1. **冲突复议从零重建上下文**：`directed_rereview` 只给冲突描述+前次结论截断 2000 字符，丢失全部预取事实/候选清单/工具指引 → 复议角色跑了 13m12s 后校验失败，**原本成功的角色反被标记 degraded**；
2. **无新证据的决策重跑**：唯一 follow-up 是 inventory 类（操作员门控、本轮必然零新证据），图仍执行补查并**完整重跑 decision_planner**（296,866ms）；
3. **重复工具调用无请求内缓存**（同参数版本比较/情报查询在重试与复议中反复执行）。

### 4.2 最小必要优化（三项，全部保留 LangGraph 四角色拓扑与全部工具能力）

1. **请求内确定性工具缓存**（`agent_base.CACHEABLE_TOOLS`）：仅缓存一次运行内事实不变的工具（版本比较=纯函数；情报源/命中/画像=仅操作员动作可变，而操作员动作不可能发生在运行中途）；**时间敏感的运行时证据工具（进程/网络/文件/进程树/数据质量）明确排除**——跨时点事实不缓存。缓存随 RunContext 生命周期创建销毁，不跨运行泄漏（有测试）。
2. **inventory-only 补查不再触发决策重跑**：全部 follow_up_requests 均为 `collection_capability=inventory` 时直接 finalize（申请仍由 finalize 幂等登记为待授权项）；`database`/`target_agent` 类定向复查保留原路径（有对照测试证明两种路由行为）。
3. **定向复议继承完整首次上下文**（`RunContext.first_contexts`）且**失败保留原结论不降级**：未消解冲突仍由 merge_rereview 确定性转人工，不再把成功角色误标 degraded。

新增 5 项效率回归测试（缓存命中/不跨运行泄漏/运行时工具绝不缓存/inventory-only 跳过/定向复查保留/复议继承与失败保原）。

### 4.3 同输入前后对照（真实业务输入、真实 LLM，非伪造指标）

同一对象（风险 12）、同模式（shadow）、同默认调查目标：

| 指标 | 基线 `m47-glm-smoke4` | 优化后 `UA-20261017084453-a65f5a` | 变化 |
| --- | --- | --- | --- |
| 总耗时 | 41m46s | **19m05s** | **−54.3%** |
| LLM 调用 | 19 | **10** | **−47.4%** |
| 总 Token | 325,405（198,473P+126,932C） | **216,674**（150,003P+66,671C） | **−33.4%** |
| 各角色 | 4 角色齐全+复议 | 4 角色齐全+复议 | 一致 |
| 最终结论 | not_affected / monitor / low / downgrade_major（conf 0.85） | **相同**（conf 0.8，模型方差内） | 一致 |
| 安全门禁 | 冲突未消解→人工复核 | **相同**（同冲突码、unresolved→人工） | 一致 |
| 降级 | 无 | 无 | 一致 |

**如实说明**：Token 成本改善 33.4%，未达任务书 40–50% 目标区间下限；耗时（−54.3%）与调用数（−47.4%）在区间内或更优。瓶颈：固定指令与 schema 的提示开销及模型输出冗长度主导剩余成本；进一步压缩需削减指令/输出约束，有判定质量风险，本轮不做（任务书禁止为达标降低适用性判断质量）。基线选择说明：风险 126 处于 `pending_human_review` 人工门禁（Q1–Q8 等待操作员裁定），为不扰动生产正式状态，对照选用有现成同输入基线的风险 12 shadow；126 的 441,460-token 基线按原样引用、未重跑。

---

## 五、P1-3 产品级 Docker 交付 —— completed

| 项 | 修复前 | 修复后（本轮实测） |
| --- | --- | --- |
| 前端镜像 | `npm run dev` Vite 开发服务器对外（含热更新/调试面） | 多阶段构建：Vite 生产构建 `dist` → **nginx 1.27-alpine**；SPA 路由刷新回退（`/risk` 200 实测）、哈希资产不可变缓存、无任何 dev server 特性 |
| API 地址 | 构建时硬编码 | `VITE_API_BASE=/api` 相对路径 + nginx `/api` 反代到后端服务；bundle 实测无 `localhost:8000` 残留 |
| 后端镜像完整性 | 缺 `collector/`（哈希钉扎的采集/修复脚本）与 `migrations/` → Docker 内采集/修复预检必失败 | 根上下文构建补齐 `collector`、`migrations`；预检所需脚本在镜像内可读 |
| 权限 | — | 非 root（uid 10001）、无 privileged、健康检查、命名卷数据 |
| 密钥防泄漏 | 无 .dockerignore | 根 `.dockerignore` 拦截 `.env*`/密钥文件/`backend/data`/`local-archive`/`reports`；镜像内核验无 `.env*`/`*.key`/`*.pem` |
| 编排 | 无 | `docker-compose.yml`（backend + frontend），显式注释**采集节点 Pull Runner 与 Falco/eBPF 传感器运行在外部 Linux 主机**，不经 compose 启动、不为此给容器 privileged |

**实测**（Docker 29.4 / Compose v5.1.2，验证端口 18000/18080 避让宿主生产后端）：`docker compose build` 双镜像成功；双容器 `healthy`；前端 `http://127.0.0.1:18080/` 200、SPA 刷新 200；`/api/health` 经反代 200 且返回四态分层；`/api/assets` 只读正常（容器自带空库，未 COPY 生产数据）。

**能力边界声明**：Docker Compose 独立启动 = API + 前端。Linux 采集节点（`backend/scripts/collection_node_runner.py`）与 Falco/eBPF 传感器（`collector/deploy/falco/`）必须运行在外部 Linux 主机上，经网络回连后端——外部采集节点未启动不是 Docker 后端故障。

---

## 六、P2 文档一致性与安全核验

- **README**：新增生产 Docker 部署节（含能力边界与四态说明）、权限契约引用、测试规模改为"以提交时 CI 输出为准"（旧的 341 已过时）；唯一正式引擎为 unified、System A/B 退役表述保持（架构核对无残留）。
- **ai_collaboration 五份文档**：Stage 10 状态块统一更新为第二轮事实（含 USN 纠正、传感器分别报告、效率对照、Docker 实测、扫描结果如实披露）。
- **测试数量**：不混用口径——M5 交付 667 → 第一轮 682（多节点注册扩展）→ 本轮 **689 passed / 0 failed（490.43s，最终树全量）**；增量 7 项全部为本轮新增（效率回归 5、健康四态 1、实验室作用域 fail-closed 1），零删除；前端 e2e 21/0。
- **Mimosa 深扫**：`scan-2026-10-17T09-08-58.996Z-4dc68ad6cebb`（seal `sha256:53c54180ef65df31cf37704572b2bfe31f23998c9a8d37bd871c59795f3a8822`）。**如实披露**：`completeness=partial`、`runStatus=inconclusive`（threatModel 阶段观察到 0 个入口点——扫描器覆盖局限，与历史 enobufs/coverage=partial 同源）；1 个 high advisory：`stage10_authorization_package.py:write_private` 静态疑似路径穿越。人工核验：该脚本是纯 CLI 工具、未被任何路由挂载（无 HTTP 面），写入路径为硬编码常量 `WORK / "authorization-request.json"`——判定为误报；仍按纵深防御在该函数内新增"仅允许写入 local-archive 内"的包含检查（真实修复而非规避，发现保留留痕）。未以扫描器异常时的放行冒充完成验收。

---

## 七、边界、授权与未关闭缺口

**全程红线**：`LINUXGUARD_ENABLE_DEVICE_REPAIR=0`、`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=0` 恒成立（多次只读取证）；原始资产 1、风险 126、两条原连接零改动（风险 126 保持 `pending_human_review` 等待操作员对象级裁定）；生产库除只读查询与产品自身业务写入外无手工修改。

**仍需用户独立批准/提供**：
1. **授权一**：源 VM 软关机窗口与克隆创建、克隆身份重配置、联网准入、基准快照与恢复验证、克隆内经批准的官方 apt 索引刷新（阶段 A–E/F，见 `clone-operation-plan.md`）；
2. **授权二**：`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR` 实验窗口置 1 + 声明 `LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE=<克隆asset_id>`、精确 Harness 计划审批、dpkg 写、（如需）回滚——授权一不自动授予授权二；
3. **Falco 传感器恢复授权**：在 VM 执行 `sudo systemctl start linuxguard-falco`（需 sudo 口令或批准一次 VM 重启；服务已 enabled）；
4. 既有人工门禁（非本轮新增）：Q1–Q8 迁移裁定、风险 126 对级人工裁定、风险 12 归档确认、补证申请授权。

**尚未关闭的真实缺口**：真实修复闭环全部执行项（等 1+2）；falco 传感器启动（等 3）；扫描覆盖完整性（扫描器 threatModel 阶段 0 入口点，已如实披露）；研判 Token 成本 −33.4% 未达 40% 目标（瓶颈与不降质约束已说明）。

完成后停止，不自行启动下一阶段、不扩大设备修复范围。
