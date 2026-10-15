# eBPF 2.0 P2-2 报告：OpenWrt 轻量化降级采集（logread 只读）

> 日期：2026-10-15。本报告为 eBPF 2.0 升级 P2-2（OpenWrt 降级采集）的正式交付。
> 核心边界：**不安装 eBPF、不修改 OpenWrt 任何系统配置、不装软件包**——使用设备原生
> logread 实现真实、只读的运行时安全证据采集；事件 source 恒为 `openwrt_logread`
> （观察模式 `syslog`），**绝不伪装 eBPF**。
> 原始证据：`reports/ebpf-p22-20261015-111451/`（本地留存，含实验网段标识不入库）。

---

## 1. 测试环境

| 项 | 值 |
| --- | --- |
| 设备 | OpenWrt 25.12.5（内核 6.12.94，x86/64，VMware 虚机，VMnet2 实验段——具体地址仅存本地证据） |
| 设备时区 | GMT0（`date +%z`=+0000，与 UTC 一致，实测） |
| 日志接口 | BusyBox logread 环形缓冲（实测 1283 行/窗口，含开机 kernel 日志与运行期 daemon/auth 日志） |
| 采集通道 | 既有 DeviceConnection 机制：SSH 主机指纹钉扎（SHA256，与 2026-10-13 受信记录一致）+ 设备私钥经 `LINUXGUARD_DEVICE_*` 环境变量引用（密钥文件仅存本地 gitignored 证据目录） |
| 后端 | Windows 11 / FastAPI + SQLite 标准模式，一次性评测库，白名单=授权实验段 |
| 对设备改动 | **零**（只读脚本：logread + 身份信息读取；脚本经 stdin 固定下发，内容哈希入审计） |

## 2. 设计与实现

### 2.1 组件

| 组件 | 说明 |
| --- | --- |
| `collector/openwrt_logread_capture.sh` | 设备端固定只读脚本：身份段（hostname/boot_id/UTC 纪元/本地偏移/TZ 规格）+ logread 全量输出；分段标记与既有资产采集器约定一致 |
| `backend/app/services/openwrt_runtime_log.py` | 核心服务：解析（`parse_capture_output`）→ 标准化（`logread_line_to_event`，纯函数）→ 经 `append_events` 接入 P0 管线（`collect_runtime_logs`：复用 `device_access.open_connection` 指纹钉扎连接 + `run_fixed_script` 固定脚本执行） |
| `POST /api/iot/connections/{id}/collect-logs` | 路由端点（统一 Trace 包裹，task_type=`runtime_log_collection` 已登记） |
| 观察模式 | `_observation_mode`：logread/syslog → `syslog`（新增第五种模式，与 ebpf/sensor/probe/runtime 并列）；`SensorHeartbeat.source` 增加 `logread` |
| 智能体 | `tool_query_runtime_data_quality`：OpenWrt 资产缺 logread 采集 → 显式 data_gap；已有 → 声明"拉取式降级采集、非 eBPF 内核级观测、ring 窗口外历史不可知" |

### 2.2 日志标准化（实测格式）

```
Thu Oct 15 02:21:57 2026 auth.err dropbear[1234]: Password auth failed for 'root' from 198.51.100.5:51234
└─周──┘└─月─┘└日┘└─时:分:秒─┘└─年─┘ └facility.level┘ └─process[pid]─┘ └──── message ────┘
```

映射：`source=openwrt_logread`、`event_type=syslog`、`process_name`/`process_id`（无 pid 如实 0）、
`severity`=level 归一（warn→warning/err→error/crit→critical/emerg→emergency）、`rule`=facility.level、
`boot_id`=设备实测值；raw 保留**原始行全文** + facility/level/process/pid/message/设备自报主机名
（设备锚点）/本地时间文本（指纹稳定性根基）/时区偏移/传输标记。

### 2.3 时间语义（不猜测原则）

- logread 时间为**设备本地时间**：按采集时刻捕获的 `date +%z` 偏移换算 UTC（实测 +0000）；
- 偏移仅在采集时刻成立，历史 TZ/时钟变更**不可追溯**（如实写入 `timezone_basis` 元数据，raw 保留原始行全文可复核）；
- **缺少年份**（RFC3164 防御形态）或不可解析行 → **跳过并计数**（year_missing/unparseable，附最多 3 条样本），不虚构年份：无完整时间的事件不具备 P0 判重身份，跳过以保重复采集幂等；
- 无法确定的信息一律 unknown/空（不猜）：如缺身份段时字段为空串并如实降级。

### 2.4 复用 P0 机制（不建第二套事件库）

- 事件经 `append_events` 走**既有** RuntimeEvent/SecurityEvidence 双表管线：指纹幂等（anchor=设备自报主机名 + boot_id + raw，asset_id/sensor_id 为传输键不参与身份）、资产绑定与回绑、证据同步生成——零新表零新库；
- 重复采集=每次全量拉取（设备只读不留游标状态）+ 服务端指纹判重收敛；
- **设备重启**：boot_id 参与指纹（同主机名跨重启不误合并，专项测试锁定：同日志行跨 boot_id 指纹集合零交集）；ring 缓冲随重启自然重置为窗口边界，不做跨重启拼接；
- **历史日志边界**：每次采集记录窗口元数据（首/末事件时间、行数、是否截断）；ring 中已被覆盖的行不可知 → 丢失计数 **unavailable**（非零丢失），写入传感器心跳语义。

### 2.5 采集过程发现并修复的真实缺陷

| # | 缺陷 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | 全量事件误分类 sensitive_file_access（1246 条 file 证据） | raw 传输标记 `logread_ssh_pull` 含关键词子串 "ssh"，命中分类关键词表 | 改名 `logread_remote_pull`（服务层注释固化命名约束） |
| 2 | "立即重复采集"并非严格 0 新增 | 每次采集本身是一次 SSH 会话，设备侧自然新增 dropbear 登录日志（3 条/次） | 验收语义改为全量对账：duplicates+stored_new=窗口行数 且 stored_new≤会话噪声（如实说明，不强行断 0） |

## 3. 真实验收结果（21/21，reports/ebpf-p22-20261015-111451/）

| 验收点 | 结果 |
| --- | --- |
| 主机指纹 | 捕获 SHA256:+CaF…NKAU，与 2026-10-13 受信记录一致（钉扎验证通过） |
| 真实采集 | 首采 **1237 条真实 logread 事件**（1283 行窗口：1237 解析 + 46 空行/kernel 时间戳外的不可解析防御路径如实计数），窗口 [00:13:30 → 03:01:55 UTC]，boot_id abbc3748… 留档 |
| 资产绑定 | 1237/1237 全部绑定 asset_id=1；SecurityEvidence 1237 条同步生成（1:1） |
| 来源标记 | source=openwrt_logread（数据库逐行核验）；观察模式=syslog；数据质量工具向智能体声明"非 eBPF 内核级观测" |
| 重复采集幂等 | 二采全量对账：duplicates 1268 + stored_new 3 = built 1271（3 条=采集会话自身 SSH 登录产生的真实新日志，如实说明）；零重复入库 |
| 窗口变化 | 失败 SSH 认证（真实制造，设备零改动）+ 会话日志 → 三采 stored_new=5、旧行 1262 判重、dropbear 相关事件 57 条可见 |
| 智能体读取 | 数据质量 found + 降级边界声明；process/network/file 证据工具均返回真实 OpenWrt syslog 证据 |
| CVE 风险层 | 评测库登记 dropbear 风险脚手架 → `cve_runtime_evidence` 下钻：真实 syslog 证据直接匹配 **direct_count=57、runtime_status=verified**（exploitation_confirmed 仍恒 False，诚实边界不变） |
| 统一 Trace/AgentOps | `GET /api/traces?task_type=runtime_log_collection` 返回 completed 记录（task_started/logread_collected/task_finished 事件齐全） |
| coverage/reliability 端点 | logread 传感器可见（dropped=None→unavailable，ring 覆盖丢失不可测语义） |
| 设备重启 | **未真实执行**（避免对设备干预）：boot_id 身份区分由专项测试锁定（跨 boot 指纹零交集），boot_id 留档供跨运行比对 |
| Zephyr | 未触碰任何 Zephyr 代码路径（unsupported/telemetry 语义不变；相关既有测试全量回归通过） |

## 4. 测试

| 项 | 结果 |
| --- | --- |
| 新增专项 `test_ebpf_p22_openwrt_logread.py`（解析/时间语义/跳过计数/事件形状/观察模式/心跳源/管线幂等/证据/重启身份/窗口元数据/数据质量/Trace） | **23/23 passed** |
| 相关域（runtime/agent/trace/ebpf/iot/evidence，实现期中检） | 306 passed / 0 failed |
| 全量回归 | 见 `reports/ebpf-p22-20261015-111451/regression-final.txt` 与 ai_collaboration/TEST_RESULTS.md（本轮记录） |

## 5. 安全与边界

- 对设备零写入、零配置改动、零软件包安装（固定只读脚本，内容 SHA256 入审计）；
- 设备私钥/实验地址/用户名全部经环境变量或本地证据目录，**跟踪文件零暴露**；
- 评测脚本（`ebpf_p22_openwrt_live.py`）数据库访问全部经生产 ORM（零原生 SQL）；HTTP 客户端环回白名单（CWE-918）；指纹捕获用原生 Transport 握手（不做信任决策）；
- 诚实边界：syslog 为降级采集（无内核级 execve/connect/openat 观测，消息内容取决于设备 daemon 的日志详略）；CVE 下钻的文本匹配属上下文/直接关联，exploitation_confirmed 恒 False；无 logread 覆盖不代表安全。

## 6. 可重复执行步骤

```bash
# 前提：仓库根目录；授权实验段内 OpenWrt 可达；设备凭据与受信指纹经环境变量提供
LINUXGUARD_OPENWRT_HOST=<设备地址> LINUXGUARD_OPENWRT_USER=<用户> \
LINUXGUARD_OPENWRT_KEY_FILE=<本地设备私钥路径> \
LINUXGUARD_OPENWRT_HOSTKEY_SHA256=<受信指纹> \
  python backend/scripts/ebpf_p22_openwrt_live.py      # 真实验收 21 项
python -m pytest backend/tests/test_ebpf_p22_openwrt_logread.py -q   # 专项语义
```

生产接入：既有 DeviceConnection（`POST /api/iot/connections`，指纹钉扎+凭据环境变量引用）
→ `POST /api/iot/connections/{id}/collect-logs`（每次全量拉取，幂等收敛）。

## 7. 最终验收结论

| 任务书要求 | 结果 |
| --- | --- |
| 1. 复用既有 SSH 只读采集连接方式 | ✅ DeviceConnection + 指纹钉扎 + 固定脚本（与资产采集同机制） |
| 2. 日志标准化（来源/时间/身份/类型/结构化字段） | ✅ §2.2；raw 保留原始行全文 |
| 3. 年份缺失/时区/重启/重复/历史边界 → unknown 不猜测 | ✅ §2.3/§2.4（跳过计数、偏移留档、boot_id 身份、窗口元数据、ring 丢失 unavailable） |
| 4. 接入 RuntimeEvent/SecurityEvidence + 资产绑定 + 来源标记 | ✅ 1237/1237 绑定、证据 1:1 |
| 5. 复用 P0 幂等与可靠传输，不建第二套事件库 | ✅ append_events 既有管线，零新表 |
| 6. Runtime Agent 真实证据与数据质量 | ✅ 数据质量/证据工具实测（含降级边界声明） |
| 7. CVE 风险层/统一 Trace/AgentOps 实际联调 | ✅ direct_count=57 verified；Trace completed |
| 8. syslog/logread 标记，严禁伪装 eBPF | ✅ source/观察模式/智能体声明三层保证 |
| 9. Zephyr 语义不变 | ✅ 零触碰，全量回归通过 |
| 10. 不修改防火墙/网络/服务/软件包 | ✅ 只读脚本，零改动 |
| 验收清单（真实采集/幂等/绑定/窗口变化/智能体/回归） | ✅ 21/21 |

**遗留（低优先）**：① 拉取式采集依赖人工/定时触发，无常驻增量（设备只读不留状态，属设计边界而非缺陷）；② syslog 消息详略取决于设备 daemon 配置，认证类之外的行为覆盖有限（降级采集固有边界）；③ 真实设备重启演练未执行（避免干预），可在专用窗口补测。

**边界**：P2-2 完成后停止；未进入第九阶段；未删改任何既有测试。
