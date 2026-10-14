# IoTGuard eBPF 2.0 — P1 准备轮实施报告（探针增强 + Falco 部署准备）

日期：2026-10-14。基线：P0（Private 同步至 public main，工作区干净）。
本轮范围：**P1-1 探针增强（execve argv + process start_time + 合成会话键）的可独立验证部分**
与 **P1-2 Falco 常驻部署准备**。未进入 P1-3/P1-4 与 P2；未在 VM 执行任何特权操作。

---

## 1. P1 前置审计结果（任务 1）

| 项 | 结果 | 证据 |
|---|---|---|
| P0 功能完整 | 是 | `test_ebpf_p0.py` 18/18 通过（本轮相关套件联跑内） |
| 历史失败集合未变 | 是 | 动手前重跑全量：374/19，19 项与 P0 基线逐项一致（`regression-baseline-p0.txt`） |
| P1 涉及源码/脚本 | 已核对 | `collector/ebpf_trace_capture.sh`（探针+内联后处理）、`collector/ebpf_event_collector.py`（转发器）、`backend/app/services/ebpf_event_collector.py`（归一化）、`runtime_telemetry.py`（timeline 已支持 exec_id/boot_pid_start_time 两种分组基）、`models.py`（`process_exec_id`/`process_start_time`/`boot_id` 列已存在——**无需数据库迁移**） |
| Falco 真实部署状态 | 未部署 | 沿用审计轮实测：VM falco 0.44.1 已装、自定义规则不在 `/etc/falco/`、`falco-custom`/`falco-kmod-inject` inactive；本轮无 VM 访问，状态未变化（无新证据声称变化） |
| WSL 探针环境 | 可用 | 实测：WSL2 Ubuntu、内核 6.6.87.2、bpftrace v0.20.2、root、BTF 存在（`/sys/kernel/btf/vmlinux` 加载成功） |
| VM 探针环境 | 不可达 | 本轮无 VM sudo 授权窗口；维持审计轮结论（sudo 需密码） |
| Mimosa | 不可用 | 本机复现：`mimosa` 命令不在 PATH（`Get-Command mimosa` 无结果）；历史记录原因为 `python_ast_unavailable`；全局安全扫描未执行，不声称完成 |

## 2. 实际完成情况

### 2.1 P1-1 探针增强：**已完成并在真实内核验证**

| 项 | 状态 | 说明 |
|---|---|---|
| execve argv 采集 | ✅ 完成 | 内核侧 `str(uptr(args->argv[i]), 48)` 逐参数读取 + NULL 守卫；后处理解析入事件（`argv` 字段 + `commandline` 含完整参数） |
| process start_time | ✅ 完成 | 三类事件（execve/connect/openat）均携带 `curtask->start_time`（自开机单调纳秒） |
| 合成会话键 | ✅ 完成 | `process_exec_id = lg-{boot_id前8}-{pid}-{start_time}`，确定性、PID 复用可区分；落列后 `timeline` 按 exec_id 基分组（既有逻辑，零改动） |
| 事件字段/数据结构适配 | ✅ 完成 | 后端 `normalize_event` 有界透传 argv（≤32 项 ×256 字符）；DB 列复用既有（无迁移）；旧事件不受影响 |
| 向后兼容 | ✅ 完成 | 旧格式行解析逐字段一致（不虚构新字段、事件身份不漂移）；`PROBE_MODE=legacy` 强制旧探针；增强探针编译失败自动回退旧探针并如实标注 |
| 专项测试 | ✅ 完成 | `test_ebpf_p1_probe.py` 11/11 通过 |
| 真实内核验证 | ✅ 完成 | WSL root 实测（见 §6 与 `reports/ebpf-p1-20261014/`） |

**实施中的真实发现（重要）**：

1. **argv 越界读取会泄漏 envp**：`str(uptr(args->argv[i]))` 在 NULL 之后继续读取，
   实测得到 `USER=root`、`HOME=/root` 等**环境变量**（argv 数组在内存中紧邻 envp）。
   修复：内核侧逐位 NULL 守卫（argv[i-1]==0 则后续位输出 `\x1e` 终止标记），
   后处理遇 `\x1e` 截断。专项测试 + 真实采双重验证。
2. **BPF 栈 512 字节预算**：8 参数 ×64B 字符串缓冲超限（verifier 拒绝加载，
   实测复现）；实测可用上限为 **argv 前 4 项 ×48B + comm16**。因此增强格式
   不再重复读内核 `filename`（argv[0] 即程序名来源，PATH 解析场景实测一致），
   父进程名改由后处理按 pid 顺序跟踪补齐（与旧 `@procname` map 同为
   "探针启动后已知"语义）。**第 5 参数起与超长参数截断**（如 curl 的 URL
   参数未入 argv——`raw` 中 commandline 由 argv 拼接，同一截断）。
3. 跨 PowerShell→WSL 传参会吞 `$` 变量：早期"赋值语法错误"为测试方法伪影，
   真实约束只有栈上限；已改用脚本文件方式验证（记录于此避免复踩）。

### 2.2 P1-2 Falco 部署准备：**准备完成，未执行部署**

新增部署包 `collector/deploy/falco/`（详见其 `README.md`）：

| 文件 | 内容 |
|---|---|
| `README.md` | 版本/内核/权限要求、部署步骤、启停流程、回滚方案、真实验证方案、丢失计数获取与不可用判定（八项齐备） |
| `deploy_falco.sh` | `--check`（默认，非特权只读体检，已在 WSL 实测运行）；`--apply`/`--install-service`/`--rollback` 需 root+键入 YES 确认，备份先行 |
| `run_standing_capture.sh` | 常驻管线 `falco(JSON stdout) → 转发器 stdin`（复用 P0 批量/重试/spool/心跳）；supervisor 每 15s 解析 stderr drops → 健康文件 |
| `linuxguard-falco.service` | systemd 单元（Conflicts 互斥发行版 falco 服务；Restart=on-failure；不擅自启用） |

## 3. 修改文件清单与原因

| 文件 | 变更 | 原因 |
|---|---|---|
| `collector/ebpf_capture_postprocess.py` | **新增** | 采集后处理从 bash 内联 Python 抽为独立可测模块；新旧格式兼容解析；argv/会话键/父名跟踪 |
| `collector/ebpf_trace_capture.sh` | **修改** | 探针增强（argv+start_time 三类事件）；增强探针失败自动回退 legacy；调用独立后处理；健康文件记录 probe_profile |
| `backend/app/services/ebpf_event_collector.py` | **修改（3 行级）** | `normalize_event` 有界透传 argv（bpftrace 顶层 / Tetragon `process.arguments`），向后兼容 |
| `backend/tests/test_ebpf_p1_probe.py` | **新增** | 11 项 P1 专项测试（见 §4） |
| `collector/deploy/falco/*` | **新增 4 文件** | Falco 部署准备包（§2.2） |

数据库：**零迁移**（复用既有列）。转发器、P0 幂等/批量/spool/清空语义：**零改动**。

## 4. 已执行测试与真实结果

| 套件 | 结果 |
|---|---|
| P1 专项 `test_ebpf_p1_probe.py`（11 项） | **11/11 通过** |
| P0 专项 `test_ebpf_p0.py` | **18/18 通过** |
| 相关套件联跑（ebpf/runtime/trace/zephyr/agent/harness + P1 新增） | **111/111 通过** |
| 全量回归（P1 后） | **385 passed / 19 failed** |
| Shell 语法检查（3 个脚本，`bash -n`） | 全部通过 |
| `deploy_falco.sh --check` 真实运行（WSL，非特权） | 正确输出体检报告（falco 缺失如实报告，rc=1） |

P1 专项覆盖：新格式解析（argv/start_time/会话键/boot_id）/ NULL 边界无 envp 泄漏 /
argv 含 `|` 与空格 / 旧格式逐字段不变 / 会话键确定性与 PID 复用区分 / 坏行跳过与控制字符清洗 /
时间换算 / 后端落列与证据携带 argv / argv 参与事件身份（幂等+区分）/ 旧事件无新列值 /
timeline 会话聚合（exec+connect 同组、PID 复用分组不同）。

## 5. 与 P0 的回归差异

| | P0 基线（本轮动手前实测） | P1 准备轮后 |
|---|---|---|
| passed | 374 | **385（+11 = P1 新专项）** |
| failed | 19 | **19** |
| 失败集合 | iot_device_upgrade 9 + mqtt_remediation_workflow 5 + scan_runs 5 | **逐项完全一致（Compare-Object 零差异，证据 `regression-*.txt`）** |

结论：**零新增回归**；19 项历史失败为 P0 前既有（conftest 审计钩子与真实监听器冲突，
文档有据），本轮未删除、未跳过、未改预期。

## 6. 真实采集验证（WSL，证据 `reports/ebpf-p1-20261014/`）

环境：WSL2 Ubuntu / 内核 6.6.87.2 / bpftrace v0.20.2 / root / BTF 可用。

**增强探针（profile=enhanced，7 条真实内核事件）**：

```
execve sh   argv=['/bin/sh','-c','echo p1-evidence ok']  exec_id=lg-784c2a48-2516-156242432849
execve cat  argv=['cat','/etc/passwd']                   exec_id=lg-784c2a48-2517-156244505700
openat cat  /etc/passwd                                  exec_id=lg-784c2a48-2517-156244505700  ← 同进程
execve curl argv=['curl','-s','--max-time','1']          exec_id=lg-784c2a48-2518-156246046377
openat curl /etc/passwd                                  exec_id=lg-784c2a48-2518-156246046377  ← 同进程
connect curl 127.0.0.1:9                                 exec_id=lg-784c2a48-2518-156246046377  ← 同进程
execve echo argv=['/bin/echo','p1','argv','pipe-test']   exec_id=lg-784c2a48-2519-156255158758
```

验收点：① exec 事件含真实 argv；② 同一进程实例（pid+start_time）的
exec→open→connect 三类事件共享会话键（P1-1 目标行为链关联达成）；
③ `boot_id` 真实（`784c2a48-…`）；④ 健康文件 `probe_profile=enhanced`、
`dropped_events=null`（本次 bpftrace 未报丢失计数，unavailable 语义保持）。

**legacy 探针对照（profile=legacy）**：3 条事件，`start_time=''`、`exec_id=''`，
与 P0 行为逐字段一致（向后兼容实证）。

**已知边界（如实）**：argv 截断于前 4 项×48B（curl 的 URL 第 5 参数未采集）；
失败连接仍产生 connect 事件（D8 属 P2，未动）；argv 内控制字符被清洗为空格。

## 7. 仍需 VM sudo 授权的操作（本轮未执行）

| # | 操作 | 命令（授权窗口内） | 最低权限 |
|---|---|---|---|
| 1 | Falco 只读体检 | `collector/deploy/falco/deploy_falco.sh --check`（非特权也可跑） | 无（VM 访问本身） |
| 2 | 部署自定义规则 | `sudo ./deploy_falco.sh --apply` | root（写 `/etc/falco/rules.d/`） |
| 3 | 安装常驻单元 | `sudo ./deploy_falco.sh --install-service` | root（systemd 单元） |
| 4 | 常驻采集启停 | `sudo systemctl start/stop linuxguard-falco` | root（加载 eBPF 探针） |
| 5 | 真实链式验收 | 目标机执行 `mosquitto→sh→wget` 等真实行为 ≥10 分钟 | root + 实验网段 |
| 6 | falco stderr drops 格式实测确认 | 观察 `journalctl -u linuxguard-falco` 与 `falco.err` | 同 4 |

## 8. WSL/VM 真实采集验证清单

WSL（本轮已完成）：增强探针 argv/start_time/会话键/NULL 边界 ✅；legacy 对照 ✅；
健康文件 profile 标注 ✅；`bash -n` ✅；`--check` 只读体检 ✅。

VM（待授权）：增强探针在 Ubuntu VM（falco 0.44.1 所在机）同法运行一遍
（`ebpf_trace_capture.sh` 12s + 行为触发）；Falco 常驻 ≥10 分钟链式规则验收；
drops 格式确认；增强→legacy 自动回退路径在真实老内核上复验（如可构造）。

## 9. Mimosa 扫描状态

**不可用，未执行，不声称完成。** 本机复现证据：`mimosa` 命令不在 PATH
（`Get-Command mimosa` → not found；`C:\Python314\python.exe` 为当前解释器）。
历史记录原因：`python_ast_unavailable`。后续若工具可用，需对 P1 改动文件
（`collector/ebpf_capture_postprocess.py`、`collector/ebpf_trace_capture.sh`、
`backend/app/services/ebpf_event_collector.py`、`backend/tests/test_ebpf_p1_probe.py`、
`collector/deploy/falco/*`）补做全局安全扫描。

## 10. 后续 P1 部署与验收步骤（建议顺序）

1. 开 VM sudo 授权窗口 → `deploy_falco.sh --check` 确认环境。
2. `--apply` 部署规则 → `--install-service` 安装单元 → 配置 `/etc/linuxguard/falco.env`。
3. `systemctl start linuxguard-falco` → 常驻 ≥10 分钟 + 真实行为链触发
   （`sudo sh -c 'cat /etc/shadow'`、`curl`、`mosquitto → sh → wget`）。
4. 后端验收：`GET /runtime/ebpf/events`（source=falco + `LG-IoT` 规则命中）、
   `GET /runtime/ebpf/reliability`（stored_events 增长、drops 语义正确）。
5. VM 侧跑一遍增强 bpftrace 探针（与 WSL 同法），核对 argv/会话键。
6. 确认 falco stderr drops 格式，必要时仅调 `run_standing_capture.sh` 解析正则。
7. 全部通过后，P1-3（证据链 session-id 聚合视图）/P1-4（CVE 关联下钻）再立项；
   本轮按边界**未实施**，未动 P2。

## 11. 边界遵守

未修改内核配置、未加载内核模块、未部署/启动 Falco 服务、未启用 LSM enforce、
未对真实 IoT 设备写操作、未执行破坏性数据库操作、未触碰 SSH 配置；
历史 19 项失败未删除/未跳过/未改预期；模拟数据仅出现在单元测试夹具中，
真实内核结论全部来自 WSL 实测（证据目录本地留存）。
