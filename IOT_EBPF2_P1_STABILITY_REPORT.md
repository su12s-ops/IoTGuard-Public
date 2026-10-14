# IoTGuard eBPF 2.0 — P1 常驻化与可靠性收尾报告

日期：2026-10-14。基线 commit：`8cfd519`（P1 部署验收轮）。
环境：Ubuntu 24.04 VM（wyh@192.168.183.129，内核 7.0.0-28-generic）+ Windows 后端。
范围：稳定后端连接、spool 续传对账、systemd 常驻、信号语义、30 分钟连续运行验收。
未进入 P1-3/P1-4/P2；未启用 LSM enforce；未触碰真实 IoT 设备。

---

## 1. 稳定后端连接

### 1.1 API_BASE 配置来源审计

部署轮配置为 `http://127.0.0.1:18000/api`——依赖 Windows 侧临时 SSH 反向隧道
（会话级，验收后即失效），不具备长期运行能力。

### 1.2 网络连通性实测与方案确定

| 测试 | 结果 |
|---|---|
| VM → `http://192.168.183.1:8000/api/health`（VMnet8 直连，Windows 已有 Python 入站放行规则） | **`{"status":"ok"}`（rc=0）** |
| 防火墙改动 | **零**（复用既有 Public profile Python 规则，未新增/修改任何规则） |

**方案：直连 `http://192.168.183.1:8000/api`**（VMnet8 主机侧静态地址，
跨 Windows 重启稳定）；彻底移除反向隧道依赖，无需重连机制。
前提：Windows 后端监听 `0.0.0.0:8000` 并在线；离线时转发器退避重试 + spool
（P0 语义，见 §7 剩余风险）。

### 1.3 配置变更（备份先行）

```bash
# 变更前备份（真实执行）
sudo cp -a /etc/linuxguard/falco.env /etc/linuxguard/falco.env.bak.20261014-stability
# 新配置（令牌经文件传输，不经终端回显）
API_BASE=http://192.168.183.1:8000/api   （ASSET_ID/SENSOR_ID/令牌不变）
```

## 2. spool 续传对账（真实验证）

**启动前基线**：

| 项 | 值 |
|---|---|
| spool | 1 行 / 31651B（1 个批次，34 条事件；规则构成：Watched Read 26 / Process Exec 6 / Shadow Access 2；时间戳 2026-10-14T11:56:30.x） |
| 批内指纹 | 34/34 唯一（`/tmp/spool_fingerprints.txt` 留存） |
| 后端 RuntimeEvent | 2418（max id 2418，2418 唯一指纹） |
| 后端 SecurityEvidence | 2418（2418 唯一哈希） |

**重启与续传**：`systemctl start linuxguard-falco` → 8 秒后 spool `0 行 / 0B`
（经服务端确认后清空，**非删除**）。

**对账结果（三要素）**：

| 对账项 | 结果 |
|---|---|
| 真实事件标识 | 续传窗口（occurred_at=11:56:30.x）入库 **34 条，34 唯一指纹**——与 spool 批内 34/34 一一对应 |
| 后端记录 | RuntimeEvent 2418→2506（+88 = 续传 34 + 重启后实时 54）；SecurityEvidence 同步 2506/2506（1:1） |
| 队列状态 | spool 1 行→0 行；全库重复指纹 **0**、重复证据哈希 **0** |

结论：在途批次恢复与发送真实验证通过；**未产生重复 RuntimeEvent/SecurityEvidence**。

## 3. systemd 常驻运行

| 项 | 命令（真实执行） | 结果 |
|---|---|---|
| 开机自启 | `sudo systemctl enable linuxguard-falco` | **enabled**（multi-user.target.wants 符号链接已建） |
| 异常恢复（SIGKILL） | `sudo kill -9 <MainPID>` | 10s 后自动拉起，**NRestarts=1**，新 PID 正常采集 |
| 异常恢复（SIGTERM） | `sudo kill -TERM <MainPID>` | 修复前**不恢复**（见下）；修复后 **NRestarts=1 自动拉起** |
| 干净停止（SIGINT=KillSignal） | `sudo systemctl stop` | inactive（非 failed）；stopped 心跳送达后端；健康文件 `stopped`+`dropped_events:0`（falco 退出摘要真实零）；在途批次入 spool 保全 |

### 3.1 发现并修复的真实缺陷：bash 前台阻塞吞信号

**现象**：外部 SIGTERM 发给主进程后服务静默躺平（NRestarts=0，inactive，
journal 记录 "Deactivated successfully"）。

**根因（两层）**：① bash 对 trap 信号的执行会挂起到前台命令结束——脚本末行
python3 转发器常驻不退出 → TERM trap 永不执行；② EXIT trap 正常收尾使退出
呈"成功"语义，叠加 `SuccessExitStatus=1` 后 `Restart=on-failure` 不触发。

**修复**（`run_standing_capture.sh`，旧版备份 `.bak.20261014`）：
转发器改后台 + `wait`（wait 可被 trap 即时中断）；显式 `trap on_term TERM`
（cleanup + exit 143 保留失败语义）；`trap on_int INT`（等转发器收尾并透传
退出码，保持 stop 干净语义）。修复后实测 TERM → **自动重启** ✓。

### 3.2 服务互斥与 falco-modern-bpf

常驻运行期间 `falco-modern-bpf`/`falco` 均 inactive（Conflicts + ExecStartPre
协调）；**无双引擎并行采集/重复消费**；停止 linuxguard-falco 后原服务可正常
手工恢复（上轮已验证 active）。单元文件未被改动，互斥语义不变。

## 4. 30 分钟连续运行验收

窗口：**20:29:46 → 21:01:38 CST（约 32 分钟）**，期间含一次窗口内 SIGKILL 恢复演练。

| 指标 | 结果 |
|---|---|
| 服务存活 | 全程 active；唯一中断 = 演练重启（kill -9 → RestartSec=10 后拉起，NRestarts=1），数据缺口 **<2 秒**（旧引擎清理前仍在采集） |
| 窗口真实采集事件 | **2619 条**（Process Exec 1369 / Outbound 1068 / Watched Read 135 / Shadow Access(CRITICAL) 12——cron PAM 周期性命中） |
| 转发与入库对账 | 窗口实例自报 received/parsed/uploaded=1433/1433/1432；duplicates/retries/failed=0；服务端窗口增量一致，全库 **6071 RuntimeEvent = 6071 SecurityEvidence（1:1）** |
| 重复检查 | 全库重复指纹 **0**、重复证据哈希 **0** |
| spool 状态 | 全程 **0**（窗口内零退避零积压） |
| 检测规则命中 | 4 种持续命中（见上行分布），无异常突发 |
| dropped events 真实来源 | 运行中=**unavailable**（falco 0.44.1 无周期 stats，实测确认，不虚构）；停止后=退出摘要 `event drop detected: 0 occurrences`（**真实零**）→ 健康文件与 reliability 端点均呈 `dropped_events: 0` |
| 异常退出及恢复 | 窗口内 kill -9 演练：10s 自动恢复、新实例正常采集、事件流连续（恢复前最后一条 12:44:23.967 → 恢复后第一条 12:44:25.900） |

### 4.1 本轮追加发现并修复的两个收尾缺陷（均已真实验证）

| # | 缺陷 | 现象 | 修复 |
|---|---|---|---|
| 1 | 停止时退出摘要竞态 ×2 | ① `on_int` 先 cleanup 后 wait——读到摘要前 falco 尚未写完（健康文件 null）；② tee 被 SIGINT 即杀，falco 摘要写入死管道（SIGPIPE）——上轮能捕获属竞态侥幸 | `on_int` 改为**先 wait 转发器再 cleanup**（等价等 falco 摘要落盘）；tee 子 shell `trap '' INT TERM`（免疫停止信号，流关闭后自然退出）。修复后实测：`falco.err` 完整含 `SIGINT received → event drop detected: 0 occurrences`，健康文件 `dropped_events: 0`，reliability 端点 stopped 心跳携带数值 0 |
| 2 | falco 退出摘要污染 rejected 指标 | falco 0.44.1 退出时向 **stdout** 追加统计摘要块（`Events detected:` / `Rule counts by severity:` + 缩进明细），转发器按坏行计入 rejected（实测单周期 rejected=6~9） | 转发器状态机：识别摘要首行后跳过全部后续行（摘要总在流末尾），不计 received/rejected。修复后实测 rejected=0（16/16 全解析） |

## 5. 修改文件

| 文件 | 变更 |
|---|---|
| `collector/deploy/falco/run_standing_capture.sh` | 转发器后台+wait（bash 前台阻塞吞信号修复）；TERM/INT 显式 trap；on_int 先 wait 后 cleanup；tee 免疫停止信号——旧版备份 `.bak.20261014` 留存 VM |
| `collector/ebpf_event_collector.py` | falco 退出摘要块状态机过滤（消除 rejected 噪声，实测 6~9→0）——旧版备份留存 VM |
| `IOT_EBPF2_P1_STABILITY_REPORT.md` | 本报告 |
| `ai_collaboration/*.md` | 运行记录追加 |

后端服务与规则零改动；转发器仅上述指标噪声修复（专项+全量回归见 §6）。

## 6. 回归测试

两次全量回归（中间态与 rejected 修复后）：均为 **385 passed / 19 failed**；
19 项失败与基线（部署轮）**逐项完全一致**（Compare-Object 零差异，证据
`regression-after-stability*.txt`）——零新增回归，未删除/隐藏/修改任何测试预期，未扩大 skip。

## 7. 剩余风险与后续建议

1. **Windows 后端在线依赖**：直连方案要求后端 `0.0.0.0:8000` 常驻在线；
   离线时转发器退避重试 + spool 累积，**spool 无容量上限**（实测 ~35KB/分钟量级
   的事件流速下长期离线会持续增长）→ 建议后续为 spool 增加容量上限/轮转策略（P2 候选）。
2. **SIGKILL 在途批次不可恢复**：kill -9 时 ≤1 批（50 条/2s 窗口）在途事件丢失——
   内核级死亡无法拦截，属系统固有边界（SIGINT/SIGTERM 路径均已 spool 保全）。
3. **falco drops 仅停止时给全量**：0.44.1 无周期 stats（实测）；运行中呈 unavailable
   （如实，不虚构）；退出摘要经 supervisor 解析入健康文件（存在毫秒级竞态，偶发 null）。
4. **VM 重启提示**：系统提示需要重启（内核更新待生效）；linuxguard-falco 已 enable，
   重启后将随 multi-user.target 自启（ExecStartPre 自动协调 falco-modern-bpf 互斥）。
5. **常驻事件量**：rule_matching=all 下本 VM 常态 ~1.4 事件/秒（32 分钟 2619 条）；
   后端库随时间线性增长，长期运行建议配套留存策略（超出本轮范围）。

## 8. 最终状态（本轮结束）

| 项 | 状态 |
|---|---|
| `linuxguard-falco` | **enabled + stopped**（开机自启已配置；当前停止——Windows 后端为本会话级进程，报告见 §7.1 在线依赖） |
| `/etc/linuxguard/falco.env` | 直连 `http://192.168.183.1:8000/api`（备份 `falco.env.bak.20261014-stability`） |
| `falco-modern-bpf` | **active（已恢复本轮开始前原状）** |
| spool | 0（在途批次已全部确认入库） |
| 健康文件 | stopped + dropped_events=0（真实零） |
| 后端累计 | RuntimeEvent 6112 = SecurityEvidence 6112，全库零重复 |

恢复常驻采集：`sudo systemctl start linuxguard-falco`（需 Windows 后端
`0.0.0.0:8000` 在线；离线时退避重试+spool 保全，恢复后续传）。

## 9. 边界遵守

未修改防火墙（直连复用既有规则）/sudoers/SSH 配置；未启用 LSM enforce；
未删除 spool（续传经服务端确认后自然清空）；未伪造任何指标——运行中 drops=
unavailable、竞态未解析=null 均如实记录。
