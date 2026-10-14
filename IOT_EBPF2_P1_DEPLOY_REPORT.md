# IoTGuard eBPF 2.0 — P1 部署验收报告（Ubuntu VM 真实常驻部署）

日期：2026-10-14。基线 commit：`f8b9f80`（P1 准备轮）。
环境：Ubuntu 24.04 VM（wyh@192.168.183.129，内核 7.0.0-28-generic，BTF 可用，
falco 0.44.1 / bpftrace 0.20.2 / python 3.12.3）。授权：用户书面授权全流程自动化
（含 sudo）；密码仅经 PTY 标准输入传递一次，未进入命令行参数、文件、
Git、报告或终端回显。

---

## 1. 验收结论总览

| §10 步骤 | 结果 | 关键证据 |
|---|---|---|
| 1. `--check` 只读体检 | ✅ 全绿 | falco 0.44.1 / BTF / rules.d / python3；如实报告 falco-modern-bpf 与 falco 服务运行中 |
| 2. 规则部署 + 单元安装 | ✅ | 备份 `/var/lib/linuxguard/falco-deploy-backups/20261014-192414`；预验证发现并修复 3 个 0.44 兼容性问题（见 §3） |
| 3/4. 常驻启动 | ✅ | `linuxguard-falco.service` active；ExecStartPre 停 falco-modern-bpf（Conflicts 协调） |
| 5. 常驻 ≥10 分钟 + 真实行为 | ✅ | **19:39:52 → 19:50:41 连续运行**；期间真实 sudo→sh→cat /etc/shadow、sh→curl、bash→wget、sshd→bash（自身 SSH/sftp）链 |
| 6. 后端入库验收 | ✅ | **2418 条真实事件 / 2418 条 SecurityEvidence（1:1）**，8 种规则命中（见 §4） |
| 7. VM 增强探针核对 | ✅ | bpftrace P1 探针 17 条真实事件：argv / start_time / 会话键（内核 7.0.0 实测） |
| 8. drops 指标 | ✅ | 运行中=unavailable（如实）；停止退出摘要=`event drop detected: 0 occurrences`（**真实零**），健康文件解析为 `dropped_events: 0` |

## 2. 部署拓扑（本次实际运行）

```
Ubuntu VM (192.168.183.129)                         Windows 后端 (E:\IoTGuard-Public)
┌────────────────────────────────────┐              ┌──────────────────────┐
│ linuxguard-falco.service (systemd) │              │ uvicorn 127.0.0.1:8000│
│  ├─ falco 0.44.1 (modern BPF,      │   SSH 反向隧道 │  ├─ /runtime/ebpf/*   │
│  │   rule_matching=all, JSON out)  │ ────────────▶ │  ├─ SQLite（资产ID=1）│
│  ├─ 转发器 2.0（批量/重试/spool）   │  VM:18000 →   │  └─ SecurityEvidence  │
│  └─ supervisor（15s drops 解析）    │  Win:8000     └──────────────────────┘
└────────────────────────────────────┘   （零防火墙改动）
```

资产绑定：`wyh-VMware-Virtual-Platform`（asset_id=1，手工登记，IP 192.168.183.129）。

## 3. 部署过程中发现并修复的真实问题

| # | 问题 | 现象 | 修复（均已同步仓库源码） |
|---|---|---|---|
| 1 | Falco 0.44 默认规则集已移除 `open_directory` 宏 | 规则加载失败（LOAD_ERR_VALIDATE） | `linuxguard_iot_rules.yaml` 条件改 `open_read`（语义等价） |
| 2 | `evt.dir=<` 已废弃（enter 事件已丢弃，恒真） | 3 条规则加载警告 | 移除该条件 |
| 3 | 默认 `rule_matching: first` | 同事件仅出首条规则——**Shadow Access CRITICAL 被低优先级规则遮蔽** | 管线 `-o rule_matching=all`（证据采集需多规则命中） |
| 4 | 资产主机名大小写 | Falco 上报原始大小写 `wyh-VMware-Virtual-Platform`，与登记的小写不匹配 → 批量 400 → spool | 数据修正（登记改为原始大小写）；未改代码（精确匹配是既有防御语义，大小写敏感性记录为互操作注意事项） |
| 5 | `KillMode=mixed` 下子进程被 SIGKILL | 转发器 stopped 心跳与 falco 退出摘要丢失 | 单元改 `KillSignal=SIGINT` + `KillMode=control-group` |
| 6 | SIGINT 中断时在途批次未 spool | 停止瞬间丢在途批次（实测 17 条进程内丢失路径） | 转发器 `KeyboardInterrupt` 并入 spool 异常路径（P0"未确认≠丢失"语义补全） |
| 7 | spool 残留的诚实退出码 1 使单元态显示 failed | 停止后 systemd 状态误导 | `SuccessExitStatus=1`；spool 状态由 reliability 端点呈现 |
| 8 | falco 0.44.1 周期 stats 未输出（即使 statistics.enabled） | 运行中 drops 无来源 | 解析器覆盖三种来源（退出摘要/JSON stats/丢失告警）；实测确认退出摘要为可靠全量来源 |

## 4. 后端验收数据（全真实，零模拟）

**入库与证据层**（验收窗口 + 全程累计，含 drain 周期）：

| 指标 | 值 |
|---|---|
| RuntimeEvent（source=syscall/falco） | **2418** |
| SecurityEvidence（process/file/network 1:1 生成） | **2418** |
| 无 sensor 归属事件 | 0 |
| 资产绑定 | 全部 asset_id=1 |

**规则命中分布**（8 种）：

```
LinuxGuard IoT Process Execution      1032    LinuxGuard IoT Shadow Access(CRITICAL)  18
LinuxGuard IoT Local Service Connect   667    Read sensitive file untrusted(默认)      3
LinuxGuard IoT Watched File Read       621    LinuxGuard IoT Shell Run Downloader      3
LinuxGuard IoT Outbound Connection      72    LinuxGuard IoT Service Spawned Shell     2
```

**链式验收（P1-2 验收方法，全部真实自然触发）**：
- `sshd → sh`（SSH 登录）与 `sshd → bash`（sftp，来自文件推送）→ **Service Spawned Shell**（WARNING）；
- `bash → curl` → **Shell Run Downloader**（WARNING）；
- `sudo → sh → cat /etc/shadow` 全链 → Process Execution ×3 + Watched File Read +
  **Shadow Access（CRITICAL）** + 默认规则 Read sensitive file untrusted 同事件多规则命中。

**转发器可靠性（10 分钟窗口结束时自报 × 服务端交叉）**：

| 自报 | 值 | 服务端观测 | 值 |
|---|---|---|---|
| received/parsed | 983/983 | stored_events（该 sensor 累计） | 2418 |
| uploaded | 982 | first/last_event_at | 11:28:13 → 11:50:49 |
| rejected/retries/failed | 0/0/0 | 无归属事件 | 0 |
| spool_pending | 0 | — | — |

## 5. VM 增强探针实测（§10 第 5 步）

`ebpf_trace_capture.sh`（P1 增强，内核 7.0.0-28-generic）14 秒真实采集 17 条：

```
execve sh   argv=['/bin/sh','-c','echo vm-p1-argv ok']  exec_id=lg-fe47fa99-81291-…
execve cat  argv=['cat','/etc/passwd']                   exec_id=lg-fe47fa99-81292-…
openat cat  /etc/passwd                                  exec_id=lg-fe47fa99-81292-…  ← 同进程
execve curl argv=['curl','-s','--max-time','1']          exec_id=lg-fe47fa99-81293-…
openat curl /etc/passwd                                  exec_id=lg-fe47fa99-81293-…  ← 同进程
connect curl 127.0.0.1                                   exec_id=lg-fe47fa99-81293-…  ← 同进程
（另捕获常驻 supervisor 自身 grep/tail/sleep 命令 = 探针自观测）
```

boot_id `fe47fa99-…` 与 Falco 路线事件一致（同主机交叉验证）。

## 6. drops 真实指标（§8 验收）

| 状态 | 值 | 依据 |
|---|---|---|
| 常驻运行中 | `unavailable`（不虚构） | 0.44.1 无周期 stderr stats（statistics.enabled 实测无效） |
| 前台探针 22s | `0 occurrences`（真实零） | `falco-drops-probe.err` 退出摘要 |
| 服务停止后 | 健康文件 `dropped_events: 0`（真实零） | SIGINT 退出摘要 → supervisor 解析（`probe-health-final.json`） |

注：停止解析存在毫秒级竞态（cleanup 与 falco 摘要落盘时序），未解析到时如实 null。

## 7. 修改文件清单（本轮相对 f8b9f80）

| 文件 | 变更 |
|---|---|
| `collector/linuxguard_iot_rules.yaml` | 0.44 兼容性修复 ×2（open_directory、evt.dir） |
| `collector/deploy/falco/run_standing_capture.sh` | `rule_matching=all`；drops 三来源解析；停止态健康文件 |
| `collector/deploy/falco/linuxguard-falco.service` | KillSignal=SIGINT / control-group / SuccessExitStatus=1 |
| `collector/ebpf_event_collector.py` | KeyboardInterrupt 在途批次入 spool + spool_pending 心跳同步 |
| `collector/deploy/falco/README.md` | 实测事实回填（兼容性记录、drops 来源、停止语义） |
| `IOT_EBPF2_P1_DEPLOY_REPORT.md` | 本报告 |

## 8. VM 最终状态（验收后）

| 项 | 状态 |
|---|---|
| `/etc/falco/rules.d/linuxguard_iot_rules.yaml` | 已部署（修复版，与仓库一致；备份含回滚脚本） |
| `/etc/systemd/system/linuxguard-falco.service` | 已安装（未 enable；按验收流程停止） |
| `/opt/linuxguard/collector/` | 部署物就位（与仓库同步） |
| `falco-modern-bpf.service` | **已恢复部署前原状（active）** |
| `/var/lib/linuxguard/falco/` | spool 留存 31651B 在途批次（未确认≠丢失，下次 start 自动续传）；健康文件 stopped |
| 证据 | `reports/ebpf-p1-deploy-20261014/`（本地留存，含服务日志/健康文件/bpftrace 采集/后端快照） |

重启常驻采集：`sudo systemctl start linuxguard-falco`（需 VM 上隧道或可达后端）。

## 9. 边界遵守

未修改 sudoers / SSH 配置 / 防火墙（反向隧道零防火墙改动）；未启用 LSM enforce
（证据层 lsm.enforce_enabled_any=false）；未触碰真实 IoT 设备；未执行破坏性操作；
falco-modern-bpf 已恢复原状；密码未落任何文件/命令行/输出/仓库。
历史 19 项回归失败未删除、未跳过、未改预期（本轮回归对比见 §10）。

## 10. 回归测试

| 套件 | 结果 |
|---|---|
| 相关套件（forwarder + P0 + P1 + evidence） | 48/48 通过（修复后复跑） |
| Shell 语法（run_standing_capture.sh 等） | `bash -n` 通过 |
| 全量回归（部署轮后） | **385 passed / 19 failed** |
| 与准备轮基线对比 | 失败集合 Compare-Object **零差异（零新增回归）**；19 项仍为既有历史冲突，未删除/未跳过/未改预期 |

## 11. 后续

- P1-3（证据链 session-id 聚合视图）/ P1-4（CVE 关联下钻）：按原计划另行立项，本轮未动；
- P2 未动；
- 长期运行建议：将 API_BASE 指向稳定可达的后端地址后 enable 服务；
  rule_matching=all 事件量放大（本 VM ~4 事件/秒常态），spool 容量按需监控。
