# eBPF 2.0 P2-1 性能评测报告

> 日期：2026-10-15。本报告为 eBPF 2.0 升级 P2-1（性能评测落地）的正式交付。
> 指标语义约定（贯穿全部数据）：**数值 0 = 真实为零；null / unavailable = 无法测得**，两者绝不互换，绝不把未知写成 0%。
> 原始证据目录：`reports/ebpf-p21-final/`（本地留存，.gitignore 排除不入库；含私网地址等实验环境标识，故仅存本地）。

---

## 1. 测试环境

| 项 | 值 |
| --- | --- |
| 后端主机 | Windows 11 Home 10.0.26300，Intel Core Ultra 5 125H（18 逻辑核），31.5 GB RAM |
| 后端栈 | FastAPI + SQLAlchemy + SQLite（单进程 uvicorn），Python 3.14.4 |
| 隔离 | 一次性 perf 库（`reports/ebpf-p21-final/perf.db`），与开发库完全隔离；每形态独立后端进程 + 随机端口 + 一次性控制令牌 |
| real-wsl 采集端 | WSL2 Ubuntu，内核 6.6.87.2-microsoft-standard-WSL2，bpftrace v0.20.2（root，enhanced 探针 profile：execve argv + start_time） |
| real-vm-falco 采集端 | Ubuntu VM（内核 7.0.0-38-generic，VMnet8 实验段——具体地址仅存本地证据），Falco 0.44.1 modern_ebpf 常驻服务（LG-IoT 规则集），journalctl 只读拉取（adm 组），对 VM 零改动、无 sudo |
| 负载发生器 | `collector/ebpf_perf_loadgen.py`：按目标节拍真实制造 execve（/bin/true -lgperf）/ connect（127.0.0.1:18099 短连接，自带监听器保证成功）/ openat（读 /etc/passwd + 追加写 /opt/firmware/.lgperf），全部行为精确计数（读写分开计数）；不可写时如实降级 no_perm，绝不计入成功数 |

## 2. 五种评测方法（严格区分，绝不混称）

| 形态 | 测什么 | 链路 |
| --- | --- | --- |
| **synthetic** | 后端摄取性能 | 编排器内直接生成结构化事件 POST `/runtime/ebpf/events/batch`（每批 500）；无内核、无转发器 |
| **replay** | 离线回放与传输可靠性 | 真实采集夹具（40 条真实内核事件）循环限速 80 行/s 流经**生产转发器** `ebpf_event_collector.py`（批 50 / WAL spool / 重试），25s 处停后端 21.6s 模拟断网，恢复后验收续传与幂等 |
| **real-wsl** | 真实内核事件采集 | WSL2 内核 bpftrace 探针（128s 窗口）+ 受控真实 syscall 负载（120s @ 目标 240 EPS，延迟 3s 启动等探针 attach）+ WSL 侧生产转发器（心跳 + 健康文件消费 + 真实跨主机 HTTP）→ Windows 后端 |
| **real-vm-falco** | 真实 Falco 采集 | VM 常驻 falco-modern-bpf（LG-IoT 规则）+ VM 上受控真实负载（120s @ 120 EPS）+ journalctl 单次只读拉取 → 后端（拉取式，非常驻转发器） |
| **bounded-spool** | 存储背压与容量保护 | 后端不可达 + spool 容量 80 事件 + 喂入 300 行 + 45s 后编排器有界终止，断言盘上不变量 |

## 3. 原始数据位置（reports/ebpf-p21-final/，本地留存）

| 文件 | 内容 |
| --- | --- |
| `summary.json` | 全部 7 次运行的完整指标汇总（synthetic×2 / bounded-spool / replay / real-wsl×2 / real-vm-falco） |
| `consolidated.json` | 五形态统一汇总视图（本报告 §5 数据源） |
| `perf.db`（+wal/shm） | 各形态一次性评测库（runtime_event / security_evidence 原始行） |
| `wsl-capture.raw / .jsonl / .err / wsl-proc-samples.txt / wsl-loadgen.out / wsl-probe-health.json / wsl-wal-after.jsonl` | real-wsl 探针原始输出、后处理事件、/proc 采样、负载计数、探针健康文件、转发后 WAL 残留 |
| `vm-falco-journal.jsonl / vm-falco-events.jsonl` | real-vm-falco journalctl 原始拉取与解析后事件 |
| `replay-wal.jsonl / forwarder-replay.out` | replay 转发器 WAL 与运行日志 |
| `bounded-stream.jsonl / bounded-wal.jsonl / forwarder-bounded.out` | bounded-spool 喂入流、触界后 WAL、转发器日志 |
| `wsl-attempt1-failed.json / wsl-attempt3-forwarder-rejected.json / vm-attempt1-tz-clamped.json` | 三次失败尝试的完整留档（harness 缺陷记录，见 §8） |
| `regression-final.txt` | 本轮回归测试输出 |

## 4. SQLite 索引缺陷根因（P2-1 实测发现并修复）

**现象**：synthetic 首轮（索引修复前）表增长到 7500 行时，批量端点 RTT P50 劣化至 ≈4.3s，吞吐仅 115 EPS，且随表规模线性劣化。

**根因**：P0 建立的部分唯一索引 `uq_runtime_event_fingerprint_v2 ON runtime_event(event_fingerprint) WHERE event_fingerprint != ''` 只能作为**并发上传防线**。SQLite 查询计划器不做"col = 字面量 ⇒ col != ''"的谓词蕴含推理，`_persist_events` 的逐事件判重查询（`filter_by(event_fingerprint=...)`）不命中该部分索引，EXPLAIN QUERY PLAN 实测仍为 `SCAN runtime_event`（全表扫描），每入库一事件的判重成本随表行数线性增长。

**修复**（`backend/app/models.py` + `backend/app/database.py`）：
- `RuntimeEvent.event_fingerprint` 增加 `index=True`（新库由 create_all 直接建出全量索引）；
- 旧库幂等补建：`_ensure_query_indexes()` 执行 `CREATE INDEX IF NOT EXISTS ix_runtime_event_event_fingerprint ON runtime_event(event_fingerprint)`；
- 部分唯一索引保留（并发防线语义不变），两索引并存各司其职。

**EXPLAIN QUERY PLAN 前后证据**（7500 行同规模复现库，参数绑定查询）：

```
== P0 态（仅部分唯一索引 uq_runtime_event_fingerprint_v2 WHERE != ''）==
(2, 0, 216, 'SCAN runtime_event')

== P2-1 修复后（并存全量索引 ix_runtime_event_event_fingerprint）==
(2, 0, 56, 'SEARCH runtime_event USING COVERING INDEX ix_runtime_event_event_fingerprint (event_fingerprint=?)')
```

**优化对比（同机同栈同批大小，仅索引差异）**：

| 指标 | 修复前（7500 行时） | 修复后（23000 行时） |
| --- | --- | --- |
| 后端摄取吞吐 | 115.23 EPS | **379.41 EPS（3.3×）** |
| 批量端点 RTT P50 | 4328.7 ms | **1314.0 ms（-70%）** |
| 批量端点 RTT P95 | 8524.3 ms | 1363.1 ms |
| 事件端到端延迟 P50（POST→持久化） | 1592.8 ms | 593.7 ms |
| 后端 CPU（进程累计） | 62.5 s / 7500 事件 | 52.4 s / 23000 事件 |

回归锁定：`test_ebpf_p21_perf.py::TestFingerprintDedupIndex` 用 EXPLAIN QUERY PLAN 断言判重路径必须走 covering index、且全量索引与部分唯一索引并存。

> **表述边界（重要）**：115→379 EPS 与 4.3s→1.3s 是 **synthetic 形态下后端摄取路径**（SQLite 判重查询修复前后）的对比，**不得表述为真实 eBPF 内核采集吞吐量的提升**。真实采集链路的数字见 §5 real-wsl / real-vm-falco。

## 5. 实际性能结果（五形态统一）

| 维度 | synthetic（修复后） | replay | real-wsl（最终轮） | real-vm-falco | bounded-spool |
| --- | --- | --- | --- | --- | --- |
| 定位 | 后端摄取 | 传输可靠性+幂等 | 真实内核采集 | 真实 Falco 采集 | 背压/容量保护 |
| 窗口 | 60.6 s | 103.2 s | 120 s | 124.6 s | 45 s（有界终止） |
| 吞吐 | 379.4 EPS（摄取） | 69.7 行/s（限速喂入，全量送达确认） | 捕获 344.4 / 入库 344.4 EPS | 捕获 119.7 / 入库 119.7 EPS | 不适用 |
| 事件计数 | 新增 23000（前轮 7500） | 喂入 7200 / 唯一 40 | 捕获 41322 = 入库 41322 | journal 14910 = LG 14910 = 入库 14910 | 喂入 300 |
| 重复记录 | 0 | 7160（同夹具循环重放，服务端指纹幂等去重，duplicates 如实计数） | 0 | 0 | — |
| 已知丢失 | 不适用 | 采集前丢失 0（7200/7200 送达） | **0.0%**（归因对账 exec 9601/9601、connect 9601/9601、固件写 9602/9601，+1 为环境噪声） | **0.021%**（exec 4800/4801，1 条采集前丢失；connect 4801/4801） | — |
| 端到端延迟 P50/P95/P99 | 594/3331/5593 ms | unavailable（夹具时间为历史采集时间） | 151.8/173.8/175.6 s（含 120s 采集窗口，capture-then-upload 路径） | 92.9/127.4/128.8 s（journal 落盘→批式拉取→入库） | — |
| CPU | 后端 52.4 s | — | bpftrace 2.36 s（≈2% 单核）/ 后端 96.0 s | falco unavailable（root 进程无 sudo 不采样） | — |
| 内存（RSS） | 后端 124 MB | — | bpftrace 峰值 128.9 MB / 后端 158.6 MB | unavailable | — |
| Spool 积压/恢复 | — | 断网 21.6 s 期间积压 WAL，恢复后 5 次重试全部成功，spool 清零（未确认≠丢失） | 0 | —（拉取式无转发器） | 终止后 18 行 ≤ 容量 80，未确认数据保全 |
| 不可测（unavailable） | capture EPS（无探针） | 端到端延迟 | 探针丢失计数（bpftrace 本次未报告→null） | falco 引擎 drops（0.44.1 未呈现）/ falco CPU | — |

**real-wsl 重复性**：两次独立完整运行（41446 / 41322 事件，两次归因对账均 0 丢失，EPS 345.4 / 344.4）结果一致，排除偶发性。

**bounded-spool 判定**：容量不变量成立（WAL 18 ≤ 80）、未确认事件未被删除、进程按设计常驻重试（由编排器有界终止）；45s 窗口内未触界，背压告警路径本轮未触发（alerts=0 如实记录；告警触发逻辑由 `test_ebpf_wal_spool.py` 单元级覆盖）。

**诚实降级（如实记录，非缺陷）**：real-vm-falco 的文件写项 openat 全部 no_perm（VM 侧用户无 root，/opt/firmware 不可写）——负载发生器不计数、评测不当作丢失；falco 引擎 drops 与 CPU 因无 sudo 不可测，标注 unavailable。

## 6. 性能瓶颈分析

1. **判重查询曾是一阶瓶颈（已修复）**：全表扫描使每事件判重 O(N)，7500 行即把批 RTT 推到 4.3s。修复后判重 O(log N) 走 covering index，23000 行时批 RTT P50 稳定 1.3s。剩余 RTT 主要构成为逐事件指纹计算（SHA-256 over raw JSON）+ SQLite 事务持久化，属语义必要成本。
2. **当前后端摄取上限约 380 EPS（本机 SQLite 单进程）**：synthetic 修复后 379 EPS、CPU ≈52s/60s（≈0.87 核）。真实采集 344 EPS（负载 320 EPS 全量无损）尚未触到摄取上限；瓶颈排序为：负载能力 < 采集链 < 后端摄取。
3. **bpftrace 探针开销极低**：120s 窗口 4.1 万事件下探针累计 CPU 2.36s（≈2% 单核）、RSS 峰值 129MB——eBPF 采集侧不是瓶颈。
4. **批式路径延迟主导**：real-wsl/real-vm-falco 的 P50 延迟（151.8s/92.9s）主要由"采集完成后统一转发/拉取"的批式窗口构成，非处理耗时；流式常驻路径（P1 稳定性轮已验证的 standing capture）延迟为秒级以下。两者语义不同，不可比较。
5. **吞吐数字的能力边界**：real-wsl 的 344 EPS 受负载发生器实际能力（320 EPS）约束，是"负载上限下的全量无损采集"，**不是采集链路上限**；上限探测超出本轮目标（观测窗内无丢失即达标）。

## 7. 测量限制（如实声明）

- synthetic 不经过采集链：其数字只评价后端摄取路径，不含探针/转发开销；
- replay 端到端延迟不可测（夹具时间戳为历史采集时间），以送达确认 + 幂等对账替代；
- real-wsl 延迟含 120s 采集窗口（capture-then-upload 路径），不代表流式实时延迟；
- real-vm-falco 延迟含 journal 落盘与批式拉取等待；falco 引擎 drops 与 CPU 不可测（无 sudo）；文件写项因权限如实降级；
- /etc/passwd 读取因环境噪声可能混入（其他进程读 passwd），双方计数均不可靠，不进入丢失结论，仅单独呈现；
- 主机间时钟：VM 与 Windows 主机实测偏差 -0.3s（小于批式路径量级），journal 时间基准为 UTC epoch，跨主机可比；
- 全部百分位为最近邻秩（nearest-rank）口径，样本数随指标一并列出（见 summary.json），不隐藏样本规模。

## 8. 评测过程中发现并修复的缺陷（全部真实验证）

| # | 缺陷 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | 判重查询全表扫描（§4，性能缺陷） | SQLite 不做部分索引谓词蕴含推理 | 全量索引 + 幂等补建迁移 + EXPLAIN 回归锁定 |
| 2 | real-wsl 首跑采集未启动（bash EOF） | 内联 `wsl bash -c` 命令中 `'\''` 转义写在双引号上下文 | 采集/转发命令改为脚本文件落盘后 `bash <file>` 执行（不经 Windows argv） |
| 3 | 重跑资产登记 UNIQUE 冲突 | `ensure_asset` 非幂等 | `INSERT OR IGNORE` |
| 4 | 真实采集被拒传（Conflicting upstream boot_id） | harness 给转发器注入伪造 boot_id，与事件真实内核 boot_id 冲突（P0 身份防线正确拦截） | 去除注入，事件携带真实 boot_id，转发器心跳自读 /proc |
| 5 | 探针健康文件非法 JSON / 后续运行根本不产出 | `grep -c` 无匹配输出 0 且退出码非零：旧写法 `|| echo 0` 产生双 0 换行嵌入 JSON 字符串；单去掉 `|| echo 0` 又被 `set -e` 中止 | `|| true` + 默认值兜底（`collector/ebpf_trace_capture.sh`，生产脚本缺陷） |
| 6 | falco 消息时间为 VM 本地时区（实测 journal 01:36:56 vs 消息 09:36:56，+8h），直接拼接产生未来 8h 的 occurred_at，端到端延迟被钳位成伪 0 | journal 解析未校验消息时间与 journal UTC 时间戳的时钟基准一致性 | journal UTC 为基准；消息时间仅 ±2s 一致时细化 μs，否则回退并计数 tz_mismatch（专项测试锁定） |
| 7 | 丢失对账口径错配虚报 25% 丢失 | expected 含 passwd 读数、captured 只计固件写数 | 负载发生器读写分开计数；对账只认可归因行为（exec+connect+固件写） |
| 8 | 固定 sensor_id 跨运行累积污染统计 | perf.db 跨形态复用 | real-wsl / real-vm-falco 每次运行随机 sensor 后缀（同 synthetic 形态做法），SQL 参数绑定 |

三次失败尝试均完整留档（`wsl-attempt1-failed.json`、`wsl-attempt3-forwarder-rejected.json`、`vm-attempt1-tz-clamped.json`），不删除、不用部分数据冒充完整结果。

## 9. 可重复执行步骤

```bash
# 前提：仓库根目录；WSL2（bpftrace 已装）；VM 常驻 falco-modern-bpf 可达
# VM 连接参数经环境变量提供（不写入跟踪文件）：
#   LINUXGUARD_PERF_VM_HOST / LINUXGUARD_PERF_VM_USER / LINUXGUARD_PERF_VM_API（形如 http://<主机侧地址>:{port}/api）

python backend/scripts/ebpf_p21_perf.py --mode synthetic     --duration 60                    # 后端摄取
python backend/scripts/ebpf_p21_perf.py --mode replay        --duration 90 --interrupt-after 25 --interrupt-seconds 20   # 断网恢复
python backend/scripts/ebpf_p21_perf.py --mode real-wsl      --duration 120 --target-eps 240  # 真实内核采集
python backend/scripts/ebpf_p21_perf.py --mode real-vm-falco --duration 120 --target-eps 120  # 真实 Falco
python backend/scripts/ebpf_p21_perf.py --mode bounded-spool                                   # 背压容量
# 全部结果追加至 --report-name 指定目录的 summary.json；评测语义单元测试：
python -m pytest backend/tests/test_ebpf_p21_perf.py -q
```

## 10. 最终验收结论

| 验收点 | 结果 |
| --- | --- |
| 五种形态全部真实执行并落盘原始数据 | ✅（7 次运行，3 次失败尝试留档） |
| 吞吐 / CPU / 内存 / 延迟 P50/P95/P99 / 事件计数 / 丢失 / 重复 / spool 统一呈现 | ✅（§5 + consolidated.json） |
| synthetic 与真实采集严格区分表述 | ✅（§4 边界声明 + §6.5 能力边界） |
| 真实内核采集零丢失（观测窗内） | ✅ real-wsl 两次独立运行归因对账 0 丢失；real-vm-falco 0.021%（1 条，如实记录） |
| 断网中断恢复不丢不重 | ✅ replay：21.6s 断网、5 次重试、spool 清零、幂等收敛 |
| 有界 spool 容量保护 | ✅ 容量不变量与数据保全成立（告警路径未触发，如实记录） |
| 0 与 unavailable 严格区分 | ✅ 全部指标（探针丢失/falco drops/CPU 等不可测项均为 unavailable） |
| SQLite 索引缺陷根因 + EXPLAIN 前后证据 + 修复 | ✅（§4，回归锁定） |
| 测试回归 | 见 `reports/ebpf-p21-final/regression-final.txt` 与 ai_collaboration/TEST_RESULTS.md（本轮记录） |

**遗留事项**：① 后端摄取上限 ~380 EPS（SQLite 单进程）——若未来需要更高吞吐，需评估批量判重（单事务 IN 查询）或 WAL 模式调优，本轮不做；② falco 引擎级 drops/CPU 采样需 sudo 窗口，本轮 unavailable，待授权窗口补测；③ bounded-spool 的告警触发路径在真实场景未复现（45s 窗口未触界），由单元测试覆盖，可在延长窗口后补真实触界验证。

**边界**：本轮未进入 P2-2（OpenWrt 降级采集）与第九阶段；未修改任何既有测试；对 VM/WSL 零持久化改动（负载发生器产物在 /tmp，运行后清理）。
