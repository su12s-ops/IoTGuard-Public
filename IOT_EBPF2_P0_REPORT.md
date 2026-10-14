# IoTGuard eBPF 2.0 — P0 工程实施报告（运行时证据可靠性）

日期：2026-10-14。基线：审计轮 Private `3ee0425`（IOT_EBPF2_AUDIT_REPORT.md）。
本轮**仅实施 P0**：D1 幂等与回绑、可靠转发、采集可靠性指标、清空语义。未进入 P1/P2；未修改内核配置/部署 Falco 服务/启用 LSM enforce/对真实设备写操作。

## 1. P0 修改文件清单

| 文件 | 变更 |
|---|---|
| `backend/app/ebpf_identity.py` | **新增**：稳定原始事件身份（纯函数，服务与迁移共用） |
| `backend/app/services/ebpf_event_collector.py` | 指纹换稳定基；判重路径资产补绑；SAVEPOINT+唯一索引并发兜底；进程级入库串行锁；clear_events 结构化语义 |
| `backend/app/services/security_evidence.py` | persist_evidence 判重路径证据回绑；先绑定不被改写 |
| `backend/app/services/runtime_telemetry.py` | 新增 reliability_snapshot（自报×服务端观测，0/unknown 严格区分） |
| `backend/app/routers/runtime.py` | 新增 `POST /runtime/ebpf/events/batch`（批量确认协议）与 `GET /runtime/ebpf/reliability`；DELETE 语义响应 |
| `backend/app/database.py` | `_migrate_ebpf_p0`：指纹重算、精确去重（绑定无歧义传递）、部分唯一索引、证据确定性回绑、迁移标记 v2 |
| `collector/ebpf_event_collector.py` | 转发器 2.0：批量+有界重试+指数退避+spool 断点续传+ack 确认+指标计数（保留 --legacy-single 兼容路径） |
| `collector/ebpf_trace_capture.sh` | bpftrace stderr 丢失计数解析 → 探针健康文件（supervisor 语义，unavailable 不虚构为零） |
| `backend/tests/test_ebpf_p0.py` | **新增** 18 项专项测试 |
| `backend/tests/test_runtime_forwarder.py` | 两测试按新契约等价改写（安全意图不变：boot_id 不注入、degraded/stopped 心跳、失败退出码） |

## 2. D1 根因与修复前后真实数据

**根因（两层）**：旧指纹基 = `sha256({"asset_id": 当前绑定, "raw": 原始报文})` —— ① 绑定态参与身份：资产注册前后同一事件指纹漂移 → 双份记录；② 传输层注入键（asset_id/sensor_id）随归一化嵌进 raw（含双层归一化的嵌套 raw），上报通道元数据污染身份。

**修复前（真实复现，审计轮证据 reports/ebpf-audit-20261014）**：注册前上传 40 条 → 注册资产 → 重传同批 → **RuntimeEvent 80 行（40+40 重复）**，SecurityEvidence 永久 asset_id=NULL。

**修复后（真实运行，reports/ebpf-p0-20261014/e2e-evidence.json）**：同一 40 条真实内核事件（阶段二 WSL 采集夹具）经真实转发器进程 **4 次上传**（断网 spool→恢复续传→两次重放）→ **db_event_count=40、evidence=40，重复 0**；服务端批量响应逐次返回 duplicates 计数。

## 3. RuntimeEvent / SecurityEvidence 新幂等设计

三层身份分离：
1. **原始事件身份** `event_fingerprint` = sha256(`{anchor, boot_id, raw 去传输键}`)：anchor 取事件自报 hostname（Falco output_fields/Tetragon source/自研顶层），boot_id 区分同主机跨重启；**剔除 asset_id/sensor_id（含沿 "raw" 嵌套链递归剔除——那是归一化 artifact）**；无时间戳事件不判重（延续旧行为）。指纹提示取**绑定前**自报主机名，绑定改写不漂移。
2. **采集来源身份**：sensor_id + boot_id 列（转发器注入，identity_fields）。
3. **资产归属**：可变绑定。判重命中时：RuntimeEvent 缺绑补绑；SecurityEvidence 同样补绑；**先到先绑定，非空归属不改写**；冲突的显式归属按既有防御语义整体拒绝。

防误合并：不同主机名 / 同主机名不同 boot → 指纹必然不同（专项测试覆盖）。并发：进程级串行锁 + 非空指纹部分唯一索引 `uq_runtime_event_fingerprint_v2` + SAVEPOINT 兜底（双线程同批并发 → 恰 20 行）。

## 4. 批量重试与确认机制

- 服务端 `POST /runtime/ebpf/events/batch`：≤500 条/批；逐条校验（坏行单条拒绝不拖累整批）；响应 `{ack:true, received, accepted, duplicates, rejected[], stored_event_ids}` —— **ack 仅代表已持久化**，服务端按指纹幂等，重放返回 duplicates。
- 转发器：批 50 条/2 秒；有界重试 5 次、指数退避 1→16s（+0~30% 安全随机抖动）；耗尽 → 整批入本地 spool（**未确认 ≠ 丢失**）；启动先续传 spool（已确认行不写回）；退出码在存在拒绝/未确认/spool 非空时非零。"请求已发出" 不视为确认——仅 HTTP 200 + 可解析 ack 响应才算。
- 真实 E2E：断网（连 127.0.0.1:9）→ 2 批重试耗尽入 spool（exit 1）；恢复 → spool 40 accepted + 文件重放 40 duplicates；再两次重放全 duplicates；对账 40/40/0。

## 5. 采集健康指标与数据来源

| 指标 | 来源 |
|---|---|
| received/parsed/rejected/retries/failed_batches/spool_pending/last_success_at/uploaded/duplicates | 转发器进程内真实计数 → 心跳 capabilities.metrics |
| dropped_events | ① 探针 supervisor 健康文件（ebpf_trace_capture.sh 解析 bpftrace stderr "N events lost" → 真实数值；解析不到 → null）；② 转发器 --health-file 消费 |
| stored_events / first/last_event_at（按 sensor） | 服务端 runtime_event 按 sensor_id 聚合（真实观测） |
| 传感器在线状态 | runtime_sensor 心跳年龄（coverage 既有语义） |

**0 与 unknown**：`GET /runtime/ebpf/reliability` 中 dropped_events 从未上报 → `"unavailable"`（真实零必须是数值 0）；转发器计数 0 = 真实零；历史无 sensor 归属事件单独计数说明。E2E 实测：`dropped: unavailable` 与 `self_reported.received: 40` 并存。

## 6. 专项测试结果（backend/tests/test_ebpf_p0.py，18/18 通过）

D1 根因复现（旧基漂移断言）/ 同批重传幂等 / 资产注册前后重传不重复+双表回绑 / 不同设备与不同 boot 不误合并 / 先绑定不改写+冲突拒绝 / 并发同批幂等 / 批量失败安全重试 / 重试预算耗尽入 spool / **服务端已提交未确认→重试不重复** / spool 往返协议 / 退避有界 / 可靠性端点（0 与 unavailable 两态）/ 旧 API 兼容（单条+upload+事件形状）/ 批量端点契约（含逐条拒绝）/ 智能体证据工具不变 / Trace 证据解析不变 / 旧库迁移（指纹重算+去重收敛+回绑+索引+标记幂等）/ 清空语义（证据保留）。

## 7. 全量回归与基线对比

- P0 前基线（第八阶段末）：356 passed / 19 failed（19 = 既有已知冲突文件 iot_device_upgrade 9 + mqtt 5 + scan_runs 5，与 conftest 审计钩子冲突，文档有据）。
- P0 后：**374 passed / 19 failed —— 失败集合逐一相同，零新增回归**；新增 18 专项全过。转发器契约测试 5/5（含两测试按新契约改写、安全意图保留）；相关套件（ebpf/runtime/trace/zephyr/agent/harness）92/92。
- 说明：既有 19 失败在 P0 前后同集合抖动出现（33↔19 之间为套件内时序抖动，本轮 19 与上轮 19 完全一致）。

## 8. 数据库迁移与兼容性

- 新库：create_all 建表 + 迁移即生效。
- 旧库：`_migrate_ebpf_p0`（标记 `ebpf_p0_stable_fingerprint_v2`，幂等可重跑）—— 指纹按新基重算（依据存储的 raw_json，确定性）；新基精确重复保留最早行（**绑定无歧义传递**：组内恰一个非空 asset_id 才补绑，多归属歧义保守置空不猜测）；防遗留行清扫；建部分唯一索引；SecurityEvidence 按 device_id 与资产 hostname/ip **精确匹配**回绑（不模糊推断）；无指纹/不可解析行一律保留。
- 兼容：旧 API（单条 POST、upload、demo、事件字段）不变；DELETE /ebpf/events 响应保留 count 并增量新键；心跳旧 payload 兼容（metrics 可选）；--legacy-single 保留转发器单条路径。

## 9. 边界遵守

未修改 Ubuntu 内核配置、未部署 Falco 服务（P1）、未启用 BPF-LSM enforce、未对真实 IoT 设备写操作；清空接口明确禁止以全表清空替代重复数据处理、保留证据审计引用（风险复核 review_evidence_ids 与 Trace evidence_refs 不被破坏——测试覆盖）。

## 10. P1 前置条件

1. VM sudo 授权窗口（Falco 规则部署 + 常驻采集 + 真实丢失计数验证）；
2. P1 探针增强（execve argv + process start_time 会话键）需在 WSL/VM 真实采集验证；
3. Mimosa 完整扫描仍不可用（python_ast_unavailable），全局安全审计未执行——如实报告，不声称完成。
