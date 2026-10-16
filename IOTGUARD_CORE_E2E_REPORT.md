# IoTGuard 核心业务主链 E2E 报告（Stage 9B M4.3）

> 日期：2026-10-16。基线 commit：`5917d84`。
> 目标：把已完成的统一四智能体接入**真实设备**的实际漏洞检测业务，打通
> 「真实设备 → 真实资产证据 → CVE 检测 → 运行时取证 → 统一四智能体研判 →
> 处置计划 → 安全审批与验证」核心主链。
> 原始证据：`reports/m43-core-e2e-*/`（本地留存，`reports/` 不入库，含实验网段标识）。

---

## 1. 结论总览

| 项 | 结果 |
| --- | --- |
| OpenWrt 真实端到端链路 | ✅ 发现入档 → SSH 只读采集（182 真实包）→ CVE 匹配（真实零命中）→ logread 证据入库（1304 行）→ 统一四智能体影子研判（runtime 分析师消费真实 logread 证据）→ Harness 只读闭环 |
| Ubuntu 真实运行时证据入链 | ✅ dpkg 真实采集（1790 包）→ 真实情报（本地存档 + NVD/KEV/EPSS 线上同步 349 条）→ 377 匹配 / 125 真实风险候选 → 影子 risk_review 消费真实 Falco 证据（stale 语义诚实降级）→ 待审批处置计划 |
| 四智能体真实调用与证据消费可追溯 | ✅ 14 次影子运行全部 completed；每次运行 trace_id 贯穿（E3 核验 22/22）；裁定引用的 SE-* 证据 ID 独立复验全部真实存在（反幻觉） |
| 候选处置计划关联真实风险与原始证据 | ✅ scheduled_fix 计划（update_package openssl 等）挂接 risk 12 与真实 SE 证据；`requires_approval` 由程序强制恒真 |
| 前端同链展示 | ✅ AgentOps 新增「统一编排（影子）」页签（列表+门禁/结论/计划/四智能体明细+正式对照）；风险详情页新增「09 统一四智能体影子研判」区块（按 risk_id 关联+深链）；浏览器实测渲染通过 |
| 影子零副作用 | ✅ 正式 RiskAssessment 字段前后快照一致（C2b）；无最终分/裁决写入（E4）；`LINUXGUARD_UNIFIED_PIPELINE=off` 全程保持（C0）；零设备写操作 |
| E2E 检查合计 | **A 12/12 + B 7/7 + C/D/E 19/19（另有 A+C/D/E 合跑 27/27）** |
| 全量回归 | **655 passed / 0 failed**（650 基线 + 5 项新增专项，零回归） |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-16T11-54-*.680Z 终扫封印，123 依赖包） |
| 敏感信息 | 干净（diff 与新增脚本无凭据字面量；密钥/口令仅环境变量引用） |

## 2. 实际打通的业务链路（溯源标识）

### 2.1 OpenWrt 设备链（真实设备：OpenWrt 25.12.5，内核 6.12.94，VMware 实验段 192.168.100.1）

```
授权网段发现入档（POST /api/iot/discovery enroll=true, 192.168.100.0/25）
  → IotDevice DEV-59CCB87534B7 + DeviceObservation + 协议指纹
操作员 SSH 只读采集（固定脚本 collector/collect_openwrt_asset.sh 经 stdin 下发，
  ED25519 主机指纹钉扎 SHA256:+CaFHIb60… 与 2026-10-13 受信记录一致）
  → 27,193 bytes 原始清单（sha256 7f154fae…）→ POST /api/assets/upload
  → LinuxAsset id=2「OpenWrt-000c2915a8c8」182 个真实软件包（inventory_complete=true）
DeviceConnection 登记（指纹钉扎 + 密钥仅经 LINUXGUARD_DEVICE_* 环境变量引用）
  → 连接 id=1；预检如实报告 node_platform=false（Windows=开发节点，见 §5 边界）
CVE 匹配（POST /api/matching/run?asset_id=2）：OpenWrt 主机线按设计仅接受
  openwrt.org 操作员公告（当前网络不可达且不引入合成公告）→ 真实零命中（有效结果）
运行时证据（POST /api/iot/connections/1/collect-logs）：logread 只读拉取 →
  source=openwrt_logread、SecurityEvidence 同步生成，跨轮幂等判重
  （累计 1304 行绑定 asset 2；单轮 26 新增/1213 判重）
统一四智能体影子研判（run m43-ow-a46aad79，trace TR-20261016115201-*）：
  路由 include_runtime=true（跨线证据键修复后，见 §4）→ runtime_analyst 以
  5 个只读工具消费真实 logread 证据，产出 6 条发现（service_active /
  attack_precondition）全部挂真实 SE 证据 ID；决策引用 6 个真实 SE ID
Harness 只读闭环：调查任务（计划哈希 16244cd0… 固化）+ 门禁演示（§5）
```

### 2.2 Ubuntu 主机链（真实主机：Ubuntu 24.04，wyh-VMware-Virtual-Platform，192.168.183.129）

```
操作员 SSH 只读采集（collector/collect_linux_asset.sh → stdout）
  → 88,952 bytes → POST /api/assets/upload 更新既有登记资产 id=1（1790 真实 dpkg 包）
真实情报：本地既有存档行级导入（canonical 72 / kev 172 / epss 172 / nvd 172，
  fetched_at 保留原值不伪装新鲜）+ 线上增量同步（NVD keyword 检索 7 词，
  saved=349，KEV/EPSS 富集；canonical/麒麟源不可达 → 情报立场如实 unavailable）
匹配与风险：377 条匹配 → POST /api/risk/calculate → 125 条真实风险候选
  （13 fixed / 24 not_affected / 2 not_applicable 等，零受影响=系统补丁齐全的
  真实结论；potentially_affected 候选保持候选语义不确认为漏洞）
影子 risk_review（run m43-ub-3bcef75c / m43-ub-3ca49554 / m43-ub-34773d24 等，
  多轮全链成功）：risk 12 = CVE-2026-63073 openssl，装机 3.0.13-0ubuntu3.16 <
  修复 3.4.7（确定性版本比较），NVD CVSS 9.8
  → 裁定 potentially_affected（Canonical unavailable，不虚判 confirmed）
  → runtime_evidence_validity=stale_verified（Falco 心跳 45.8h 前，如实降级）
  → urgency_basis=static_evidence_only → scheduled_fix（拒绝无依据升级 immediate）
  → 门禁 pending_human_review（confidence<0.70 / evidence_partial /
     stale_runtime_evidence / high_critical 四理由）
  → 待审批计划：update_package openssl + backup_file /etc/ssl + restart falco 传感器，
     附验证步骤与回滚要求；requires_approval 程序强制 true
Harness 只读闭环：调查任务执行（证据包 15 条原始证据挂接 risk 12）+ 修复门禁演示
```

## 3. 对应代码与接口

| 层 | 内容 |
| --- | --- |
| E2E 编排器（新增） | `backend/scripts/m43_core_e2e.py`：五阶段（A 发现/采集/匹配/logread、B Ubuntu 采集/情报/风险、C 影子研判、D Harness、E 一致性核验），幂等可重入，全部检查落 `reports/m43-core-e2e-*/summary.json` |
| 复用的既有模块（未改语义） | 发现闭环 `discovery_pipeline`/`device_inventory`、清单解析 `asset_parser` + `POST /api/assets/upload`、连接与采集 `device_access`/`iot_devices`/`collection_tasks`、logread `openwrt_runtime_log` + `POST /api/iot/connections/{id}/collect-logs`、匹配 `matching_engine` + `POST /api/matching/run`、风险 `risk_engine` + `POST /api/risk/calculate`、情报 `real_intel_collector`/`vulnerability_intelligence`、Harness `agent_harness` + `/api/harness/*`、统一编排 `services/unified/*`（LangGraph 唯一编排器） |
| 后端小改（只读） | `GET /api/unified/runs` 新增 `risk_id` / `target_ref` 过滤（前端风险详情关联用；`routers/unified.py`） |
| 前端（新增展示，不新建页面） | `AgentOps.vue` 新增「统一编排（影子）」页签；`CveWorkflowDetail.vue` 新增「09 统一四智能体影子研判」区块；`api/deviceOperations.js` 新增 4 个只读 API 封装 |
| 影子运行入口 | 既有隔离入口：直接调用 `unified.runner.run_unified_sync`（mode=shadow），全局开关保持 off，正式入口不受影响 |

## 4. 本轮发现并修复的真实缺陷（全部回归锁定）

| # | 缺陷（E2E 真实暴露） | 修复 | 回归 |
| --- | --- | --- | --- |
| 1 | 情报同步二次运行崩溃：`autoflush=False` 会话内同轮两处创建 ThreatIntelSource 互不可见 → 重复行；下次同步 `one_or_none()` 抛 MultipleResultsFound（实测复现） | `vulnerability_intelligence/service.py`、`real_intel_collector.py`：查改 `first()` + 插入后 `flush()`；存量 6 条重复行清理 | `test_enrichment_tolerates_legacy_duplicate_threat_rows` |
| 2 | 设备身份降级：重复入档的弱探测轮（瞬时协议未应答）把已识别 IotDevice 无条件改写为 `unknown-device-<ip>` 低置信身份 | `device_inventory.upsert_device`：本轮置信度低于已存身份时不覆盖身份承载字段，只刷新在线画像（防降级不阻碍升级） | `test_upsert_device_identity_never_downgrades` |
| 3 | 设备线↔主机线证据键失配：logread/eBPF 证据锚定设备自报主机名（`OpenWrt-000c2915a8c8`），设备面研判按 `DEV-*` 键查证得"无运行时证据"，routing 裁剪 runtime 分析师 | `agents/tools._evidence_keys`：经同 IP 资产与指纹钉扎 DeviceConnection（平台权威同机绑定）双向传递证据键 | `test_evidence_keys_reconcile_device_and_host_lines` + `test_evidence_keys_resolve_via_pinned_connection_when_asset_ip_missing` |

修复 #3 后，最终 C1 运行（m43-ow-a46aad79）：routing `include_runtime=true`，
runtime_analyst 以 5 工具产出 6 条真实发现，决策引用 6 个真实 SE 证据 ID。

## 5. Harness 安全边界（全部实测，零设备写操作）

| 检查 | 结果 |
| --- | --- |
| 调查任务（goal=investigate）创建与只读执行 | ✅ 计划哈希固化；Ubuntu 风险调查产出 15 条原始证据包（needs_evidence=缺完整采集心跳，如实） |
| 设备采集步骤节点策略 | ✅ Windows 开发节点发起 OpenWrt 采集被产品策略拒绝（`node_platform_invalid` / 认证引用缺失），任务如实 failed、Trace 收口——清单由操作员 SSH 采集经官方上传 API 入库，Linux 采集节点路径为主链升级项（§7） |
| 审批哈希绑定 | ✅ 伪造 64-hex 哈希审批 → 409；调查计划拒绝修复式授权 → 409 |
| 修复任务前置门禁 | ✅ 未满足前置条件（需 OpenWrt 完整清单/连接/产物登记/风险过审）→ status=blocked，执行 409 |
| 影子隔离 | ✅ 影子运行前后 RiskAssessment 正式字段快照一致；`review_status` 保持候选侧语义（reanalysis_required 为正式引擎自身"证据变化需重研判"状态，非影子写入） |
| 设备写操作 | 本轮未注册修复产物、未批准修复计划、未触发任何设备写；`LINUXGUARD_ENABLE_DEVICE_REPAIR=0` 保持 |

## 6. 前端展示（浏览器实测）

- **智能体分析与修复工作流 →「统一编排（影子）」**：影子提示横幅（明确"不改变正式结论、不触发设备写"）；运行列表（模式/状态/风险关联）；运行详情 = 图拓扑十阶段进度、确定性门禁（状态+理由+LLM 用量）、影子结论（影响判定/处置/证据有效性/紧迫度依据/引用证据/证据缺口/完整研判依据）、四智能体执行明细（工具调用+引用证据）、待审批处置计划（白名单动作/验证/回滚）、与正式链路对照入口。
- **风险详情页（CVE-2026-63073）→「09 统一四智能体影子研判」**：按 risk_id 关联的全部影子运行 + Trace + 深链按钮，页首正式结论与影子区块明确分层；截图存证 `reports/m43-core-e2e-20261016-110220/frontend-risk-detail-section09.png`。
- 数据分层：真实设备数据（资产页/风险中心）、影子研判（明确标注"影子"）、合成测试数据（Fixture，仅存在于历史实验库，不在本轮业务库）在前端可区分。

## 7. 尚未打通的主链阻塞与边界（如实陈述）

1. **产品内设备 SSH 采集需 Linux 采集节点**：Windows 开发节点被策略拒绝（本轮如实演示该边界）。主链升级项：在 Ubuntu 采集节点运行同一后端完成产品内采集（身份升级 pinned_ssh_inventory 0.95）。当前清单经由操作员 SSH 采集 + 官方上传 API 入库（同一固定 Collector、指纹钉扎、SHA256 审计），真实性不受影响。
2. **OpenWrt 主机线 CVE 零命中**：按设计仅接受 openwrt.org 官方公告（当前网络不可达，不引入合成公告）。设备线协议指纹版本证据弱（横幅不含版本），设备线匹配亦无候选。均为诚实结果；接通 openwrt.org 公告源后主链自动受益。
3. **Ubuntu Falco 传感器停转**：常驻采集需 sudo 密码（操作员交接项），当前证据为 2026-10-14 授权部署窗口的真实事件（2418 条），影子研判以 stale_verified 诚实降级并生成 restart_service 处置建议——证据过期语义按设计工作。
4. **正式引擎的重研判状态**：risk 12 处 `reanalysis_required`（正式引擎在证据变化后的设计行为）；影子对照不受影响，正式结论仍空（E4 锁定）。

## 8. 实际测试与成本

| 项 | 值 |
| --- | --- |
| 全量回归 | **655 passed / 0 failed**（650 基线 + 5 新增：unified runs 过滤 1、情报重复行 1、身份防降级 1、证据键跨线 2；两轮独立复跑零回归） |
| 专项实机验证 | `m43_core_e2e.py` 五阶段 38 项检查全通过（A 12 + B 7 + C/D/E 19；另有合跑 27/27 一轮） |
| 影子运行 | 14 次 completed（多次全链 LLM 成功），累计 141 次 LLM 调用 / 1,530,562 tokens（meter 口径）；单次评审运行 143k–244k tokens |
| Mimosa 深度扫描 | **0 findings**（scan-2026-10-16T11-54-28.320Z-b7c5bff9c409，seal sha256:52fbd4fbeb18dd3bd42b9d7022dd95bdc8515c34e4f856c8a4dd334d358e18a7；123 依赖包，离线公告 1 包 2 条与 M4.2 交付态一致） |
| 敏感信息 | 干净；主机指纹/实验网段仅存本地 gitignored 证据目录 |

## 9. 边界承诺（与指令一致）

- `LINUXGUARD_UNIFIED_PIPELINE=off` 全程保持；旧 System B 仍为正式业务入口，影子运行零触碰正式字段；
- 未退役旧编排器；未切换全局 flag；未实施任何未经批准的真实设备修复（无产物登记、无修复审批、无写操作）；
- 真实漏洞零命中如实展示（OpenWrt 主机线 0 候选），无合成 CVE 冒充真实检测成果。

## 10. 提交

本轮交付以最终 commit 为准（见 git log）；原始运行证据 `reports/m43-core-e2e-20261016-*/`（含 summary.json、原始清单、前端截图）本地留存不入库。
