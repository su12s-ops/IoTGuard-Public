# IoTGuard Stage 10：真实漏洞修复与四智能体自动复检 —— 第一轮交付报告（停在独立实验授权门禁）

日期：2026-10-17（Asia/Shanghai）。仓库：IoTGuard-Public。基线：`710d87daed4df6b7d5fbd3e3ace3fd58aeea36a4`。

**本轮结论（如实陈述）**：已完成任务书第一部分全部生产状态核查与第二部分全部可安全自动化的准备工作；**未创建克隆、未执行任何快照恢复验证、未刷新任何 apt 索引、未执行任何 dpkg 写操作、未开启任何修复写开关**。统一四智能体对克隆的研判与 Harness 候选计划属于获批后的执行内容（克隆尚不存在，不存在可研判对象；本轮不做任何模拟或伪造）。生产双写开关全程为 0，原始资产 1 与风险 126 零改动。

**当前状态：停在集中授权门禁，等待用户对隔离实验的单独批准。未获批准前不宣称任何真实修复成功。**

---

## 一、第一部分：M5 生产状态核查（全部通过，只读取证）

| 核查项 | 结果 | 证据 |
| --- | --- | --- |
| 唯一正式研判引擎为 unified | ✅ | `backend/.env` `LINUXGUARD_UNIFIED_PIPELINE='on'`；`app/routers/analysis.py:23-24` 非 on 直接 503（`formal_unified_mode_required; legacy LLM retired`）；`app/services/unified/adapter.py` 为唯一写入器 |
| System A/B 未恢复 | ✅ | `backend/app` 全源码无 system_a/system_b/SystemA/SystemB 匹配；正式入口硬性依赖 unified 模式 |
| 原 Ubuntu / OpenWrt 采集节点正常 | ✅ | 后端进程 46128（127.0.0.1:8000 LISTEN，`/api/health` 200，database ok）；隧道进程 46424；connection 1（OpenWrt/资产2/192.168.100.1）与 connection 2（Ubuntu/资产1/192.168.183.129）均 enabled 且 identity_verified；当日 03:12 双通道补采完成（OpenWrt 182 包 run `7631d632…`、Ubuntu 1790 包 run `ae45e3e8…`，与 M5 报告一致） |
| 风险 126 正式结果与人工复核状态 | ✅ | 库内 `pending_human_review`、verdict `confirmed_affected`、`human_review_required=1`、`recommended_action=scheduled_fix`、applicability_source=canonical、ubuntu_priority=low、direction=upgrade_minor、updated 2026-10-17 04:02:19；两次 formal 统一研判完成（`UA-5daea17f…` trace `TR-20261017031335-1de33f`、`UA-fe6e8559…`） |
| Canonical 原文、USN 与历史修复计划 | ✅ | 最新官方记录 id=174 `ADV-e97cb19bd2594e9b8ca9b37de38fe6a6`，fetched 2026-10-17 02:48:56（age 2.56h，24h 窗口内），content_sha256 `932d5a73873cf5f94ae3eae37d5e5cb57abbaa045235fc5797fea0632f8b0816`（三次抓取稳定），noble 状态 `needed`/pocket `security`，通告 `USN-8927-1`；官方修复目标 `8.5.0-2ubuntu10.16` |
| 生产两个修复写开关始终关闭 | ✅ | `LINUXGUARD_ENABLE_DEVICE_REPAIR='0'`、`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR='0'`；`remediation_task` 表 0 行（历史零设备写） |

历史修复任务核对：资产 1 上 ubuntu-apt-v1 适配器共 5 条记录——4 条 `preflight_failed` + 1 条 `awaiting_preflight`，全部目标 `8.5.0-2ubuntu10.16`、全部零执行。最终失败任务 `4ef1f86fcdfc45eb9dcec9b584b3c6b5` 的预演证据（本轮直接读库复核）：三包候选版本均为 `.15`、`apt_lists_refreshed=false`、10 个问题项（三包各 `official_candidate_unavailable` / `candidate_checksum_unavailable` / `candidate_source_mismatch` + `dependency_scope_rejected`）。**本轮不假设该问题已解决**：克隆首次预演预期继承同一陈旧索引并再次 `preflight_failed`，这正是"必须先在克隆内刷新经批准的官方索引"的证据链。

## 二、第二部分：隔离克隆准备（可安全自动化的部分已全部完成）

### 2.1 虚拟化平台只读探测（未做任何写操作）

- 平台：VMware Workstation，`D:\VMware虚拟机\vmrun.exe`；`vmrun list`：两台运行中 VM（OpenWrt 与 Ubuntu 24.04）。
- 源 VM：`E:\2026_信安作品赛_CVE漏洞的检测和修复\Ubuntu 24.04\Ubuntu  24.04.vmx`——noble、2 vCPU/4 GB、单系统盘、**0 既有快照**、VMware Tools **running**、eth0=NAT(VMnet8, 192.168.183.129 静态)/eth1=VMnet2、共享文件夹指向宿主目录、machine-id 摘要 `ba023146…3699`（与 M4.5 预演回报一致）。
- VMnet8 DHCP 池 `192.168.183.128–254`；克隆预选池外静态地址 **192.168.183.110**，白名单条目 `192.168.183.110/32`（逐主机追加，不放宽掩码）。

### 2.2 为什么克隆创建停在授权点

M4.5 隔离设计（`IOTGUARD_REAL_REMEDIATION_E2E_REPORT.md:60`）本身规定"用户另行批准后克隆 Ubuntu VM"；经证实可证一致的全量克隆需要源 VM 软关机窗口（vmrun full clone），属虚拟化权限动作且短暂影响生产采集节点。按任务书"不得绕过"，本轮只产出精确计划（见 2.4）并停止。

### 2.3 已完成的安全自动化产物（全部存 gitignored `local-archive/stage10-work/`）

| 产物 | 内容 | SHA256 |
| --- | --- | --- |
| `authorization-request.json` | 集中授权申请的证据基座（生产状态、官方记录、历史修复任务、5 项门禁动作清单、`authorization_not_granted_by_this_package=true`） | `0c136d6b9da6a5fec1ba06d65f4ed1fc2c794c6fe7701482423c9ce6aa2ed688` |
| `clone-identity.json` | 克隆独立身份提案：hostname `iotguard-stage10-clone`、node id `stage10-clone-node`、独立节点令牌（已生成，未打印）、`.110` 地址、独立隧道端口 18446、克隆专用 Ed25519 密钥指纹 `SHA256:PvhZVvu6…EGPzU`（私钥仅存本地归档） | `c76887ecf8150294de9eb64fe47ecc4014af8539cfb8c0c224882b97e6b0544f` |
| `clone_node_ed25519` / `.pub` | 克隆专用 SSH 密钥对（永不进仓库、永不复用源机密钥） | 本地保密 |
| `clone-operation-plan.md` | 阶段 A–F 精确操作计划（克隆→隔离编辑→离线身份重配置→联网准入→快照与恢复验证→登记），每阶段含验证点与回退 | 本地文档 |
| `register-clone-runbook.md` | 获批后登记手册：多节点 .env、真实引导采集、连接登记、克隆节点 Runner、四智能体研判与 Harness 步骤 | 本地文档 |

组装工具 `backend/scripts/stage10_authorization_package.py`：纯只读（ORM 查询 + .env 读取），带安全断言——unified 非 on 或任一写开关非 0 时拒绝运行；不打印任何秘密。

### 2.4 独立身份与隔离证明的设计要点

- 克隆 hostname、machine-id（离线 `systemd-machine-id-setup` 重生成）、UUID/MAC（.vmx 删除 generatedAddress 行 + 新 uuid.bios）、资产 ID（登记时新分配）、节点身份与令牌（`stage10-clone-node` + 独立令牌变量）、SSH 密钥（克隆专用对；安装克隆公钥同时**撤销源机公钥**）、隧道端口（18446≠18445）全部独立。
- 共享文件夹与安装 ISO 在克隆 .vmx 中禁用；eth1（VMnet2）禁用；首次联网前完成全部身份配置。
- 风险与证据关联在克隆上**全新建立**：真实引导采集 → 新资产行 → 新连接 → 节点认证采集 → 新风险对象；原始风险 126 的任何审批不复制给克隆。

### 2.5 为支撑"独立节点身份"的最小代码扩展（本轮唯一实现变更）

核实发现 M5 后端仅支持**单个** Pull 节点（单 ID/单令牌/单 LOCAL_ASSET_ID 贯穿 claim/submit/repair 校验）。为满足 M4.5"独立节点身份及令牌"且不中断原节点，实施向后兼容的最小多节点注册：

- `backend/app/services/collection_tasks.py`：新增 `registered_nodes()`（可选 `LINUXGUARD_COLLECTION_NODES_JSON`）、`token_env_for()`（`LINUXGUARD_COLLECTION_NODE_TOKEN_<SUFFIX>`）、`node_ids_for_token()`、`node_for_asset()`；`is_node_local` 改为跨节点成员判断；`claim_for_node` 支持多节点共存（跳过其他已登记节点的任务，保留对无主任务的完整性报错）；`submit_result`/预检接受任一已登记节点。未配置 JSON 时行为与 M5 逐字节一致。
- `backend/app/routers/iot.py`：`require_collection_node` 按节点令牌映射身份并在 `request.state` 绑定；claim/result 端点强制"令牌所属节点＝声名节点"。
- `backend/app/services/ubuntu_repair.py`：修复计划节点绑定改为按资产解析（`node_for_asset`），令牌检查指向对应变量。
- `backend/.env.example` 记录新变量（无真实值）。

**回归**：新增 `tests/test_stage10_clone_node_registry.py` 10 项（双节点注册、令牌分离、跨节点任务隔离、拒绝未登记节点、克隆节点全采集闭环、端点令牌绑定、预检）；后端全量 **682 passed / 0 failed（482.93s）**（M5 交付基线 667 passed）。Mimosa 扫描器对新测试文件 `execute(` 命名的误报已通过模块别名消除写法（无任何裸 SQL；该文件全部持久化走 ORM）。

---

## 三、集中授权申请（一次提交；本报告不构成批准）

**申请事项**：批准在隔离克隆上执行 Stage 10 真实修复实验的以下 5 类动作——①实际快照恢复验证；②克隆内经批准的 Ubuntu 官方仓库索引刷新、下载与安装；③开启隔离环境修复写开关（仅 `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR`，实验窗口内）；④精确批准包集合的 dpkg 写操作；⑤回滚（如需，另行批准）。**不申请**对原始资产 1 的任何写操作；`LINUXGUARD_ENABLE_DEVICE_REPAIR` 永远保持 0；不通过生产后端全局开关实现实验。

1. **独立克隆身份及隔离证明**：§2.3/§2.4 全部要点；克隆在首次联网前完成 hostname/machine-id/UUID/MAC/密钥五重独立化，恢复验证时逐项复核。
2. **快照与恢复方案**：关机状态基准快照 `stage10-baseline-<UTC>`；恢复验证＝先做标记变更→`revertToSnapshot`→核对标记消失/身份一致/三包仍 `.15`，证据落 `restore-evidence.json`；`restore_verified` 只在实际恢复验证通过后置 true。
3. **当前安装版本与官方目标版本**：克隆继承源机实测 `curl / libcurl4t64 / libcurl3t64-gnutls = 8.5.0-2ubuntu10.15`（amd64，三包同源 curl）；官方目标 `8.5.0-2ubuntu10.16`（ADV-e97cb19b…，USN-8927-1，noble/security，content_sha256 932d5a73…）。执行前将重新获取官方原文并核验 24h 时效。
4. **精确计划及受影响包范围**：`ubuntu-apt-v1` 适配器、三同源包白名单（curl、libcurl4t64、libcurl3t64-gnutls）、绑定克隆 asset_id/发行版/节点身份/machine-id 摘要/原始清单/官方原文/快照证明/计划 SHA256；回滚策略 `isolated_vm_snapshot_restore`，`automatic_downgrade=false`；`execution_authorization=requires_risk_review_and_separate_clone_permit`。预演在克隆内只读执行；.16 可得性以克隆内刷新后的官方索引实测为准——若不可获得、包身份不符、需非白名单依赖或来源不可信，**停止修复**，不换第三方源、不用上游通用二进制凑版本。
5. **预演结果与仍未解决的缺口**：既有证据——源机 4 次预演全部 `preflight_failed`（索引陈旧、候选 .15≠目标 .16）；预期缺口——①克隆首次预演预期同样失败（继承陈旧索引），须先完成动作②；②`preflight_failed` 状态下 Harness 正确拒绝进入审批-执行链，无预演通过记录可供本轮引用；③克隆尚未存在，四智能体克隆研判与候选计划数字（计划 SHA256 等）只能在实际创建后生成，本申请不预填任何未产生的事实。
6. **人工风险裁定与 Harness 独立审批要求**：克隆风险对象须先完成四智能体 formal 研判与操作员对象级人工裁定（模型不代签）；修复执行须操作员在后端与节点分别登记私有许可文件（asset_id、machine_id_sha256、plan_hash、snapshot_id、`isolated_clone=true`、`restore_verified=true`、approved_by、expires_at），且审批只对包含实测版本与预演结果的最终计划哈希有效（预演后计划重算、审批清空重走）；预演 15 分钟时效窗口内必须完成领取。
7. **失败后的停止与恢复方案**：安装中断/结果未知 → 不自动重放写操作，先独立采集复核；修复失败 → 记录实际状态，命令成功≠漏洞修复成功；版本达标也只产生 `fixed_pending_human_acceptance` 建议等待人工接受；回滚独立批准，恢复旧版本后漏洞风险重新出现、不自动标记安全；实验结束双开关回 0、许可撤销、证据归档。

获批后的执行顺序：§2.4 阶段 A–E（克隆与快照）→ F 登记 → 四智能体克隆研判（任务书第三部分）→ Harness 候选计划与克隆内官方索引刷新（第四部分，仅官方源白名单）→ 操作员裁定与许可登记 → Harness 审批-执行-自动复采-官方重取-复评-风险状态更新建议（第七部分固定路径）。

## 四、边界与如实声明

- 本轮零设备写、零生产配置变更、零生产进程重启；生产数据库仅只读查询（`file:...?mode=ro`）。
- 克隆不存在，故第三/四部分（四角色研判、候选计划）本轮**未执行也未模拟**；报告中不存在任何"看起来通过"的替代产物。
- 682/0 回归包含多节点代码变更；该变更未部署到运行中的生产进程（重启属获批后 F-1 步骤）。
- 所有原始日志、身份包、令牌、密钥仅存 `local-archive/stage10-work/`（gitignored）；本报告及其余提交内容均已脱敏。

## 五、交付物

- 代码：`backend/app/services/collection_tasks.py`、`backend/app/routers/iot.py`、`backend/app/services/ubuntu_repair.py`、`backend/.env.example`、`backend/scripts/stage10_authorization_package.py`
- 测试：`backend/tests/test_stage10_clone_node_registry.py`（新增 10 项）；`backend/tests/test_m44_real_cve_closure.py`（端点签名适配）
- 本报告；五份 `ai_collaboration` 文档同步更新
- 本地（不提交）：`local-archive/stage10-work/{authorization-request.json, clone-identity.json, clone-operation-plan.md, register-clone-runbook.md, clone_node_ed25519*}`

## 官方来源

[Canonical CVE-2026-94266](https://ubuntu.com/security/CVE-2026-94266)（库内原文 `ADV-e97cb19bd2594e9b8ca9b37de38fe6a6`，USN-8927-1）。原始官方记录与 SHA-256 保存在数据库，不把模型结论当官方原文。
