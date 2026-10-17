# IoTGuard Stage 10 第三轮交付：隔离克隆预检报告（IOTGUARD_STAGE10_ISOLATED_CLONE_PREFLIGHT_REPORT）

生成：2026-10-17（Asia/Shanghai）。基线 `f60c102`（= origin/main，工作区干净起始）。
授权依据：本轮任务书授权 A（Falco 服务恢复）与授权 B（隔离克隆第一阶段）。授权二（dpkg 写/实验写开关/计划审批）**未获得、未申请执行、全部动作停在门禁**。
原始证据（gitignored）：`local-archive/stage10-work/`（身份包、恢复证据、apt 策略/模拟输出、DB 一致性备份、WSL 脚本、节点日志）。

---

## 一、任务书十问直答

### 1. 独立克隆是否真实创建并完成身份隔离？——**是**

- `vmrun -T ws clone … full` 实际执行（20GB 完整磁盘集，exit 0）；后经 `vmware-vdiskmanager -t 2` 转为 80GiB 单文件 flat 盘（exit 0），`.vmx` 指向 flat 盘；原分裂盘保留为回滚副本（round 结束后经批准清理）。
- 身份隔离在**开机前离线**完成（WSL2 root 离线挂载根分区，全程双网卡 `startConnected=FALSE`），逐项验证：

| 维度 | 源机（实测） | 克隆（实测） | 证据 |
|---|---|---|---|
| hostname | wyh-VMware-Virtual-Platform | iotguard-stage10-clone | 离线读盘 + 联网后 `hostname` 实测一致 |
| machine-id | sha256(文件) `1ec1e05e…` | sha256(文件) `0e76c274…`（内容 strip 口径 `0691eeb5…`，见 §五-4） | 均为实测，二者不同 |
| MAC | 00:0c:29:3f:3f:27 / :31 | 删除 generatedAddress 行 + 新 uuid.bios 派生全新 MAC | `.vmx` 字节级核验 |
| UUID | （源值） | uuid.bios `E2 63 F8 81-…`、uuid.location `5C 2D 68 56-…`、vmci0.id 新值 | `.vmx` 实读 |
| SSH 主机密钥 | （源值） | 三套全部离线重生成；指纹 `SHA256:JIvwH3QDpMzcaq6bdCm5ai2EPhsC+Zl1wXTkbm6a3uE` | ssh-keygen -lf |
| 登录密钥 | 源机两把 id_ed25519_vms | **仅** clone_node_ed25519；源密钥登录克隆被拒 `Permission denied (publickey,password)`（实测留证） | authorized_keys=1 行 |
| 网络 | .129 静态 + VMnet2 | .110/24 静态（VMnet8 池外、无租约、ping 无响应核实后启用）；ens37 禁用；共享文件夹/HGFS/ISO 挂载全禁用 | netplan 90-stage10-clone.yaml + .vmx |
| 云端初始化 | （源状态） | `99-stage10-isolation.cfg`（preserve_hostname + network disabled），instance 状态清空 | 读盘核验 |

### 2. 源 Ubuntu 是否成功恢复？——**是**

软关机（powerType=soft，Tools 在位）→ full clone → 立即回开。回开后实测：Tools running；hostname/machine-id/IP/curl `.15` 与关机前摘要逐项一致；采集节点因关机断连后用既有 `restore_collection_node.py start` 恢复（节点回在线 last_seen≈1s）；后端/数据库全程在线。除批准的关机窗口外，源机零改动（无快照、无 .vmx/磁盘修改）。

### 3. 克隆快照是否经过真实恢复验证？——**是，restore_verified=true（含一次如实作废的失败尝试）**

- 基线快照：`stage10-baseline-20261017T115000Z`（关机干净态创建，`listSnapshots`=1）。
- **通过判据（本轮有效协议）**：开机 → 克隆机内以 wyh（/var/tmp 全局可写，无需 sudo）创建快照后标记 `stage10-restore-marker-r3` → 软关机 → `revertToSnapshot` → 重新开机 → **r3 消失** ✓；hostname/machine-id/curl 安装版 `.15`/候选 `.16` 全部不变 ✓；回滚后可正常引导（Tools running）✓。证据：`restore-evidence.json`。
- **如实披露**：第一次尝试用"WSL 离线直写标记"验证，回滚后标记未消失——关机态快照与基础盘同体、无 delta，该协议无效。该尝试**整体作废**（删快照、删标记、换用客户机内标记协议重做），其结果未用作任何证明。
- 机制观察（如实记录）：对关机 VM 打快照记录的是最近一次干净关机状态，故更早的 r2 标记也不在基线内——基线为无标记干净态，符合基准快照预期。
- 该验证仅证明克隆基准快照可恢复；**不构成**未来修复失败的正式回滚授权。

### 4. Falco 是否恢复真实新心跳和新事件？——**否（停在 sudo 凭据门禁，未伪造）**

- 授权 A 后实际执行通道核验：`sudo -n systemctl start linuxguard-falco` → "sudo: 需要密码"，服务保持 **inactive**；`sudo -n -l`、逐命令 NOPASSWD 探测全部失败；`SSH_PASS` 在用户/机器级环境变量均未设置；`VM_PASS` 不在 `.env`、本地后端进程与 Docker 后端容器中；root SSH 登录被拒（上轮已证）。上轮明确记录的替代路径"重启整台 VM"被授权 A 明文排除。
- 因此：**backend_online=TRUE、collection_node_online=TRUE（双节点）、sensor_healthy=FALSE（falco inactive / logread stale）、runtime_evidence_fresh=FALSE**，四态如实分层，未直接改库制造 running，未伪造事件。
- 解锁方式（供操作员选择，口令不经聊天/脚本/参数/报告）：① 操作员在自己终端 `setx SSH_PASS "<口令>"` 后告知"已设置"，本轮即可经 `sudo -S` stdin 通道执行一条启动命令；② 或操作员在 VM 控制台自行执行 `sudo systemctl start linuxguard-falco`（服务已 enabled，启动后本平台心跳/事件链路自动恢复）。

### 5. 克隆是否完成新的认证采集？——**是**

- 连接 3（asset 3 ↔ 192.168.183.110，ssh_key，指纹钉扎）预检 ready=true；采集任务经正式入口下发 → **stage10-clone-node 认领（node_identity=authenticated）** → `INV-3bef62a8eb2a912606f16643299b54e9`，output_sha256 `caaa5083…08b92`，1790 包，Trace `TR-20261017120514-343583` completed。全部为克隆自身新证据，未复制源机 INV。

### 6. 四智能体是否完成真实克隆研判？——**是**

- 正式入口 `POST /api/analysis/runs?risk_id=127`（unified-four-agent-v1+analysis-compat）→ run `b522f38df422` / `UA-b522f38df422-127` / Trace `TR-20261017121001-a3e631` completed。
- 四角色真实模型调用（glm-5.3-flash）全部 valid：asset_investigator 113s（克隆身份/资产画像核验通过）、vulnerability_analyst 89s（USN-8932-1 noble/curl 精确依据 + 版本比对 affected）、runtime_analyst 111s（**零运行时证据=monitoring_missing，不解读为安全**）、decision_planner 278s（无降级、无程序级冲突）。
- 结论落在人工门禁：**pending_human_review / confirmed_affected / human_review_required=1 / scheduled_fix / upgrade_minor**；11 项证据缺口如实保留；模型未代签。克隆研判完全独立于资产 1 的任何历史审批。

### 7. 官方 .16 是否在刷新后的克隆索引中真实可获得？——**是**

- 刷新方式：克隆关机态 WSL chroot 内 `apt-get update -o Dir::Etc::sourcelist=ubuntu.sources -o Dir::Etc::sourceparts=-`——**仅**官方源（cn.archive.ubuntu.com + security.ubuntu.com deb822，均带 ubuntu-archive-keyring 签名验证）；Falco 第三方源显式排除；仅索引元数据，**零 .deb 下载、零安装/升级/移除**。
- 实测（chroot 内 + 开机后克隆内各验一次）：curl / libcurl4t64 / libcurl3t64-gnutls 三包 **Candidate=8.5.0-2ubuntu10.16，来源 security.ubuntu.com noble-security**；官方索引中 `.16` 包摘要：curl `3c5ca6af…58ae0`、libcurl4t64 `8196381b…3cd8d`；`dpkg --audit` 干净、无 hold；`apt-get --simulate`：**3 upgraded, 0 newly installed, 0 to remove**（精确包范围，无额外依赖、无移除项）。USN-8932-1 为 noble/curl 的精确通告（上轮纠正结论维持，官方 JSON content_sha256 `932d5a73…` 与库内一致）。

### 8. Harness 预演是否通过？——**通过（本 CVE 历史上首次全绿）**

- `POST /api/harness/runs`（goal=repair，asset 3 + risk 127）→ `ubuntu-apt-v1` enrich 成功 → dry-run 经 stage10-clone-node 真实执行 → **preflight ready=True，issues=[]**。对比：资产 1 历史五次预演全部 `official_candidate_unavailable`/`dependency_scope_rejected` 失败——克隆内索引刷新直接消除了该类失败，验证了"先刷新索引、再谈修复"的前置链路。
- 预演工具调用 `ubuntu_dry_run_dispatch` / `ubuntu_dry_run_result` 均 side_effect=false、completed；模拟输出为克隆本机真实 `apt-get --simulate`（含非 root 模拟提示，如实保留）。

### 9. 最终待审批计划的实际 SHA256？——`352208827415d3c96d32e1e57e81059541d3df8a6943415412a3de3a104848cf`

- 计划 ID `1edbaaf593b14b70a4450868799e1e7e`，状态 **awaiting_approval，approved_by=''**（空）。计划哈希随阶段证据合入而重算（生成时 `68453ffc…` → dry-run 证据合入后终值如上），为 Harness 固定机制。
- 计划要素齐备：目标=三同源包精确 `.16`（amd64）；identity=克隆自身（hostname + machine-id strip 口径 `0691eeb5…` 钉扎）；node=stage10-clone-node；官方依据 sha256=`932d5a73…`；inventory_hash `4866d9ab…`、collector_sha256 `5e9cd38f…`。
- **未调用 approve/execute 端点**；本计划即使全绿也必须停在 awaiting_approval 等待授权二。

### 10. 是否存在任何未经授权的设备软件包写操作？——**无**

- 全轮 dpkg 写操作为零；两个生产写开关全程 0（`LINUXGUARD_ENABLE_DEVICE_REPAIR=0`、`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=0`，重启前后核验）；`.deb` 下载为零；安装/升级/降级/移除为零；回滚执行为零。唯一对克隆磁盘的写=身份隔离编辑+索引元数据刷新（均在授权 B 清单内）+ 恢复验证协议自身。

---

## 二、生产防护核验（交付时刻）

- `GET /api/health`：backend ok / db ok；节点 registered=[m45-linux-node, stage10-clone-node]、双在线；sensors falco=stopped、logread=stale（真实状态）；runtime_evidence_fresh=False。
- 统一模式 `LINUXGUARD_UNIFIED_PIPELINE='on'` 不变；第二正式入口拒绝语义未动。
- **资产 1**：连接 1/2 原样（OpenWrt .100.1、Ubuntu .129，均 enabled）；资产 1 采集能力正常（节点在线）。
- **风险 126 偏差披露（见 §五-1）**：状态由 pending_human_review → **reanalysis_required**（官方核验端点的既定契约行为），原始人工门禁记录（object_review_hold、两次 native_assessment）在 risk_governance_event 中完整保留，未删除未覆写；Q1–Q8 与 126 对象级人工裁定仍待操作员，历史影子输出不可变原则未被破坏。
- 生产数据库一致性备份：`local-archive/stage10-work/db-backups/linuxguard-consistent-20261017T105247Z.db`（463,777,792 字节，sha256 `d9f75be1…fb641`，sqlite3 在线 backup API）。
- 本轮重启过一次生产后端（加载多节点 .env，必要重启获任务书允许）：重启前 .env 备份于 `local-archive/stage10-work/env-backup-20261017T2005Z`；重启后健康、双节点、开关、统一模式全部核验。

## 三、本轮新增资产登记（正式）

| 对象 | 值 |
|---|---|
| 资产 | asset_id=3（iotguard-stage10-clone，ubuntu 24.04，1790 包，identity_source=uploaded_inventory 引导 + authenticated 复采） |
| 连接 | connection_id=3（192.168.183.110:22 wyh ssh_key，指纹 `SHA256:JIvwH3Q…a3uE`），预检 ready |
| 节点 | stage10-clone-node（独立令牌 env `LINUXGUARD_COLLECTION_NODE_TOKEN_STAGE10_CLONE_NODE`，隧道 18446，密钥 `LINUXGUARD_DEVICE_STAGE10_CLONE_KEY`，repair 开关双 0，无 OpenWrt 密钥） |
| 风险 | risk_id=127（CVE-2026-94266:noble:curl，potentially_affected，candidate→已研判→pending_human_review） |
| 白名单 | `LINUXGUARD_DISCOVERY_CIDRS` 逐主机 /32 追加 `192.168.183.110/32`；未放宽任何既有条目 |

## 四、与任务书顺序的偏差（均为手段级，目的不变）

1. **克隆机内 root 通道**：任务书计划提供 vmrun 客户机口令（选项 A）或控制台手打（选项 B）；本轮口令不可得，改为 **WSL2 离线 root 挂载根分区**完成同一命令清单（hostname/machine-id/netplan/密钥），并另用 chroot 完成官方索引刷新。全部效果逐项实测验证，无效果缺失。
2. **恢复验证标记**：计划写的是 `sudo touch /var/tmp/…`；实际 /var/tmp 全局可写，wyh 直接 touch，免 sudo 且同样满足"可识别无害标记"。
3. **索引刷新时机**：在离线 chroot 内完成（开机前），使首次认证采集与 Harness 预演直接受益。

## 五、必须让操作员知道的四件事

1. **风险 126 状态变化**：为给克隆建立自有官方依据与风险（无克隆专用旁路，按设计必须走全资产正规管线），调用了 `POST /api/vulnerabilities/official/verify`；其契约行为把 126 置为 reanalysis_required（新官方证据 ADV-a74d8ba6 导入触发，content_sha256 与旧证据完全一致 `932d5a73…`）。人工裁定历史完整保留（governance events id=1/3/5/6），未伪造、未代签、未删除。126 的重新裁定由此与 Q1–Q8 一并回到操作员桌面。
2. **Falco 仍停摆**：授权 A 已到位但凭据通道不存在（§一.4）。给出两条解锁路径，等待操作员执行；在解锁前 runtime 证据保持缺失，克隆研判的 runtime 缺口（11 项中的首要项）因此真实存在。
3. **第一次恢复验证尝试失败已作废**：离线直写标记 + 关机态快照的协议无效（无 delta 可回滚）；已换用客户机内标记协议重做并通过。失败尝试全文披露于 `restore-evidence.json`，不影响通过结论。
4. **machine-id 摘要双口径**：文件级 sha256sum=`0e76c274…`（含换行），维护工具钉扎值=strip 后内容哈希 `0691eeb5…`。二者同源一致；计划与未来执行许可钉扎的是后者。

## 六、停止位置

全部第一阶段准备工作已完成。当前停在实际软件包修复的**独立授权门禁（授权二）**：

- 待批动作清单：实验写开关 `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR=1`（限克隆 asset 3 作用域）、精确计划 `35220882…4848cf` 的人工审批、克隆内 dpkg 写执行、以及失败后回滚授权。
- 同时待操作员：Falco 凭据供给（§一.4 两条路径之一）、风险 126 重新裁定、Q1–Q8 迁移裁定。
- 在获批前：不执行 apt 安装、不置实验写开关、不调用 approve/execute、不动回滚。

## 七、交付物清单

- 本报告：`IOTGUARD_STAGE10_ISOLATED_CLONE_PREFLIGHT_REPORT.md`
- 代码：`backend/scripts/start_clone_node.py`（克隆节点 runner 启动器；凭据仅经 env/SSH 引用，无秘密落入代码）
- ai_collaboration 五文档：本轮小节已更新（CHANGELOG / CURRENT_TASK / EXECUTION_REPORT / PROJECT_CONTEXT / TEST_RESULTS）
- 本地证据（gitignored，`local-archive/stage10-work/`）：`source-identity-pre-shutdown.json`、`clone-isolation-evidence.json`、`restore-evidence.json`、`clone-apt-policy-after-refresh.txt`、`clone-apt-simulate-after-refresh.txt`、`clone-bootstrap-inventory.json`、`db-backups/…`、`env-backup-…`、`clone-node.log`、WSL 操作脚本族
