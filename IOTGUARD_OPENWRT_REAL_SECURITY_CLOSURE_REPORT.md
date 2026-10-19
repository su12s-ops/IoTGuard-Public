# IoTGuard OpenWrt 真实安全闭环一体化执行报告

- 执行窗口：2026-10-19（本地 UTC+8，约 10:30–14:30）
- 代码基线：main `1ff170a` + 本轮工作区变更（含上一轮 OpenWrt 情报接入成果，未回退）
- 唯一仓库：`E:\IoTGuard-Public`；原始证据目录：`reports/openwrt-closure-20261019/`（gitignored）
- 实验材料目录：`local-archive/openwrt-closure-materials/`（gitignored，含镜像/apk/密钥/清单）
- 回归：后端全量 **761 passed / 0 failed**（含本轮新增 5 项作用域契约测试）；前端构建通过；`docker compose config` 校验通过；变更文件敏感扫描 0 命中

## 0. 结论速览

| 阶段 | 状态 | 关键证据 |
|---|---|---|
| 第二部分 原始 OpenWrt-01 基线封存 | ✅ 完成 | 设备/包/服务/logread/匹配/风险/VM 身份九类快照+SHA256（`baseline-openwrt01/`） |
| 第三部分 实验 CVE 选型 | ✅ 完成 | **CVE-2026-62947**（cgi-io）；62948 在线重核无修复无冲突，不选用；验收标准冻结（`EXPERIMENT-DESIGN-FROZEN.md`） |
| 第四部分 OpenWrt-Lab 克隆与 S0 | ✅ 完成 | 冻结基盘复制（原机未关机）；联网前离线身份隔离；S0-CLEAN 快照+无害标记真实恢复测试通过 |
| 第五部分 产品内自动发现与接入 | ✅ 完成 | 发现→建档 asset 4→连接 4（独立密钥）→节点真实采集 182 包→匹配=原机基线→独立风险 146/147，零串号 |
| 第六部分 受影响态准备（S1） | ⛔ **pending_authorization A** | 申请包已固化（计划 SHA256 `384575c3…9953cf8`）；用户未应答授权问询，按任务书 §1.3 暂停设备写入 |
| 第七部分 受影响态检测+四智能体 | ⏸ 依赖 S1 | 原机侧四智能体链路已在风险 128 上验证过（上轮） |
| 第八部分 Harness 修复 | ⏸ 依赖 S1+授权 B | 产物/清单/检查脚本/作用域契约全部就绪；未授权态 fail-closed 已实证（blocked + 409） |
| 第九部分 复采+复评 | ⏸ 依赖修复执行 | — |
| 第十部分 快照回滚实验 | ⏸ 依赖授权 C | 回滚机制本身已在 S0 恢复测试中真实验证 |
| 第十一部分 全链路对照 | ◐ 非门禁项已验 | 门禁相关行待 S1 后补 |
| 第十二部分 交付 | ✅ 本报告+回归+文档+提交 | — |

**核心诚实声明**：任务书要求"任何阻断都必须如实报告，不得为了实现全部完成而伪造"。本轮在授权 A 门禁处真实停下：**未对任何设备执行写入**（Lab 仍处于 S0-CLEAN 基线态，原机零触碰），三项授权（A/B/C）均未签署，等待用户对已固化申请包的明确批准。

## 1. 设备与克隆架构（现状）

```
宿主 Windows（后端 8000 + 采集隧道 watcher + WSL2 离线盘改工具链）
├─ VMware VMnet8 (NAT 192.168.183.0/24)
│   ├─ Ubuntu 平台机/采集节点 m45-linux-node（ens33 .129）
│   │    + ens37 → VMnet2（到达原机 LAN）
│   │    + ens39 → VMnet1（本轮新增，到达 Lab LAN）
│   └─ OpenWrt-01 WAN 侧（原机 eth1，.134）
├─ VMnet2 (host-only 192.168.100.0/24) — 原机 LAN（br-lan .1）
└─ VMnet1 (host-only 192.168.206.0/24) — 本轮启用为 Lab 隔离 LAN
    └─ OpenWrt-Lab（br-lan .2，独立 dnsmasq 池 .50–.59）
        LAN NIC 00:50:56:3A:B0:01 / WAN NIC 00:50:56:3A:B0:02(NAT .135)

数据库资产：asset 1 Ubuntu 节点机 / asset 2 OpenWrt-01（原机，对照）/ asset 3 stage10 克隆 / asset 4 OpenWrt-Lab（本轮）
连接：conn 1 原机（原密钥+原主机钥钉扎）/ conn 4 Lab（LINUXGUARD_DEVICE_OPENWRT_LAB_KEY+新主机钥钉扎）
```

## 2. 第二部分：原始设备基线（已封存）

- 设备事实（SSH 只读实测）：OpenWrt 25.12.6 r33311-981c978eff / x86/64 / 内核 6.12.112 / 182 包（166 x86_64 + 16 noarch）；服务 dnsmasq:53、uhttpd:80/443、dropbear:22 正常；logread 活跃。
- 数据库快照+SHA256：asset2、逐包清单、服务、5 条匹配（fixed 1 / not_affected 2 / affected 2）、风险 128（pending_human_review，置信 0.55）与 129（candidate）、13 条 OpenWrtAdvisory、治理事件、四智能体 run 记录、VM 身份（VMX 路径/MAC/磁盘链/快照名）。
- **CVE-2026-62948 冲突核对**（在线 9 条公告全量重取，`ghsa-live-20261019.json`）：官方范围仍为 `main`，`first_patched_version` 仍为空 → 无修复版本、无证据冲突；现有分支域判定维持，不需要纠错。
- 原机本轮全程零写入；采集节点与 logread 传感器持续在线（一次后端重启造成的 running 任务卡滞由既有 900s 超时契约自愈，如实留痕）。

## 3. 第三部分：实验选型（冻结）

选定 **CVE-2026-62947 / GHSA-jw5r-xhf5-2xcq**（cgi-io ACL bypass + arbitrary root file read，medium）：

| 证据 | 值 | 核验方式 |
|---|---|---|
| 官方受影响范围 | `<= 25.12.4 (cgi-io HEAD 658b14b)` | 在线抓取官方公告 |
| 受影响固件 | 官方 25.12.4 x86/64 ext4-combined，SHA256 `9d080bca…619695` | 官方 sha256sums 校验 OK |
| 受影响组件版本 | `cgi-io 2025.12.11~658b14bd-r1`（镜像内 APK DB 实测，源码位=公告注记 658b14b） | 镜像字节级检索 |
| 修复版本 | `cgi-io 2026.07.21~31cb3c89-r1`，官方 .apk SHA256 `78960f33…f946f` | 官方仓库直下；25.12.4/25.12.6 双仓库字节级一致 |
| 对照组现状 | 原机 25.12.6 已装修复版 → 通用匹配 not_affected | 本轮实测 |

- 选型理由：受影响态=**完整官方旧版发行环境**（非混合组件）；修复=官方应用级 .apk（cgi-io 不在 Harness 封禁清单）；x86/64 兼容；快照可恢复。
- 62948 不作修复对象（无官方修复版本）；62526（ubusd）为备选但核心守护进程修复风险更高，未选用。
- **检测器冻结**：`openwrt_intel.py` / `match_openwrt` 本轮零修改；预期验收矩阵先行写入 `EXPERIMENT-DESIGN-FROZEN.md`（含各 CVE 在 25.12.4 上的预期四态）。

## 4. 第四部分：克隆与身份隔离

- **克隆方式**：原机已有快照 `iotguard-25.12.6-verified-20261018`，其基盘（CID bda27580，冻结只读）被字节复制为 Lab 基盘 → **原机全程无需关机**（任务书 §1.2 关机窗口授权因此不需要触发）。基盘经 `vmware-vdiskmanager` 转为 flat 后作为 Lab 磁盘。
- **身份隔离（首次联网前完成）**：串口控制台无 getty（实测），改用 **WSL2 loop 挂载 ext4 离线盘改**：
  - hostname `OpenWrt` → `OpenWrt-Lab`（DHCP client-hostname 实证）
  - dropbear 主机密钥删除 → 重启再生：新指纹 `SHA256:+ptdJBs…` ≠ 原机钉扎 `SHA256:+CaFHIb…`
  - VMX 静态新 MAC（00:50:56:3A:B0:01/02）、独立 UUID
  - br-lan `192.168.100.1` → `192.168.206.2`（独立管理网段 VMnet1，无其他 VM；dnsmasq 池 .50–.59 与 VMware DHCP 池不相交）
  - 审计标记 `/etc/iotguard-lab-identity.txt` 全程留痕
- **S0-CLEAN 快照 + 真实恢复测试**：快照后写入 /tmp 标记 → `vmrun revertToSnapshot` → 设备重启后标记消失、主机密钥/hostname/182 包/cgi-io 版本全部与快照前一致、原机无影响（`part4-clone-and-S0-evidence.json`）。注：revert 后 VM 处关机态，需 `vmrun start` 拉起（VMware 行为差异，如实记录）。

## 5. 第五部分：产品内接入（正式业务入口）

| 步骤 | 入口 | 结果 |
|---|---|---|
| 发现 | `POST /api/iot/discovery`（192.168.206.2/32，enroll） | 新设备 DEV-3B7036022B91；banner 无版本证据 → `insufficient_evidence`（如实） |
| 建档 | 操作员钉扎 SSH 只读采集（固定脚本 stdin）→ `POST /api/assets/upload` | asset 4 `OpenWrt-Lab-0050563ab001`，182 包，inventory_complete |
| 连接 | `POST /api/iot/connections` | conn 4，密钥引用 `LINUXGUARD_DEVICE_OPENWRT_LAB_KEY`，主机钥钉扎新指纹 |
| 凭据独立 | 节点新生成 lab 专用密钥对；Lab authorized_keys 仅含该公钥 | 原采集密钥实测被拒（Permission denied） |
| 采集 | `POST collection-runs` + execute → queued_remote → m45-linux-node 执行 | run `10a5bcb4…` completed，182 包，证据 `INV-10a5bcb4…` |
| 匹配 | `POST /api/matching/run` | 与原机基线**完全一致**：5 候选=1 fixed(ubusd)+2 not_affected(procd/cgi-io)+2 affected(62948 分支域 luci/odhcpd)；absent 5 组件独立统计 |
| 风险 | `POST /api/risk/calculate` | 独立候选风险 146/147（62948），与原机 128/129 完全分离 |
| logread | `.env` 增 conn 4 → 双传感器 | openwrt-logread-1（原机）与 openwrt-logread-4（Lab）均在报 |

串号检查：原机 asset 2 匹配行、连接 1、风险 128/129 在整个接入过程前后无变化；Lab 全链路使用独立资产/连接/密钥引用/主机钥。

## 6. 第八部分前置：修复契约与材料（已就绪、未执行）

- **独立作用域写契约**（本轮最小权限修改，模式对齐既有 `LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR`）：
  `openwrt_lab_write_state(asset_id)` = `LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR=1` **且** asset_id 精确出现在 `LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE`，否则一律拒绝；**不读取**生产总开关 `LINUXGUARD_ENABLE_DEVICE_REPAIR`（互不可替代，双向隔离，空值 fail-closed）。5 项新测试覆盖四种拒绝路径+生产开关不越权路径。
  生产开关本轮全程保持 `0`。
- **修复产物清单**（`local-archive/openwrt-closure-materials/repair-manifest.json`，当前未挂载到后端 env）：
  - 修复产物：官方 `cgi-io-2026.07.21~31cb3c89-r1.apk`（SHA256 `78960f33…`，官方双源比对）
  - 回滚产物：`cgi-io-2025.12.11~658b14bd-r1-labrebuild.apk`（SHA256 `1b9b2e66…`）——**实验室重建产物**：在线仓库已全部刷新为修复版、无官方受影响版独立文件，故从官方 25.12.4 镜像内字节级提取官方二进制与符号链接，用 apk-tools 3.0.8 static 以镜像自带元数据重建容器；构建脚本与来源哈希留档，明确不冒充官方发布
  - 检查脚本：`check_regression_cgi_io.py`（读后端已认证采集的版本+新鲜度）、`check_business_cgi_io.py`（LuCI HTTP + DNS 存活；目标限定冻结网段 IP 字面量、钉死协议、禁重定向——Mimosa SSRF 约束落地）；两脚本对当前 Lab 实测行为符合设计（业务检查通过且拒绝原机 IP；回归检查在新鲜采集后通过）
- **未授权态 fail-closed 实证**：对 Lab 风险 146 创建修复任务 → `blocked`（理由：风险尚未通过现有审核策略+产物未登记）；执行尝试 → HTTP 409 未批准。
- **待授权后解决的已知不确定点**（如实预告）：OpenWrt apk v3 对本地 .apk 安装的信任语义（官方包本身不带包级签名，仓库级索引签名不适用于离线安装）。若设备要求信任锚，方案为生成实验室签名密钥、对两产物签名、并把实验室公钥加入 **Lab 仅** `/etc/apk/keys/`（已列入授权 A 申请的执行细节）；绝不使用 `--allow-untrusted`（任务书 §8 禁止禁用签名）。

## 7. 三项授权申请（等待用户批复）

| 授权 | 对象 | 计划哈希 | 状态 |
|---|---|---|---|
| A 受影响态准备 | OpenWrt-Lab（asset 4）sysupgrade→官方 25.12.4（保配置）+ 签名信任锚 + 实验室回滚产物登记 → S1-AFFECTED 快照 | `384575c3b6b07f5861c25870b87952afe217fad936879283cda2cc09d9953cf8`（`authorization-A-request.json`） | **已提交未批复**（本轮问询无应答，未自签） |
| B Harness 真实修复 | 待 S1 后以实际 asset/match/计划哈希固化（人审确认+计划 SHA256+产物 SHA256 绑定） | 届时生成 | 未提交 |
| C 快照回滚+最终恢复 | S2-FIXED→S1-AFFECTED→再恢复 | 届时生成 | 未提交 |

## 8. 第十一部分：已完成的对照验证

| 项 | 结果 |
|---|---|
| 原始 OpenWrt-01 保持基线 | ✅ 版本/身份/182 包/匹配 5 判定全程不变；采集与 logread 在线 |
| Lab S0 独立资产与正确匹配 | ✅ 匹配与原机一致且行归属 asset 4；风险独立编号 |
| 新增公告零专用代码 | ✅ 上轮已实证（公告表 0→13 行后匹配即时产出）；本轮 Lab 复用同一规则集得到一致结果 |
| 同一 CVE 多组件不重复计为多 CVE | ✅ 62948 的 luci+odhcpd 各一条风险行但共享同一 cve_id；候选发现层对别名扩展只取代表包，不重复告警 |
| 数据库审计不随 VM 快照消失 | ✅ 结构性保证：DB 在宿主 `backend/data/`，VM 快照不触及；S0 恢复测试期间风险/治理记录连续可查 |
| 设备身份/采集任务不串号 | ✅ 见 §5 串号检查 |
| 断线/失败/日志过期如实展示 | ✅ 实例：后端重启致 conn1 任务卡滞→传感器如实 stale→900s 契约自愈；Falco stale（Ubuntu VM 重启后需 sudo 口令，历史门禁）如实展示未掩盖 |
| 四智能体失败不掩盖 | ✅ 风险 128 留存 `review_failed_agents=[runtime_analyst, vulnerability_analyst]` 真实降级记录（上轮） |
| 受影响/修复/回滚/最终恢复四态 | ⏸ 待授权 A/B/C 后执行 |
| 其他 CVE 不产生错误活跃风险 | ✅ S0 实测：mdnsd/jsonpath/ead/ltq-ptm 未安装仅入 absent 统计；procd/ubusd 判定与官方范围一致 |
| 实验临时写许可撤销 | 契约默认即拒绝（env 未设置=全禁）；授权 B 批复后执行期间才显式开启，完成即撤 |

## 9. 尚未关闭的边界

1. **授权 A/B/C 未批复** → S1 受影响态、四智能体受影响态研判、真实修复、复评、快照回滚实验均未发生；本报告不含任何对应"结果"。
2. OpenWrt apk 本地安装信任语义待设备端实测（§6 已列方案；不排除需把签名信任锚写入 Lab `/etc/apk/keys/`，属授权 A 范围）。
3. Falco 传感器因 Ubuntu VM 重启后 sudo 口令门禁未恢复（历史已知），Ubuntu 资产运行时通道如实降级展示。
4. 62948 仍无官方修复：等官方发布后重同步即自动复评（现有机制）。
5. 快照回滚实验要求的外部审计连续性已由结构保证，但"回滚后风险判定随设备事实回退"的端到端演示依赖授权 C。

## 10. 文档与提交

- 本报告；`docs/STATUS.md`、`docs/VALIDATION.md`、`README.md`、`TECHNICAL_ARCHITECTURE.md`、`DEPLOYMENT.md` 同步更新。
- ai_collaboration 五件套已于上一轮文档整理（`1ff170a`）中按当时决定移除并入 docs/，本轮沿用该结构不复活，相应状态并入 `docs/STATUS.md`。
- 回归 761/0；前端构建通过；compose 校验通过；敏感扫描 0 命中；本地材料（密钥/镜像/apk/清单）全部留在 gitignored 目录。
