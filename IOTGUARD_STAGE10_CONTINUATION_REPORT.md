> 历史记录（第四轮，2026-10-17）：当前状态见 [第五轮完成记录](IOTGUARD_STAGE10_COMPLETION_REPORT.md)。下文“尚未执行/待启动”为当时事实，现已完成克隆修复与Falco恢复。

# Stage 10 第四轮：人工确认、独立实验环境与执行权限验收

日期：2026-10-17（Asia/Shanghai）。起始提交 `76eac0b`。

本报告承接第三轮；第三轮“预检全绿”只证明当时的软件包和依赖检查通过，不能证明执行节点具有安装权限。当前真实修复尚未执行。

## 已完成

- 用户在本次会话对风险 127 确认受影响及在隔离克隆升级三个 curl 同源包的询问回复“可以的”。通过正式 human-review API 记录 `human_confirmed`，审计 actor 为 `operator:29504 (current chat authorization)`，理由明确来源于本次对话；没有编造实名签署。风险最终分数 27.46 / Low，建议 scheduled_fix。
- 旧计划 `1edbaaf593b14b70a4450868799e1e7e` 已通过正式 API 取消。人工确认改变 review hash，维护脚本也已更新，旧计划不能继续沿用。取消保留全部历史预演和审计。
- 生产数据库只读在线一致性备份：`local-archive/stage10-continuation/before-20261017T132233Z.db`，SHA256 `1d685c2afc63a86fc73592e32bed87da4d5649b5ec4e7c8bccf1e79213621e0b`。
- OpenWrt 正式只读补采入库 **98 条新日志**，1093 条幂等去重，Trace `TR-20261017132252-72faec`。日志实际事件时间仍可能过期，不据此伪称运行时证据新鲜。
- 风险 126 通过唯一正式入口重新研判：`UA-ada3c8644aab-126`，已完成，四角色有效、零降级；`confirmed_affected / pending_human_review`，保留人工门禁。

## 执行权限缺口的修复与真实复现

源机与克隆 SSH 用户实际 UID 均为 1000，`sudo -n true` 均失败。用户/机器/当前进程均没有 SSH_PASS 或 VM_PASS；用户明确表示暂时无法操作克隆控制台。

- 固定维护工具预演增加真实 UID 与 `package_ready`；没有 root 权限时 `ready=false`、issues 包含 `root_execution_node_required`。
- 后端接收预演、执行排队和节点领取均拒绝缺失、非 root 或格式错误的权限证明；旧记录不能因缺少字段而获得执行权限。节点执行时仍核对当前实际 UID，并在任何检查或下载前拒绝非 root。
- 前端分别显示软件包检查与管理员权限，并给出可操作的阻断原因。
- 克隆 SSH 私钥原本继承普通用户组读权限，导致 Windows OpenSSH 拒绝使用。已收紧为当前账号、SYSTEM 与 Administrators；旧 ACL 留本地备份，SSH 实测恢复。

## 独立实验环境

使用 `backend/scripts/start_stage10_lab.py` 已实际准备并启动：

| 项目 | 实际配置 |
|---|---|
| 后端 | `127.0.0.1:18001`，独立进程；禁止加载生产 .env |
| 数据库 | `local-archive/stage10-continuation/lab/lab.db`，在线备份建立的独立副本 |
| 连接范围 | 副本仅连接 3 启用，地址白名单仅 `192.168.183.110/32` |
| 节点 | `stage10-lab-clone-node`，仅绑定资产 3，独立新令牌 |
| 隧道 | 18447 → 实验后端 18001，与生产 18445/18446 分离 |
| 凭据 | 独立控制令牌、节点令牌、许可路径；本地 backend.env 限当前账号/SYSTEM/Administrators 读取 |
| 后端写开关 | DEVICE=0、LAB=0；生产 .env 未用于实验开写 |
| root 节点 | 固定脚本已发布至克隆；未启动，需操作员管理员通道 |

真实普通用户节点只读预演 `c35b28cf696749ecb9305e3d7e675e0f` 已完成：

- `package_ready=true`、`execution_context.effective_uid=1000`、`ready=false`。
- **唯一问题为 `root_execution_node_required`**，软件包来源、目标与依赖范围检查通过。
- 状态 `preflight_failed`；审批与执行两个 API 实测均返回 **409**；无写派发。
- 原始证据、哈希与拒绝响应位于 `local-archive/stage10-continuation/lab/`。

克隆控制台需要的命令（本轮未执行，用户明确暂时无法操作）：

```bash
sudo python3 /home/wyh/.local/share/iotguard-stage10-lab/node.py --serve --interval 3
```

该脚本仅连接独立实验后端，root 启动后仍需重新预演、精确审批、资产/机器/计划绑定许可及短时写开关。当前没有生成许可文件，也没有下载或安装 .deb。

## 验收记录

- Ubuntu 适配器与多节点专项：**54 passed**。
- 前端生产构建：通过。
- 前端 E2E：**23 passed**，包含普通用户节点阻止审批/执行及已取消计划不显示待审批的页面场景。
- 后端全量回归：**698 passed / 0 failed**（486.82s），5 个既有 datetime.utcnow 弃用警告。
- 风险 126：**completed**，13:22:53→14:05:23 UTC，约 **42m30s**；**21 次 LLM 调用 / 356,370 tokens**（211,620 prompt + 144,750 completion），一轮真实补查及再次决策，全部阶段成功、零降级。最终 `pending_human_review / confirmed_affected / human_review_required=1`；模型未代签。
- Falco：本轮检查仍为 inactive；用户表示会在源 Ubuntu 控制台启动，尚未收到完成通知。

## 生产部署与凭据轮换

- 在一次历史身份归档读取中，工具输出曾包含克隆节点令牌；已删除身份清单中的明文令牌字段，改留配置引用，并完成令牌轮换。没有在本报告或代码中复制该值。
- 等正式研判与 Harness 全部排空后，在线备份 `before-restart-20261017T140547Z.db`，integrity_check=ok，SHA256 `c4d8330a2bc0370d65bbe46f25d71ca49ae77e3b9aba6119de9c16e259dd98ec`。
- 生产后端一次重启：PID 38492→38076；克隆 SSH Runner 重新启动，主节点自行恢复。生产 .env 与凭据备份均限制当前账号、SYSTEM 与 Administrators 读取。
- 旧克隆令牌实测 **401**；新令牌经正式节点完成新的真实只读预演 `936214b307e74b57847da9fea476b319`，`package_ready=true / effective_uid=1000 / ready=false / issues=[root_execution_node_required]`。状态 `preflight_failed`，证明新代码已在生产进程生效且认证链恢复。
- 最终 `/api/health`：后端/数据库正常，m45 与 clone 两节点均在线；Falco stopped、logread stale、运行时证据过期，未伪称恢复。源机 `systemctl show` 独立复核 Falco inactive/dead、MainPID=0。
- 最终 `/api/unified/specs`：mode=on、formal_writer=unified、生产 DEVICE=0/LAB=0。风险126仍待人工，127仍 human_confirmed；运行中研判/远程 Harness 均为 0。
- 独立实验后端仍运行于 18001，实验后端写开关保持双0；专属 root 节点未启动。没有生成执行许可、没有 .deb 下载、没有 dpkg 写、没有回滚。

## 停止边界与下一步

本轮还发现一项独立运行限制：风险 126 首轮决策耗时 1,069,650ms（约 17m50s），超过配置的单角色 900s 协作预算。现有检查主要发生在工具轮次之间，底层 HTTP 请求、SDK 重试及证据校验重试可使实际墙钟时间继续延长；该时限缺口本轮未修复。首轮决策另提出 database 与 inventory 两类补查，触发一轮真实补查及再次决策。因此不能用风险 12 的历史效率对照替代本次风险 126 的最终表现，也不能把全量功能回归通过解释为时限约束通过。

本轮模型未代替用户确认风险 126、未签署 Q1–Q8、未执行包安装或回滚。风险 127 确认仅依据本会话用户答复。真实修复当前唯一新增必需条件为克隆的 root 执行通道；恢复后必须重新预演，不能使用已过期或已取消计划。

后续固定顺序：root 节点真实上线 → 重新预演并生成最终计划哈希 → 后端与克隆独立许可 → 仅实验后端短时 LAB=1 → Harness 审批与执行 → 自动复采/官方重取/复评 → 实验 LAB 归 0、许可撤销 → 人工验收。生产两个写开关保持 0。
