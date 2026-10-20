# IoTGuard 虚拟物联网设备最终验收报告

验收日期：2026-10-20（Asia/Shanghai）  
交付基线：`1c234b7bbd62aa0d1d799b7a577a9d157af21aaf`  
范围：现有 VMware OpenWrt 原机、OpenWrt-Lab 与 QEMU Zephyr；Ubuntu/Falco 仅作采集基础设施。

## 结论先行

1. **OpenWrt 核心实验已完成。** 真实证据对应 `reports/openwrt-focus-20261019/`、`reports/openwrt-intel-20261019/` 及历史闭环报告；原机与 Lab 独立身份、cgi-io 一次安装、verification-only resume、修复后复采与四智能体复评、S2→S1→S2 回滚和原始未修改证据均保留。未重复安装、回滚或创造历史结果。
2. **Zephyr 官方快照为 281 条，当前 125 条开放复核项。** 复核清单分类为 `potentially_affected` 54、`insufficient_data` 71；另有 156 条 `not_in_reported_range`。这不是“125 个漏洞”，也没有把缺失证据批量解释为安全。
3. **当前 QEMU Zephyr 固件没有真实确认的 affected 漏洞。** 54 条是候选、71 条证据不足；因此确认命中数为 0，不能表述为全部排除。
4. **四智能体可以消费 Zephyr 实际固件证据，但本轮没有把模型建议当作业务签收。** 复核项绑定公告、ELF 和 `.config` 哈希；正式模型结果仍需人审，缺口保持 `business_accepted=false`。
5. **Windows CI 已最终成功。** Run `39299728933`，Commit `1c234b7...`；Windows `817 passed, 3 skipped`，Linux 同为 `817 passed, 3 skipped`，前端生产构建和 Chromium 回归 26 项通过。Windows 作业开始 `2026-10-19T18:06:14Z`、结束 `2026-10-19T19:36:26Z`；Run 结束 `2026-10-19T19:36:26Z`。失败轮 `39288356646` 属前一提交的跨平台/配置问题，已由后续提交修复，不是当前交付缺陷。
6. **连续运行未达到 24 小时。** 最长稳定健康窗口为 599.84 秒（约 10 分钟，21/21 样本三传感器健康）；另有 297.87 秒、178.22 秒和 59.10 秒窗口。失败样本和恢复窗口均保留，不能宣称长期稳定或零丢失。
7. **生产写权限当前保持阻断。** 标准 Compose 三个写开关为 0，OpenWrt 资产未自动登记生产/实验域，`unassigned` 拒绝写入；旧明文演示凭据不再接受，节点令牌与资产/采集权限绑定。具体对象的人工签署仍未完成。
8. **本次只完成虚拟设备验收。** OpenWrt VMware 与 Zephyr QEMU 的结论不能外推到实体板；Zephyr 设备侧 OTA、安全启动、断电恢复和实体签名更新仍需后续硬件阶段。
9. **需要独立人工签署的对象**：OpenWrt CVE-2026-62948 的适用性、Zephyr 54 候选与 71 证据不足项、模型 pending-human-review 风险，以及任何生产修复计划。CVE-2026-62948 不因本轮自动关闭；历史 Mimosa coverage 仍为 `partial/inconclusive`。
10. **研发可冻结并进入竞赛交付，但须带边界交付。** 冻结对象是当前虚拟设备实现、证据和报告；不要把 24 小时运行、实体 OTA、完整扫描或人工接受写成已完成。

## Zephyr 固件身份与证据

当前可直接验证的构建身份来自本地忽略目录 `reports/delivery-20261020/`：

| 项目 | 结果 | 证据 |
|---|---|---|
| RTOS / 应用 | Zephyr RTOS 4.4.2 / `0.3.0-iotguard`（`0.1.0-stage7` 仅为 2026-10-18 历史身份记录，不与当前交付合并） | `zephyr-assessment.json`、QEMU 回归 |
| board / 架构 | `qemu_cortex_a9` / ARM | `zephyr-identity.json`、固件启动日志 |
| ELF SHA256 | `759bb5b6b00e412574cdd49782defa5916d79fcff7d82ccf53250112a34e4d2c` | `zephyr.elf` |
| `.config` SHA256 | `098a8da93749458425f5ef7b202a8345aa20ec4e91a1d0ada2741b365851eafb` | `zephyr.config` |
| 官方快照 SHA256 | `49097d000b68f0b54b842a3779d7037a50bbc4021fc10fbb6694315f351901b7` | `zephyr-snapshot.json` |
| 实际启用组件 | IPv4/IPv6、TCP、DHCP、HTTP socket、entropy；未启用 Bluetooth、IEEE 802.15.4、IPv6 fragment/PMTU 等 | `.config` 哈希绑定观察 |
| west / 源码 commit | **证据缺口**：公开仓库没有完整 west manifest、模块锁定修订或可复现源码 commit；启动日志只能证明运行时 banner | 不推测缺失配置 |

因此本报告只把 ELF、`.config`、板型、启动日志和 HTTP 身份作为已证据；没有把 Zephyr 版本 banner 推导成全部模块启用。

## 125 条公告适用性核验

公告统计口径为：官方 Zephyr 仓库快照 281 条原始记录；在去重/规范化后仍按 GHSA 记录保存，当前开放复核队列为 125 条。快照来源为 `zephyrproject-rtos/zephyr` 官方安全公告接口，原文与规范化摘要保留哈希；当前快照未发现撤销记录，重复/更新关系由公告 ID 和快照时间保留。公告中结构化影响范围不足的记录进入 `insufficient_data`，不自动转为安全。

筛选顺序是产品/仓库归属 → 官方版本范围 → 实际组件 → Kconfig/运行条件 → 修复或回移补丁 → 设备级证据。结果如下：

| 分类 | 数量 | 含义 |
|---|---:|---|
| `affected` | 0 | 没有足够证据确认当前固件受影响 |
| `fixed` | 0（在 125 开放队列中） | 当前队列没有足够修复证据可直接闭合 |
| `not_affected` | 156 | 不在官方报告版本范围；不是全部 281 条的安全结论 |
| `potentially_affected` | 54 | 版本/产品方向相关，但组件、配置、链接或可达性仍需证据 |
| `insufficient_data` | 71 | 官方影响结构或固件组成证据不足 |

`zephyr-applicability-review.json` 的 `open_count=125`，每项均保留 `official_sha256`、ELF/config 哈希、配置观察和四类补证要求：组件/修订、必要配置、链接代码/补丁来源、可达触发路径。该文件明确 `configuration_exclusion_is_proven=false`。

## 运行与恢复

- **OpenWrt**：原机和 Lab 独立在线，近期 logread 新证据回传，指纹去重、资产/节点身份隔离和风险不串号均沿用既有证据。cgi-io 安装次数仍为一次；Harness verification-only resume 与 S2→S1→S2 证据不重跑。
- **Zephyr**：QEMU 实际运行，身份/固件版本/遥测入库；重启前后 HTTP 回归通过，既有签名更新/失败回退测试通过。温湿度为模拟值，熵依赖受信任 QEMU 宿主。
- **Falco/Ubuntu**：辅助监控线已恢复，后端、采集节点、三传感器健康和证据新鲜度分别有健康记录；Falco 丢失计数为 unavailable，不写成 0。运行时窗口最长约 600 秒，不覆盖宿主重启、长期丢失或所有事件类型。

## 治理、边界与人工操作

机器验证、模型建议、代理执行和人工签署保持分离。生产设备写开关、OpenWrt-Lab 写开关和 Ubuntu-Lab 写开关均由标准部署关闭；资产 `repair_domain` 默认 `unassigned`，生产与实验域一次登记、不可由 IP/主机名/清单改写，安装和回退均重新核验。演示目标只保存凭据环境变量引用，旧明文行阻止运行。没有未经授权的自动审批或风险接受。

OpenWrt CVE-2026-62948 的 LuCI/odhcpd 触发链仍未闭合；不能因为 cgi-io 已修复而代替该判断。历史 Mimosa 仅为 partial/inconclusive。签名 QEMU 测试不等同于实体设备签名 OTA 验收。

## 可复核交付

- CI：<https://github.com/su12s-ops/IoTGuard-Public/actions/runs/39299728933>
- 当前提交：`1c234b7bbd62aa0d1d799b7a577a9d157af21aaf`
- Docker：本机 `docker compose config` 通过，`docker compose build --no-cache` 成功构建 backend/frontend；前端构建保留依赖的 PURE 注释警告，不影响成功状态。
- 原始日志、数据库、固件、私钥和运行证据继续位于 gitignored `reports/`、`local-archive/` 等目录，不提交到公开仓库。
