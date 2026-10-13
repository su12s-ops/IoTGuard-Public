# IoTGuard 自主联调执行记录（受认证阻塞，尚未完成真实验收）

日期：2026-10-13。工作副本：`E:\IoTGuard-Project`。

用户本轮自主执行授权已生效，不再按常规步骤反复请求批准。本轮已实际尝试 Windows → Ubuntu SSH，并重新完成 Windows 完整资产离线导入验收、后端回归、前端浏览器回归和构建。**Windows 到 Ubuntu 登录认证失败，未进入远端部署、真实 OpenWrt 采集和第五阶段 CVE 适用性验证。** 这是凭据/登录配置阻塞，不是等待部署授权。

## 1. 阶段状态

| 阶段 | 本轮实际结果 | 尚缺证据 |
| --- | --- | --- |
| A：部署 | 指定历史地址的 SSH 服务可达，严格主机密钥检查未报错；<ubuntu-user> 登录认证失败。Windows 前端测试与构建通过 | Ubuntu 当前地址、节点身份、部署源码/依赖、后端进程、隧道、真实 API 健康与 collection_only 限制 |
| B：资产导入 | Windows 完整 JSON 与原 SHA 基线一致；原有上传 API 在新临时 SQLite 中重复导入通过 | Ubuntu session-001 实际数据库导入、当前 Ubuntu 原文件及外部 integrity 原文件复核 |
| C：真实采集 | 未执行；没有真实 OpenWrt 任务 ID、认证记录或采集时间 | 首次及第二次只读采集、实际 MAC、182 包逐项对比、稳定资产关联和失败恢复 |
| D：CVE 适用性 | 只检查现有代码路径，未运行候选匹配或导入厂商公告 | 阶段 C 验收后，核对真实快照对应的 OpenWrt 官方公告、完整 APK 版本、补丁回移及适用性证据 |

用户报告 Ubuntu 的 103 项指定隔离测试及本地检查已通过；由于本轮未登录 Ubuntu，这两项保留为用户提供的先前结果，不能记作本代理已复核的远端实验。

## 2. SSH 尝试与身份边界

仅尝试已明确提供的 `<ubuntu-user>@<ubuntu-nat-ip>`，未扫描地址段，也未试探其他设备或账号。Windows VMnet8 接口本轮查询为 `<windows-vmnet8-ip>`。

- Windows 系统 OpenSSH 使用 `BatchMode=yes`、`StrictHostKeyChecking=yes`、单次连接、8 秒连接超时及指定现有 Windows 密钥引用。
- 服务返回 `Permission denied (publickey,password).`，进程退出码为 1。
- 现有 known_hosts 校验未报错，但未取得远端账号会话，不能据此宣称已验证 Ubuntu 操作系统、当前网卡地址或部署目录。
- 查询 SSH agent 返回未提供服务；当前没有可用 agent 身份。
- 没有自动接受未知主机密钥，没有读取/输出密钥内容，没有改用密码文件，也没有从 Ubuntu 复制 OpenWrt 私钥。
- 没有建立隧道，没有启动、停止或修改远端进程，没有访问 Ubuntu 或历史实验数据库，没有尝试 OpenWrt SSH。

脱敏证据见 `reports/integration-20261013/ssh-access-status.json`。其中 recorded_at 是保存证据的时间，不能作为未单独捕获的 SSH 开始/结束时间。

继续所必需的信息仅为：确认当前 Ubuntu SSH 地址、用户名，并在本地提供可用登录机制，例如授权 Windows 现有公钥或配置 SSH agent。无需把密码、私钥、口令或平台令牌发送到聊天。获得可用连接后，本轮授权足以继续 A → B → C → D，无需再次逐步批准。

## 3. 完整 JSON 和隔离数据库真实执行结果

执行原有 `backend/scripts/verify_openwrt_inventory_import.py`，输入为 Windows 完整 `asset_inventory.json`，不是脱敏样本，也不是合成数据。

| 检查 | 实测 |
| --- | --- |
| 文件字节数 | 63083 |
| SHA-256 | da80bf3c8393668e747fa10c9a507b3eda5c85e3b2b4065f4c81b164dbbdc40e |
| 与第三阶段基线一致 | 是 |
| JSON Schema / Pydantic 校验 | 通过，schema_version=1.0 |
| 文件声明的固件 | OpenWrt 25.12.5，r33051-f5dae5ece4，x86/64 |
| 原始 / 声明解析 / 数组长度 / 导入解析数量 | 182 / 182 / 182 / 182 |
| 解析错误 | 0 |
| raw 与名称、完整版本、架构、来源、许可证、installed 状态逐项一致 | 182/182 |
| 架构 | x86_64 166，noarch 16 |
| 非空来源 / 不同来源数 | 182 / 70 |
| 原始许可证为空 | 3；原样保留，不补造 |
| 导入前资产 / 包 | 0 / 0 |
| 首次导入后资产 / 包 | 1 / 182 |
| 重复导入后资产 / 包 | 1 / 182，资产 ID 保持一致 |
| API 回读及另建数据库引擎回读 | 通过 |
| 外键检查 | 通过 |
| 软件完整版本、来源和时间保留 | 通过 |

本次临时库：`C:\Users\<user>\AppData\Local\Temp\iotguard-stage3-n3hsybh0\acceptance.sqlite3`。脚本审计钩子将 SQLite 连接限制到该新文件，并阻断实际网络和外部进程；原实验数据库不在访问范围。该库中的 ID 1 仅是本次临时库编号，不能用于 Ubuntu 的连接登记。

导入后连接、漏洞情报、OpenWrt 公告、匹配及运行时事件均为 0，因为本轮没有创建这些记录；这不表示检测出零漏洞。文件没有 MAC，平台 SSH 身份仍未验证，外部 integrity 哈希仍只有声明，缺少 Ubuntu 原文件的复核。

完整结果：`reports/integration-20261013/windows-offline-import.json`。未复制完整档案到报告，也未进行 Git 提交。数据库内的真实资产数据保留在独立临时目录。

## 4. 本轮实际测试命令与结果

均在 `E:\IoTGuard-Project` 执行。

```powershell
python -B backend/scripts/verify_openwrt_inventory_import.py asset_inventory.json
python -B -m pytest -q --tb=short -p no:cacheprovider backend/tests --ignore=backend/tests/test_iot_device_upgrade.py --ignore=backend/tests/test_scan_runs.py --ignore=backend/tests/test_scan_targets.py --ignore=backend/tests/test_mqtt_remediation_workflow.py
node frontend/scripts/verify_stage4.mjs e2e
node frontend/scripts/verify_stage4.mjs build
```

- 完整真实档案离线导入验收：PASS。
- 后端：**298 passed in 125.22s**，涵盖 Linux 兼容性、导入、匹配、风险和第四阶段模拟 SSH 回归。明确排除上述四个真实协议/扫描/MQTT 操作相关测试文件，不能称为全项目全部测试通过。
- 前端：**20 passed (16.9s)**；API 全部为明确的模拟 fixtures，不连接真实设备。故意触发的 400/422 错误是验证拒绝行为的测试，最终没有失败测试。
- 前端构建：PASS，2232 个模块。产物在 `C:\Users\<user>\AppData\Local\Temp\iotguard-stage4-frontend-YVgADw\build`，没有覆盖生产 dist。依赖 PURE 注释及颜色设置存在非阻断警告。
- 浏览器测试产物：`C:\Users\<user>\AppData\Local\Temp\iotguard-stage4-frontend-yYwlRN`。不能用这些模拟页面截图证明真实采集。

本轮日志保存在 `reports/integration-20261013/` 下的 backend-regression.log、frontend-regression.log 和 frontend-build.log。构建标准错误中的警告由工具输出记录，文本日志主要保存标准输出。

## 5. 文件改动

本轮没有修改业务源码或测试代码；没有故障证据要求重构现有功能。实际文件变化为：

- `IOT_STAGE4_DEVICE_CHECKLIST.md`：反映本轮自主执行授权；推荐 Ubuntu 回环后端 + Windows 回环 SSH 隧道；替换旧逐步等待批准的停止条件，不要求修改 UFW。
- `IOT_STAGE4_LIVE_INTEGRATION_REPORT.md`：本执行记录。
- `reports/integration-20261013/windows-offline-import.json`：真实完整文件离线验收的脱敏汇总。
- `reports/integration-20261013/ssh-access-status.json`：指定地址登录认证失败证据。
- `reports/integration-20261013/windows-source-manifest.json`：93 个白名单源码/依赖文件的 Windows SHA 基线，供后续与 Ubuntu 比较；不是已部署一致的证明。
- 上述目录中的三个测试/构建日志：实际执行结果。

本轮未操作 Windows 原始 LinuxGuard 竞赛目录；未访问或覆盖已有真实实验库；未将完整档案、私钥、口令或令牌提交到 Git。

## 6. CVE 代码检查与适用性结论

`matching_engine.run_matching(..., asset_id=...)` 已保留范围限制，OpenWrt 分派到 `iot_devices.match_openwrt`；Linux 仍保留原匹配路径。OpenWrt 不使用 dpkg 版本比较，当前只将固件 release + 包名称 + 人工公告完整版本进行精确对应。

当前限制：`OpenWrtAdvisory.source_url` 的官方域名验证不会自动验证公告正文；人工受影响版本表的精确命中也需要可追溯的公告、源码/补丁和构建证据。不得把“官方域名 URL”或版本相等本身作为独立漏洞确认。collection_only 继续禁止执行匹配，不因本轮 CVE 授权而关闭采集隔离保护。

后续在阶段 C 完成后，应使用现有模型与匹配服务，在另一独立分析副本中导入真实情报、只对已验收资产匹配；采集实例继续 collection_only。分别保留候选来源、版本匹配、官方适用性/回移证据、确认结论和人工待复核状态，记录本次资产快照 SHA。不能把其他发行版 fixed_version 套用于 OpenWrt。

**本轮未执行 CVE 候选匹配，没有确认任何受影响 CVE，也没有得出设备安全结论。** 未访问公告正文并形成当前设备适用性证据，因而不能报告第五阶段完成。

## 7. 继续执行、恢复与后续升级

SSH 登录配置解决后，代理按现有授权继续核对 Ubuntu 当前身份、地址、UTC 时间、源码摘要、虚拟环境和独立 session-001 标记。若已有进程或数据，先核对所属实例并使用 SQLite 一致性备份，禁止以新库覆盖。随后建立只绑定回环地址的隧道，启动/恢复已标记实例，验证健康、节点信息和禁止写操作限制。

完整档案在该实例重复导入后，使用 Ubuntu 本地密钥引用和已从可信控制台核验的 OpenWrt 服务器指纹绑定已有资产。先元数据检查，再分别执行两次新任务，回读真实时间、四项独立状态、Collector 摘要和包关联；出现超时先查询记录，不自动重放。失败恢复验证优先用模拟 SSH 或连接前安全校验失败，避免额外修改设备。

当前未修改远端状态，无远端回滚操作可执行。临时库与报告保留，后续只备份/恢复明确标记的独立运行目录，不回退设备、不触碰历史库。

eBPF/Falco/Tetragon 后续需要真实事件输入、来源校验、时钟/覆盖范围/心跳、资产归属、丢失与重复处理；Collector 能力线索不等于已安装或工作中的传感器。四智能体后续应消费真实采集任务与适用性证据，绑定资产快照、审计工具动作、审批与结果回写，显式区分证据不足和执行失败。当前没有本轮真实运行时事件或四智能体设备验收，不能填造记录。
