# IoTGuard 第三阶段：真实 OpenWrt 资产导入验收报告

验收日期：2026-10-13。真实档案验收运行时间：08:43:30（Asia/Shanghai）。

结论：**正式档案导入验收通过；资产及软件清单具备进入原有 OpenWrt 离线 CVE 候选分析流程的数据条件。尚未执行真实 CVE 匹配，也未确认任何漏洞。**

## 1. 验收对象与边界

- 输入：`E:\IoTGuard-Project\asset_inventory.json`，63,083 字节。
- JSON 版本：字符串 `"1.0"`；外部资产编号：`IOT-OPENWRT-001`。
- 输入 SHA-256：`da80bf3c8393668e747fa10c9a507b3eda5c85e3b2b4065f4c81b164dbbdc40e`。
- 使用现有 `POST /api/assets/upload`，通过进程内 TestClient 调用；没有启动对外 API 服务。
- 全部 SQLite 连接限制到一个新建临时文件。禁用 dotenv 加载，事件及归档路径也指向临时目录。
- 没有读取、连接、迁移或修改原实验数据库，没有连接 OpenWrt，也没有执行扫描、修复、软件升级或重启。
- 没有读取任何 SSH 私钥、密码或真实令牌。管理字段中的密钥引用仅作声明性元数据保存，不读取引用目标，不自动登记连接。
- 完整档案没有复制到测试 fixtures，没有提交 Git；新增根目录忽略规则保护该文件。验收后重算文件摘要一致，原档案未修改。

## 2. 文件与字段校验结果

同时使用 `OpenWrtExportDocument.model_json_schema()` 生成的 JSON Schema（Draft 2020-12，含格式检查）和 Pydantic 业务约束校验。拒绝重复 JSON 字段、非法数值、结构样本、不一致条数、重复包名和上游解析错误。

| 项目 | 实际值 | 结果 |
| --- | --- | --- |
| 发行版 / 固件 | OpenWrt / 25.12.5 | 与本次预期一致 |
| revision | r33051-f5dae5ece4 | 保存并回读一致 |
| target / 资产架构 | x86/64 / x86_64 | 一致 |
| 内核 | 6.12.94 | 保存并回读一致 |
| 设备型号 | VMware, Inc. VMware Virtual Platform | 原始型号保存在元数据 |
| board_name | vmware-inc-vmware-virtual-platform | 映射为 device_model |
| 管理地址 | <openwrt-ip> | 从 management 映射为资产 IP |
| 快照时间 | 2026-10-12T14:51:14.889979+00:00 | SQLite UTC 回读一致 |
| 登记主机名 | OpenWrt-IOT-OPENWRT-001 | 外部编号区分默认主机名 |
| 外部关联键 | openwrt-json:IOT-OPENWRT-001 | 维持原整数资产 ID 模型 |

固件校验是对交付档案与本次预期的核对，不代表重新向设备采集或独立验证其运行状态。快照时间使用导出生成时间，不扩大解释为经过平台验证的远程采集时间。

## 3. 软件包逐条核验

| 数量依据 | 实际数量 |
| --- | ---: |
| 档案声明 raw_count | 182 |
| 档案声明 package_count | 182 |
| 实际 packages 数组长度 | 182 |
| 现有导入器 parsed_count | 182 |
| 实际独立包名数量 | 182 |
| 与完整 raw 字符串一致的记录 | 182 |
| 上游 parse_error_count | 0 |
| 导入器 rejected_count | 0 |

逐条核对包名、完整版本、架构、来源、许可证及 installed 状态与 raw 原文。所有包名、版本、架构及来源均非空；182 条来源信息覆盖 70 种来源字符串。架构分布：166 条 x86_64，16 条 noarch。

没有按连字符拆分、截断或标准化版本。包含日期、提交摘要、`~` 和 `-rN` 的版本按原字符串保存。例如 kernel 的完整包版本为 `6.12.94~a7bc15f451f9652701ba04af9cfb0b95-r1`，与资产内核字段 `6.12.94` 分开保存。

3 个固件包的许可证原文为空：bnx2-firmware、i915-firmware-dmc、r8169-firmware。它们的 raw 原文也为 `()`，因此按原样保留；本轮要求的软件包名称、版本、架构及来源并未缺失。

包名称、版本、管理器 apk 和架构进入原有 AssetPackage。来源、许可证和安装状态进入资产 inventory_metadata 中的 package_metadata，按包名关联；回读时全部逐条比较通过。没有新增一套独立资产表。

`raw_count` 是交付档案中的原始计数声明。本轮还核对了 JSON 内全部 182 条 raw，但未读取 Ubuntu 独立原始输出文件，因此不宣称重新验证了远程采集过程。

## 4. 独立临时数据库验收

数据库：`C:\Users\<user>\AppData\Local\Temp\iotguard-stage3-ub1zhyxm\acceptance.sqlite3`。

机器可读验收摘要：同目录 `acceptance_summary.json`，只包含汇总、检查结果和溯源摘要，没有完整包数组或密钥引用。临时文件保留供本次验收复核，系统清理临时目录后可能不可用。

| 数据 | 导入前 | 首次导入后 | 同一文件再次导入后 |
| --- | ---: | ---: | ---: |
| LinuxAsset | 0 | 1 | 1 |
| AssetPackage | 0 | 182 | 182 |
| AssetService | 0 | 0 | 0 |
| DeviceConnection | 0 | 0 | 0 |
| VulnerabilityInfo | 0 | 0 | 0 |
| OpenWrtAdvisory | 0 | 0 | 0 |
| VulnerabilityMatch | 0 | 0 | 0 |
| RuntimeEvent | 0 | 0 | 0 |

验证通过：

1. 两次上传均返回 HTTP 200；资产整数 ID 两次均为 1。
2. 所有 182 个包均关联资产 ID 1；开启 SQLite 外键约束，foreign_key_check 无违规。
3. 重复导入的资产与软件包数量不变，软件包内容及来源回读一致。现有保存实现会替换包行，幂等性指资产身份、数量及业务内容稳定，不保证包行的内部主键不变。
4. 资产列表与详情接口回读成功；随后关闭原引擎，用新引擎、新会话重新打开物理数据库，逐条检查包字段和来源信息，结果一致。
5. 资产固件、内核、型号、管理 IP、外部编号、完整性、档案摘要及时间均回读一致。
6. 没有因声明 SSH 管理信息而创建连接、执行采集或产生漏洞匹配、运行时记录。

验收工具阻止访问其他 SQLite 文件、读取 dotenv/常见私钥文件、发起外部连接或启动子进程。Windows 异步测试运行器所需的标准库内部回环 socketpair 仅允许连接其自身临时端口；接口请求仍通过进程内 ASGI 调用，不向设备或后端服务发送网络请求。

## 5. 发现的问题与处理

初次兼容性检查失败：上一阶段严格的 1.0 模型没有定义正式档案新增的 management 和 integrity，报 extra_forbidden。已增加两组可选且严格的类型约束；未知字段仍拒绝，旧档案无需这两组字段。

management 的 IP 映射到原有资产字段，完整声明保存为元数据；integrity 校验两项 SHA-256 的格式并保留声明，同时明确标记外部来源文件哈希未验证。

验收脚本初版将许可证也要求为非空，误判了原始许可证为空的 3 个固件包；已改为检查字段类型与 raw 一致性。Windows 测试运行器内部 socketpair 也曾被网络禁用规则阻止，已按上述严格范围兼容。它们是验收工具适配问题，未更改真实档案。

**最终导入验收失败项：0。** 以下事项未在本轮完成，不能用导入成功替代：

- 两项 integrity 哈希对应的 Ubuntu 原始文件未交付，不能复核哈希所指内容；它们不是此完整档案的 SHA-256，也不能直接当作嵌套对象的规范化摘要。
- 档案没有 MAC；使用外部编号关联，身份来源 uploaded_inventory_id、置信度 0.5。声明 collection_method=ssh 不等于平台已验证 SSH 身份。
- 档案没有服务端口、运行时行为及 Falco/Tetragon/eBPF 证据；临时库中的这些数据为空。
- 临时库没有漏洞情报或 OpenWrt 25.12.5 适用性公告。本轮不检查原库是否有这些数据。

## 6. CVE 流程就绪判断

**资产输入数据已就绪。** 原有 matching_engine.run_matching 根据 distribution=openwrt 调用 iot_devices.match_openwrt。该分支使用当前固件 release、APK 包名及完整安装版本；本次资产已具备这些字段且 inventory_complete=true。

**开展可信适用性分析还需要情报输入。** 应补充对应 OpenWrt 25.12.5 的厂商适用性、受影响/已修复版本及来源证据，并处理包名到上游组件的映射。现有分支采用厂商范围内的版本精确记录；缺少对应证据时只能得到 insufficient_data 候选，不能套用 Ubuntu/Debian 修复版本规则。

代码中 insufficient_data 候选仍可能保守标记 affected=true，应结合 match_status、reason_code 和证据解释，不能仅凭布尔字段当作漏洞确认。精确受影响版本命中同样属于适用性判断，不能证明本设备已被利用。

本轮没有对真实档案调用漏洞情报同步、CVE 匹配、风险研判或漏洞验证。临时库匹配行数为 0 表示这些操作未执行，**不表示设备不存在漏洞**。设备服务与运行时证据也仍不足以确认可达性、可利用性或修复结果。

## 7. 实际修改及新增文件

| 文件 | 本轮用途 |
| --- | --- |
| backend/app/schemas.py | 严格定义 management/integrity，校验地址、端口、认证声明、哈希格式及地址冲突 |
| backend/app/services/asset_import.py | 映射管理 IP；保存两组声明及未验证来源哈希状态；继续复用原资产持久层 |
| backend/scripts/verify_openwrt_inventory_import.py | 新增可重复运行的离线真实档案验收工具，限定独立临时 SQLite，逐包与回读检查 |
| backend/tests/test_stage3_import_acceptance.py | 新增合成回归，验证新增字段、失败保护、离线隔离和 Linux 兼容性 |
| .gitignore | 忽略根目录真实 asset_inventory.json，防止后续误加入版本控制 |
| IOT_STAGE3_ACCEPTANCE_REPORT.md | 本验收报告 |

没有修改 collector、frontend、数据库模型或迁移逻辑，没有删除或重构 LinuxGuard 模块。没有修改真实 asset_inventory.json。

## 8. 回归测试与停止点

执行命令：

```powershell
python -B backend/scripts/verify_openwrt_inventory_import.py asset_inventory.json
python -B -m pytest -q -p no:cacheprovider backend/tests/test_stage3_import_acceptance.py backend/tests/test_stage12_ingestion.py backend/tests/test_asset_parser.py backend/tests/test_version_compare.py
```

真实验收工具最终返回 PASS。定向回归 **48 passed in 15.23s**：覆盖新增字段、无效档案不覆盖已有数据、旧 1.0 格式兼容、原 Linux 文本与标准 JSON 导入、完整 Debian 版本保留、Linux/OpenWrt 资产共存，以及原有 Linux 检测分支的合成数据回归。合成检测测试没有使用正式 182 包档案，没有远程采集或真实扫描。

本轮没有重跑与本改动无关的全部后端/前端测试；没有验证实时 SSH 采集或生产部署。第三阶段已停止，等待下一步指令，不自动启动检测或设备操作。
