# IoTGuard 第四阶段源码实施与隔离测试报告

日期：2026-10-13。工作副本：`E:\IoTGuard-Project`。

**已完成源码实施、模拟 SSH / 临时 SQLite 验证及安全范围内的后端、前端回归。未执行真实设备联调。** Windows 和 Ubuntu 复用同一套 IoTGuard 后端，不新增独立平台或分布式 worker 协议。

真实操作步骤见 [IOT_STAGE4_DEVICE_CHECKLIST.md](E:/IoTGuard-Project/IOT_STAGE4_DEVICE_CHECKLIST.md)。该清单是待批准步骤，不是实验结果。

## 1. 实现的链路

```text
Windows 前端登记已有资产的 SSH 连接
→ Ubuntu 运行同一后端、解析本地密钥引用
→ 创建并持久化纯采集 HarnessRun
→ 执行端领取任务、取得已有 HarnessAssetLock
→ 校验授权目标、连接配置、节点、Collector 摘要与 SSH 主机指纹
→ 固定 Collector 经 SSH 执行
→ 完整清单解析与资产身份比对
→ 同一事务更新已有资产、包、观察记录、成功审计并释放锁
→ 通过 API 回读真实任务结果
```

所有纯采集任务实际执行均要求 Linux 平台，Windows 只能开发、检查和模拟测试。现有标准模式 Linux 导入、CVE 匹配和风险研判保留；专用 collection_only 模式显式禁止这些分析执行及设备写操作，等待后续独立授权。

## 2. 复用与安全行为

- 数据表继续使用 LinuxAsset、AssetPackage、DeviceConnection、HarnessRun、HarnessToolCall 和 HarnessAssetLock；models.py 未修改，没有新增业务表或列迁移。
- JSON 1.0 适配继续使用原有 asset_import.py / schemas.py。本轮未重新实现导入器，也未修改完整档案。
- 新任务必须绑定已有 OpenWrt 资产。保存使用明确 asset_id，保留 inventory_external_id；不依靠默认主机名创建资产。
- request_id 生成稳定任务 ID；重复创建复用已有任务。completed/failed/interrupted/cancelled 任务不再次 SSH，重试需要新任务。
- 任务创建不联网。执行时检查节点与连接签名，以及两次检查之间的 Collector 变化；不接受客户端脚本或结果状态。
- SHA256 主机指纹必填并固定校验，无 AutoAddPolicy。认证仅使用后端本地专用变量引用，禁用 agent 和自动找钥。
- 成功认证后先持久化 SSH 结果。后续退出码错误、超时、缺字段、解析失败或数据库错误不会把 SSH 成功改成资产成功。
- 资产与包替换先 flush，最终成功事务一起 commit；任何异常先 rollback，再单独记录失败。完整旧清单、来源和摘要得到保留。
- 数据库持续不可写时，最终失败记录也可能无法持久化；此前已提交的创建/运行记录用于重启后的中断恢复。本版不宣称数据库完全不可用时仍能写入审计。

## 3. 采集字段与独立状态

Collector 保留 `apk list --installed --manifest`，新增 `APK_PACKAGE_DETAILS` 段取得完整详细记录。解析器以 manifest 的 name + 完整 version 对应详细记录，校验架构、来源、许可证和 installed 状态，避免猜测连字符边界。

manifest 与详细记录不一致、重复、缺失或数量不符时，在线采集失败；不补造架构、来源或包记录。许可证原文为空时允许保留为空。原 dpkg/rpm/opkg 文本解析继续可用，旧 manifest 文件也仍可解析；真实在线 APK 更新则要求详细字段。

每次采集审计保留：节点、Collector 类型和摘要、开始/结束时间、耗时、退出状态、输出字节数和摘要、包解析统计、资产 ID、包数及架构分布。前置包清单和来源元数据快照保留在任务中；本版不保存完整原始 stdout/stderr 文件，也不将任务快照当作整库回滚备份。

| 状态 | 含义 |
| --- | --- |
| ssh_host_identity | 服务器主机公钥指纹校验状态 |
| ssh_authentication | SSH 客户端认证状态 |
| asset_collection | 本次完整清单校验与数据库提交状态 |
| cve_applicability | 纯采集任务始终为 not_evaluated |

连接的 identity_verified 表示当前连接配置与已有成功 SSH 清单的签名一致，属于已保存快照证据，不是实时在线判定；本次成功/失败应查看任务记录。采集失败不覆盖旧的已验证快照。

没有自动运行 CVE 匹配、模型复核、运行时注入或修复。BPF/Falco/Tetragon 仅记录 Collector 读到的能力线索，不据此生成 RuntimeEvent 或宣称有效传感覆盖。

## 4. API

所有路径均在原项目 API 下：

| API | 用途 |
| --- | --- |
| POST /api/assets/upload | 复用完整 JSON 基线导入；collection_only 下拒绝无外部编号的文本，避免另建资产 |
| GET/POST /api/iot/connections、PUT /api/iot/connections/{id} | 复用登记与编辑；联调模式要求绑定资产及密钥引用 |
| GET /api/iot/connections/{id}/preflight | 新增无网络、无私钥加载的元数据检查 |
| POST /api/iot/connections/{id}/collection-runs | 新增创建任务，body 仅 request_id |
| GET /api/iot/collection-runs | 新增最近 100 条采集记录，可按 connection_id 查询 |
| GET /api/iot/collection-runs/{run_id} | 新增结果、时间和工具审计回读 |
| POST /api/iot/collection-runs/{run_id}/execute | 新增执行；同步有界，执行时可另行查询状态 |
| POST /api/iot/connections/{id}/collect | 保留原入口，内部复用持久化任务；成功返回原 asset 并附 collection_run，失败返回可查询 run_id |
| POST /api/harness/runs，goal=collect | 原 Harness 支持纯采集目标；不接受风险、修复产物或模型复核参数 |
| POST /api/harness/runs/{id}/execute | 原执行入口分派纯采集任务到同一实现 |
| POST /api/matching/run?asset_id={id} | 标准模式可选资产范围；增加操作令牌，默认仍处理全部资产；联调模式禁止执行 |

新增采集检查、创建、列表、详情和执行需要 X-Control-Token。collection_only 下其他资产及审计读取也需要令牌；health、capabilities 和无任务数据的旧 demo/progress 读取保留用于页面启动状态。

原匹配服务的可选 asset_id 同时限定资产处理与旧匹配记录失效范围，避免针对一台设备计算时使另一台 Linux 主机的匹配失效。原 Linux 版本与风险逻辑没有重构。

## 5. Ubuntu 接入方式

新增 start_iot_integration.py：

- --check 只做本地元数据检查，不创建数据库、不载入私钥、不联网。
- --serve 仅 Linux 可运行，要求本地设置操作令牌。
- 新目录必须不存在或为空；已有目录只能用匹配标记的 --resume 恢复，禁止覆盖已有数据。
- 在导入配置/数据库模块之前，选择标记运行目录中的唯一 SQLite 路径；配置模块也在打开 SQLite 之前再次校验。
- 数据、事件、归档路径隔离，禁用 dotenv 与旧 VM 引用；不运行旧样例清理，也不启动自动分析或设备操作。
- collection_only SQLite 打开外键约束；一目录一进程，Linux flock 防止同时启动。重启恢复仅标记 interrupted，不重放 SSH。

Linux 私钥只由批准执行后的 Ubuntu 本地认证组件使用，API / 数据库仅保存变量名称，检查接口不返回路径值或内容。本轮没有部署此节点，Ubuntu 地址、实际依赖、进程锁行为及真实认证仍待现场确认。

## 6. 实际修改和新增文件

| 文件 | 作用 |
| --- | --- |
| backend/app/config.py | 独立数据目录、禁用 dotenv、采集模式早期保护 |
| backend/app/integration_runtime.py（新） | 无依赖地校验运行标记、目标与 SQLite 路径 |
| backend/app/database.py | 仅采集模式启用 SQLite 外键；不增加表列迁移 |
| backend/app/main.py | 采集模式跳过历史清理、执行操作白名单、查询授权及异常脱敏 |
| backend/app/routers/assets.py | 联调基线限定带编号的 OpenWrt JSON，保留标准模式导入 |
| backend/app/routers/iot.py | 采集 API、检查和回读；身份签名判定；旧入口兼容 |
| backend/app/routers/harness.py | 增加 collect 目标和工具结束时间返回 |
| backend/app/routers/matching.py | 匹配授权和可选资产范围 |
| backend/app/services/device_access.py | 节点信息、连接签名、认证失败分类、严格 UTF-8 与固定指纹 |
| backend/app/services/asset_parser.py | APK 详细字段关联、来源保存、可由调用方统一提交 |
| backend/app/services/iot_devices.py | 完整校验、已有资产回写、统一事务、真实结果摘要 |
| backend/app/services/collection_tasks.py（新） | 复用 Harness 模型的纯采集生命周期、幂等、审计与中断恢复 |
| backend/app/services/agent_harness.py | collect 分派及联调模式限制；保留原调查修复逻辑 |
| backend/app/services/matching_engine.py | 可选资产范围与对应历史匹配作用域 |
| collector/collect_openwrt_asset.sh | 保留 manifest 并增加 APK 详细输出 |
| backend/scripts/start_iot_integration.py（新） | Ubuntu 独立采集节点启动与恢复 |
| backend/requirements-test.txt（新） | 明确 pytest/httpx/jsonschema 测试依赖 |
| backend/tests/conftest.py | 临时存储、网络/真实 SSH/真实密钥加载阻断 |
| backend/tests/test_stage4_collection.py（新） | 合成 182 包、事务、身份、幂等、隔离与失败回归 |
| backend/tests/test_stage12_ingestion.py | 既有模拟采集明确模拟 Ubuntu 节点 |
| frontend/src/api/index.js | 内存令牌请求头与匹配授权、资产范围参数 |
| frontend/src/api/deviceOperations.js | 检查、创建、执行及查询采集任务 |
| frontend/src/components/DeviceControlToken.vue | 准确说明联调读取也需授权 |
| frontend/src/views/IoTWorkspace.vue | 节点、配置检查、绑定门禁及四项独立状态展示 |
| frontend/src/views/DeviceTasks.vue | 识别纯采集目标，禁止失败任务自动重试，联调限制 |
| frontend/src/views/RiskRanking.vue | 匹配令牌入口、错误处理及候选措辞 |
| frontend/tests/e2e/iot-upgrade.spec.js | 新增纯采集、失败独立状态、无自动重放与页面布局回归 |
| frontend/scripts/verify_stage4.mjs（新） | 不读取 dotenv、不覆盖 dist 的构建与浏览器验证 |
| IOT_STAGE4_IMPLEMENTATION_REPORT.md（新） | 本报告 |
| IOT_STAGE4_DEVICE_CHECKLIST.md（新） | 待批准的实际联调步骤与回滚清单 |

未修改原 LinuxGuard 目录；未修改 Linux Collector、simulator、数据库模型及 JSON 1.0 适配源码。未修改 .gitignore；其真实档案保护规则继续有效。没有 Git 提交。

## 7. 测试执行与真实结果

测试均在 Windows 执行。这里的“真实结果”是工具实际执行的测试结果，不是实际设备实验结果。

### 广泛后端安全回归

```powershell
python -B -m pytest -q --tb=short -p no:cacheprovider backend/tests --ignore=backend/tests/test_iot_device_upgrade.py --ignore=backend/tests/test_scan_runs.py --ignore=backend/tests/test_scan_targets.py --ignore=backend/tests/test_mqtt_remediation_workflow.py
```

最终结果：**298 passed in 100.47s**。包含第四阶段、第三阶段和既有 Linux、匹配、风险、审计及 Harness 回归。

明确未执行上述四个测试文件；本机真实协议监听/扫描及 MQTT 配置修改和重启测试不属于本轮模拟验证范围，其中目标登记文件也保守排除。不能把本结果称为全部项目测试通过。

测试启动先禁用 dotenv 和真实服务配置，所有 SQLite 连接只允许测试临时根目录。真实 SSH 与 ED25519 文件加载被替身阻断；网络与 DNS 被禁止，Windows 异步运行器自身标准库回环 socketpair 除外。

### 独立链路及受影响组

曾执行以下最终保护改动前的受影响组，最后一轮结果 **102 passed in 36.28s**；此后 Linux 执行节点限制及 APK 组合一对一检查由上面的最终 298 项回归覆盖：

```powershell
python -B -m pytest -q --tb=short -p no:cacheprovider backend/tests/test_stage4_collection.py backend/tests/test_stage12_ingestion.py backend/tests/test_stage3_import_acceptance.py backend/tests/test_iot_upgrade.py backend/tests/test_asset_parser.py backend/tests/test_version_compare.py
```

其中模拟数据明确为 SYNTHETIC：182 个生成的软件包，架构分布 166 x86_64 / 16 noarch。模拟前置导入 1 个资产、182 个包；重复成功采集后仍为 1 个资产、182 个包，增加任务记录，不产生 CVE 匹配或运行时事件。

失败覆盖：认证失败、错误指纹、超时、非零退出、部分清单、数量不符、缺详情、来源格式、型号/MAC 冲突、数据库 flush/commit 失败、连接/节点/脚本限制及脚本在检查与派发间变化。SQLite 外键检查无违规。新会话可以读回持久化结果，失败保留原始完整资产。

### 前端与构建

```powershell
node frontend/scripts/verify_stage4.mjs e2e
node frontend/scripts/verify_stage4.mjs build
```

浏览器最终结果：**20 passed (15.1s)**，API 全部拦截为明确的合成 fixtures，不连接后端或设备。覆盖旧页面与新增任务状态、令牌引用、失败不合并状态、无自动重放及页面宽度。

构建：最终成功，2232 个模块转换，输出在 `C:\Users\<user>\AppData\Local\Temp\iotguard-stage4-frontend-6hUAqG\build`，不写 frontend/dist、不加载项目 dotenv。依赖的 PURE 注释位置和颜色环境有非阻断警告，没有构建失败。

浏览器验收产物目录：`C:\Users\<user>\AppData\Local\Temp\iotguard-stage4-frontend-0bm6kP`。截图仅说明模拟页面，不能作为真实 SSH/设备证据。临时目录可能被系统清理。

本轮完整 asset_inventory.json 重算摘要仍为 `da80bf3c8393668e747fa10c9a507b3eda5c85e3b2b4065f4c81b164dbbdc40e`，文件未改变。未对其执行第四阶段真实导入。

## 8. 未完成和使用限制

1. 没有部署或访问 Ubuntu/OpenWrt，未验证实际 IP、依赖组合、Linux 进程锁、真实 ED25519 加载、主机指纹及 BusyBox/APK 实际输出。
2. execute 是同步有界执行，状态持久化可查询；不是分布式后台队列，没有多节点路由、自动重试或无人值守调度。
3. 审计使用单一操作令牌，未新增用户身份系统或多租户。API 没有自带 HTTPS，真实实验部署需限制到可信实验网和明确来源。
4. 输出记录为摘要及规范化数据；没有原始 stdout/stderr 完整文件归档，外部 integrity 原文件验证也未完成。
5. 没有确认任何真实 CVE 适用性、可达性、可利用性或运行时事件。采集成功不是漏洞确认，旧风险记录也不是本次新快照的自动复核结果。
6. 部分源字段缺失可以使软件包清单或设备验收不成立；不能以旧值或占位符补造本次数据。实际设备验收还需按操作清单逐项核对。

## 9. 下一轮配合与停止点

你需要在 Ubuntu 本地确认实际地址、时间、完整 JSON 和可信主机指纹；按清单准备独立源码/虚拟环境，设置已有密钥引用，并运行无网络检查。真实联调批准后才启动独立节点、导入基线、登记绑定并显式执行一次采集。

本轮已停止在源码和隔离测试完成处，等待真实设备联调批准；不会自行进行部署、真实导入、连接、扫描、修复、升级或重启。
