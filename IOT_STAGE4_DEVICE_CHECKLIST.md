# IoTGuard 第四阶段真实设备联调操作清单

本清单描述操作步骤，不代表这些步骤已经执行。2026-10-13 用户已授权在指定独立环境中自主部署、导入、只读采集及后续 CVE 适用性验证；本文原有逐步批准要求已由该授权替代。实际执行证据以当轮联调报告为准，不能把计划或历史隔离测试当作设备验收。

当前部署方式优先为 Ubuntu 后端绑定 `127.0.0.1:8000`，Windows 通过严格校验主机密钥的 SSH 本地隧道访问；无需修改 UFW 或已有服务。只有 Windows 到 Ubuntu 的账号认证完成并核对目标节点后，才继续远端步骤；认证失败不通过自动接受主机密钥、尝试其他设备或读取密码文件绕过。

## 1. 部署与数据位置

采用同一套 IoTGuard 后端在 Ubuntu 运行，承担 API、受控采集、资产更新和审计；Windows 运行前端并负责开发测试。本版没有 Windows 后端向另一个 Ubuntu worker 派发任务的分布式协议。

建议目录如下，均为部署计划，本轮未访问这些 Linux 路径：

```text
/home/<ubuntu-user>/IoTGuard-stage4/
├── app/
│   ├── backend/
│   │   ├── app/
│   │   ├── scripts/
│   │   ├── tests/                 # 合成回归测试
│   │   ├── requirements.txt
│   │   └── requirements-test.txt
│   └── collector/
│       └── collect_openwrt_asset.sh
├── venv/
└── runtime/session-001/           # 首次启动前不存在或为空
```

原 `/home/<ubuntu-user>/IoTGuard/data/openwrt/` 保留，真实资产文件从该目录中由你确认。已有私钥继续使用原位置，既不复制到此部署目录，也不复制到 Windows。

交接源码时只选择上述源码、测试和依赖文件；不要整体复制旧项目的数据目录、`.env*`、密钥或数据库。保留 backend 与 collector 相邻关系。当前 backend/Dockerfile 没有打包 Collector，本轮启动方式采用独立 Python 环境。

## 2. 你在 Ubuntu 需要先确认的信息

1. 当前 NAT 地址：在 Ubuntu 本地查看接口地址；`<ubuntu-nat-ip>` 是历史地址，不能直接当作当前值。
2. 当前时间：检查 Ubuntu UTC 时间。任务时间记录来自采集节点，不冒充 OpenWrt 独立时钟证据。
3. 原有完整资产文件的实际路径、固件、计数和 SHA-256；不要选择 sample_only 结构样本。
4. 已验证 SSH 使用的用户名和端口。
5. 通过既有可信公共主机密钥记录或可信控制台确认 OpenWrt 的 SSH 主机 SHA256 指纹。它是**服务器主机指纹**，不是客户端 ED25519 密钥指纹。不用自动接受未知密钥的方式取得信任。
6. 由你在本地确认已有 ED25519 私钥的绝对路径、服务账号可读性及是否需要口令。无需把文件内容、路径值、口令或平台令牌发送到聊天。

源码与 Windows 文件已经验证的完整资产摘要为：

```text
da80bf3c8393668e747fa10c9a507b3eda5c85e3b2b4065f4c81b164dbbdc40e
```

Ubuntu 文件若有不同摘要，先确认是否是同一份档案或新快照，不能将其直接说成第三阶段已经验收的相同文件。两项 integrity 中的外部来源文件哈希仍需对应原文件才能复核。

## 3. 安装与离线回归

当前自主执行授权下使用独立虚拟环境，不改变旧项目环境：

```bash
python3 -m venv /home/<ubuntu-user>/IoTGuard-stage4/venv
. /home/<ubuntu-user>/IoTGuard-stage4/venv/bin/activate
cd /home/<ubuntu-user>/IoTGuard-stage4/app/backend
python -m pip install -r requirements.txt -r requirements-test.txt
python -B -m pytest -q --tb=short -p no:cacheprovider tests/test_stage4_collection.py tests/test_stage12_ingestion.py tests/test_stage3_import_acceptance.py tests/test_iot_upgrade.py tests/test_asset_parser.py tests/test_version_compare.py
```

这些测试生成合成资产、使用 SSH 替身和临时数据库，并禁止真实 SSH、真实私钥加载及实际网络连接。它们不会使用你原来的完整资产文件或私钥。不要在本阶段执行本机真实监听/扫描/MQTT 修复的其他测试组。

## 4. 采集节点本地检查

仍不连接设备，不加载私钥，不创建数据库：

```bash
python -B scripts/start_iot_integration.py \
  --runtime-dir /home/<ubuntu-user>/IoTGuard-stage4/runtime/session-001 \
  --node-id ubuntu-openwrt-node-01 \
  --target <openwrt-ip> \
  --check
```

检查输出应为 local_metadata_checked，network_attempted=false、key_loaded=false。此结果只证明部署目录和脚本元数据通过，不证明 SSH 认证或实际采集成功。

配置认证引用时，在 Ubuntu 本地以静默输入设置环境变量。例如：

```bash
read -r -s -p '输入本轮平台操作令牌：' LINUXGUARD_CONTROL_TOKEN
printf '\n'
export LINUXGUARD_CONTROL_TOKEN
read -r -s -p '输入已有 ED25519 私钥的绝对路径（仅路径）：' LINUXGUARD_DEVICE_OPENWRT_KEY
printf '\n'
export LINUXGUARD_DEVICE_OPENWRT_KEY
```

需要私钥口令时，再在本地静默设置 `LINUXGUARD_DEVICE_OPENWRT_KEY_PASSPHRASE`；无需口令时不设置。不能用读取私钥文件内容的命令填充变量。API 登记只填写上述**变量名称**。

建议以已验证密钥所属的 <ubuntu-user> 账号运行服务。环境变量只需保留在该次节点运行环境，不写入前端 VITE 配置、Git 或交付文档。

## 5. 启动独立节点

此步骤只启动 API，不自动采集。当前授权下使用回环绑定：

```bash
python -B scripts/start_iot_integration.py \
  --runtime-dir /home/<ubuntu-user>/IoTGuard-stage4/runtime/session-001 \
  --node-id ubuntu-openwrt-node-01 \
  --target <openwrt-ip> \
  --bind 127.0.0.1 \
  --port 8000 \
  --serve
```

Windows 到 Ubuntu 的 SSH 已认证且节点身份确认后，建立只绑定 Windows 回环地址的本地端口转发：Windows `127.0.0.1:8000` → SSH → Ubuntu `127.0.0.1:8000`。如果 Windows 端口占用，选择另一个空闲本地端口并同步配置前端。SSH 使用 `StrictHostKeyChecking=yes`、`ExitOnForwardFailure=yes` 和已授权登录方式；不自动接受未知主机密钥。不要在终端参数中放密码、口令或平台令牌。本版没有自带 HTTPS 网关，实验 API 不绑定公网接口。

启动器自动选择：

- `runtime/session-001/iotguard-stage4.sqlite3`：独立数据库；
- `runtime/session-001/data/`、events.jsonl、archives/：独立运行路径；
- `collection_only`：只允许完整 OpenWrt JSON 基线导入、连接登记和纯采集任务；
- `<openwrt-ip>/32`：唯一设备管理范围；
- 单进程与目录进程锁：同一运行目录不能重复启动；
- 禁用 dotenv、旧 VM 环境引用、自动归档清理、模型调用、扫描、匹配执行、运行时注入与修复入口。

不要用旧 `start_backend.bat` 或旧 `start_backend.py` 启动此次联调。它们属于原有启动路径，没有本启动器的独立目录保护。

## 6. Windows 前端接入与基线导入

在 Windows 前端进程配置 `VITE_API_BASE=http://127.0.0.1:<SSH隧道本地端口>/api`，前端开发服务也绑定回环地址。不要在 VITE 变量中放令牌、私钥路径值或口令。健康检查后核对 capabilities 中的 Linux 采集节点、collection_only 模式及唯一授权目标，再进行资产操作。

进入“物联网接入”：

1. 确认页面显示实际 Ubuntu/Linux 采集节点，以及联调只采集模式。
2. 在“设备操作配置”输入本轮操作令牌；令牌仅保存在当前页面会话。
3. 导入第三阶段验收的**完整 JSON**，在独立实例形成已有资产。此为新的联调库，不使用第三阶段临时库的整数 ID。
4. 查看软件包数量应为 182、解析错误为 0；身份仍是离线交接来源，不因 JSON 声明 SSH 而显示平台已认证。
5. 记录该实例返回的真实 asset_id，不能硬编码为 1。

JSON 本身的 management 与 key_reference 只作为声明元数据；不会自动登记连接或访问密钥文件。联调模式拒绝不带外部编号的文本导入，避免初次 MAC 采集另建资产。

## 7. 登记连接与无网络配置检查

登记内容：

| 字段 | 填写依据 |
| --- | --- |
| 管理 IP | <openwrt-ip> |
| SSH 用户名 / 端口 | 你此前已验证的实际值 |
| 认证方式 | ED25519 密钥 |
| 关联已有资产 | 选取本次独立实例的资产 |
| 私钥路径变量名称 | LINUXGUARD_DEVICE_OPENWRT_KEY |
| 口令变量名称 | 需要时填写 LINUXGUARD_DEVICE_OPENWRT_KEY_PASSPHRASE，否则留空 |
| SSH 主机 SHA256 指纹 | 你通过可信来源核验的真实指纹 |

点击“配置检查”。它只检查本地引用配置、文件元数据、目标范围、Collector 和节点平台；不读取私钥内容、不建立 SSH、不修改资产。即使 ready=true，SSH 身份与认证仍应为 not_attempted。

Windows 后端不能执行纯采集任务；看到 Windows 节点时停止并修正 API 地址。不要把 Ubuntu 密钥复制到 Windows 来绕过这个限制。

## 8. 执行已授权的真实只读采集

点击已绑定连接的“采集”，前端先创建任务，再执行同一任务。也可从“智能体设备任务”选择纯资产采集；不要选调查或修复。

采集接口链路：

```text
POST /api/iot/connections/{connection_id}/collection-runs
  {"request_id":"该次操作的唯一编号"}
POST /api/iot/collection-runs/{run_id}/execute
GET  /api/iot/collection-runs/{run_id}
GET  /api/assets/{asset_id}
```

只传操作令牌请求头和任务编号，不传私钥或采集结果。结果由 Ubuntu 后端执行固定 Collector 后生成。execute 当前为同步有界执行；执行过程中可通过另一查询请求查看已持久化状态。

记录以下独立结果：

- SSH 主机公钥指纹校验：verified 或实际失败；
- SSH 认证：succeeded 或实际失败；
- 资产采集：succeeded、failed 或 interrupted；
- CVE 适用性：本轮始终 not_evaluated。

Collector 读取设备信息并使用自己的临时输出文件，结束时清理；不改变设备配置或软件，不安装探针，不生成运行时事件。

## 9. 真实验收与停止条件

1. 核对固件 25.12.5、设备型号、内核、实际 MAC；不存在的字段不能用假值补齐。MAC 为空或与既有可信记录不符时，不宣称完整设备验收通过。
2. 软件未变化时 raw_count、parsed_count、declared_count、实际关联包数应均为 182，rejected_count=0，APK details_matches=true。
3. 对比逐包名称、完整版本、架构和来源。原档案的架构基线为 x86_64 166 条、noarch 16 条；软件发生变化时如实记录差异，不硬凑数量。
4. 检查 started_at、finished_at、Collector 类型、脚本摘要、输出摘要、退出状态、节点及失败原因。
5. 资产 ID、外部编号和连接关联保持不变；按当前授权再创建一次新任务采集，确认不创建重复资产。
6. 同一 request_id 复用同一任务；重复执行终态任务不再 SSH。重试需要明确创建新编号，不是自动重放。
7. 失败后旧资产、软件包、来源和摘要应保持不变。任务失败不等于 SSH 一定失败，SSH 成功也不等于资产采集成功。
8. 没有真实运行时采集时不展示事件、心跳或已利用证据。版本匹配不作为漏洞确认。

偏离上述条件时停止并反馈脱敏任务摘要。可以反馈实际地址、任务 ID、开始/结束时间、错误码、固件、包数、摘要和公钥指纹；不要反馈令牌、私钥内容或口令。

## 10. 中断、恢复与回滚

- 请求断开时先查询任务，不重新发送 execute 来猜测状态。超时记录的远端执行状态为 unknown；不声称远端必已结束。
- 停止该独立节点后，可用 SQLite 一致性备份机制保存其数据库；不要仅复制运行中的主 .sqlite3 而忽略 WAL。
- 恢复同一联调目录时使用同样的 node-id、target，增加 `--resume --serve`。进程锁成功取得后，启动器将遗留 running 采集任务标为 interrupted，不自动重放 SSH。
- 仍为 pending 的任务也不会在启动时自动执行；配置或 Collector 改变后创建新任务。
- 数据回退只恢复本次独立运行目录的数据库，源码回退只切换独立部署版本；原实验库与原资产目录不在回退范围。
- 本阶段没有设备软件或配置变更，所以不执行设备重启、软件包回退或升级操作。

当前自主执行授权允许按阶段顺序继续导入和真实只读采集，无需逐步重复确认。登录凭据缺失、身份不一致、范围变化或存在实际数据丢失风险时保留已有成果并说明阻塞；不伪造成功结果。
