# IoTGuard 资产接入与认证改造

本次继续复用 FastAPI、LinuxAsset、软件包清单、风险研判及设备 Harness。原虚拟机演示模块保留为历史兼容。没有连接真实设备、迁移现有实验数据库、执行扫描或修复。

## 支持的导入方式

`POST /api/assets/upload` 接收 UTF-8 的 `.txt` 或 `.json` 文件。写入需在请求头提供 `X-Control-Token`，前端“设备操作配置”中的令牌只保存在内存。

### Ubuntu OpenWrt 导出格式：字符串版本 `"1.0"`

已按根目录 `asset_inventory_sample.json` 的结构适配：

- 外部 `asset_id` → 稳定的外部编号关联；数据库仍使用原来的整数 ID。
- `device.hostname` → 展示身份名称；`device.board_name` → 设备匹配型号。
- `device.firmware.version` → OS/固件完整版本；revision、target、builddate、型号等保存在来源元数据。
- `device.kernel` → 内核版本；`x86/64` target → `x86_64` 架构，其他 target 可从非 noarch 包的唯一架构推导。
- `software_inventory.packages[].name/version/architecture` → 原有 AssetPackage，不拆分或改写版本字符串。
- `source/license/status` → 软件包来源元数据；有 raw 字段时同时核对包名、版本、架构/安装标记。
- `generated_at` → 快照时间，并标注时间依据为导出生成时间，不作为经过独立验证的设备采集时间。

该结构样本声明 raw_count/package_count 为 182，但仅包含 3 条包记录，而且 `sample_only=true`。它用于结构适配，接口明确拒绝将其当作完整资产入库。测试将副本改为实际包含的 3 条合成清单，仅验证代码，不证明 182 条正式实验数据已经导入。

正式档案要求：

1. `sample_only` 不存在或为 false。
2. raw_count、package_count、实际包数组长度一致，且大于 0。
3. parse_error_count=0，所有包格式合法，无重复名称，status=installed。
4. 同外部编号重复导入更新同一资产；早于现有快照的档案不能覆盖它。

未提供 MAC 时，使用命名空间下的外部编号关联资产，身份来源标记 uploaded_inventory_id、置信度 0.5。JSON 中声明 collection_method=ssh 不会获得平台已校验 SSH 身份的状态。

导入后可在“物联网接入”登记连接，并选择“关联已有资产”。后续经主机指纹校验的采集会复用该资产、核对型号、补充 MAC。已绑定连接不能直接改绑其他资产。

Linux 路径 `/home/<ubuntu-user>/IoTGuard/data/openwrt/` 是 Ubuntu 文件位置，Windows 后端不会自动读取。正式文件需要由用户交接或在能够访问该路径的同一后端上上传。本次未复制或读取该目录。

### 平台标准格式：整数版本 `1`

另支持 `schema_version: 1`，顶层为 asset、collection、packages、可选 services。字段由 `backend/app/schemas.py` 中 AssetInventoryDocument 定义：

```json
{
  "schema_version": 1,
  "asset": {
    "hostname": "synthetic-example",
    "distribution": "ubuntu"
  },
  "collection": {
    "collected_at": "2026-10-13T00:00:00Z",
    "source": "synthetic_example",
    "packages_complete": true,
    "package_count": 1,
    "parser_error_count": 0
  },
  "packages": [
    {"package_name": "fixture-package", "package_version": "1:2.0~rc1-1", "package_manager": "dpkg"}
  ],
  "services": []
}
```

这是合成格式示例，不代表实验资产。标准格式 OpenWrt 要提供 MAC、os_version、architecture、device_model；普通 Linux 仍可使用旧分段文本。

## 文本清单保护

OpenWrt 采集器保留 `apk list --installed --manifest`。官方源码明确其输出为 `<name> <version>`：
https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-list.8.scd

采集器新增 package_count；解析器逐行记录 raw_count、parsed_count、rejected_count，并核对声明条数。坏行、重复包或条数不一致拒绝保存，不回显原始坏行。空清单不会被认定为完整；显式不完整的采集保留上次软件包。重复段落、重复 JSON 字段及非法编码被拒绝。

导入响应包含 package_parse_stats、文件 SHA256 和来源元数据。SHA256 提供文件追踪能力，不等同于来源签名认证。

## ED25519 密钥引用

新登记连接在前端默认使用密钥认证；已有连接默认继续使用 password，兼容旧数据。API 字段为：

```json
{
  "host": "<openwrt-ip>",
  "port": 22,
  "username": "root",
  "auth_type": "ssh_key",
  "credential_env": "",
  "key_path_env": "LINUXGUARD_DEVICE_OPENWRT_KEY_PATH",
  "key_passphrase_env": "",
  "host_key_sha256": "通过可信渠道取得的真实 SSH 主机指纹"
}
```

以上指纹为说明占位值，不能直接提交。key_path_env 指向后端环境变量名称，变量值须为后端可读的 ED25519 私钥绝对文件路径。若密钥加密，key_passphrase_env 指向独立的口令变量；未加密则留空。私钥内容、密码和口令不进入连接 API 或数据库。

密码模式继续使用 credential_env。所有认证引用变量名称须以 LINUXGUARD_DEVICE_ 开头；两种认证字段不能混用。保留主机指纹校验，并关闭 SSH agent 与隐式密钥搜索。加载失败返回通用错误，不回显文件路径、密钥或口令。

若私钥仅位于 Ubuntu，Windows 后端无法直接使用该路径。可以部署同一现有后端在 Ubuntu 并配置引用，再由前端访问它；本次未进行部署或密钥搬运。

## 接口与历史凭据

新增门禁覆盖资产上传、运行时事件写入/上传/演示生成/清空、人工风险确认、旧演示目标读取/修改及旧演示启动。传感器心跳原有门禁保留。

旧演示接口只返回 password_configured。编辑同一目标时，留空保留原密码，输入新密码才替换。新增归档不导出密码字段；历史归档查看及下载在响应中脱敏，不改写原始归档文件。

兼容模型中的旧 password 字段尚保留。本次没有读取、清除或迁移现有数据库内的历史密码；完整历史凭据迁移应另行规划。校验错误不再回显请求 input 值。

## 验证与部署边界

测试禁用 dotenv、真实模型密钥和旧 VM 环境配置；数据库、事件、研判文件及归档使用临时目录。SSH/密钥加载使用替身；浏览器测试截获所有 API 请求，不访问真实后端。

新增数据库列走现有增量 SQLite 迁移，旧连接以 password 回填。本次仅在临时旧库验证迁移，未启动应用迁移现有 linuxguard.db。

真实验收仍需未删减的正式档案，核对 182 条包记录的名称、完整版本和条数。在线 ED25519 采集、网络可达性及设备身份验收需要后续明确执行，不由本轮代码测试代替。

## 本轮验证结果

- 后端隔离回归：247 项通过。未执行 test_iot_device_upgrade、test_scan_runs、test_scan_targets、test_mqtt_remediation_workflow 四个设备/扫描/服务实验测试组。
- 新导入、认证和隐私测试：27 项通过，包含原样结构样本拒绝、合成副本字段保真、条数错误、重复包、陈旧档案、密钥引用、资产绑定、门禁及归档脱敏。
- 浏览器流程：17 项通过；最后的资产身份状态与可移植样本路径调整后，两条相关流程再次通过。
- 当前前端源码的生产构建通过。构建及浏览器结果写入临时目录，未替换 frontend/dist。

旧麒麟解析测试依赖的外部样例路径在当前目录缺失，已改为测试目录内明确标记的合成夹具。OpenWrt 用户样本原文件保持不变，另在测试夹具目录保留结构副本，使测试不依赖外部路径。

数据库新增字段尚未应用到现有实验库；部署时由原启动流程运行增量迁移。现有历史密码字段仍保留，接口及归档响应的脱敏不等同于历史凭据已经迁出数据库。
