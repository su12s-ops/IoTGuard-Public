# 环境重建与软件配置

本目录发布可复用的脱敏配置，不包含原虚拟机磁盘、UUID / MAC、宿主路径、SSH 主机密钥、登录密码或 API 令牌。以下重建步骤需在新环境执行；当前没有自动改动运行中的实例。

## 环境清单

| 层次 | 实验基线 | 发布内容 |
|---|---|---|
| Windows 控制端 | Python 3.12+（现有开发机 3.14）、Node.js 24、Docker Desktop / Compose v2、VMware Workstation | 根目录 Compose、Dockerfile、依赖文件、环境变量示例 |
| Ubuntu 采集与构建机 | Ubuntu 24.04，2 vCPU、4 GiB；网卡 0 NAT、网卡 1 VMnet2 | VMware 参数、依赖安装脚本、Pull Runner 配置及服务模板 |
| OpenWrt | 25.12.6 x86/64、2 vCPU、1 GiB；网卡 0 VMnet2、网卡 1 NAT | VMware 参数与 VMX 生成工具；采集脚本在 collector/ |
| Zephyr | v4.4.2、SDK 1.0.1（原环境记录）、qemu_cortex_a9、QEMU ARM 8.2.2（原环境记录） | 应用、Kconfig、设备树、SLCR 补丁、构建及 QEMU 服务入口 |
| Falco | 原环境 0.44.1；modern eBPF 需要 Linux BTF | 规则、既有部署器、服务及脱敏环境示例 |

CPU / 内存 / NAT 与自定义网卡顺序依据现有主实验虚拟机；控制器和网卡型号在公开模板中统一为 LSI Logic SCSI / e1000，属于重建参数，不是原 VMX 的逐字导出。VMnet2 是可替换的实验网名称，不携带原网段。

## 1. VMware 与 OpenWrt

在 VMware 虚拟网络编辑器创建隔离的自定义 VMnet2（或自行指定名称），确保 Ubuntu 和 OpenWrt 对应网卡连接到同一个网段。为该网段自行分配互不冲突的地址；不要让多个 DHCP 服务相互竞争。NAT 用于出站联网，隔离网用于授权管理及采集。

从 [Ubuntu 官方](https://releases.ubuntu.com/24.04/)获取安装介质，从 [OpenWrt 官方](https://downloads.openwrt.org/releases/25.12.6/targets/x86/64/)获取 x86/64 镜像，按官方校验清单验证下载。Ubuntu 先通过 VMware 安装到新 VMDK；OpenWrt 可在安装有 qemu-img 的机器上解压并转换：

```bash
gunzip -k openwrt-25.12.6-x86-64-generic-ext4-combined.img.gz
qemu-img convert -f raw -O vmdk openwrt-25.12.6-x86-64-generic-ext4-combined.img openwrt.vmdk
```

然后在项目根目录生成 VMX：

```powershell
python scripts/create_vm_config.py --role openwrt --disk "D:/lab/openwrt.vmdk" --output-dir "D:/lab/openwrt"
python scripts/create_vm_config.py --role ubuntu --disk "D:/lab/ubuntu.vmdk" --output-dir "D:/lab/ubuntu"
```

工具只创建新 VMX，已有文件会拒绝覆盖；不会操作磁盘或启动虚拟机。磁盘必须处于关机状态，不要将同一可写磁盘同时挂给多个运行实例。VMware 17 系列支持硬件版本 21；其他版本需自行检查兼容性。首次启动选择复制身份，生成新的 UUID / MAC。确认实际网卡名后再配置 LAN/WAN、防火墙、SSH 公钥与管理密码；仓库不复制旧设备的 network / wireless / shadow 配置。

## 2. Ubuntu 构建依赖

把仓库放在自己的工作目录，执行：

```bash
bash deploy/linux/install-build-deps.sh
```

脚本面向 Ubuntu 24.04，安装构建工具、Python venv、QEMU ARM、qemu-img 和 SSH 客户端；会使用 sudo / apt，不启动服务、不安装 Falco、不启用任何设备修复。

## 3. Zephyr 固件

从 [Zephyr SDK 官方发布](https://github.com/zephyrproject-rtos/sdk-ng/releases)自行安装支持 `arm-zephyr-eabi` 的 SDK，设置其路径后在一个不存在的新工作目录构建：

```bash
export ZEPHYR_SDK_INSTALL_DIR=/your/path/to/zephyr-sdk
bash deploy/linux/build-zephyr.sh /your/path/to/new-zephyr-workspace
bash firmware/zephyr-sensor-01/start-qemu.sh /your/path/to/new-zephyr-workspace/build-arm 8080
```

构建脚本创建 venv、初始化官方 Zephyr v4.4.2 west 工作区、下载模块、安装 Python 构建依赖、应用 SLCR MMU 补丁，再构建 `qemu_cortex_a9`；SDK 需提前安装，构建结果输出 ELF 哈希。失败会中止，不修改已有 west 工作区。原阶段源码包使用的 CMSIS 接线模块保留在固件目录，标准 west 模块下载不额外启用它。

ARM `start-qemu.sh` 为当前入口；`run_qemu.sh` 是保留的早期 x86 实验工具，不用于此基线。启用宿主熵通道时 QEMU 使用 semihosting，仅运行你信任的固件；该配置不是实体 TRNG。

启动后可检查：

```bash
python3 firmware/zephyr-sensor-01/verify_live.py --host 127.0.0.1 --port 8080
```

若希望作为系统服务运行，参考 `linux/iotguard-zephyr.service`：先自行创建非 root `iotguard` 用户，令仓库位于 `/opt/iotguard`、构建产物位于 `/opt/iotguard-zephyr/build-arm`，或者编辑模板指向实际路径。确认目录、可执行文件与权限后才安装、启用服务。模板不会自动开启防火墙入口。

## 4. Linux 采集节点

后端先在本地配置独立节点 ID / 令牌、授权网段，并在平台登记设备连接、公钥引用与经可信渠道验证的 SSH 指纹。设备私钥保存在采集节点，不上传。

复制 `linux/collection-node.env.example` 到 `/etc/iotguard/collection-node.env`，权限设为 `0600`，属主 root。填写后端基地址（不含 `/api`）、解析出的后端 IP/CIDR 白名单、节点身份与令牌、私钥路径。后端与节点使用同一节点令牌，控制令牌不作为节点令牌。

`linux/iotguard-collection-node.service` 假设已存在 `iotguard` 用户和 `/opt/iotguard` 仓库；确保该用户可读设备私钥、可执行 python3 / ssh / ssh-keyscan，再安装服务。systemd 读取环境文件，服务进程无需读取文件本身。默认修复开关为 0，不使用 root 节点作为自动修复捷径。

可先在已配置环境的终端以 `python3 backend/scripts/collection_node_runner.py --once` 验证任务领取，再启用常驻服务。

原宿主恢复脚本 `backend/scripts/restore_collection_node.py` 依赖本地历史授权回执，仅适用于原环境恢复，不是新机器初始化入口；重建请使用上述独立节点方式。

## 5. Falco 与前后端

Falco 按 [官方安装说明](https://falco.org/docs/setup/)安装；检查 `/sys/kernel/btf/vmlinux` 和驱动兼容性。规则与部署器在 [collector/deploy/falco](../collector/deploy/falco/README.md)，空白环境模板为 `linux/falco.env.example`。

既有 Falco 服务默认使用 `/opt/linuxguard` 和 `/etc/linuxguard/falco.env`，与新模板 `/opt/iotguard` 不同：部署前编辑服务的 `ExecStart` / `ExecStartPre` 或使用 systemd override 指向实际仓库，勿直接混用路径。Falco 需要相应内核权限；不在后端容器内启动。环境文件填写含 `/api` 的 API_BASE、登记资产 ID 与控制令牌，并设为 `0600`。

API、nginx、模型提供方、授权范围和令牌配置见 [部署说明](../DEPLOYMENT.md)及 `backend/.env.example`。模型配置保留兼容变量前缀 `DEEPSEEK_*`，不要求固定提供方；真实密钥只在本地注入。

## 6. 重建后验证

分别核对 API / 数据库、采集节点心跳、Falco / logread 状态与证据新鲜度；再验证设备身份、完整组件、公告覆盖、风险与复采。重建会产生新的设备身份，需要重新登记及钉扎。无需导入原数据库或模型输出即可启动代码；完整现场验收需按 [产品状态](../docs/STATUS.md)补齐。

这些模板经静态与本地工具验证；尚未在全新 VMware / Ubuntu 宿主执行端到端重建。
