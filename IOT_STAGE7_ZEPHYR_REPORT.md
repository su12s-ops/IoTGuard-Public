# IoTGuard 第七阶段：Zephyr RTOS 异构终端接入报告

日期：2026-10-13 立项，2026-10-14 完成真实端到端联调。工作副本：`E:\IoTGuard-Project`。

## 1. Zephyr 版本与板级目标

| 项 | 值 |
|---|---|
| Zephyr 版本 | **v4.4.2**（官方最新稳定版，2026-08-07 发布） |
| SDK | sdk-ng **v1.0.1**（模块化：x86_64 GNU 工具链 65.5MB + hosttools 70.6MB + minimal cmake 70.7MB + arm-zephyr-eabi 工具链） |
| 板级目标 | **qemu_cortex_a9**（Zynq-7000 仿真；qemu_x86_64 路径因 e1000 驱动崩溃已弃用） |
| 工具链 | arm-zephyr-eabi（SDK GNU cross-compiler） |
| QEMU 运行时 | **系统 qemu-system-arm 8.2.2**（Ubuntu 24.04 apt 版，machine `xilinx-zynq-a9`；SDK 捆绑 QEMU 不含 32 位 ARM 机器，为先前阻塞根因之一） |
| 部署位置 | Ubuntu VM `~/zephyr-stage7/`（全部用户空间，零 sudo 依赖） |

## 2. 固件源码与构建结果

### 源码（`firmware/zephyr-sensor-01/`）

| 文件 | 说明 |
|---|---|
| `main.c` (~300 行) | 真实 Zephyr 应用：TCP 服务线程（zsock BSD socket API）+ DHCP 网络初始化（轮询模式）+ 模拟传感线程（原子量数据）+ /api/system JSON 身份接口（板级/固件版本/MAC/内核版本/遥测；arch 按编译期 `CONFIG_ARM`/`CONFIG_X86_64` 如实上报） |
| `prj.conf` | 网络（IPv4+TCP+Sockets+DHCP+**NET_QEMU_ETHERNET**，后者为 QEMU 目标板启用 eth_xlnx_gem 驱动的必要条件）+ 控制台（SERIAL+UART_CONSOLE）+ 线程栈 |
| `Kconfig` | 设备身份（name/vendor/model/UID/固件版本/端口号/传感间隔），通过 Kconfig 系统编译时注入 |
| `CMakeLists.txt` | 标准 Zephyr 应用构建 |
| `start-qemu.sh` | QEMU SLIRP + hostfwd 运行器（系统 qemu-system-arm + xilinx-zynq-a9 + `-nic user,model=cadence_gem`，入站 8080 → 固件 :80） |
| `stage7-cmsis-wiring/` | 实验室接线模块（Kconfig live 定义 + CMSIS 头文件 include 路径）：补偿源码包部署（非 git 仓库）下 west 模块发现不可用的环境缺口，非上游组件 |
| `patches/0001-*.patch` | Zephyr 树补丁：zynq7000 SoC 在 GEM 启用时映射 SLCR（eth_xlnx_gem 初始化要写 GEM 时钟分频寄存器，上游 soc.c 未映射 → 裸启翻译错误） |

### 构建产物（Ubuntu 实测，qemu_cortex_a9）

```
zephyr.elf  2,334,920 bytes  ELF 32-bit LSB executable, ARM EABI5, statically linked
RAM 964KB / 512MB（含完整网络栈：eth_xlnx_gem + IPv4 + TCP + DHCPv4 + Sockets）
```

构建命令（Ubuntu venv 内）：
```bash
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr ZEPHYR_SDK_INSTALL_DIR=~/zephyr-stage7/sdk
export ZEPHYR_EXTRA_MODULES=~/zephyr-stage7/firmware/zephyr-sensor-01/stage7-cmsis-wiring
west build -p always -b qemu_cortex_a9 -d build-arm .
```

依赖布局修正（源码包部署的历史遗留）：CMSIS 模块按 west 清单路径部署到
`modules/hal/cmsis` 与 `modules/hal/cmsis_6`（钉住 west.yml 中的 SHA），树内
兼容层 `modules/cmsis{,_6}/`（提供 `<cmsis_core.h>` 包装）保持原位——二者是
不同组件，此前混置于同一路径导致 Kconfig 双定义与头文件缺失。

## 3. IoTGuard 后端适配（增量，零架构变更）

| 文件 | 变更 |
|---|---|
| `services/discovery_pipeline.py` | +`ZEPHYR_UNSUPPORTED_CAPABILITIES` 常量 + `_capability_marks()` 函数（Zephyr 设备的 enrollment 证据自动标注 ssh/package/eBPF=unsupported） |
| `routers/iot.py` | capabilities 端点新增 `os_capability_profiles` 字段（Linux/OpenWrt vs Zephyr 的能力矩阵） |
| `services/device_inventory.py` | `build_identity()` 保留固件扩展元数据（board/soc/arch/build_id/device_id/status/uptime/telemetry → identity.metadata） |
| `tests/test_zephyr_pipeline.py` | 5 项专项测试（新增） |

## 4. 测试结果

### Mock 测试（5/5 通过）

| # | 测试 | 验证点 |
|---|---|---|
| 1 | `test_zephyr_discovery_enrollment_with_metadata` | HTTP 探测 → /api/system 身份识别（confidence=0.9）→ IotDevice 建档（device_type=os=firmware_version=os_version 全正确）→ 版本化组件（固件+httpd）→ CVE 匹配触发 → metadata 含 board/build_id/telemetry(simulated=true) → capabilities 三项 unsupported |
| 2 | `test_two_zephyr_instances_same_firmware_not_merged` | 同固件版本、不同 MAC/UID 的两台 Zephyr 设备 → 2 个独立 IotDevice，不合并；重复扫描幂等 |
| 3 | `test_zephyr_cve_three_tiers` | 精确层（厂商公告→affected/confidence=0.95）+ 候选层（NVD→potentially_affected）+ 无证据层（无关 CVE 不出现） |
| 4 | `test_zephyr_without_version_evidence_defers` | 无版本组件 → 零匹配（不伪造）；固件组件版本化仍可匹配 |
| 5 | `test_capabilities_expose_os_profiles` | capabilities API 返回 Zephyr/Linux 能力画像 |

### 回归（26/26 通过，2026-10-14 复跑确认）

Zephyr 5 + discovery_pipeline 9 + identity_edge_cases 5 + api_smoke 7 = 26 passed

### 真实联调（20/20 通过，见第 5 节）

backend/scripts/stage7_zephyr_live.py：预检 2 + 后端 2 + 发现/建档 6 + CVE 4 +
幂等 1 + 边界 3 + 组件 2 项（含清洁库诚实零命中与 TEST-FIXTURE 三层）。

## 5. 真实端到端联调（2026-10-14 完成，reports/zephyr-live-20261014-085507/）

### 运行链路（全真实，无模拟跳变）

```
Windows IoTGuard 后端(标准模式, 临时库)
  → 真实 TCP/HTTP 扫描 192.168.100.0/25（VMware VMnet2 实验 LAN）
    → Ubuntu 24.04 VM 的 VMnet2 地址:8080（SLIRP hostfwd 入口，具体地址见本地证据）
      → qemu-system-arm 8.2.2 (xilinx-zynq-a9, cadence_gem)
        → Zephyr v4.4.2 固件 :80（DHCP 获取 10.0.2.15，TCP 服务线程）
```

固件串口启动证据：`*** Booting Zephyr OS build 4.4.2 ***` → `dhcp ok` →
`zephyr-sensor-01 http on :80 (uid ZEPHYR-SENSOR-0001 fw 0.1.0-stage7)`。

### 运行器与验收点（backend/scripts/stage7_zephyr_live.py，20/20 PASS）

| # | 验收点 | 结果要点 |
|---|---|---|
| 0 | 固件预检 | 真实 HTTP 直连 /api/system：device_type=zephyr_sensor、os=Zephyr RTOS 4.4.2、board=qemu_cortex_a9、arch=arm、telemetry.simulated=true |
| 1 | 后端白名单+能力画像 | 192.168.100.0/24 白名单、repair=false、os_capability_profiles 含 Zephyr(unsupported)/Linux(OpenWrt supported) |
| 2 | 真实自动发现 | 单 /25 扫描（≤128 地址上限）端口 [22,80,443,8080]，Zephyr 设备上线 |
| 3 | 身份建档 | identity_source=device_identity_endpoint、confidence=0.9、os/device_type/firmware_version 全部来自固件自报 |
| 3 | 固件元数据 | metadata：board=qemu_cortex_a9、arch=arm、build_id、device_id、mac=00:00:00:01:02:03、telemetry(simulated=true) |
| 3 | 版本化组件 | "Zephyr-Sensor-01 firmware"=0.1.0-stage7 + "zephyr-sensor-httpd 0.1.0-stage7"=0.1.0-stage7 |
| 3 | 协议指纹 | :8080 http 服务 product=zephyr-sensor-httpd 0.1.0-stage7（设备自报覆盖） |
| 3 | 能力边界标注 | enrollment 证据 ssh_inventory/package_inventory/ebpf_runtime = unsupported（如实，不伪造） |
| 4 | CVE 诚实零命中 | 清洁临时库无公告/情报 → 0 命中（无证据 ≠ 无漏洞） |
| 5 | CVE 三层分级 | TEST-FIXTURE（仅一次性临时库）：厂商精确→affected/0.95/vendor_advisory；NVD 通用→potentially_affected/nvd_generic；无关 CVE 不出现 |
| 5 | 复扫幂等 | 二扫 enrolled_new=0、设备唯一、组件无重复（复扫同时自动重跑设备匹配） |
| 6 | 安全边界 | 未授权网段 400；harness/remediation 零副作用 |

### 联调过程中发现并修复的真实缺陷

1. **固件 JSON 拼接缺陷**（mock 测试无法暴露）：`"port":"port":80` 键重复导致
   /api/system 返回非法 JSON——后端将降级为横幅推断（0.35 置信）。真实探测发现后
   修复（b_num 自带键名，前置字面量不再重复写键）。
2. **上游 SoC 映射缺口**：eth_xlnx_gem 初始化写 SLCR GEM 时钟分频寄存器
   （gem reg idx 1 = 0xf8000140），soc.c 仅映射 gem reg idx 0 → 裸启翻译错误。
   以补丁补齐（patches/0001，8 行）。
3. **环境修正**：CMSIS 模块路径与 west 清单对齐（见第 2 节），west 工作区
   `.west/config` 重建（源码包部署无 git 仓库，west 模块发现不可用 → 以
   stage7-cmsis-wiring 显式模块补齐 Kconfig/include 接线）。

### NAT 拓扑边界（证据如实记录）

<ubuntu-vmnet2-addr>:8080 是 Ubuntu 宿主的 SLIRP hostfwd 入口，QEMU guest 固件经
NAT 呈现；:22/:80 属宿主服务（OpenSSH 9.6p1 组件来自宿主，宿主 :80 产品串被
固件自报 services 覆盖——设备自报优先的既有管线行为）。固件身份结论（os/
board/MAC/固件版本）全部来自固件自身 /api/system，不受宿主混入影响。

## 6. 与 OpenWrt 的差异

| 维度 | OpenWrt (阶段六) | Zephyr (阶段七) |
|---|---|---|
| OS 类型 | Linux 发行版 | RTOS |
| 发现方式 | TCP 端口扫描 + 协议横幅 | 相同（TCP 端口扫描 + HTTP 协议指纹） |
| 身份来源 | SSH 采集 (pinned_ssh_inventory) | HTTP /api/system (device_identity_endpoint) |
| SSH 采集 | ✅ 完整软件包/Board/MAC | ❌ unsupported（无 SSH 服务端） |
| 软件包管理 | apk (182 包) | ❌ unsupported（无包管理器） |
| CVE 匹配 | OpenWrt 精确版本 + 厂商公告 | IotDevice 组件 × IotDeviceAdvisory 精确版本 + NVD 候选 |
| eBPF 运行时 | ✅ bpftrace 探针 | ❌ unsupported |
| 修复 | Harness（默认关闭） | 同（默认关闭） |

## 7. 安全边界确认

- ✅ 未扩大授权网段白名单
- ✅ 未触发任何设备写操作/修复
- ✅ 固件不提供任何控制接口（只读 /api/system + HTML 页面）
- ✅ 遥测数据标记 `simulated: true`
- ✅ 设备 UID/MAC 来自编译配置与运行时状态，不伪造
- ✅ 未修改 Ubuntu 防火墙/OpenWrt 配置/SSH 设置
