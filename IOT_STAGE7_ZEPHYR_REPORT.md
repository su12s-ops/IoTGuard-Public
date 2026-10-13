# IoTGuard 第七阶段：Zephyr RTOS 异构终端接入报告

日期：2026-10-13。工作副本：`E:\IoTGuard-Project`。

## 1. Zephyr 版本与板级目标

| 项 | 值 |
|---|---|
| Zephyr 版本 | **v4.4.2**（官方最新稳定版，2026-08-07 发布） |
| SDK | sdk-ng **v1.0.1**（模块化：x86_64 GNU 工具链 65.5MB + hosttools 70.6MB + minimal cmake 70.7MB） |
| 板级目标 | **qemu_x86_64**（Zephyr 官方虚拟板级，Intel Atom/q35 仿真） |
| 工具链 | x86_64-zephyr-elf（SDK GNU cross-compiler） |
| 部署位置 | Ubuntu VM `~/zephyr-stage7/`（全部用户空间，零 sudo 依赖） |

## 2. 固件源码与构建结果

### 源码（`firmware/zephyr-sensor-01/`）

| 文件 | 说明 |
|---|---|
| `main.c` (~290 行) | 真实 Zephyr 应用：TCP 服务线程（zsock BSD socket API）+ DHCP 网络初始化（轮询模式）+ 模拟传感线程（原子量数据）+ /api/system JSON 身份接口（板级/固件版本/MAC/内核版本/遥测，全部来自编译配置 `CONFIG_*` 或运行时 `sys_kernel_version_get()` / `net_if_get_link_addr()`） |
| `prj.conf` | 网络（IPv4+TCP+Sockets+DHCP）+ 控制台（SERIAL+UART_CONSOLE+EARLY_CONSOLE）+ 线程栈 |
| `Kconfig` | 设备身份（name/vendor/model/UID/固件版本/端口号/传感间隔），通过 Kconfig 系统编译时注入 |
| `CMakeLists.txt` | 标准 Zephyr 应用构建 |
| `start-qemu.sh` | QEMU SLIRP + hostfwd 运行器（入站 18080 → 固件 :80） |
| `run_qemu.sh` | 备用运行器 |

### 构建产物（Ubuntu 实测）

```
zephyr.elf                5,709,080 bytes  ELF 64-bit x86-64, statically linked
zephyr-qemu-locore.elf       28,600 bytes  ELF 32-bit i386 (multiboot 引导)
zephyr-qemu-main.elf      5,658,912 bytes  ELF 64-bit x86-64 (主应用)
```

构建命令：
```bash
cmake -B build -GNinja -DBOARD=qemu_x86_64 \
  -DZephyr-sdk_DIR=.../sdk/cmake \
  -DZEPHYR_TOOLCHAIN_VARIANT=zephyr -DZEPHYR_SDK_INSTALL_DIR=.../sdk
ninja -C build && ninja -C build qemu_kernel_target
```

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

### 回归（26/26 通过）

Zephyr 5 + discovery_pipeline 9 + identity_edge_cases 5 + api_smoke 7 = 26 passed

## 5. 阻塞项：QEMU 运行

**阻塞描述**：SDK 捆绑 QEMU v10.0.2 加载 locore ELF 后，Zephyr 内核不产生任何串口输出（SeaBIOS → iPXE → "Boot from ROM" 后挂起）。已尝试：

1. `-kernel locore.elf -device loader,main.elf`（Zephyr 官方 x86_64 QEMU 启动方式）
2. `-kernel zephyr.bin`（32 位原始二进制）
3. `-kernel locore.elf -initrd main.bin` + `-machine pc`
4. `-cpu qemu64,+x2apic` / `-cpu kvm64` / `-cpu qemu64`
5. 添加 `CONFIG_CONSOLE/SERIAL/UART_CONSOLE/EARLY_CONSOLE` 后重建

**根因**：SDK 捆绑的 QEMU v10.0.2 与 Zephyr v4.4.2 的 locore 启动链在 x86_64 上存在兼容性问题（内核加载后未执行到 C 入口点）。Ubuntu VM 无 sudo 权限 → 无法安装系统 QEMU（版本 < v10）或 GCC（native_sim 也不可用）。

**解决方案**（需人工操作）：
```bash
# 在 Ubuntu 控制台执行：
sudo apt install qemu-system-x86
# 或
sudo apt install gcc build-essential  # 解锁 native_sim 路径
```

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
