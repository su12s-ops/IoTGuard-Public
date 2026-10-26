# OpenWrt LAN 多设备模拟接入

2026-10-26。本文采用单台 OpenWrt 网关、LAN 下独立 IP 的实验方式。地址来自 `simulator/lan_devices.json` 示例配置；用于其他网络前须调整网关、IP/MAC 与授权范围，检查冲突。当前实例已部署并接入平台。

## 当前设备

| 设备 | DHCP 地址 | 独立 MAC | 服务 |
|---|---|---|---|
| 模拟摄像头 01 | 192.168.100.20 | 02:49:4f:54:00:20 | HTTP 80/8080、MQTT 1883、RTSP 554 发现 |
| 模拟摄像头 02 | 192.168.100.21 | 02:49:4f:54:00:21 | HTTP 80/8080、MQTT 1883、RTSP 554 发现 |
| 模拟温湿度传感器 01 | 192.168.100.22 | 02:49:4f:54:00:22 | HTTP 80/8080、MQTT 1883 |
| 模拟智能插座 01 | 192.168.100.23 | 02:49:4f:54:00:23 | HTTP 80/8080、MQTT 1883、模拟开关 |

网关原有 LAN 为 `192.168.100.0/24`，动态池 `.100–.249`。这四个池外地址通过 dnsmasq 静态租约分配，udhcpc 实际完成 DHCP 申请并常驻续租。设备分别位于 `ig-cam01`、`ig-cam02`、`ig-sensor01`、`ig-plug01` 网络命名空间，通过独立 veth 端口接入现有 `br-lan`。没有重配 LAN/WAN 地址、重启网关或启用 WAN 端口转发。

这是共享 OpenWrt 内核的协议与业务状态模拟，不是四份独立固件或物理硬件。设备自报厂商为 `IoTGuard Lab`、固件 `sim-1.0.0`，身份、遥测与图片均标明模拟，不伪造厂商组件或已确认 CVE。平台保留 simulation、网关、媒体能力等元数据，资产详情可打开各设备页面。

## 使用

在本机浏览器打开：

- 摄像头：[01](http://192.168.100.20:8080/) / [02](http://192.168.100.21:8080/)。`/stream.mjpg` 为 640×360、2 fps 的动态测试图，`/snapshot.jpg` 为当前 JPEG。
- [温湿度传感器](http://192.168.100.22:8080/)：温湿度随时间变化，`/api/telemetry` 返回数值。
- [智能插座](http://192.168.100.23:8080/)：页面按钮或 `POST /api/switch` 的 `{"power":true}` / `{"power":false}` 切换模拟负载。

四台设备均提供 `/api/system` 只读身份端点。MQTT 3.1.1 支持匿名实验连接、订阅、PING、QoS 0/1 的模拟命令。每两秒发布 `iotguard/<id>/telemetry`，插座命令主题为 `iotguard/plug01/set`，负载同 HTTP 开关格式。匿名接入是明确的模拟暴露条件，平台按真实 CONNACK 记录，未对其虚构漏洞。

摄像头 RTSP 实现 OPTIONS/DESCRIBE；PLAY 返回 501，身份中明确 `rtp=false`。实际连续画面使用 HTTP MJPEG，不宣称支持完整 RTSP/RTP 播放。

当前 Windows 访问 80 正常，但 Docker 后端对 80 的 HTTP 探测超时；同 IP 的 8080 实测正常。因此平台登记的发现端口为摄像头 `554,1883,8080`，其他设备 `1883,8080`。增加了兼容入口，没有将未识别的 80 端口伪装成已成功探测。

## 部署文件与维护

- `simulator/lan_devices.json`：四设备配置及地址/MAC；更换网络时先调整此文件。
- `simulator/lan_device.py`：每台设备独立运行的协议与模拟状态服务，只依赖 Python 标准库。
- `simulator/openwrt_lan.py`：地址与身份冲突检查、静态租约、命名空间及桥端口准备。
- `simulator/openwrt-iot-lab.init`：安装为 `/etc/init.d/iotguard-lan`，procd 分别监督四个 DHCP 客户端和四个设备进程。
- `simulator/udhcpc.script`：只在设备命名空间内配置 DHCP 地址与默认路由。
- `simulator/frames/`：可复现的合成 JPEG 帧；可在有 Pillow 的构建机执行 `python simulator/build_test_frames.py` 重新生成，路由器不需要 Pillow。

OpenWrt 依赖为 `ip-full kmod-veth python3-light python3-urllib python3-email`。本轮使用与原机内核匹配的官方仓库索引与 APK，保持签名和仓库内容校验；没有使用 `--allow-untrusted`。因原机直连仓库超时，通过本机 TLS 校验下载官方原始索引与包，再用本地签名索引按包名离线安装。只新增 11 个依赖包，原有软件包未升级，根分区仍有约 59 MiB 可用。

一般部署步骤是在自己的 OpenWrt 上安装上述依赖，将模拟器文件和 frames 目录复制到 `/opt/iotguard-lan/`，将 init 文件安装为 `/etc/init.d/iotguard-lan` 并赋予执行权限，再执行：

```sh
chmod 755 /etc/init.d/iotguard-lan /opt/iotguard-lan/udhcpc.script
/etc/init.d/iotguard-lan start
/etc/init.d/iotguard-lan enable
```

这些命令只适用于已核对配置、完成备份且允许创建实验设备的网关；配置检查拒绝非预期网关、重复 IP/MAC、已有占用地址和不属于本工具的 DHCP 条目。

日常维护：

```sh
/etc/init.d/iotguard-lan restart
ubus call service list '{"name":"iotguard-lan"}'
ip netns list
cat /tmp/dhcp.leases
```

停止并移除虚拟链路：

```sh
/etc/init.d/iotguard-lan stop
/etc/init.d/iotguard-lan disable
python3 /opt/iotguard-lan/openwrt_lan.py stop
```

此操作保留四条 `dhcp.iotguard_*` 地址预约。若不再使用，再分别删除这四个命名配置节并提交 dhcp、reload dnsmasq；不要删除已有其他主机的租约配置。实际网关配置备份保存在本机被忽略的 `reports/iot-lan-20261026/router-config-before.tar.gz`。

## 本轮实际验证

- 网关 DHCP 租约中出现四个独立 MAC、主机名与预定 IP；桥上存在四个独立 veth 端口。
- 八个 procd 实例均运行，服务已启用；仅终止摄像头 02 的模拟进程后，约 7 秒自行恢复。没有执行整机重启验证。
- 四台 HTTP 身份端点与 MQTT 实际订阅通过；温湿度连续两次发布发生变化。
- 两台摄像头实际返回 JPEG、MJPEG 帧及 RTSP OPTIONS 响应。
- 通过 MQTT 打开模拟插座，再通过 HTTP 关闭，读取状态一致。
- 平台通过真实协议发现建立四个不同设备 ID，并登记四个精确授权扫描目标；白名单只新增这四个 `/32`，未开放整个 LAN 网段。
- 通过原有 Linux pull 节点完成网关新清单采集，任务 `7bf89b5672afd0df06206ab6d5d13206`，SSH 身份钉扎通过，193 个包、完整清单与原始证据回执已落库。

平台设备 ID：摄像头 01 `DEV-59F22F0A68B6`，摄像头 02 `DEV-E9C22E50D6FE`，温湿度 `DEV-297A2044DF55`，插座 `DEV-AA0E8297EE3C`。初次 80 端口失败产生的本任务临时未识别行已先备份、确认无依赖后撤销，保留四个 MAC 身份记录。

设备新增测试覆盖独立身份、真实 MJPEG、RTSP 能力边界、MQTT 订阅与插座控制、中文配置、重复地址拒绝及备用 HTTP 入口。现有设备发现与业务视图回归通过。部署材料、签名包来源与哈希、协议回执保存在被 Git 忽略的 `reports/iot-lan-20261026/`。

本轮交付为 LAN 接入与协议模拟；设备漏洞适用性、真实固件、实体驱动和这些新设备的正式多智能体研判不作为已完成事项。参考 [OpenWrt DHCP 配置](https://openwrt.org/docs/guide-user/base-system/dhcp_configuration)与 [ip-full 软件包](https://openwrt.org/packages/pkgdata/ip-full)。
