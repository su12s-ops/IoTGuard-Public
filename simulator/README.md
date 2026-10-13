# SmartCam-X1 智能摄像头模拟器（阶段一测试设备）

一个只依赖 Python 标准库的智能摄像头设备模拟器，真实监听四个服务，
供 IoTGuard 后端做在线发现与服务识别（不是 mock：所有识别都来自真实协议交互）。

| 服务 | 默认端口 | 说明 |
| --- | --- | --- |
| SSH | 22 | 优先 paramiko 完整握手（服务端横幅 `dropbear_2022.83`）；无 paramiko 时退化为真实版本横幅交换 |
| HTTP | 80 | 嵌入式 Web 管理页（`/`）与只读身份接口（`/api/system`，JSON） |
| MQTT | 1883 | MQTT 3.1.1 最小 broker：CONNECT/CONNACK、PING、SUBSCRIBE、PUBLISH（含通配符转发）；接受匿名接入 |
| RTSP | 554 | RTSP/1.0 控制面：OPTIONS/DESCRIBE(SDP)/SETUP/PLAY；RTP 媒体面未实现 |

设备身份：SmartCam Technologies SmartCam-X1，固件 2.4.7（身份通过 `/api/system` 由设备自报，
后端 `device_inventory.build_identity` 优先采信设备身份接口，其次横幅推断）。

## 本地运行

```bash
python 代码/simulator/smartcam_x1.py                       # 标准端口
python 代码/simulator/smartcam_x1.py --http-port 8080 --ssh-port 22022 --mqtt-port 21883 --rtsp-port 28554
```

后端发现该设备需要（`backend/.env`）：

```
LINUXGUARD_CONTROL_TOKEN=<操作令牌>
LINUXGUARD_DISCOVERY_CIDRS=127.0.0.0/8
```

然后在前端「智能设备中心」输入 `127.0.0.1` 与对应端口执行发现。

## Docker 运行

`Docker配置/docker-compose.yml` 已内置 `smartcam` 服务（固定 IP `172.28.0.20`，
后端默认允许 `172.28.0.0/24`）。`docker compose up --build` 后在「智能设备中心」发现 `172.28.0.20`。

## 测试

设备本身的真实性由后端测试 `backend/tests/test_iot_device_upgrade.py` 直接拉起本模拟器验证：
横幅/页面/CONNACK/OPTIONS 逐协议断言，发现 API、幂等性、令牌与网段边界逐项覆盖。
