# IoTGuard 实际链路连通性测试

测试时间：2026-10-18 22:57–22:59（北京时间）。对象是既有 OpenWrt VMware 实例和 Zephyr QEMU 实例，未以新建模拟资产替代。

## 结果

26 项入口、节点、服务和回传检查全部通过；另通过 Zephyr 原 8080 入口的 HTTP 健壮性回归。此结论覆盖本次测试窗口，不等于长期可用性或全漏洞修复验收。

| 链路 | 实测结果 |
|---|---|
| Windows → 5173 前端、8000 实时 API | HTTP 200；localhost:5173 跨域携带控制请求头预检通过 |
| Windows → 18080 页面及 API、18000 API、18001 实验 API | 均 HTTP 200；这些独立环境不能视作实时资产已同步 |
| Windows → Ubuntu SSH | 使用既有密钥及严格主机身份校验执行成功 |
| Ubuntu → Windows 192.168.183.1:8000 | 健康接口 HTTP 200 |
| Ubuntu → OpenWrt | SSH 钉扎验证及认证成功；管理 HTTP 200；DNS、默认路由、外网 HTTPS 正常；dnsmasq/uhttpd/dropbear running |
| 实时后端 → 节点 → OpenWrt → 台账 | 新采集 completed，182 包完整解析，inventory_complete=true，系统 25.12.6 |
| 实时后端 → Zephyr 8080 → 台账 | 同一 UID，应用 0.3.0-iotguard，刷新成功 |
| Ubuntu → Zephyr | 连续 10 次身份接口 HTTP 200；systemd active，Linger=yes |
| Windows → Zephyr 8080 | 合法身份、分片、空闲/超长请求恢复、非法路径/方法/请求行拒绝、连续 20 次请求全部通过 |
| OpenWrt 日志 → 节点 → 后端 | completed，新增 8 条，去重 1,242 条，未截断；9 行无法解析 |

26 项计数来自本地 9 项、Ubuntu 侧 15 项及补充 2 项；Zephyr 协议回归另计。Windows → Ubuntu SSH 同时是远端 15 项的执行前提。

## 新增闭环证据

- OpenWrt 资产采集：`e68ad55283dd7df64438881d521e8ae2`；trace `TR-20261018145733-573f5a`。执行节点 `m45-linux-node`，节点认证、SSH 身份校验及认证均成功，约 2 秒读回 completed。
- Zephyr 实时刷新：`TR-20261018145733-12bf51`。
- OpenWrt 日志：`3040884d5588d7d27cf5cb99c9d312ab`；trace `TR-20261018145814-c0dc76`，证据 `LOG-3040884d5588d7d27cf5cb99c9d312ab`。
- 本地原始证据位于忽略目录 `reports/iot-update-20261018/`：`connectivity-local.json`、`connectivity-remote.json`、`connectivity-extra.json`、`connectivity-collection.json`、`connectivity-runtime-logs.json`、`zephyr-connectivity-regression.json`。未公开控制令牌或密钥。

## 使用入口及边界

查看本次真实实例数据使用 `http://localhost:5173`，开发前端默认 API 为 `http://localhost:8000/api`。`http://localhost:18080` 的 nginx 代理到独立 Docker backend（宿主 18000），不是本次实时后端；18001 也是独立实验后端。本次未改写这些环境的数据或代理。前端验证覆盖页面交付、API 地址配置及 CORS，未执行浏览器逐页点击验收。

OpenWrt 预检的 Windows 本地采集能力为 false，但远端节点已配置且 ready=true；本次通过实际远端任务完成验证。日志拉取不证明常驻监控零丢失，环形缓冲已经覆盖的历史行数量未知。Zephyr 温湿度仍为模拟值，熵来自 QEMU 宿主 urandom 通道，非实体 TRNG。

官方公告入库、配置感知适用性、签名 OTA 和实体硬件验收仍有缺口；Zephyr 安全状态保持 unassessed，连通性通过不代表不存在漏洞。
