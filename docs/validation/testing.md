# 构建与验证

## 本地回归

在仓库根目录使用独立 Python 虚拟环境，避免混入宿主其他项目依赖：

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
.venv/Scripts/python -m pip check
.venv/Scripts/python -m pytest -q --tb=short
npm --prefix frontend ci
npm --prefix frontend run build
node --test frontend/tests/*.test.js
python scripts/check_docs.py
git diff --check
```

Windows 本地浏览器回归使用已安装的 Edge，无需下载其他浏览器：

```powershell
cd frontend
$env:PLAYWRIGHT_CHANNEL='msedge'
npm run test:e2e
```

浏览器测试启动隔离 Vite 实例并拦截 API，不操作现场数据库。后端夹具使用临时库与回环测试服务，阻止真实 SSH 和非回环连接。CI 的 Linux 浏览器环境单独配置，不代表本地需要安装同一浏览器。

## CI

`.github/workflows/ci.yml` 使用 Python 3.12，在 Windows/Linux 执行后端回归，并在 Windows runner 上使用预装的 Microsoft Edge 运行前端浏览器测试，不下载 Chromium。`native-ebpf.yml` 在 Ubuntu 单独编译 CO-RE 探针并验证内核与传输行为。普通后端测试通过不代表内核探针兼容性通过。

本地结果、远端 CI 和现场验证分别记录。最新远端结论应绑定具体提交查看 [GitHub Actions](https://github.com/su12s-ops/IoTGuard-Public/actions)，不能沿用旧提交的通过数量。

## 协议与现场验证

- 模型计量回归核对：截断响应按实际用量计账、保留失败原因，不原样自动重发；后续请求仍受角色与整轮预算约束。无响应的网络超时允许有界重试，缺失用量不按估算值伪造。
- `backend/tests/test_review_completion_budget.py` 覆盖完整风险准入、并行额度隔离、等待归还、低预算/不足时限时的 0 调用延期、轮次剩余计数、迟到计量与落库回滚，以及单风险决策 Schema 和无消息循环时的报告交接。延期对象不能计为已研判，预留额度不能记成实际模型消耗。
- `backend/tests/test_iot_lan_simulator.py` 覆盖模拟设备身份、MQTT、JPEG/MJPEG、有限 RTSP、配置冲突及模拟状态。
- [LAN 模拟指南](../guides/openwrt-lan.md)记录单网关部署、DHCP 和协议实测方法。
- [黑盒检查](agent-blackbox.md)从公开 API 区分契约通过、角色降级与有效研判。
- [质量基准](agent-quality-bench.md)要求固定事实、相同真值、重复实验与失败留存。
- [设备验收](device-acceptance.md)要求身份、组件、适用性、执行与业务检查分别闭环。

现场至少检查 `GET /api/health`、每个资产的运行时覆盖、传感器心跳和证据时间。HTTP 200 只能证明对应接口返回，不能代替模型质量、漏洞适用性、24 小时稳定性或人工业务接受。

历史运行数量与失败见 [验证历史](../archive/2026-10-23-validation-history.md)和[当前开放问题](../status.md)。
