# 构建与验证

## 本地命令

```powershell
# 根目录
python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
python -m pytest -q
cd frontend
npm ci
npm run build
npm run test:e2e
```

Playwright 使用 Microsoft Edge；测试夹具、模拟器与隔离数据库不是实体设备证据。

## CI 与联调范围

GitHub Actions 使用 Python 3.12、Node.js 24，执行后端常规回归及前端构建。CI 当前排除四个含真实套接字场景的文件：`test_iot_device_upgrade.py`、`test_scan_runs.py`、`test_scan_targets.py`、`test_mqtt_remediation_workflow.py`；需在支持本机回环监听的环境单独验证。CI 通过不代表现场联调完成。

`python backend/scripts/live_discovery_check.py` 启动 SmartCam 本机服务和一次性测试库。现场设备验证需另行核对授权、配置、节点与服务。

## 验证边界

2026-10-19 整理前：前端构建成功；官方公告、IoT 业务与 Zephyr 管线专项共 21 项通过。依赖存在不阻塞构建的 PURE 注释警告。此结果不作为新提交的全量回归证明。

VMX 工具仅创建虚拟机配置，不创建磁盘、安装系统或启动虚拟机。Ubuntu / Zephyr 脚本提供重建入口，新宿主上的下载安装和完整构建仍需独立验证，不继承旧实例验收结论。

## 本次整理检查

- Ubuntu / OpenWrt 两种 VMX 参数均可生成，重复生成拒绝覆盖，非法网络名拒绝，测试磁盘内容保持不变。
- 两个新 Bash 脚本通过语法检查；所有当前 Markdown 本地链接有效。
- SLCR 补丁原先存在无效 hunk 计数和上下文格式，本次仅修正补丁格式；已对官方 v4.4.2 `soc.c` 通过 `git apply --check`。
- 尚未执行新主机 apt 安装、完整 west / SDK 构建或 VMware 导入启动。
