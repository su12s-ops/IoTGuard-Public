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

Playwright 默认 Chromium，需先安装 `npx playwright install chromium`；Windows 使用已安装 Edge 时设置 `$env:PLAYWRIGHT_CHANNEL='msedge'`。测试夹具、模拟器与隔离数据库不是实体设备证据。

## CI 与联调范围

当前工作区 GitHub Actions 使用 Python 3.12、Node.js 24，在 Windows/Linux 执行完整后端回归，并执行前端构建与隔离 Chromium 浏览器回归。含套接字场景使用本机回环测试服务，非回环连接及真实 SSH 被测试钩子阻断。CI 与隔离夹具随本轮交付；本地工作区通过不等于远端 CI 已通过。

`python backend/scripts/live_discovery_check.py` 启动 SmartCam 本机服务和一次性测试库。现场设备验证需另行核对授权、配置、节点与服务。

## 验证边界

2026-10-19 整理前：前端构建成功；官方公告、IoT 业务与 Zephyr 管线专项共 21 项通过。依赖存在不阻塞构建的 PURE 注释警告。此结果不作为新提交的全量回归证明。

VMX 工具仅创建虚拟机配置，不创建磁盘、安装系统或启动虚拟机。Ubuntu / Zephyr 脚本提供重建入口，新宿主上的下载安装和完整构建仍需独立验证，不继承旧实例验收结论。

## 本次整理检查

- Ubuntu / OpenWrt 两种 VMX 参数均可生成，重复生成拒绝覆盖，非法网络名拒绝，测试磁盘内容保持不变。
- 两个新 Bash 脚本通过语法检查；所有当前 Markdown 本地链接有效。
- SLCR 补丁原先存在无效 hunk 计数和上下文格式，本次仅修正补丁格式；已对官方 v4.4.2 `soc.c` 通过 `git apply --check`。
- 尚未执行新主机 apt 安装、完整 west / SDK 构建或 VMware 导入启动。

## 2026-10-19 OpenWrt 闭环轮

- 后端全量回归 **761 passed / 0 failed**（含 OpenWrt 实验作用域写契约 5 项新测试：未配置拒绝、资产未声明拒绝、声明资产放行、生产开关不越权授实验、范围外资产 fail-closed）。
- 前端 `npm run build` 通过（PURE 注释警告不阻塞）；`docker compose config` 校验通过。
- 变更文件敏感扫描（令牌/私钥/控制令牌模式）0 命中；密钥、镜像、apk 与修复清单仅存于 gitignored `local-archive/`。
- 真实设备验证（只读）：OpenWrt-01 基线封存与 S0-Lab 匹配一致性实测，见 `IOTGUARD_OPENWRT_REAL_SECURITY_CLOSURE_REPORT.md`。

## 2026-10-19 完善程度检查及设备收尾

- 本轮代码修订前：宿主 Python 3.14.4 全量 **783 passed，5 warnings，786.37 秒**；前端 Edge **26 passed**，生产构建和 Compose 配置通过。5 条警告来自测试夹具的 `datetime.utcnow()`。
- 修正资产列表当前风险汇总后：资产风险、API 冒烟和 IoT 业务专项 **15 passed**，含新增 4 项回归；未将专项结果记为再次全量通过。
- 当前风险仅聚合 active 且未 resolved/inactive 的记录；无当前评估时返回 null 与 unassessed，不把历史 Critical 或空记录当作当前风险。
- 标准 Compose 显式关闭生产、Ubuntu 实验和 OpenWrt 实验三个修复开关，并清空 OpenWrt 实验作用域；未重建正在运行的 Docker 快照库。
- 真实只读设备验收及剩余项见 [设备验收](DEVICE_ACCEPTANCE.md)。本轮不重复历史软件包安装或快照恢复。
- 新正式复评约50分18秒后以 human_review 结束：三角色完成、漏洞角色证据引用校验未通过并降级；该真实结果不计为四角色全通过。接口重载后4个资产风险汇总核对、无令牌变更401及历史记录连续性检查通过；3/3传感器健康，证据新鲜。

## 2026-10-20 五项修复交付

具体代码、锁定依赖、安全扫描、真实 QEMU 及模型复评结果见 [本轮交付](DELIVERY_20261020.md)。Python 3.12 首轮全量 810 passed / 1 teardown error 的失败留存；修复测试线程方法名冲突后，最终代码 `4dfc91d` 的 Linux CI 为 817 passed / 3 skipped；Windows 托管回归已完成并通过。前端生产构建、26 项浏览器回归通过。

真实隔离模型标准预算复评耗时 1805.28 秒，四角色全部 succeeded、无 degraded；最终因部分证据与快照时效保持 pending_human_review，不代签业务接受。相关端口重启及 WAL 跨平台修复在本地 Windows/Linux 各 18 项通过。


最终虚拟设备验收报告：[`IOTGUARD_VIRTUAL_IOT_FINAL_ACCEPTANCE_REPORT.md`](../IOTGUARD_VIRTUAL_IOT_FINAL_ACCEPTANCE_REPORT.md)。当前提交对应 GitHub Actions Run `39299728933`：Windows/Linux 各 817 passed、3 skipped，前端 26 项通过。
