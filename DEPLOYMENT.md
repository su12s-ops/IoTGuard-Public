# 部署说明

## Docker

在根目录复制 `backend/.env.example` 为 `backend/.env.docker`，本地填写控制令牌、模型接口及其他必需参数。三个修复开关保持 0；标准 Compose 将其固定为 0，并清空 OpenWrt 实验作用域。

```powershell
$env:IOTGUARD_BUILD_REVISION = git rev-parse HEAD
$env:IOTGUARD_BUILD_DATE = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://127.0.0.1:18000/api/health
```

nginx 工作台位于 <http://127.0.0.1:18080>，后端位于 <http://127.0.0.1:18000>；仅回环绑定。前端采用 Node.js 24 / npm ci / Vite 多阶段构建，运行时由 nginx 提供 SPA 和 `/api` 反代。后端以非 root 运行、cap_drop ALL、无 privileged，数据库位于命名卷。

全新卷启动为空库，设备、节点、情报、模型接口和授权需另行配置。运行中的采集节点不会自动获得新库身份和令牌。后端容器不加载 eBPF、不存设备私钥；采集节点和 Falco 在外部 Linux 主机运行。

## 本地开发

Python 3.12+、Node.js 24，在根目录执行：

```powershell
Copy-Item backend/.env.example backend/.env
Copy-Item frontend/.env.example frontend/.env
python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
# 新终端
cd frontend
npm ci
npm run dev
```

前端 <http://localhost:5173>，API <http://localhost:8000/api>。uvicorn 命令通过应用生命周期建表及迁移；不要把遗留阶段启动器当作新环境初始化入口。

## 软件与设备配置

参见 [环境重建指南](deploy/README.md)：VMware 参数、Ubuntu / OpenWrt 重建、Zephyr 构建、Pull Runner、Falco 和 systemd 模板。环境变量示例不包含真实凭据。扫描范围、节点注册和主机指纹由操作员在新环境重新配置。

设备写入相关配置包括生产开关 `LINUXGUARD_ENABLE_DEVICE_REPAIR`、Ubuntu 实验作用域（`LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR` + `LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE`）、OpenWrt 实验作用域（`LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR` + `LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE`）。OpenWrt 最终安装与回退先核验持久 `repair_domain`：`production` 仅使用生产开关；`openwrt_lab` 必须同时满足实验开关和精确资产范围，生产开关不能越权；`unassigned` 拒绝写入。登记及计划绑定见 [权限规范](docs/SECURITY_MODEL.md)；标准部署全部保持 0。

OpenWrt-Lab 隔离克隆（VMware）与管理网段、专用采集密钥（`LINUXGUARD_DEVICE_OPENWRT_LAB_KEY`）的接线见 `IOTGUARD_OPENWRT_REAL_SECURITY_CLOSURE_REPORT.md` 与 `deploy/README.md`；修复产物注册表经 `LINUXGUARD_REPAIR_MANIFEST` 挂载，产物与检查脚本须 SHA256 登记且位于清单目录内。

## 数据与检查

本地开发与 Docker 默认使用独立数据库，不能把同一 SQLite 文件同时交给两个工作实例。原 Docker 验证库是宿主库的时间点备份，不是实时采集库。迁移或恢复先停写、排空任务、使用 SQLite 一致性备份，再核验文件属主及权限；不要改为 root 运行解决权限问题。

检查 SPA 根页和深层路由、资源文件、业务 API 及 `/api/health` 的四层状态：backend、collection node、sensor、runtime evidence。全局证据新鲜可能仅由一个资产满足，须再核对每个设备。构建成功与 HTTP 200 不能代替设备与漏洞验收。

镜像源失败应修复网络或 registry mirror 后重试；已有基础镜像的增量发布不能作为从零依赖重建证明。当前环境限制见 [产品状态](docs/STATUS.md)。

## 2026-10-20 升级与常驻运行

先确认无活动安装/复评及资产锁，使用 SQLite backup API 做一致性备份，再部署代码与 `requirements.txt`（自动引用审计过的 `requirements-constraints.txt`）。旧 OpenWrt 资产迁移为 `unassigned`，不会默认获得生产或实验写权限；旧审批不能直接安装。清单、历史风险及失败回执不删改。演示密码如仍在旧库中，须迁移为专用环境变量引用并重新保存目标；当前验收库无此类明文行。

Windows 可在已安装依赖的独立 venv 中注册当前用户登录任务：

```powershell
./deploy/windows/Register-IotGuardStartup.ps1 -PythonExe 'C:/path/to/venv/Scripts/pythonw.exe'
```

任务 `IoTGuard-API` 为当前用户非提权进程：登录自动启动、失败一分钟后重试、拒绝并行实例；启动脚本固定关闭三个修复开关和启动清库开关。日志写到被 Git 忽略的 `backend/data/api-service.log`。这是登录恢复，不是无人登录的 Windows 启动服务；本轮没有重启宿主操作系统。需要删除本轮任务时，使用 `Unregister-ScheduledTask -TaskName IoTGuard-API`，不要关闭无关任务。

Linux 的 `deploy/linux/iotguard-backend.service`、`iotguard-intel.service` 和 `iotguard-intel.timer` 提供 API 重启与每日官方公告同步入口。服务运行于 `iotguard` 用户；配置文件为 `/etc/iotguard/backend.env`（root 持有、0600）。同步只刷新快照，不自动修复设备或关闭风险。模板仍需在目标宿主安装并启用，不能把文件存在算作已部署。

连续观察：

```powershell
python scripts/observe_runtime.py --seconds 86400 --interval 30 --output reports/runtime-observation.jsonl
```

输出独立记录 API、节点、传感器与证据新鲜度；任何失败以非零退出，丢失计数保持未知。短窗口通过不等于 24 小时或宿主重启验收。
