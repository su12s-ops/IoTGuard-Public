# 部署指南

## Docker

需要 Docker Engine / Docker Desktop 与 Docker Compose v2。在项目根目录复制配置并填写本地控制令牌及需要的模型配置：

```powershell
Copy-Item backend/.env.example backend/.env.docker
docker compose up -d --build
docker compose ps
Invoke-RestMethod http://127.0.0.1:18080/api/health
```

控制台与 API 统一入口为 <http://127.0.0.1:18080>，API 前缀为 `/api`。nginx 监听回环映射，FastAPI 8000 仅在容器网络内使用。镜像中不编入控制令牌，控制请求由服务端代理注入授权；不要将此本地控制入口直接开放到不可信网络。

后端非 root 运行，移除全部 capabilities，不使用 privileged。数据库保存在 `linuxguard-data` 命名卷中；新卷为空库，需要重新登记设备、节点、授权范围、情报与模型服务。升级前排空设备写入任务并进行一致性备份，保留原卷后重建镜像。

标准 Compose 固定关闭设备、Ubuntu 实验与 OpenWrt 实验修复开关。模型输出、控制令牌、设备写域和最终审批各自校验；详见 [权限模型](../reference/security-model.md)。

## 本地开发

需要 Python 3.12+ 和 Node.js 24。在项目根目录执行：

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
Copy-Item backend/.env.example backend/.env
Copy-Item frontend/.env.example frontend/.env
.venv/Scripts/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
# 另一终端，在根目录执行：
npm --prefix frontend ci
npm --prefix frontend run dev
```

打开 <http://localhost:5173>；Vite 将同源 `/api` 转发至本机 8000。API 文档仅在此开发后端提供：<http://127.0.0.1:8000/docs>。后端生命周期负责建表与迁移。

Python 虚拟环境、真实 `.env`、数据目录与依赖目录不提交。Linux/macOS 将 `.venv/Scripts/python` 替换为 `.venv/bin/python`，配置复制可使用 `cp`。

## 采集节点和设备

Compose 只运行平台；设备私钥与内核传感器位于外部 Linux 主机。新环境按 [环境重建](../../deploy/README.md)安装系统依赖、创建节点 ID/令牌并登记设备连接及 SSH 指纹。节点令牌不等于平台控制令牌。

Docker 接外部 Pull Runner 时，在 `backend/.env.docker` 显式设置：

```dotenv
LINUXGUARD_COLLECTION_EXECUTION_MODE=pull
```

`pull` 要求已登记可执行节点，不回退到容器 SSH；`auto` 保留平台默认路由；`local` 仅适用于具备合法本地采集环境的 Linux 后端。预检通过只说明元数据就绪，仍须核对采集任务终态、原文哈希和采集时间。

当前推荐实验拓扑是一台 OpenWrt 网关加四个 LAN 协议模拟器，不需要额外 OpenWrt 克隆。安装与维护见 [LAN 实验指南](openwrt-lan.md)。平台保留实验修复适配器供独立授权场景使用，不能据此默认开启设备写。

Falco 和原生 eBPF 的前提及部署分别见 [Falco 指南](../../collector/deploy/falco/README.md)与[原生采集器](../../collector/native/README.md)。OpenWrt 当前使用 logread，不把日志采集标记为 eBPF。

## 数据与生命周期

主机版与 Docker 默认使用不同数据库，数据不会自动同步；不要让两套工作进程同时操作同一个 SQLite 文件。迁移先停写，使用 SQLite backup API 做一致性复制，恢复后核对属主、权限、节点身份与连接引用。

控制台“刷新本轮”只在无活动流程、模型、同步及设备任务时执行，清理语义见 [控制台流程](../architecture/console-workflow.md)。旧归档接口保留兼容契约，不等于当前页面仍有旧归档面板。服务重启和页面刷新不应静默清空实验库。

`backend/data/`、`reports/`、`local-archive/` 和本地 Compose 覆盖均被忽略；原始证据和凭据不上传仓库。

## 常驻与恢复

Windows 可为已有独立 venv 注册当前用户登录任务：

```powershell
./deploy/windows/Register-IotGuardStartup.ps1 -PythonExe 'C:/path/to/venv/Scripts/pythonw.exe'
```

任务启动 `scripts/run_local_backend.py`，固定关闭设备写及启动清库开关，日志在 `backend/data/api-service.log`。这是登录恢复，不是无人登录时启动的系统服务。

Linux 的 `deploy/linux/` 提供后端、Pull Runner、情报同步和 Zephyr 的 systemd 模板。部署前调整实际路径、用户与配置文件权限，模板存在不等于目标机已启用。

需要不读取现场配置的临时实例时使用 [隔离运行指南](local-runtime.md)。重建与升级后的验证见 [验证方法](../validation/testing.md)，现场限制见 [当前状态](../status.md)。
