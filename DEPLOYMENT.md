# 部署说明

## Docker

在根目录复制 `backend/.env.example` 为 `backend/.env.docker`，本地填写控制令牌、模型接口及其他必需参数。两个修复开关保持 0；Compose 也将它们固定为 0。

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

## 数据与检查

本地开发与 Docker 默认使用独立数据库，不能把同一 SQLite 文件同时交给两个工作实例。原 Docker 验证库是宿主库的时间点备份，不是实时采集库。迁移或恢复先停写、排空任务、使用 SQLite 一致性备份，再核验文件属主及权限；不要改为 root 运行解决权限问题。

检查 SPA 根页和深层路由、资源文件、业务 API 及 `/api/health` 的四层状态：backend、collection node、sensor、runtime evidence。全局证据新鲜可能仅由一个资产满足，须再核对每个设备。构建成功与 HTTP 200 不能代替设备与漏洞验收。

镜像源失败应修复网络或 registry mirror 后重试；已有基础镜像的增量发布不能作为从零依赖重建证明。当前环境限制见 [产品状态](docs/STATUS.md)。
