# LinuxGuard 真实数据验证启动顺序

## Docker 方式

```powershell
cd <工程根目录>\Docker配置
docker compose up --build
```

访问 `http://localhost:5173`，后端 API 为 `http://localhost:8000/api`。

## 本地方式

1. 启动后端：

```powershell
cd <PROJECT_ROOT>\代码\backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

2. 同步真实漏洞情报：

```powershell
cd <PROJECT_ROOT>\代码\backend
python scripts\sync_real_intel.py --keyword linux --days 30 --limit 100
```

3. 启动前端：

```powershell
cd <PROJECT_ROOT>\代码\frontend
npm.cmd install
npm.cmd run dev
```

4. 打开浏览器访问：

```text
http://localhost:5173
```
