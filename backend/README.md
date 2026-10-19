# IoTGuard Backend

FastAPI + SQLAlchemy + SQLite；统一四智能体与 Harness。需 Python 3.12+。

```powershell
# 项目根目录
Copy-Item backend/.env.example backend/.env
python -m pip install -r backend/requirements.txt -r backend/requirements-test.txt
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
python -m pytest -q
```

本地填写模型接口、控制令牌与授权范围。`.env.example` 为变量规范；真实凭据不提交。正式流水线为 on，两个修复开关默认 0。

- API 文档：<http://127.0.0.1:8000/docs>
- 健康分层：`GET /api/health`
- IoT 工作台：`GET /api/devices/business/overview`
- 官方覆盖：`GET /api/devices/official-coverage/{ecosystem}?version=...`
- 正式研判：`/api/analysis`
- 设备与节点：`/api/iot`、`/api/devices`
- 运行时、执行与追踪：`/api/runtime`、`/api/harness`、`/api/traces`

详见 [部署](../DEPLOYMENT.md)、[权限治理](../docs/SECURITY_MODEL.md)及[验证范围](../docs/VALIDATION.md)。
