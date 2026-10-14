import os
import re
import sys
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import API_TITLE, API_VERSION, DATABASE_URL, DEEPSEEK_MODEL
from app.database import SessionLocal, init_db
from app.routers import analysis, assets, dashboard, demo, matching, remediation, reports, risk, runtime, vulnerabilities, workflow, traces
from app.routers import iot, harness, devices, agents, remediation_workflow, scans


# ── 启动时记录的诊断信息 ──
_startup_info = {
    "database_path": "",
    "database_absolute_path": "",
    "pid": os.getpid(),
    "started_at": datetime.now(timezone.utc).isoformat(),
    "instance_id": f"{os.getpid()}-{int(datetime.now(timezone.utc).timestamp())}",
    "python_executable": sys.executable,
    "working_directory": str(Path.cwd().resolve()),
}


def _env_enabled(name: str, default: str = "1") -> bool:
    value = os.getenv(name, default).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _cleanup_derived_data() -> None:
    """每次启动时清空衍生数据，只保留资产清单（LinuxAsset/AssetPackage/AssetService）。"""
    if not _env_enabled("LINUXGUARD_ARCHIVE_ON_STARTUP", "0"):
        print("[startup] LINUXGUARD_ARCHIVE_ON_STARTUP=0, 跳过清理，保留上次实验数据")
        return

    from app import models

    db = SessionLocal()
    try:
        asset_count = db.query(models.LinuxAsset).count()
        if asset_count == 0:
            print("[startup] 资产为空，跳过清理（全新状态）")
            return

        from app.services.experiment_lifecycle import clear_derived_data

        counts = clear_derived_data(db)

        total = sum(counts.values())
        print(f"[startup] 已清空衍生数据（共 {total} 条），保留 {asset_count} 个资产")
        for name, cnt in counts.items():
            if cnt > 0:
                print(f"  - {name}: {cnt} 条")

    finally:
        db.close()


def _cleanup_legacy_reports() -> None:
    """标记旧报告为 interrupted 或 legacy_failed。"""
    from app import models as m
    from datetime import datetime, timezone

    db = SessionLocal()
    try:
        for r in db.query(m.AnalysisReport).filter_by(status="running").all():
            r.status = "interrupted"
            r.termination_reason = "legacy_interrupted"
            r.completed_at = r.completed_at or datetime.now(timezone.utc)
        for r in db.query(m.AnalysisReport).filter(
            m.AnalysisReport.termination_reason.contains("max_turns")
        ).all():
            r.status = "legacy_failed"
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    # 记录数据库绝对路径
    _record_db_path()
    from app.services.device_access import collection_only_mode
    if not collection_only_mode():
        _cleanup_derived_data()
        _cleanup_legacy_reports()
    print(f"[startup] 实例ID: {_startup_info['instance_id']}")
    print(f"[startup] PID: {_startup_info['pid']}")
    print(f"[startup] 数据库: {_startup_info['database_absolute_path']}")
    print(f"[startup] 工作目录: {_startup_info['working_directory']}")
    yield


def _record_db_path():
    """解析并记录数据库文件的绝对路径。"""
    db_url = DATABASE_URL
    if db_url.startswith("sqlite:///"):
        rel_path = db_url.replace("sqlite:///", "", 1)
        abs_path = str(Path(rel_path).resolve())
        _startup_info["database_path"] = rel_path
        _startup_info["database_absolute_path"] = abs_path
    else:
        _startup_info["database_path"] = db_url
        _startup_info["database_absolute_path"] = db_url


app = FastAPI(title=API_TITLE, version=API_VERSION, lifespan=lifespan)


@app.middleware("http")
async def collection_profile_guard(request: Request, call_next):
    from app.services.device_access import collection_only_mode, require_control
    from fastapi import HTTPException
    if collection_only_mode() and request.url.path.startswith("/api/") and request.method != "OPTIONS":
        if request.url.path not in {"/api/health", "/api/iot/capabilities", "/api/demo/progress"}:
            try:
                require_control(request)
            except HTTPException as exc:
                return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        if request.method not in {"GET", "HEAD"}:
            path = request.url.path
            permitted = (
                request.method == "POST" and (path in {"/api/assets/upload", "/api/iot/connections", "/api/harness/runs"}
                    or re.fullmatch(r"/api/iot/connections/\d+/(?:collection-runs|collect)", path)
                    or re.fullmatch(r"/api/iot/collection-runs/[a-f0-9]{32}/execute", path)
                    or re.fullmatch(r"/api/harness/runs/[a-f0-9]{32}/(?:execute|cancel)", path))
                or request.method == "PUT" and re.fullmatch(r"/api/iot/connections/\d+", path))
            if not permitted:
                return JSONResponse(status_code=403, content={"detail": "联调采集模式禁止扫描、CVE 执行、运行时注入、旧演示及修复操作"})
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, exc: RequestValidationError):
    # Validation errors otherwise echo input values, including mistakenly submitted credentials.
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]})

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "service": "LinuxGuard",
                "database": "unavailable",
                "detail": str(exc) or type(exc).__name__,
            },
        )
    finally:
        db.close()

    return {"status": "ok", "service": "LinuxGuard", "database": "ok"}


@app.get("/api/diagnostics")
def diagnostics():
    """返回后端诊断信息（不含 API Key 等敏感数据）。

    包含数据库绝对路径、进程 PID、启动时间和实例 ID，
    用于排查因工作目录不同导致的"多个空数据库"问题。
    """
    from app.config import DEEPSEEK_BASE_URL

    return {
        "instance_id": _startup_info["instance_id"],
        "pid": _startup_info["pid"],
        "started_at": _startup_info["started_at"],
        "python_executable": _startup_info["python_executable"],
        "working_directory": _startup_info["working_directory"],
        "database": {
            "url_template": _startup_info["database_path"],
            "absolute_path": _startup_info["database_absolute_path"],
        },
        "model": {
            "provider": "DeepSeek",
            "model": DEEPSEEK_MODEL,
            "base_url": DEEPSEEK_BASE_URL,
            "configured": bool(os.getenv("DEEPSEEK_API_KEY", "")),
        },
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """全局异常处理：确保任何未捕获的异常都返回结构化的错误信息。"""
    from app.services.device_access import collection_only_mode
    if collection_only_mode():
        print(f"[ERROR] {request.method} {request.url.path}: {type(exc).__name__}")
        return JSONResponse(status_code=500, content={"error": True, "detail": "联调服务异常；错误内容已脱敏，请查询采集任务状态", "type": type(exc).__name__})
    detail = str(exc) if str(exc) else type(exc).__name__
    print(f"[ERROR] {request.method} {request.url.path} — {detail}")
    traceback.print_exc()
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "detail": detail,
            "type": type(exc).__name__,
            "path": request.url.path,
        },
    )


app.include_router(dashboard.router, prefix="/api")
app.include_router(vulnerabilities.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(matching.router, prefix="/api")
app.include_router(risk.router, prefix="/api")
app.include_router(remediation.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(workflow.router, prefix="/api")
app.include_router(runtime.router, prefix="/api")
app.include_router(demo.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(iot.router, prefix="/api")
app.include_router(harness.router, prefix="/api")
app.include_router(devices.router, prefix="/api")
app.include_router(agents.router, prefix="/api")
app.include_router(remediation_workflow.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
app.include_router(traces.router, prefix="/api")
