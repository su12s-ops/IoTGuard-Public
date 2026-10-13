"""互联网授权目标主动扫描（阶段六）。

流程：双重授权校验（环境 CIDR 白名单 + ScanTarget 显式登记）→ 有上限的
TCP 端口扫描 → 协议级指纹识别（复用 device_inventory，含横幅兜底）→
设备/服务/组件清单落库 → 设备级 CVE 匹配与风险更新 → ScanRun 审计记录。

边界（写入每次运行的 findings）：
- 只做指纹识别，不发任何漏洞利用载荷；
- 无响应不能证明服务不存在；横幅与自报身份可被伪造；
- 端口数、并发、超时受环境变量上限约束，不做大规模扫描。
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app import models
from app.services.device_access import allowed_host
from app.services.device_inventory import upsert_device
from app.services.device_vulnerability import run_device_matching

# 默认端口画像：常见互联网服务端口，全部有对应探测路线（协议或横幅）。
DEFAULT_SCAN_PORTS = [
    21, 22, 23, 25, 80, 443, 554, 1883, 3306, 3389,
    5432, 587, 6379, 8000, 8080, 8443, 8554, 8883, 9200,
]

_BOUNDARIES = [
    "端口开放仅来自 TCP 连接成功；协议结论以真实响应为准，横幅兜底端口未识别协议。",
    "横幅与自报身份可被伪造；版本结论置信度有限，需结合资产登记或登录采集复核。",
    "本次未发送任何漏洞利用载荷；CVE 命中为版本比对结论，不代表利用成功。",
]


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def scan_limits() -> dict:
    """读取扫描上限配置（环境变量，均有安全上限）。"""
    def _int_env(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)))
        except (TypeError, ValueError):
            return default

    def _float_env(name: str, default: float) -> float:
        try:
            return float(os.getenv(name, str(default)))
        except (TypeError, ValueError):
            return default

    return {
        "max_ports": int(_clamp(_int_env("LINUXGUARD_SCAN_MAX_PORTS", 128), 1, 1024)),
        "timeout": round(_clamp(_float_env("LINUXGUARD_SCAN_TIMEOUT", 2.5), 0.5, 8.0), 2),
        "workers": int(_clamp(_int_env("LINUXGUARD_SCAN_WORKERS", 16), 1, 64)),
        "default_ports": list(DEFAULT_SCAN_PORTS),
    }


def normalize_ports(raw: list[int] | None) -> list[int]:
    """校验并归一化端口列表；None 使用默认画像。"""
    limits = scan_limits()
    if raw is None:
        return list(DEFAULT_SCAN_PORTS)
    if len(raw) > limits["max_ports"]:
        raise ValueError(f"单次扫描最多 {limits['max_ports']} 个端口（LINUXGUARD_SCAN_MAX_PORTS）")
    if any(not isinstance(port, int) or port < 1 or port > 65535 for port in raw):
        raise ValueError("端口必须在 1–65535 之间")
    return sorted(set(raw))


def target_ports(target: models.ScanTarget, override: list[int] | None = None) -> list[int]:
    """目标扫描端口：本次覆盖 > 目标画像 > 默认画像。"""
    if override:
        return normalize_ports(override)
    profile = json.loads(target.ports_profile_json or "[]")
    return normalize_ports(profile if profile else None)


def new_scan_run_id() -> str:
    return "SCAN-" + secrets.token_hex(6).upper()


def sweep_ports(host: str, ports: list[int], timeout: float, workers: int) -> list[int]:
    """有上限的 TCP 连接扫描：仅判定端口开放，不做协议判断。"""
    def _check(port: int) -> int | None:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_check, ports))
    return sorted(port for port in results if port is not None)


def execute_scan(db: Session, run: models.ScanRun, target: models.ScanTarget,
                 ports: list[int], timeout: float, workers: int) -> models.ScanRun:
    """同步执行一次扫描并更新 ScanRun（由后台线程或测试直接调用）。"""
    run.status = "running"
    run.ports_scanned = json.dumps(ports)
    run.ports_scanned_count = len(ports)
    db.commit()

    # 双重授权第一层：扫描时重新校验环境网段白名单（配置可能在登记后收紧）。
    host = allowed_host(target.ip_address)  # ValueError → 调用方记为 failed

    open_ports = sweep_ports(host, ports, timeout, workers)
    run.open_ports_json = json.dumps(open_ports)
    run.open_ports_count = len(open_ports)
    db.commit()

    if not open_ports:
        run.status = "completed"
        run.findings = json.dumps({
            "host": host, "summary": "指定端口均无响应",
            "boundaries": _BOUNDARIES[:1] + ["无响应不能证明目标离线，仅说明本次扫描端口未开放。"],
        }, ensure_ascii=False)
        run.completed_at = models.utcnow()
        target.last_run_id = run.id
        db.commit()
        return run

    try:
        device, report = upsert_device(
            db, host, ports=open_ports, timeout=max(timeout, 2.0),
            banner_fallback=True, scan_scope="internet_target",
            device_type_default="internet_server",
        )
    except ValueError as exc:
        # TCP 可连但无可读协议响应（横幅兜底也无法取证）：如实记录为无识别结果。
        run.status = "completed"
        run.findings = json.dumps({
            "host": host, "summary": f"端口开放但未取得可识别的协议响应：{exc}",
            "boundaries": _BOUNDARIES,
        }, ensure_ascii=False)
        run.completed_at = models.utcnow()
        target.last_run_id = run.id
        db.commit()
        return run

    match_result = run_device_matching(db, device)  # 内部已更新 risk_score/security_status

    open_services = [service for service in device.services if service.status == "open"]
    identified = [
        {"port": service.port, "service_type": service.service_type,
         "product": service.product, "version": service.version, "auth_state": service.auth_state}
        for service in sorted(open_services, key=lambda item: item.port)
        if service.service_type != "unknown"
    ]
    unmatched = [
        {"port": service.port, "banner": service.banner}
        for service in sorted(open_services, key=lambda item: item.port)
        if service.service_type == "unknown"
    ]
    run.identified_services_json = json.dumps(identified, ensure_ascii=False)
    run.unmatched_ports_json = json.dumps(unmatched, ensure_ascii=False)
    run.identified_count = len(identified)
    run.vulnerability_hits = int(match_result.get("affected_count", 0))
    run.device_id = device.device_id
    run.findings = json.dumps({
        "host": host,
        "device_name": device.device_name,
        "device_type": device.device_type,
        "identity_source": device.identity_source,
        "identity_confidence": device.identity_confidence,
        "risk_score": device.risk_score,
        "risk_score_basis": device.risk_score_basis,
        "security_status": device.security_status,
        "match_stats": match_result.get("stats", {}),
        "silent_ports": report.get("no_response", []),
        "boundaries": _BOUNDARIES,
    }, ensure_ascii=False)
    run.status = "completed"
    run.completed_at = models.utcnow()
    target.last_run_id = run.id
    db.commit()
    return run


def start_scan_run(run_id: str, engine: Engine) -> None:
    """后台线程执行扫描。engine 由调用方（路由）传入：与请求会话同库，
    测试环境下即测试数据库，避免误写生产/启动库。"""
    def worker() -> None:
        db = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
        run = None
        try:
            run = db.query(models.ScanRun).filter_by(run_id=run_id).one()
            target = db.get(models.ScanTarget, run.target_id)
            if target is None:
                raise ValueError("扫描目标不存在或已被删除")
            limits = scan_limits()
            ports = json.loads(run.ports_scanned or "[]") or list(DEFAULT_SCAN_PORTS)
            execute_scan(db, run, target, ports, limits["timeout"], limits["workers"])
        except Exception as exc:  # 含授权失效、网络异常：运行记为 failed 并保留原因
            try:
                if run is not None:
                    run.status = "failed"
                    run.error = f"scan: {type(exc).__name__}: {exc}"
                    run.completed_at = models.utcnow()
                    db.commit()
            except Exception:
                pass
        finally:
            db.close()

    threading.Thread(target=worker, daemon=True).start()
