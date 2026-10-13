"""Start the existing backend as an Ubuntu collection-only integration node.

--check performs local metadata validation only. --serve is a separate explicit
action and requires Linux. Existing runtime reuse requires --resume and a marker;
no original database, dotenv, inventory, or key is copied into this directory.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import sys


BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from app.integration_runtime import DATABASE_NAME, MARKER_NAME  # Does not import config/database.


def validate_arguments(runtime_dir, node_id, target, resume=False):
    if not runtime_dir.is_absolute():
        raise ValueError("运行目录必须为独立目录的绝对路径")
    root = runtime_dir.resolve()
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", node_id):
        raise ValueError("采集节点名称格式无效")
    address = ipaddress.ip_address(target)
    if address.version != 4 or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError("须明确指定已授权 OpenWrt 的 IPv4 管理地址")
    marker = {"profile": "collection_only", "database": DATABASE_NAME, "node_id": node_id, "target": str(address)}
    if resume:
        try:
            existing = json.loads((root / MARKER_NAME).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError("恢复运行须有本启动器创建的联调标记") from exc
        if existing != marker or not (root / DATABASE_NAME).is_file() or (root / DATABASE_NAME).is_symlink():
            raise ValueError("联调标记、节点、目标或数据库不一致")
    elif root.exists() and any(root.iterdir()):
        raise ValueError("新联调必须使用不存在或为空的独立目录；禁止覆盖已有数据")
    script = BACKEND.parent / "collector" / "collect_openwrt_asset.sh"
    if not script.is_file():
        raise ValueError("部署缺少相邻的 collector/collect_openwrt_asset.sh")
    return root, marker, hashlib.sha256(script.read_text(encoding="utf-8").encode()).hexdigest()


def configure(root, marker):
    # All storage paths are chosen by this launcher, never inherited from an old .env.
    os.environ.update({"PYTHON_DOTENV_DISABLED": "1", "LINUXGUARD_DEPLOYMENT_MODE": "collection_only",
        "LINUXGUARD_INTEGRATION_RUNTIME": str(root), "LINUXGUARD_DATA_DIR": str(root / "data"),
        "LINUXGUARD_DATABASE_URL": "sqlite:///" + str(root / DATABASE_NAME),
        "LINUXGUARD_EVENT_FILE": str(root / "events.jsonl"), "REPORT_ARCHIVE_DIR": str(root / "archives"),
        "LINUXGUARD_COLLECTOR_NODE_ID": marker["node_id"], "LINUXGUARD_DISCOVERY_CIDRS": marker["target"] + "/32",
        "LINUXGUARD_ARCHIVE_ON_STARTUP": "0", "LINUXGUARD_ENABLE_DEVICE_REPAIR": "0",
        "LINUXGUARD_REPAIR_MANIFEST": "", "DEEPSEEK_API_KEY": "", "NVD_API_KEY": ""})
    for name in ("VM_HOST", "VM_HOSTS", "VM_PORT", "VM_PORTS", "VM_USER", "VM_PASS", "BIONIC_CONTAINER"):
        os.environ[name] = ""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--serve", action="store_true")
    args = parser.parse_args(argv)
    try:
        root, marker, script_hash = validate_arguments(args.runtime_dir, args.node_id, args.target, args.resume)
        ipaddress.ip_address(args.bind)
        if not 1 <= args.port <= 65535:
            raise ValueError("API 端口无效")
        if args.check:
            print(json.dumps({"status": "local_metadata_checked", "node_id": marker["node_id"],
                "runtime_directory": str(root), "database": str(root / DATABASE_NAME), "profile": "collection_only",
                "collector_sha256": script_hash, "network_attempted": False, "key_loaded": False,
                "control_configured": bool(os.getenv("LINUXGUARD_CONTROL_TOKEN")),
                "ssh_host_identity": "not_attempted", "ssh_authentication": "not_attempted"}, ensure_ascii=False, indent=2))
            return 0
        if platform.system() != "Linux":
            raise ValueError("真实采集节点须在 Ubuntu/Linux 运行；Windows 仅允许 --check")
        if not os.getenv("LINUXGUARD_CONTROL_TOKEN"):
            raise ValueError("须由操作人员在本地设置操作令牌，启动器不会读取旧配置文件")
        root.mkdir(parents=True, exist_ok=True)
        # Hold a process lock until uvicorn exits, including after crashes/restarts.
        import fcntl
        with (root / ".node.lock").open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("该运行目录已有采集节点运行，禁止并发启动或恢复") from exc
            if not args.resume:
                (root / MARKER_NAME).write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")
            configure(root, marker)
            # App/database imports occur only after runtime validation and lock acquisition.
            from app.database import init_db, SessionLocal
            init_db()
            if args.resume:
                from app.services.collection_tasks import recover
                with SessionLocal() as db:
                    recover(db)
            import uvicorn
            uvicorn.run("app.main:app", host=args.bind, port=args.port, workers=1)
        return 0
    except (ValueError, OSError) as exc:
        # Do not display library exception text or operator-supplied environment values.
        print(json.dumps({"status": "refused", "error_type": type(exc).__name__,
                          "detail": "联调启动条件不满足；未连接设备。请核对目录、节点、目标、模式及本地令牌配置"}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
