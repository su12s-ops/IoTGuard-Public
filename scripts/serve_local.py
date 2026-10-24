"""Run the built IoTGuard console and API on one loopback origin.

Uses an isolated local data directory by default, never reads operator .env files,
and always disables device writes and startup result cleanup. No demo data is
created automatically. Import inventory through the UI/API to populate a round.
"""
from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
import secrets
import sys

from starlette.exceptions import HTTPException
from starlette.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parents[1]


class ConsoleFiles(StaticFiles):
    """SPA deep links fall back to index; API and missing assets stay 404."""

    async def get_response(self, path, scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            if exc.status_code != 404 or scope["method"] not in {"GET", "HEAD"}:
                raise
            # Only known client-side routes receive the app shell. A missing
            # script, typo or unknown API must not return HTML with status 200.
            route = path.replace("\\", "/").strip("/")
            routes = {"", "assets", "risks", "agents", "repairs", "runtime",
                      "reports", "soc"}
            if route not in routes and not re.fullmatch(r"risks/(?:[0-9]+|CVE-[0-9]{4}-[0-9]{4,})", route):
                raise
            return await super().get_response("index.html", scope)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "reports/local-runtime")
    parser.add_argument("--frontend-dir", type=Path, default=ROOT / "frontend/dist")
    args = parser.parse_args(argv)
    frontend = args.frontend_dir.resolve()
    if not (frontend / "index.html").is_file():
        parser.error("Frontend build missing: run npm run build in frontend first")
    data = args.data_dir.resolve()
    data.mkdir(parents=True, exist_ok=True)
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"
    os.environ["LINUXGUARD_DATA_DIR"] = str(data)
    os.environ["LINUXGUARD_DATABASE_URL"] = "sqlite:///" + (data / "iotguard.db").as_posix()
    os.environ["LINUXGUARD_EVENT_FILE"] = str(data / "events.jsonl")
    os.environ["REPORT_ARCHIVE_DIR"] = str(data / "archives")
    os.environ["LINUXGUARD_DEPLOYMENT_MODE"] = "standard"
    for name in ("LINUXGUARD_ENABLE_DEVICE_REPAIR", "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR",
                 "LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR", "LINUXGUARD_ARCHIVE_ON_STARTUP"):
        os.environ[name] = "0"
    for name in ("LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE", "LINUXGUARD_UBUNTU_LAB_ASSET_SCOPE",
                 "LINUXGUARD_OPENWRT_LOG_CONNECTION_IDS"):
        os.environ[name] = ""
    os.environ.setdefault("LINUXGUARD_UNIFIED_PIPELINE", "on")
    if not os.environ.get("LINUXGUARD_CONTROL_TOKEN"):
        token_path = data / "control-token.txt"
        if not token_path.exists():
            with token_path.open("x", encoding="utf-8") as handle:
                handle.write(secrets.token_urlsafe(32))
        token = token_path.read_text(encoding="utf-8").strip()
        if not token:
            parser.error(f"Empty control token file: {token_path}")
        os.environ["LINUXGUARD_CONTROL_TOKEN"] = token
        print(f"Operator token file (keep private): {token_path}", flush=True)
    sys.path.insert(0, str(ROOT / "backend"))
    from app.main import app
    import uvicorn
    app.mount("/", ConsoleFiles(directory=frontend, html=True), name="console")
    print(f"Console and API: http://{args.host}:{args.port}; data: {data}", flush=True)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
