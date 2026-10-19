"""Foreground API service entrypoint enforcing read-only device defaults."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / "backend"))
from dotenv import load_dotenv

env_file = ROOT / "backend/.env.local"
load_dotenv(env_file if env_file.exists() else ROOT / "backend/.env")
for name in ("LINUXGUARD_ENABLE_DEVICE_REPAIR", "LINUXGUARD_ENABLE_UBUNTU_LAB_REPAIR",
             "LINUXGUARD_ENABLE_OPENWRT_LAB_REPAIR", "LINUXGUARD_ARCHIVE_ON_STARTUP"):
    os.environ[name] = "0"
os.environ["LINUXGUARD_OPENWRT_LAB_ASSET_SCOPE"] = ""
log_dir = ROOT / "backend/data"
log_dir.mkdir(exist_ok=True)
stream = (log_dir / "api-service.log").open("a", encoding="utf-8", buffering=1)
sys.stdout = sys.stderr = stream

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000)
