import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("LINUXGUARD_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# 加载 .env 文件（优先级：.env.local > .env）
_env_local = BASE_DIR / ".env.local"
_env_default = BASE_DIR / ".env"
if os.getenv("PYTHON_DOTENV_DISABLED") == "1" or os.getenv("LINUXGUARD_DEPLOYMENT_MODE") == "collection_only":
    pass
elif _env_local.exists():
    load_dotenv(_env_local)
elif _env_default.exists():
    load_dotenv(_env_default)

DATABASE_URL = os.getenv("LINUXGUARD_DATABASE_URL", f"sqlite:///{DATA_DIR / 'linuxguard.db'}")
if os.getenv("LINUXGUARD_DEPLOYMENT_MODE") == "collection_only":
    from app.integration_runtime import validate_environment
    validate_environment(os.environ)
API_TITLE = os.getenv("LINUXGUARD_API_TITLE", "LinuxGuard API")
API_VERSION = os.getenv("LINUXGUARD_API_VERSION", "0.2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
